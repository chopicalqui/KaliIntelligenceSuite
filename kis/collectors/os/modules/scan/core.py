# -*- coding: utf-8 -*-
"""
implements all base functionality for RPC collectors
"""

__author__ = "Lukas Reiter"
__license__ = "GPL v3.0"
__copyright__ = """Copyright 2018 Lukas Reiter

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
__version__ = 0.1

import re
import logging
import os
from typing import List
from database.model import Network
from database.model import CollectorName
from database.model import Command
from database.model import Source
from database.model import HostName
from database.model import ServiceState
from database.model import ExecutionInfoType
from view.core import ReportItem
from configs.config import ScannerConfig
from collectors.os.core import PopenCommand
from collectors.os.core import PopenCommandWithoutStderr
from collectors.os.modules.core import BaseCollector
from collectors.filesystem.nmap import DatabaseImporter as NmapDatabaseImporter
from collectors.filesystem.masscan import DatabaseImporter as MasscanDatabaseImporter
from sqlalchemy.orm.session import Session

logger = logging.getLogger('collector')


class BaseNmap(BaseCollector):
    """
    This class implements basic functionality for collectors that use Nmap.
    """

    def __init__(self,
                 priority: int,
                 timeout: int,
                 **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         **kwargs)
        self._nmap_config = ScannerConfig()

    @staticmethod
    def get_argparse_arguments():
        return {"help": __doc__, "type": str, "metavar": "TYPE", "nargs": "+"}

    def _create_domain_commands(self,
                                session: Session,
                                host_name: HostName,
                                host_names: List[str],
                                collector_name: CollectorName,
                                nmap_arguments: List[str],
                                interesting_ports: List[int],
                                nmap_options: List[str],
                                nse_scripts: List[str],
                                ipv6: bool) -> List[BaseCollector]:
        results = []
        if host_names:
            # write in-scope host names to file
            tool_path = self.create_file_path(host_name=host_name)
            if not os.path.exists(tool_path):
                os.makedirs(tool_path)
            input_file = os.path.join(tool_path, "host_names6.txt" if ipv6 else "host_names4.txt")
            with open(input_file, "w") as f:
                for item in host_names:
                    f.write(item + os.linesep)
            # create command
            results = self.create_commands(session=session,
                                           host_name=host_name,
                                           input_file=input_file,
                                           arguments=nmap_arguments,
                                           nmap_options=nmap_options,
                                           interesting_ports=interesting_ports,
                                           nse_scripts=nse_scripts,
                                           collector_name=collector_name,
                                           ipv6=ipv6)
        return results

    def _create_commands(self,
                         session: Session,
                         collector_name: CollectorName,
                         nmap_options: List[str] = [],
                         nse_scripts: List[str] = [],
                         network: Network = None,
                         host_name: HostName = None,
                         input_file: str = None,
                         exclude_hosts_file: str = None,
                         ipv6: bool = False) -> List[BaseCollector]:
        """This method creates and returns a list of commands based on the given service.

        This method determines whether the command exists already in the database. If it does, then it does nothing,
        else, it creates a new Collector entry in the database for each new command as well as it creates a corresponding
        operating system command and attaches it to the respective newly created Collector class.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param network: The IPv4 network based on which commands shall be created.
        :param collector_name: The name of the collector as specified in table collector_name
        :param nmap_options: Additional options for Nmap
        :param nse_scripts: The names of the NSE scripts
        :return: List of Collector instances that shall be processed.
        """
        collectors = []
        nse_scripts_tmp = []
        if host_name and network and input_file:
            raise ValueError("either host name or IPv4 network must be specified")
        if network:
            target = network.network
        elif host_name:
            target = host_name.full_name
        else:
            raise ValueError("host name or IPv4 network must be specified")
        xml_file = self.create_xml_file_path(network=network,
                                             host_name=host_name,
                                             file_suffix="6" if ipv6 else "4")
        if nse_scripts:
            nse_scripts_tmp = ["--script={}".format(",".join(nse_scripts))]
        os_command = [self._path_nmap]
        os_command += self._nmap_config.nmap_general_settings
        os_command += nmap_options
        os_command += nse_scripts_tmp
        if ipv6:
            os_command.append("-6")
        os_command += ["-oX", ExecutionInfoType.xml_output_file.argument]
        if input_file:
            os_command += ["-iL", ExecutionInfoType.input_file.argument]
        else:
            os_command.append(target)
        if exclude_hosts_file:
            os_command += ["--excludefile", ExecutionInfoType.input_file_2.argument]
        collector = self._get_or_create_command(session,
                                                os_command,
                                                collector_name,
                                                network=network,
                                                host_name=host_name,
                                                xml_file=xml_file,
                                                input_file=input_file,
                                                input_file_2=exclude_hosts_file)
        collectors.append(collector)
        return collectors

    def create_commands(self,
                        session: Session,
                        arguments: List[str],
                        nmap_options: List[str],
                        interesting_ports: List[int],
                        nse_scripts: List[str],
                        collector_name: CollectorName,
                        network: Network = None,
                        host_name: HostName = None,
                        input_file: str = None,
                        exclude_hosts_file: str = None,
                        ipv6: bool = False) -> List[BaseCollector]:
        """This method creates and returns a list of commands based on the given IPv4 address or host name.

        This method determines whether the command exists already in the database. If it does, then it does nothing,
        else, it creates a new Collector entry in the database for each new command as well as it creates a corresponding
        operating system command and attaches it to the respective newly created Collector class.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param network: The IPv4 network based on which commands shall be created
        :param arguments: List of arguments provided by user
        :param nmap_options: Additional options for Nmap
        :param collector_name: The name of the collector as specified in table collector_name
        :return: List of Collector instances that shall be processed.
        """
        collectors = []
        ports = {}
        additional_ports = []
        re_port_range = re.compile("^[0-9]{1,5}-[0-9]{1,5}$")
        re_top = re.compile("^top([0-9]{1,5})$", re.IGNORECASE)
        if (network is not None and network.network != "0.0.0.0/0" and network.network != "::/0") or (
                host_name is not None and host_name.name is None and host_name.domain_name
        ):
            for item in arguments:
                match_top = re_top.match(item)
                if match_top:
                    nmap_options_per_command = list(nmap_options)
                    top_ports = match_top.group(1)
                    nmap_options_per_command += ["--top-ports", top_ports]
                    collectors += self._create_commands(session=session,
                                                        network=network,
                                                        collector_name=collector_name,
                                                        nmap_options=nmap_options_per_command,
                                                        nse_scripts=nse_scripts,
                                                        host_name=host_name,
                                                        exclude_hosts_file=exclude_hosts_file,
                                                        input_file=input_file,
                                                        ipv6=ipv6)
                elif "interesting" == item:
                    additional_ports = interesting_ports
                elif "all" == item:
                    nmap_options_per_command = list(nmap_options)
                    nmap_options_per_command += ["-p", "0-65535"]
                    collectors += self._create_commands(session=session,
                                                        network=network,
                                                        collector_name=collector_name,
                                                        nmap_options=nmap_options_per_command,
                                                        nse_scripts=nse_scripts,
                                                        host_name=host_name,
                                                        exclude_hosts_file=exclude_hosts_file,
                                                        input_file=input_file,
                                                        ipv6=ipv6)
                elif item.isnumeric() or re_port_range.match(item):
                    ports[item] = True
                else:
                    raise ValueError("invalid argument '{}' for collector '{}'".format(item, self.name))
            for item in additional_ports:
                ports[item] = True
            if ports:
                nmap_options_per_command = list(nmap_options)
                ports_str = ",".join(ports)
                nmap_options_per_command += ["-p", ports_str]
                collectors += self._create_commands(session=session,
                                                    network=network,
                                                    collector_name=collector_name,
                                                    nmap_options=nmap_options_per_command,
                                                    nse_scripts=nse_scripts,
                                                    host_name=host_name,
                                                    exclude_hosts_file=exclude_hosts_file,
                                                    input_file=input_file,
                                                    ipv6=ipv6)
        return collectors

    def verify_results(self, session: Session,
                       command: Command,
                       source: Source,
                       report_item: ReportItem,
                       process: PopenCommand = None, **kwargs) -> None:
        """This method analyses the results of the command execution.

        After the execution, this method checks the OS command's results to determine the command's execution status as
        well as existing vulnerabilities (e.g. weak login credentials, NULL sessions, hidden Web folders). The
        stores the output in table command. In addition, the collector might add derived information to other tables as
        well.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param command: The command instance that contains the results of the command execution
        :param source: The source object of the current collector
        :param report_item: Item that can be used for reporting potential findings in the UI
        :param process: The PopenCommand object that executed the given result. This object holds stderr, stdout, return
        code etc.
        """
        if command.return_code and command.return_code > 0:
            self._set_execution_failed(session, command)
            return
        with open(os.devnull, "w") as f:
            di = NmapDatabaseImporter(session,
                                      command.workspace,
                                      [],
                                      stdout=f,
                                      report_item=report_item,
                                      service_states=[ServiceState.Open, ServiceState.Closed])
            di.import_content(command.xml_output)


class BaseMasscan(BaseCollector):
    """
    This class implements basic functionality for collectors that use Masscan.
    """

    def __init__(self,
                 priority: int,
                 timeout: int,
                 **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         execution_class=PopenCommandWithoutStderr,
                         **kwargs)
        self._masscan_config = ScannerConfig()

    def _create_commands(self,
                         session: Session,
                         collector_name: CollectorName,
                         masscan_options: List[str],
                         network: Network = None,
                         host_name: HostName = None,
                         input_file: str = None,
                         exclude_hosts_file: str = None) -> List[BaseCollector]:
        """This method creates and returns a list of commands based on the given service.

        This method determines whether the command exists already in the database. If it does, then it does nothing,
        else, it creates a new Collector entry in the database for each new command as well as it creates a corresponding
        operating system command and attaches it to the respective newly created Collector class.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param network: The IPv4 network based on which commands shall be created.
        :param collector_name: The name of the collector as specified in table collector_name
        :return: List of Collector instances that shall be processed.
        """
        collectors = []
        if host_name and network:
            raise ValueError("either host name or IPv4 network must be specified")
        if network:
            target = network.network
        elif host_name:
            target = host_name.full_name
        else:
            raise ValueError("host name or IPv4 network must be specified")
        xml_file = self.create_xml_file_path(network=network, host_name=host_name)
        os_command = [self._path_masscan]
        os_command += self._masscan_config.masscan_general_settings
        os_command += masscan_options
        os_command += ["-oX", ExecutionInfoType.xml_output_file.argument]
        if input_file:
            os_command += ["-iL", ExecutionInfoType.input_file.argument]
        else:
            os_command.append(target)
        if exclude_hosts_file:
            os_command += ["--excludefile", ExecutionInfoType.input_file_2.argument]
        collector = self._get_or_create_command(session,
                                                os_command,
                                                collector_name,
                                                network=network,
                                                host_name=host_name,
                                                xml_file=xml_file,
                                                input_file=input_file,
                                                input_file_2=exclude_hosts_file)
        collectors.append(collector)
        return collectors

    def create_commands(self,
                        session: Session,
                        arguments: List[str],
                        interesting_ports: List[str],
                        collector_name: CollectorName,
                        network: Network = None,
                        host_name: HostName = None,
                        exclude_hosts_file: str = None,
                        input_file: str = None) -> List[BaseCollector]:
        """This method creates and returns a list of commands based on the given IPv4 address or host name.

        This method determines whether the command exists already in the database. If it does, then it does nothing,
        else, it creates a new Collector entry in the database for each new command as well as it creates a corresponding
        operating system command and attaches it to the respective newly created Collector class.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param network: The IPv4 network based on which commands shall be created
        :param arguments: List of arguments provided by user
        :param nmap_options: Additional options for Nmap
        :param collector_name: The name of the collector as specified in table collector_name
        :return: List of Collector instances that shall be processed.
        """
        collectors = []
        ports = {}
        additional_ports = []
        re_port_range = re.compile("^[0-9]{1,5}-[0-9]{1,5}$")
        re_top = re.compile("^top([0-9]{1,5})$", re.IGNORECASE)
        if network.version == 4 and network.network != "0.0.0.0/0":
            for item in arguments:
                match_top = re_top.match(item)
                if match_top:
                    top_ports = match_top.group(1)
                    collectors += self._create_commands(session=session,
                                                        network=network,
                                                        collector_name=collector_name,
                                                        masscan_options=["--top-ports", top_ports],
                                                        host_name=host_name,
                                                        exclude_hosts_file=exclude_hosts_file,
                                                        input_file=input_file)
                elif "interesting" == item:
                    additional_ports = interesting_ports
                elif "all" == item:
                    collectors += self._create_commands(session=session,
                                                        network=network,
                                                        collector_name=collector_name,
                                                        masscan_options=["-p", "0-65535"],
                                                        host_name=host_name,
                                                        exclude_hosts_file=exclude_hosts_file,
                                                        input_file=input_file)
                elif item.isnumeric() or re_port_range.match(item):
                    ports[item] = True
                else:
                    raise ValueError("invalid argument '{}' for collector '{}'".format(item, self.name))
            for item in additional_ports:
                ports[item] = True
            if ports:
                ports_str = ",".join(ports)
                collectors += self._create_commands(session=session,
                                                    network=network,
                                                    collector_name=collector_name,
                                                    masscan_options=["-p", ports_str],
                                                    host_name=host_name,
                                                    exclude_hosts_file=exclude_hosts_file,
                                                    input_file=input_file)
        return collectors

    def verify_results(self, session: Session,
                       command: Command,
                       source: Source,
                       report_item: ReportItem,
                       process: PopenCommand = None, **kwargs) -> None:
        """This method analyses the results of the command execution.

        After the execution, this method checks the OS command's results to determine the command's execution status as
        well as existing vulnerabilities (e.g. weak login credentials, NULL sessions, hidden Web folders). The
        stores the output in table command. In addition, the collector might add derived information to other tables as
        well.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param command: The command instance that contains the results of the command execution
        :param source: The source object of the current collector
        :param report_item: Item that can be used for reporting potential findings in the UI
        :param process: The PopenCommand object that executed the given result. This object holds stderr, stdout, return
        code etc.
        """
        with open(os.devnull, "w") as f:
            di = MasscanDatabaseImporter(session,
                                         command.workspace, [],
                                         down=False,
                                         stdout=f,
                                         report_item=report_item)
            di.import_content(command.xml_output)

