# -*- coding: utf-8 -*-
"""
run tool nmap on any open in-scope service to obtain additional intelligence. this collector useful after
importing masscan scan results or after executing collector tcpmasscannetwork. with this collector, nmap obtains the
service name (e.g, ssh or http) from non-standard ports, which allows subsequently executed collectors to determine
whether they apply
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

import logging
from typing import List
from collectors.os.modules.scan.core import BaseNmap
from collectors.os.modules.core import BaseCollector
from collectors.os.modules.core import ServiceCollector
from collectors.os.core import PopenCommand
from database.model import CollectorName
from database.model import Command
from database.model import Source
from database.model import Service
from database.model import ServiceState
from database.model import ProtocolType
from database.model import ExecutionInfoType
from view.core import ReportItem
from sqlalchemy.orm.session import Session

logger = logging.getLogger('anyservicenmap')


class CollectorClass(BaseNmap, ServiceCollector):
    """This class implements a collector module that is automatically incorporated into the application."""

    def __init__(self, **kwargs):
        super().__init__(priority=1350,
                         exec_user="root",
                         timeout=0,
                         **kwargs)

    @staticmethod
    def get_argparse_arguments():
        return {"help": __doc__, "action": "store_true"}

    def create_service_commands(self,
                                session: Session,
                                service: Service,
                                collector_name: CollectorName) -> List[BaseCollector]:
        """This method creates and returns a list of commands based on the given service.

        This method determines whether the command exists already in the database. If it does, then it does nothing,
        else, it creates a new Collector entry in the database for each new command as well as it creates a corresponding
        operating system command and attaches it to the respective newly created Collector class.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param service: The service based on which commands shall be created.
        :param collector_name: The name of the collector as specified in table collector_name
        :return: List of Collector instances that shall be processed.
        """
        collectors = []
        if service.state == ServiceState.Open:
            xml_file = self.create_xml_file_path(service=service)
            if service.protocol == ProtocolType.tcp:
                nmap_options = self._nmap_config.nmap_tcp_options
                nse_scripts = self._nmap_config.tcp_nse_scripts
            else:
                nmap_options = self._nmap_config.nmap_udp_options
                nse_scripts = self._nmap_config.udp_nse_scripts
            os_command = [self._path_nmap, "-p", service.port, "-Pn"]
            if service.host.version == 6:
                os_command.append("-6")
            os_command += self._nmap_config.nmap_general_settings
            os_command += nmap_options
            os_command += ["--script={}".format(",".join(nse_scripts))]
            os_command += ["-oX", ExecutionInfoType.xml_output_file.argument]
            os_command.append(service.host.address)
            collector = self._get_or_create_command(session,
                                                    os_command,
                                                    collector_name,
                                                    service=service,
                                                    xml_file=xml_file)
            collectors.append(collector)
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
        super().verify_results(session=session,
                               command=command,
                               source=source,
                               report_item=report_item,
                               process=process)
        command.hide = True
