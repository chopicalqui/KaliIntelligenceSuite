# -*- coding: utf-8 -*-
"""
submit in-scope web applications (except TCP ports 5985 and 5986) to Burp Suite Professional for scanning via Burp's
REST API. use this collector with caution as these scans are aggressive and therefore, might cause damage. therefore,
it might be desired to limit the number of OS commands by using the optional argument --filter. note that Burp's scan
results are not fed back into KIS
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

import os
import logging
from collectors.os.modules.osint.core import BaseKisImport
from collectors.os.modules.core import DomainCollector
from collectors.os.modules.core import HostCollector
from collectors.os.modules.core import BaseCollector
from collectors.os.modules.http.core import HttpServiceDescriptor
from collectors.apis.burpsuite import BurpSuiteProfessional
from database.model import Source
from database.model import Command
from database.model import CollectorName
from database.model import Host
from database.model import HostName
from database.model import VhostChoice
from collectors.os.core import PopenCommand
from view.core import ReportItem
from sqlalchemy.orm.session import Session
from typing import List

logger = logging.getLogger('burpsuitepro')


class CollectorClass(BaseKisImport, HostCollector, DomainCollector):
    """This class implements a collector module that is automatically incorporated into the application."""

    def __init__(self, **kwargs):
        super().__init__(priority=91225,
                         timeout=0,
                         argument_name="--burpsuitepro",
                         returned_item="",
                         source=BurpSuiteProfessional.SOURCE_NAME,
                         **kwargs)

    @staticmethod
    def get_argparse_arguments():
        return {"help": __doc__, "action": "store_true"}

    def api_credentials_available(self) -> bool:
        """
        This method shall be implemented by sub classes. They should verify whether their API keys are set in the
        configuration file
        :return: Return true if API credentials are set, else false
        """
        return self._api_config.config.get(BurpSuiteProfessional.SOURCE_NAME, "api_url") and \
               self._api_config.config.get(BurpSuiteProfessional.SOURCE_NAME, "api_key") and \
               self._api_config.config.get(BurpSuiteProfessional.SOURCE_NAME, "api_version") and \
               self._api_config.config.get(BurpSuiteProfessional.SOURCE_NAME, "resource_pool") and \
               self._api_config.config.get(BurpSuiteProfessional.SOURCE_NAME, "scan_named_configuration")

    def create_domain_commands(self,
                               session: Session,
                               host_name: HostName,
                               collector_name: CollectorName) -> List[BaseCollector]:
        """This method creates and returns a list of commands based on the given service.

        This method determines whether the command exists already in the database. If it does, then it does nothing,
        else, it creates a new Collector entry in the database for each new command as well as it creates a corresponding
        operating system command and attaches it to the respective newly created Collector class.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param host_name: The host name based on which commands shall be created.
        :param collector_name: The name of the collector as specified in table collector_name
        :return: List of Collector instances that shall be processed.
        """
        collectors = []
        paths = []
        # Only submit vhosts to burp, if user specified vhost processing
        if self._vhost and (self._vhost == VhostChoice.all or self._vhost == VhostChoice.domain):
            # Identify HTTP services
            descriptor = HttpServiceDescriptor()
            for service in host_name.services:
                if descriptor.match_nmap_service_name(service) and service.port not in [5985, 5986]:
                    paths += [service.get_urlparse().geturl()]
            if paths:
                # Create output directory
                output_path = self.create_path(host_name=host_name)
                # Create input file
                input_file = self.create_file_path(host_name=host_name, file_extension="txt")
                with open(input_file, "w") as file:
                    file.write(os.linesep.join(paths))
                # Create command
                collectors = self._get_commands(session=session,
                                                collector_name=collector_name,
                                                host_name=host_name,
                                                workspace=host_name.domain_name.workspace,
                                                input_file=input_file,
                                                output_path=output_path)
        return collectors

    def create_host_commands(self,
                             session: Session,
                             host: Host,
                             collector_name: CollectorName) -> List[BaseCollector]:
        """This method creates and returns a list of commands based on the given service.

        This method determines whether the command exists already in the database. If it does, then it does nothing,
        else, it creates a new Collector entry in the database for each new command as well as it creates a corresponding
        operating system command and attaches it to the respective newly created Collector class.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param host: The host based on which commands shall be created.
        :param collector_name: The name of the collector as specified in table collector_name
        :return: List of Collector instances that shall be processed.
        """
        collectors = []
        paths = []
        if self._vhost is None or self._vhost == VhostChoice.all:
            # Identify HTTP services
            descriptor = HttpServiceDescriptor()
            for service in host.services:
                if descriptor.match_nmap_service_name(service) and service.port not in [5985, 5986]:
                    paths += [service.get_urlparse().geturl()]
            if paths:
                # Create output directory
                output_path = self.create_path(host=host)
                # Create input file
                input_file = self.create_file_path(host=host, file_extension="txt")
                with open(input_file, "w") as file:
                    file.write(os.linesep.join(paths))
                # Create command
                collectors = self._get_commands(session=session,
                                                collector_name=collector_name,
                                                host=host,
                                                workspace=host.workspace,
                                                input_file=input_file,
                                                output_path=output_path)
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
