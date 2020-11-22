# -*- coding: utf-8 -*-
"""
submit in-scope web applications to Burp Suite Professional for scanning via Burp's REST API. use this collector with
caution as these scans are aggressive and therefore, might case damage. therefore, it might be desired to limit the
number of OS commands by using the optional argument --filter. note that Burp's scan results are not fed back into KIS
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
from collectors.os.modules.core import HostNameServiceCollector
from collectors.os.modules.core import ServiceCollector
from collectors.os.modules.core import BaseCollector
from collectors.os.modules.http.core import HttpServiceDescriptor
from collectors.apis.burpsuite import BurpSuiteProfessional
from database.model import Source
from database.model import Command
from database.model import CollectorName
from database.model import Service
from collectors.os.core import PopenCommand
from view.core import ReportItem
from sqlalchemy.orm.session import Session
from typing import List

logger = logging.getLogger('burpsuitepro')


class CollectorClass(BaseKisImport, ServiceCollector, HostNameServiceCollector):
    """This class implements a collector module that is automatically incorporated into the application."""

    def __init__(self, **kwargs):
        super().__init__(priority=91225,
                         timeout=0,
                         service_descriptors=HttpServiceDescriptor(),
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

    def create_host_name_service_commands(self,
                                          session: Session,
                                          service: Service,
                                          collector_name: CollectorName) -> List[BaseCollector]:
        """This method creates and returns a list of commands based on the given host name.

        This method determines whether the command exists already in the database. If it does, then it does nothing,
        else, it creates a new Collector entry in the database for each new command as well as it creates a corresponding
        operating system command and attaches it to the respective newly created Collector class.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param service: The service based on which commands shall be created.
        :param collector_name: The name of the collector as specified in table collector_name
        :return: List of Collector instances that shall be processed.
        """
        result = []
        if service.host_name.name:
            result = self.create_service_commands(session, service, collector_name)
        return result

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
        if self.match_nmap_service_name(service):
            # Create output directory
            output_path = self.create_path(service=service)
            # Create input file
            input_file = self.create_file_path(service=service, file_extension="txt")
            paths = [service.get_urlparse().geturl()]
            results = os.linesep.join(paths)
            if results:
                with open(input_file, "w") as file:
                    file.write(results)
                # Create command
                collectors = self._get_commands(session=session,
                                                collector_name=collector_name,
                                                service=service,
                                                workspace=service.workspace,
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
