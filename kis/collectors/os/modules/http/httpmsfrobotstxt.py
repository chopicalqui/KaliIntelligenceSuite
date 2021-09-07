# -*- coding: utf-8 -*-
"""
run Metasploit auxiliary module robots_txt on each identified in-scope HTTP(S) service to enumerate existing URIs. use
optional argument --http-proxy to specify an HTTP proxy
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
from typing import List
from collectors.os.modules.core import ServiceCollector
from collectors.os.modules.core import HostNameServiceCollector
from collectors.os.modules.http.core import BaseHttpMsfConsole
from collectors.os.modules.core import BaseCollector
from collectors.os.core import PopenCommand
from database.model import Command
from database.model import CollectorName
from database.model import Service
from database.model import Source
from view.core import ReportItem
from sqlalchemy.orm.session import Session

logger = logging.getLogger('httpmsfrobotstxt')


class CollectorClass(BaseHttpMsfConsole, ServiceCollector, HostNameServiceCollector):
    """This class implements a collector module that is automatically incorporated into the application."""

    def __init__(self, **kwargs):
        super().__init__(priority=1900,
                         timeout=0,
                         **kwargs)
        self._re_paths = [re.compile("^allow: *(?P<path>/.*)$", re.IGNORECASE),
                          re.compile("^disallow: *(?P<path>/.*)$", re.IGNORECASE),
                          re.compile("^(?P<path>/.*)", re.IGNORECASE)]
        self._re_no_response = re.compile("^.*? /robots.txt - No response$")

    @staticmethod
    def get_argparse_arguments():
        return {"help": __doc__, "action": "store_true"}

    @staticmethod
    def get_invalid_argument_regex() -> List[re.Pattern]:
        """
        This method returns a regular expression that allows KIS to identify invalid arguments
        """
        return []

    @staticmethod
    def get_service_unreachable_regex() -> List[re.Pattern]:
        """
        This method returns a regular expression that allows KIS to identify services that are not reachable
        """
        return []

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
        if service.host_name.name or self._scan_tld:
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
            if self.http_proxy:
                additional_command = "set Proxies {}:{}".format(self.http_proxy.scheme, self.http_proxy.netloc)
            else:
                additional_command = ""
            collectors = self._create_commands(session=session,
                                               service=service,
                                               collector_name=collector_name,
                                               module="scanner/http/robots_txt",
                                               rhosts=service.address,
                                               rport=service.port,
                                               ssl=service.tls,
                                               additional_commands=[additional_command])
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
        for line in command.stdout_output:
            if self._re_no_response.match(line):
                command.hide = True
                break
        paths = self.add_robots_txt(session=session,
                                    command=command,
                                    service=command.service,
                                    robots_txt=command.stdout_output,
                                    source=source,
                                    report_item=report_item)
        if not paths:
            command.hide = True
