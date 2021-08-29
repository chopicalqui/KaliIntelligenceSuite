# -*- coding: utf-8 -*-
"""
run tool kiterunner on each identified in-scope HTTP(S) service to enumerate existing URIs. if credentials for basic
authentication are known to KIS, then they will be automatically used. alternatively, use optional arguments -u and -p
to provide a user name and password for basic authentication. use optional argument --user-agent to specify a
different user agent string
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
from collectors.os.modules.http.core import BaseHttpCollector
from collectors.os.modules.core import BaseCollector
from collectors.os.modules.core import HostNameServiceCollector
from collectors.os.core import PopenCommand
from database.model import Service
from database.model import Command
from database.model import CollectorName
from view.core import ReportItem
from database.model import Source
from sqlalchemy.orm.session import Session

logger = logging.getLogger('httpkiterunner')


class CollectorClass(BaseHttpCollector, ServiceCollector, HostNameServiceCollector):
    """This class implements a collector module that is automatically incorporated into the application."""

    def __init__(self, **kwargs):
        super().__init__(priority=51150,
                         exec_user="kali",
                         timeout=0,
                         **kwargs)
        self._result_re = re.compile("^(?P<method>\w+)\s+(?P<status>\d+)\s+\[\s*(?P<size>\d+),.+?\]\s+(?P<url>.+?)\s.*$")

    @staticmethod
    def get_argparse_arguments():
        return {"help": __doc__, "action": "store_true"}

    @staticmethod
    def get_invalid_argument_regex() -> List[re.Pattern]:
        """
        This method returns a regular expression that allows KIS to identify invalid arguments
        """
        return [re.compile("^\s*Error: unknown flag: (?P<argument>.+?)\s*$", re.IGNORECASE)]

    def _get_commands(self,
                      session: Session,
                      service: Service,
                      collector_name: CollectorName,
                      command: str) -> List[BaseCollector]:
        """Returns a list of commands based on the provided information."""
        collectors = []
        wordlists = self._wordlist_files if self._wordlist_files else [self._wordlist_kiterunner]
        for wordlist in wordlists:
            os_command = [command,
                          'scan',
                          '--output', 'text',
                          '--kitebuilder-full-scan',
                          '-q',
                          '-w', wordlist,
                          '-x', 10,
                          '--user-agent', self._user_agent if self._user_agent else self.default_user_agent,
                          service.get_urlparse().geturl()]
            collector = self._get_or_create_command(session, os_command, collector_name, service=service)
            collectors.append(collector)
        return collectors

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
        collectors = []
        command = self._path_kiterunner
        # Kiterunner does not support IPv6. Therefore, we are check for 'not service.host_name.resolves_to_in_scope_ipv6_address()'
        if service.host_name.name and self.match_nmap_service_name(service) and \
                not service.host_name.resolves_to_in_scope_ipv6_address():
            tmp = self._get_commands(session, service, collector_name, command)
            collectors.extend(tmp)
        return collectors

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
        command = self._path_kiterunner
        if service.host.ipv4_address and self.match_nmap_service_name(service):
            logger.info(service.host.ipv4_address)
            tmp = self._get_commands(session, service, collector_name, command)
            collectors.extend(tmp)
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
        else:
            command.hide = True
        for line in command.stdout_output:
            line = line.strip()
            match = self._result_re.match(line)
            if match:
                size_bytes = int(match.group("size"))
                status_code = int(match.group("status"))
                url = match.group("url")
                self.add_url(session,
                             command.service,
                             url,
                             status_code=status_code,
                             size_bytes=size_bytes,
                             source=source,
                             report_item=report_item)
