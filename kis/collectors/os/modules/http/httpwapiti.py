# -*- coding: utf-8 -*-
"""
run tool wapiti on each identified in-scope HTTP(S) service. if credentials for basic authentication are known to KIS,
then they will be automatically used. alternatively, use optional arguments -u and -p to provide a user name and
password for basic authentication. use optional argument --user-agent to specify a different user agent string or
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
import os
from typing import List
from collectors.os.modules.core import ServiceCollector
from collectors.os.modules.http.core import BaseHttpCollector
from collectors.os.modules.core import HostNameServiceCollector
from collectors.os.modules.core import BaseCollector
from collectors.os.modules.core import CommandFailureRule
from collectors.os.modules.core import OutputType
from collectors.os.core import PopenCommand
from database.model import Command
from database.model import CollectorName
from database.model import Source
from database.model import Service
from database.model import CredentialType
from database.model import CollectorType
from database.model import ExecutionInfoType
from view.core import ReportItem
from sqlalchemy.orm.session import Session

logger = logging.getLogger('httpwapiti')


class CollectorClass(BaseHttpCollector, ServiceCollector, HostNameServiceCollector):
    """This class implements a collector module that is automatically incorporated into the application."""

    def __init__(self, **kwargs):
        super().__init__(priority=92200,
                         timeout=0,
                         **kwargs)
        self._re_evil_request = re.compile(
            "Evil request:\s+((POST)|(GET)|(PUT)|(DELETE)|(OPTIONS)) (?P<path>.+?) HTTP/[0-9]+\.[0-9]+\s+Host:\s*(?P<host>.+?)\s+",
            re.DOTALL)

    @staticmethod
    def get_argparse_arguments():
        return {"help": __doc__, "action": "store_true"}

    @staticmethod
    def get_invalid_argument_regex() -> List[re.Pattern]:
        """
        This method returns a regular expression that allows KIS to identify invalid arguments
        """
        return [re.compile("^.*wapiti: error: unrecognized arguments: (?P<argument>.*?)\s*$", re.IGNORECASE)]

    @staticmethod
    def get_service_unreachable_regex() -> List[re.Pattern]:
        """
        This method returns a regular expression that allows KIS to identify services that are not reachable
        """
        return []

    @staticmethod
    def get_failed_regex() -> List[CommandFailureRule]:
        """
        This method returns regular expressions that allows KIS to identify failed command executions
        """
        return [CommandFailureRule(regex=re.compile("^\[!\] Connection error with URL.*$"),
                                   output_type=OutputType.stdout)]

    def _get_commands(self,
                      session: Session,
                      service: Service,
                      collector_name: CollectorName,
                      command: str,
                      user: str = None,
                      password: str = None,
                      output_file: str = None) -> List[BaseCollector]:
        """Returns a list of commands based on the provided information."""
        collectors = []
        url = service.get_urlparse().geturl()
        url = url if url[-1] == "/" else url + "/"
        if url:
            os_command = [command,
                          "--scope", "url",
                          "--scan-force", "normal",
                          "--format", "txt",
                          "--no-bugreport",
                          "--flush-attacks",
                          "--flush-session"]
            if self._user_agent:
                os_command += ['--user-agent', '{}'.format(self._user_agent)]
            else:
                os_command += ['--user-agent', '{}'.format(self._default_user_agent_string)]
            if user:
                password = password if password else ""
                os_command += ["--auth-type", "basic", "--auth-cred", "{}%{}".format(user, password)]
            if self._http_proxy:
                os_command += ['--proxy', self.http_proxy.geturl()]
            if output_file:
                os_command += ["--output", ExecutionInfoType.binary_output_file.argument]
            os_command += ["-u", url]
            collector = self._get_or_create_command(session,
                                                    os_command,
                                                    collector_name,
                                                    service=service,
                                                    binary_file=output_file)
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
        command = self._path_wapiti
        if self.match_nmap_service_name(service):
            if not service.has_credentials:
                output_file = self.create_file_path(service=service, file_extension="bin", create_new=True)
                tmp = self._get_commands(session,
                                         service,
                                         collector_name,
                                         command,
                                         self._user,
                                         self._password,
                                         output_file=output_file)
                collectors.extend(tmp)
            else:
                output_file = self.create_file_path(service=service, file_extension="bin", create_new=True)
                for credential in service.credentials:
                    if credential.complete and credential.type == CredentialType.Cleartext:
                        tmp = self._get_commands(session,
                                                 service,
                                                 collector_name,
                                                 command,
                                                 credential.username,
                                                 credential.password,
                                                 output_file=output_file)
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
        # set execution status
        if command.return_code > 0:
            self._set_execution_failed(session, command)
            return
        output = os.linesep.join(command.stdout_output) + " "
        dedup = {}
        for item in self._re_evil_request.finditer(output):
            path_str = item.group("path")
            host_str = item.group("host")
            if host_str:
                if command.collector_name.type == CollectorType.host_name_service and \
                        command.host_name.full_name != host_str:
                    logger.debug("extracted host name '{}' not equal "
                                 "to targeted host name '{}'".format(host_str,
                                                                     command.host_name.full_name))
                    break
                elif command.collector_name.type == CollectorType.service and \
                        command.host.ipv4_address != host_str:
                    logger.debug("extracted host name '{}' not equal "
                                 "to targeted IPv4 address '{}'".format(host_str,
                                                                        command.host.ipv4_address))
                    break
            path_str = path_str.strip()
            if path_str and path_str != "/" and path_str not in dedup:
                dedup[path_str] = True
                self.add_url(session=session,
                             service=command.service,
                             url=path_str,
                             source=source,
                             report_item=report_item)
