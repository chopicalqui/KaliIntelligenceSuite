# -*- coding: utf-8 -*-
"""
run tool nuclei on each identified in-scope HTTP(S) service to enumerate existing URIs. if credentials for basic
authentication are known to KIS, then they will be automatically used. alternatively, use optional arguments -u and -p
to provide a user name and password for basic authentication. use optional argument --cookies to specify a list of
cookies, or optional argument --http-proxy to specify an HTTP proxy
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
import shlex
import base64
import logging
from typing import List
from collectors.os.modules.core import ServiceCollector
from collectors.os.modules.core import ExecutionInfoType
from collectors.os.modules.core import CommandFailureRule
from collectors.os.modules.core import HostNameServiceCollector
from collectors.os.modules.http.core import BaseHttpCollector
from collectors.os.modules.core import BaseCollector
from collectors.os.core import PopenCommand
from database.model import Command
from database.model import CollectorName
from database.model import Service
from database.model import CredentialType
from database.model import Source
from view.core import ReportItem
from sqlalchemy.orm.session import Session

logger = logging.getLogger('httpnuclei')


class CollectorClass(BaseHttpCollector, ServiceCollector, HostNameServiceCollector):
    """This class implements a collector module that is automatically incorporated into the application."""

    def __init__(self, **kwargs):
        super().__init__(priority=51050,
                         timeout=0,
                         exec_user="kali",
                         **kwargs)

    @staticmethod
    def get_argparse_arguments():
        return {"help": __doc__, "action": "store_true"}

    @staticmethod
    def get_invalid_argument_regex() -> List[re.Pattern]:
        """
        This method returns a regular expression that allows KIS to identify invalid arguments
        """
        return [re.compile("^\s*flag provided but not defined: (?P<argument>.+?)\s*$", re.IGNORECASE)]

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
        return []

    def _get_commands(self,
                      session: Session,
                      service: Service,
                      collector_name: CollectorName,
                      command: str,
                      user: str = None,
                      password: str = None) -> List[BaseCollector]:
        """Returns a list of commands based on the provided information."""
        collectors = []
        url = service.get_urlparse()
        number_threads = 1 if self._delay.sleep_active() else 25
        template_dir = self.get_config_str("nuclei", "template_dir")
        args = self.get_config_str("nuclei", "additional_arguments")
        if url:
            headers = []
            os_command = [command,
                          '-t', ExecutionInfoType.input_dir.argument,
                          '-fhr',  # follow redirects on the same hosts
                          '-c', number_threads,  # maximum number of templates to be executed in parallel (default 25)
                          '-u', url.geturl()]
            if self._delay.sleep_active():
                os_command += ['-rl', 1]  # maximum number of requests to send per second
            if self._http_proxy:
                os_command += ['-p', self.http_proxy.geturl()]  # list of http/socks5 proxy to use (comma separated or file input)
            # Build custom headers
            if user:
                value = base64.b64encode("{user}:{password}".format(user=user,
                                                                    password=password if password else "").encode()).decode()
                headers += ["Authorization: Basic {}".format(value)]
            if self._cookies:
                cookies = "; ".join(self._cookies)
                headers += ["Cookie: {}".format(cookies)]
            # Add custom headers
            if headers:
                os_command.append("-H")
                os_command += headers
            if args:
                args = shlex.split(args)
                os_command += args
            collector = self._get_or_create_command(session,
                                                    os_command,
                                                    collector_name,
                                                    service=service,
                                                    input_dir=template_dir)
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
        command = self._path_nuclei
        if self.match_nmap_service_name(service):
            if not service.has_credentials:
                tmp = self._get_commands(session=session,
                                         service=service,
                                         collector_name=collector_name,
                                         command=command,
                                         user=self._user,
                                         password=self._password)
                collectors.extend(tmp)
            else:
                for credential in service.credentials:
                    if credential.complete and credential.type == CredentialType.cleartext:
                        tmp = self._get_commands(session=session,
                                                 service=service,
                                                 collector_name=collector_name,
                                                 command=command,
                                                 user=credential.username,
                                                 password=credential.password)
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
        command.hide = False
        if command.return_code and command.return_code > 0:
            self._set_execution_failed(session=session, command=command)
