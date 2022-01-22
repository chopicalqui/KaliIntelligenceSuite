# -*- coding: utf-8 -*-
"""
run tool nikto on each identified in-scope HTTP(S) service to enumerate existing URIs. if credentials for basic
authentication are known to KIS, then they will be automatically used. alternatively, use optional arguments -u and -p
to provide a user name and password for basic authentication. use optional argument --user-agent to specify a different
user agent string, or optional argument --http-proxy to specify an HTTP proxy
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
from collectors.os.modules.core import HostNameServiceCollector
from collectors.os.modules.core import BaseCollector
from collectors.os.core import PopenCommand
from database.model import Command
from database.model import CollectorName
from database.model import Source
from database.model import Service
from database.model import CredentialType
from view.core import ReportItem
from sqlalchemy.orm.session import Session

logger = logging.getLogger('httpnikto')


class CollectorClass(BaseHttpCollector, ServiceCollector, HostNameServiceCollector):
    """This class implements a collector module that is automatically incorporated into the application."""

    def __init__(self, **kwargs):
        super().__init__(priority=91200,
                         timeout=0,
                         **kwargs)
        self._re_path = re.compile("^\+\s(OSVDB-[0-9]+:\s)?(?P<path>/.+?):\s.*$")
        self._re_creds = re.compile("\+ Default account found for '.+?' at (?P<path>(/[0-9a-zA-Z-_\.\+]+)+) \(ID "
                                    "'(?P<user>.+?)', PW '(?P<pwd>.+?)'\)\..*$")
        self._re_methods = re.compile("^\+ OSVDB\-\d+: HTTP method \('Allow' Header\): '((?P<method>.+?)'.+)$")
        self._re_header_info = re.compile("^\+ Retrieved (?P<header>[0-9a-zA-Z_\-]+) header: (?P<value>.+)$")
        self._re_robots = re.compile("^\+ Entry '(?P<path>.+?)' in robots.txt returned a non-forbidden or redirect HTTP code \((?P<code>[0-9]+)\)$")

    @staticmethod
    def get_argparse_arguments():
        return {"help": __doc__, "action": "store_true"}

    def _get_commands(self,
                      session: Session,
                      service: Service,
                      collector_name: CollectorName,
                      command: str,
                      user: str = None,
                      password: str = None) -> List[BaseCollector]:
        """Returns a list of commands based on the provided information."""
        collectors = []
        if (service.host and service.host.version == 4) or service.host_name:
            url = service.get_urlparse()
            os_command = [command]
            if self._user_agent:
                os_command.extend(['-useragent', '{}'.format(self._user_agent)])
            else:
                os_command.extend(['-useragent', '{}'.format(self._default_user_agent_string)])
            if user:
                password = password if password else ""
                os_command.extend(["-id", "{}:{}".format(user, password)])
            if self._cookies:
                os_command.extend(['-c', self._cookies])
            if service.nmap_tunnel == 'ssl':
                os_command.append('-ssl')
            if self._http_proxy:
                os_command.extend(['-useproxy', self.http_proxy.geturl()])
            os_command.extend(['-Tuning', '12357b', '-no404', '-nointeractive', '-host', url.geturl()])
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
        result = []
        # Nikto does not support IPv6. Therefore, we are checking for 'service.host_name.resolves_to_in_scope_ipv4_address()'
        if (service.host_name.name or self._scan_tld) and self.match_nmap_service_name(service) and \
                service.host_name.resolves_to_in_scope_ipv4_address():
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
        command = self._path_nikto
        if self.match_nmap_service_name(service):
            if not service.has_credentials:
                tmp = self._get_commands(session,
                                         service,
                                         collector_name,
                                         command,
                                         self._user,
                                         self._password)
                collectors.extend(tmp)
            else:
                for credential in service.credentials:
                    if credential.complete and credential.type == CredentialType.cleartext:
                        tmp = self._get_commands(session,
                                                 service,
                                                 collector_name,
                                                 command,
                                                 credential.username,
                                                 credential.password)
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
        # We analyze Nikto's output
        for line in command.stdout_output:
            line = line.strip()
            match_path = self._re_path.match(line)
            match_creds = self._re_creds.match(line)
            match_methods = self._re_methods.match(line)
            match_header_info = self._re_header_info.match(line)
            match_robots = self._re_robots.match(line)
            if "+ No web server found on " in line:
                self._set_execution_failed(session, command)
            elif match_path:
                path_str = match_path.group("path").strip()
                path_str = path_str.split()[0]
                url = self.add_url_path(session=session,
                                        service=command.service,
                                        url_path=path_str,
                                        source=source,
                                        report_item=report_item)
                if not url:
                    logger.debug("ignoring URL due to invalid IPv4 address in line: {}".format(line))
            elif match_header_info:
                header_info_header = match_header_info.group("header")
                header_info_value = match_header_info.group("value")
                self.add_additional_info(session=session,
                                         command=command,
                                         service=command.service,
                                         name=header_info_header,
                                         values=[header_info_value],
                                         source=source,
                                         report_item=report_item)
            elif match_methods:
                self.add_service_method(session=session,
                                        service=command.service,
                                        name=match_methods.group("method"),
                                        report_item=report_item)
            elif match_creds:
                path_str = match_creds.group("path").strip()
                path_str = path_str.split()[0]
                user = match_creds.group("user").strip()
                password = match_creds.group("pwd").strip()
                credential = self.add_credential(session=session,
                                                 command=command,
                                                 username=user,
                                                 password=password,
                                                 credential_type=CredentialType.cleartext,
                                                 source=source,
                                                 service=command.service,
                                                 report_item=report_item)
                if not credential:
                    logger.debug("ignoring credentials in line: {}".format(line))
                path = self.add_url_path(session=session,
                                         service=command.service,
                                         url_path=path_str,
                                         source=source,
                                         report_item=report_item)
                if not path:
                    logger.debug("ignoring URL due to invalid IPv4 address in line: {}".format(line))
            elif match_robots:
                path_str = match_robots.group("path").strip()
                code = match_robots.group("code").strip()
                path = self.add_url_path(session=session,
                                         service=command.service,
                                         url_path=path_str,
                                         status_code=int(code) if code else None,
                                         source=source,
                                         report_item=report_item)
                if not path:
                    logger.debug("ignoring URL due to invalid IPv4 address in line: {}".format(line))
