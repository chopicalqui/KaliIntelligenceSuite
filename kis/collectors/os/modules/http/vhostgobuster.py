# -*- coding: utf-8 -*-
"""
run tool gobuster on each identified in-scope HTTP(S) service to enumerate existing URIs. if credentials for basic
authentication are known to KIS, then they will be automatically used. alternatively, use optional arguments -u and -p
to provide a user name and password for basic authentication. use optional argument --cookies to specify a list of
cookies, optional argument --user-agent to specify a different user agent string, or optional argument --http-proxy to
specify an HTTP proxy
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
from collectors.os.modules.http.core import BaseHttpGoBuster
from collectors.os.modules.core import BaseCollector
from collectors.os.core import PopenCommand
from database.model import Command
from database.model import CollectorName
from database.model import Service
from database.model import CredentialType
from database.model import Source
from database.model import HostName
from database.model import DomainName
from database.model import DnsResourceRecordType
from view.core import ReportItem
from sqlalchemy.orm.session import Session

logger = logging.getLogger('vhostgobuster')


class CollectorClass(BaseHttpGoBuster, ServiceCollector, HostNameServiceCollector):
    """This class implements a collector module that is automatically incorporated into the application."""

    def __init__(self, **kwargs):
        super().__init__(priority=51100,
                         timeout=0,
                         mode="vhost",
                         **kwargs)
        self._re_dns = re.compile("^Found: (?P<host>.+?)$")

    @staticmethod
    def get_argparse_arguments():
        return {"help": __doc__, "action": "store_true"}

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
        command = self._path_gobuster
        if self.match_nmap_service_name(service):
            # Compile list of host names that do not resolve to any IP address
            host_names = []
            for host_name in session.query(HostName) \
                 .join(DomainName) \
                 .filter(DomainName.workspace_id == service.workspace_id, HostName._in_scope):
                resolves_to = host_name.get_host_host_name_mappings([DnsResourceRecordType.a,
                                                                     DnsResourceRecordType.aaaa])
                if not resolves_to:
                    host_names.append(host_name.full_name)
            # Write wordlist to filesystem
            file_path = self.create_text_file_path(service=service,
                                                   delete_existing=True,
                                                   file_suffix="wordlist")
            with open(file_path, "w") as file:
                file.writelines(host_names)
            # Create commands
            if not service.has_credentials:
                tmp = self._get_commands(session,
                                         service,
                                         collector_name,
                                         command,
                                         [file_path],
                                         self._user,
                                         self._password)
                collectors.extend(tmp)
            else:
                for credential in service.credentials:
                    if credential.complete and credential.type == CredentialType.Cleartext:
                        tmp = self._get_commands(session,
                                                 service,
                                                 collector_name,
                                                 command,
                                                 [file_path],
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
        pass
