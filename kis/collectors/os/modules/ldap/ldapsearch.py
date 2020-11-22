# -*- coding: utf-8 -*-
"""
run ldapsearch on each identified in-scope LDAP(S) service. if credentials for user authentication are known to KIS,
then they will be automatically used. alternatively, use optional arguments -u and -p to provide a user name and
password for user authentication.
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

from typing import List
from collectors.os.modules.core import ServiceCollector
from collectors.os.modules.ldap.core import BaseLdapCollector
from collectors.os.modules.core import BaseCollector
from collectors.os.core import PopenCommand
from database.model import Service
from database.model import Command
from database.model import CollectorName
from database.model import CredentialType
from database.model import Source
from view.core import ReportItem
from sqlalchemy.orm.session import Session


class CollectorClass(BaseLdapCollector, ServiceCollector):
    """This class implements a collector module that is automatically incorporated into the application."""

    def __init__(self, **kwargs):
        super().__init__(priority=21600,
                         timeout=0,
                         **kwargs)

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
        address = service.host.address
        host = ("ldaps" if service.nmap_tunnel == "ssl" else "ldap") + "://{}".format(address)
        if address:
            os_command = [command,
                          '-x',
                          '-H', host,
                          '-s', 'base']
            if user:
                os_command.extend(['-D', '{}'.format(user)])
            if password:
                os_command.extend(['-w', '{}'.format(password)])
            collector = self._get_or_create_command(session, os_command, collector_name, service=service)
            collectors.append(collector)
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
        command = self._path_ldapsearch
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
                    if credential.complete and credential.type == CredentialType.Cleartext:
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
        contexts = {}
        unique={}
        matchers = ["defaultNamingContext:", "defaultNamingContext:", "rootDomainNamingContext:"]
        command.hint = []
        for line in command.stdout_output:
            for matcher in matchers:
                if matcher in line:
                    tmp = line.split(":")
                    if len(tmp) >= 2:
                        key = tmp[0]
                        value = ":".join(tmp[1:])
                        contexts[key] = value
                        unique[value] = True
        for key, value in contexts.items():
            self.add_additional_info(session=session,
                                     command=command,
                                     service=command.service,
                                     name="{} {}".format(command.collector_name.name, key),
                                     values=[value],
                                     source=source,
                                     report_item=report_item)
        for key, _ in unique.items():
            new_command = command.os_command_substituted[:-2]
            new_command.extend(['-b', '"{}"'.format(key)])
            self.add_hint(command=command,
                          hint="$ {}".format(" ".join(new_command)))
