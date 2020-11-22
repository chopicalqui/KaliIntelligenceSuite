# -*- coding: utf-8 -*-
"""
run tool curl on each identified in-scope FTP service where access credentials are known to KIS (use ftphydra to brute-
force credentials). alternatively, use optional arguments -u and -p to specify a user name and password
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
from collectors.os.modules.core import ServiceCollector
from collectors.os.modules.core import BaseCollector
from collectors.os.core import PopenCommand
from database.model import Service
from database.model import CollectorName
from database.model import CredentialType
from database.model import Source
from database.model import Command
from database.model import PathType
from view.core import ReportItem
from sqlalchemy.orm.session import Session
from typing import List

logger = logging.getLogger('ftpfilelist')


class CollectorClass(BaseCollector, ServiceCollector):
    """This class implements a collector module that is automatically incorporated into the application."""

    def __init__(self, **kwargs):
        super().__init__(priority=12100,
                         timeout=0,
                         **kwargs)

    @staticmethod
    def get_argparse_arguments():
        return {"help": __doc__, "action": "store_true"}

    def _create_command(self,
                        session: Session,
                        service: Service,
                        collector_name: CollectorName,
                        username: str,
                        password: str = None) -> BaseCollector:
        password = password if password else ""
        ip_address = service.host.ip_address
        os_command = [self._path_curl,
                      "-l",
                      "-s",
                      "-{}".format(service.host.version),
                      "--user", "{}:{}".format(username, password),
                      "ftp://{}".format(ip_address) if ip_address.version == 4 else "ftp://[{}]".format(ip_address)]
        return self._get_or_create_command(session, os_command, collector_name, service=service)

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
            if self._user:
                collector = self._create_command(session,
                                                 service,
                                                 collector_name,
                                                 self._user,
                                                 password=self._password)
                collectors.append(collector)
            else:
                for credential in service.credentials:
                    if credential.complete and credential.type == CredentialType.Cleartext:
                        collector = self._create_command(session,
                                                         service,
                                                         collector_name,
                                                         credential.username,
                                                         password=credential.password)
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
        for line in command.stdout_output:
            line = line.strip().lower()
            self.add_path(session=session,
                          command=command,
                          service=command.service,
                          path=line,
                          path_type=PathType.FileSystem,
                          source=source,
                          report_item=report_item)
