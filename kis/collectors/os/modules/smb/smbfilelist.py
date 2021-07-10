# -*- coding: utf-8 -*-
"""
run smbclient on each identified in-scope SMB network share to get a directory listing. per default this collector
tests SMB services for NULL sessions. alternatively, use optional arguments -u, -p, and -d to provide a user name, a
password/NTLM hash, and domain/workgroup for authentication
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
from database.model import Path
from typing import List
from collectors.os.modules.core import ServiceCollector
from collectors.os.modules.smb.core import SmbServiceDescriptor
from collectors.os.modules.core import BaseCollector
from collectors.os.modules.core import BaseSmbClient
from collectors.os.core import PopenCommand
from database.model import Service
from database.model import Command
from database.model import CollectorName
from database.model import PathType
from database.model import Source
from view.core import ReportItem
from sqlalchemy.orm.session import Session

logger = logging.getLogger('collector')


class CollectorClass(BaseSmbClient, ServiceCollector):
    """This class implements a collector module that is automatically incorporated into the application."""

    def __init__(self, **kwargs):
        super().__init__(priority=13200,
                         timeout=0,
                         service_descriptors=SmbServiceDescriptor(),
                         **kwargs)
        self._nt_status_re = re.compile("(?P<value>NT_STATUS_[a-z0-9_]+)", re.IGNORECASE)

    @staticmethod
    def get_argparse_arguments():
        return {"help": __doc__, "action": "store_true"}

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
        if self.match_service_port(service):
            for path in session.query(Path).join(Service).filter(Service.id == service.id,
                                                                 Path.type == PathType.Smb_Share).all():
                collectors += self._create_commands(session,
                                                    service,
                                                    collector_name,
                                                    path=path.name,
                                                    arguments=["-c", "dir"])
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
        command.hide = command.return_code > 0
        output = os.linesep.join(command.stderr_output) + os.linesep.join(command.stdout_output)
        for match in self._nt_status_re.finditer(output):
            code = match.group("value")
            if code in self._failed_status:
                command.hide = True
                break

