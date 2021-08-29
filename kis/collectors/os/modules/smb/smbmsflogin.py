# -*- coding: utf-8 -*-
"""
run Metasploit auxiliary module smb_login on each identified in-scope SMB service to determine if the given credentials
are valid.

use mandatory arguments -u and -p to specify access credentials. if optional argument -H is given, then the
provided password (argument -p) is treated as an HTLM hash. the optional argument -d can be used to specify a domain.
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
from collectors.os.modules.smb.core import BaseSmbMsfConsole
from collectors.os.modules.core import BaseCollector
from collectors.os.core import PopenCommand
from database.model import Command
from database.model import CollectorName
from database.model import Service
from database.model import CredentialType
from database.model import Source
from view.core import ReportItem
from sqlalchemy.orm.session import Session

logger = logging.getLogger('smbmsflogin')


class CollectorClass(BaseSmbMsfConsole, ServiceCollector):
    """This class implements a collector module that is automatically incorporated into the application."""

    def __init__(self, **kwargs):
        super().__init__(priority=9999,
                         timeout=0,
                         **kwargs)
        self._success_re = re.compile("^\[\+\].+?\s+-\s+.+?\s+-\s+Success: '(?P<domain>.+?)\\\\(?P<user>.+?):(?P<lm>.+?):(?P<ntlm>.+?)'$")

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
        if self._user and self._password and self.match_nmap_service_name(service):
            password = "aad3b435b51404eeaad3b435b51404ee:{}".format(self._password) \
                if self._hashes and ":" not in self._password else self._password
            additional_commands = ["set SMBUser {}".format(self._user),
                                   "set SMBPass {}".format(password)]
            if self._domain:
                additional_commands.extend(["set SMBDomain {}".format(self._domain)])
            collectors = self._create_commands(session=session,
                                               service=service,
                                               collector_name=collector_name,
                                               module="auxiliary/scanner/smb/smb_login",
                                               rhosts=service.address,
                                               rport=service.port,
                                               additional_commands=additional_commands)
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
        command.hide = True
        for line in command.stdout_output:
            match = self._success_re.match(line)
            if match:
                ntlm = match.group("ntlm")
                lm = match.group("lm")
                user_name = match.group("user")
                domain = match.group("domain")
                self.add_credential(session=session,
                                    command=command,
                                    password="{}:{}".format(lm, ntlm),
                                    credential_type=CredentialType.hash,
                                    username=user_name,
                                    domain=domain,
                                    source=source,
                                    service=command.service,
                                    report_item=report_item)
