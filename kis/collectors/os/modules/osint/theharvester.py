# -*- coding: utf-8 -*-
"""
run tool theharvester on each identified in-scope second-level domain
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
from collectors.core import EmailUtils
from collectors.core import DomainUtils
from collectors.core import IpUtils
from collectors.core import CertificateUtils
from database.model import Host
from database.model import HostName
from database.model import Source
from database.model import Command
from database.model import CollectorName
from collectors.os.modules.core import DomainCollector
from collectors.os.modules.core import BaseCollector
from collectors.os.core import PopenCommand
from view.core import ReportItem
from sqlalchemy.orm.session import Session

logger = logging.getLogger('theharvester')


class CollectorClass(BaseCollector, DomainCollector):
    """This class implements a collector module that is automatically incorporated into the application."""

    def __init__(self, **kwargs):
        super().__init__(priority=150,
                         timeout=0,
                         active_collector=True,
                         delay_min=1,
                         **kwargs)
        self._re_email = re.compile("^{}$".format(EmailUtils.RE_EMAIL))
        self._re_domain_ip = re.compile("^{}\s?:\s?(?P<ipv4_address>.*)$".format(DomainUtils.RE_DOMAIN))

    @staticmethod
    def get_argparse_arguments():
        return {"help": __doc__, "action": "store_true"}

    def _get_commands(self,
                      session: Session,
                      host_name: HostName,
                      collector_name: CollectorName,
                      command: str,
                      module: str) -> List[BaseCollector]:
        """Returns a list of commands based on the provided information."""
        collectors = []
        os_command = [command,
                      '-d', host_name.domain_name.name,
                      '-b', module]
        collector = self._get_or_create_command(session, os_command, collector_name, host_name=host_name)
        collectors.append(collector)
        return collectors

    def create_domain_commands(self,
                               session: Session,
                               host_name: Host,
                               collector_name: CollectorName) -> List[BaseCollector]:
        """This method creates and returns a list of commands based on the given service.

        This method determines whether the command exists already in the database. If it does, then it does nothing,
        else, it creates a new Collector entry in the database for each new command as well as it creates a corresponding
        operating system command and attaches it to the respective newly created Collector class.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param host_name: The host name based on which commands shall be created.
        :param collector_name: The name of the collector as specified in table collector_name
        :return: List of Collector instances that shall be processed.
        """
        collectors = []
        if host_name.name is None:
            for item in ['all']:
                command = self._path_theharvester
                tmp = self._get_commands(session, host_name, collector_name, command, item)
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
        for line in command.stdout_output:
            match_email = self._re_email.match(line)
            match_domain_ip = self._re_domain_ip.match(line)
            if match_email:
                email = match_email.group("email")
                email = self.add_email(session=session,
                                       command=command,
                                       email=email,
                                       source=source,
                                       report_item=report_item)
                if not email:
                    logger.debug("ignoring email in line: {}".format(line))
            if match_domain_ip:
                ipv4_address = match_domain_ip.group("ipv4_address")
                domain = match_domain_ip.group("domain")
                if IpUtils.is_valid_address(ipv4_address):
                    host = self.add_host(session=session,
                                         command=command,
                                         address=ipv4_address,
                                         source=source,
                                         report_item=report_item)
                    if not ipv4_address:
                        logger.debug("ignoring IPv4 address in line: {}".format(line))
                else:
                    host = None
                host_name = self.add_host_name(session=session,
                                               command=command,
                                               source=source,
                                               host=host,
                                               host_name=domain,
                                               report_item=report_item)
                if not host_name:
                    logger.debug("ignoring host name in line: {}".format(line))
