# -*- coding: utf-8 -*-
"""
run tool whois on all identified in- and out-of-scope second-level domains. depending on the
number of domains in the current workspace, it might be desired to limit the number of OS commands by using the
optional argument --filter
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
import re
from typing import List
from collectors.os.modules.core import DomainCollector
from collectors.os.modules.core import BaseCollector
from collectors.os.modules.core import CommandFailureRule
from collectors.os.modules.core import OutputType
from collectors.os.modules.osint.core import BaseWhois
from collectors.os.core import PopenCommand
from collectors.core import DomainUtils
from collectors.core import IpUtils
from database.model import Source
from database.model import HostName
from database.model import Command
from database.model import CollectorName
from database.model import DnsResourceRecordType
from view.core import ReportItem
from sqlalchemy.orm.session import Session

logger = logging.getLogger('whoisdomain')


class CollectorClass(BaseWhois, DomainCollector):
    """This class implements a collector module that is automatically incorporated into the application."""

    def __init__(self, **kwargs):
        super().__init__(priority=210,
                         whois_attributes=["Registrant Name",
                                           "Registrant",
                                           "Registrant Organization",
                                           "Registrant Contact Organisation",
                                           "name",
                                           "address",
                                           "org",
                                           "contact",
                                           "nom",
                                           "International Organisation",
                                           "organization"],
                         **kwargs)
        self._re_name_server_info = re.compile("^{}\s+\[(?P<ipv4>{})\]\s*$".format(DomainUtils.RE_DOMAIN,
                                                                                   IpUtils.RE_IPV4))

    @staticmethod
    def get_argparse_arguments():
        return {"help": __doc__, "action": "store_true"}

    @staticmethod
    def get_failed_regex() -> List[CommandFailureRule]:
        """
        This method returns regular expressions that allows KIS to identify failed command executions
        """
        return [CommandFailureRule(regex=re.compile("^.*getaddrinfo\(.+?\): Name or service not known.*$"),
                                   output_type=OutputType.stderr),
                CommandFailureRule(regex=re.compile("^.*Your connection limit exceeded. Please slow down and try again later..*$"),
                                   output_type=OutputType.stderr)]

    def _get_commands(self,
                      session: Session,
                      host_name: HostName,
                      collector_name: CollectorName,
                      command: str) -> List[BaseCollector]:
        """Returns a list of commands based on the provided information."""
        collectors = []
        if host_name and host_name.name is None and host_name.domain_name and host_name.domain_name.name:
            os_command = [command, host_name.domain_name.name]
            collector = self._get_or_create_command(session, os_command, collector_name, host_name=host_name)
            collectors.append(collector)
        return collectors

    def create_domain_commands(self,
                               session: Session,
                               host_name: HostName,
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
        command = self._path_whois
        tmp = self._get_commands(session, host_name, collector_name, command)
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
        command.hide = True
        if command.return_code > 0:
            self._set_execution_failed(session, command)
        for line in command.stdout_output:
            match = self._re_organizations.match(line)
            if match:
                name = match.group("name").strip().lower()
                company = self.add_company(session=session,
                                           workspace=command.workspace,
                                           name=name,
                                           domain_name=command.host_name.domain_name,
                                           source=source,
                                           report_item=report_item)
                if not company:
                    logger.debug("ignoring company: {}".format(name))
            emails = self._email_utils.extract_emails(line)
            match = self._re_name_server_info.match(line)
            if match:
                host_name = match.group("domain")
                ipv4_address = match.group("ipv4")
                host = self.add_host(session=session,
                                     command=command,
                                     address=ipv4_address,
                                     source=source,
                                     report_item=report_item)
                if not host:
                    logger.debug("ignoring host due to invalid address in line: {}".format(line))
                host_name = self.add_host_name(session=session,
                                               command=command,
                                               host_name=host_name,
                                               source=source,
                                               report_item=report_item)
                if not host_name:
                    logger.debug("ignoring host name due to invalid domain in line: {}".format(line))
                elif host:
                    self.add_host_host_name_mapping(session=session,
                                                    command=command,
                                                    host=host,
                                                    host_name=host_name,
                                                    source=source,
                                                    mapping_type=DnsResourceRecordType.ns,
                                                    report_item=report_item)
            for item in emails:
                email = self.add_email(session=session,
                                       command=command,
                                       email=item,
                                       source=source,
                                       report_item=report_item)
                if not email:
                    logger.debug("ignoring company: {}".format(item))
