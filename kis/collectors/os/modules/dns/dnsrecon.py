# -*- coding: utf-8 -*-
"""
run tool dnsrecon on each in-scope second-level domain (e.g., megacorpone.com) using the operating system's DNS
server. use optional argument --dns-server to explicitly specify another DNS server
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
from collectors.os.modules.core import DomainCollector
from collectors.os.modules.core import BaseCollector
from collectors.os.core import PopenCommand
from database.model import Command
from database.model import CollectorName
from database.model import Host
from database.model import Source
from view.core import ReportItem
from sqlalchemy.orm.session import Session

logger = logging.getLogger('dnsrecon')


class CollectorClass(BaseCollector, DomainCollector):
    """This class implements a collector module that is automatically incorporated into the application."""

    def __init__(self, **kwargs):
        super().__init__(priority=114200,
                         timeout=0,
                         **kwargs)
        self._re_type_host_ip = re.compile("\[.?\]\s+(?P<type>(A)|(NS)|(SOA)|(MX)) (?P<values>.+)$")

    @staticmethod
    def get_argparse_arguments():
        return {"help": __doc__, "action": "store_true"}

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
        command = self._path_dnsrecon
        if host_name.name is None:
            os_command = [command, "-a", "-g", "-b", "-k", "-s", "-z", "--iw", "-d", host_name.domain_name.name]
            if self._dns_server:
                os_command.extend(["-n", self._dns_server])
            collector = self._get_or_create_command(session, os_command, collector_name, host_name=host_name)
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
            item = None
            line = self._remove_console_color(line).strip()
            match = self._re_type_host_ip.match(line)
            if match:
                dns_type = match.group("type")
                dns_items = match.group("values").split()
                dns_items_len = len(dns_items)
                if dns_items_len == 2:
                    item = dns_items
                elif dns_items_len == 3 and dns_type == "MX":
                    item = dns_items[1:]
                else:
                    logger.debug("{} - ignoring line: {}".format(self._name, line))
            if item:
                host_name, ipv4_address = item
                # Add IPv4 address to database
                host = self.add_host(session=session,
                                     command=command,
                                     source=source,
                                     address=ipv4_address,
                                     report_item=report_item)
                if ipv4_address and not host:
                    logger.debug("ignoring host due to invalid IPv4 address in line: {}".format(line))
                # Add host name to database
                host_name = self.add_host_name(session=session,
                                               command=command,
                                               source=source,
                                               host=host,
                                               host_name=host_name,
                                               report_item=report_item)
                if not host_name:
                    logger.debug("ignoring host name due to invalid domain in line: {}".format(line))
