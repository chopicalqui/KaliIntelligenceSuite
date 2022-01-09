# -*- coding: utf-8 -*-
"""
run tool Crobat on each collected in-scope IP network to passively perform a reverse DNS lookup.
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
import os
import json
import logging
from typing import List
from database.model import Network
from database.model import CollectorName
from database.model import Command
from database.model import Source
from sqlalchemy.orm.session import Session
from collectors.os.modules.core import BaseCollector
from collectors.os.modules.core import Ipv4NetworkCollector
from collectors.os.modules.dns.core import BaseCrobat
from collectors.os.core import PopenCommand
from view.core import ReportItem

logger = logging.getLogger('dnscrobatreversenetwork')


class CollectorClass(BaseCrobat, Ipv4NetworkCollector):
    """This class implements a collector module that is automatically incorporated into the application."""

    def __init__(self, **kwargs):
        super().__init__(priority=550,
                         timeout=0,
                         delay_min=1,
                         **kwargs)
        self._re_entry = re.compile("\{.+?\}", re.DOTALL)

    @staticmethod
    def get_argparse_arguments():
        return {"help": __doc__, "action": "store_true"}

    def create_ipv4_network_commands(self,
                                     session: Session,
                                     network: Network,
                                     collector_name: CollectorName) -> List[BaseCollector]:
        """This method creates and returns a list of commands based on the given IPv4 network.

        This method determines whether the command exists already in the database. If it does, then it does nothing,
        else, it creates a new Collector entry in the database for each new command as well as it creates a corresponding
        operating system command and attaches it to the respective newly created Collector class.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param ipv4_network: The IPv4 network based on which commands shall be created.
        :param collector_name: The name of the collector as specified in table collector_name
        :return: List of Collector instances that shall be processed.
        """
        return self.create_commands(session=session,
                                    collector_name=collector_name,
                                    argument="-r",
                                    network=network)

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
        super().verify_results(session=session,
                               command=command,
                               source=source,
                               report_item=report_item,
                               process=process)
        command_output = os.linesep.join(command.stdout_output)
        for item in self._re_entry.findall(command_output):
            json_object = json.loads(item)
            if "domains" in json_object:
                for domain in json_object["domains"]:
                    # Add host name to database
                    host_name = self.add_host_name(session=session,
                                                   command=command,
                                                   source=source,
                                                   host_name=domain,
                                                   report_item=report_item)
                    if not host_name:
                        logger.debug("ignoring host name due to invalid domain in line: {}".format(domain))
            else:
                logger.debug("result of crobat output does not contain 'domains' attribute.")
