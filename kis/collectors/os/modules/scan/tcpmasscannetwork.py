# -*- coding: utf-8 -*-
"""
run tool masscan on all in-scope IPv4 networks. valid parameters for this argument are: topX for scanning top X TCP
ports; interesting for scanning interesting TCP ports; all for scanning all TCP ports; or a list of port numbers/ranges
(e.g., 0-1024 8080) to scan just those TCP ports
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
import os
from typing import List
from database.model import Network
from database.model import CollectorName
from database.model import Command
from database.model import Source
from view.core import ReportItem
from database.config import ScannerConfig
from collectors.os.core import PopenCommand
from collectors.os.modules.scan.core import BaseMasscan
from collectors.os.modules.core import BaseCollector
from collectors.os.modules.core import Ipv4NetworkCollector
from collectors.filesystem.masscan import DatabaseImporter
from collectors.core import IpUtils
from sqlalchemy.orm.session import Session

logger = logging.getLogger('tcpmasscannetwork')


class CollectorClass(BaseMasscan, Ipv4NetworkCollector):
    """
    This class implements basic functionality for collectors that use Masscan.
    """

    def __init__(self, **kwargs):
        super().__init__(priority=1300,
                         timeout=0,
                         exec_user="root",
                         **kwargs)
        self._masscan_config = ScannerConfig()

    @staticmethod
    def get_argparse_arguments():
        return {"help": __doc__, "type": str, "metavar": "TYPE", "nargs": "+"}

    def create_ipv4_network_commands(self,
                                     session: Session,
                                     network: Network,
                                     collector_name: CollectorName) -> List[BaseCollector]:
        """This method creates and returns a list of commands based on the given network.

        This method determines whether the command exists already in the database. If it does, then it does nothing,
        else, it creates a new Collector entry in the database for each new command as well as it creates a corresponding
        operating system command and attaches it to the respective newly created Collector class.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param network: The IPv4 network based on which commands shall be created
        :param collector_name: The name of the collector as specified in table collector_name
        :return: List of Collector instances that shall be processed.
        """
        exclude_hosts_file = []
        arguments = self.get_commandline_argument_value("tcpmasscannetwork")
        exclude_hosts = IpUtils.get_excluded_hosts(session=session, network=network)
        if exclude_hosts:
            # write in-scope host names to file
            tool_path = self.create_file_path(network=network)
            exclude_hosts_file = os.path.join(tool_path, "excluded-hosts.txt")
            if not os.path.exists(tool_path):
                os.makedirs(tool_path)
            with open(exclude_hosts_file, "w") as f:
                for item in exclude_hosts:
                    f.write(item + os.linesep)
        return self.create_commands(session=session,
                                    network=network,
                                    arguments=arguments,
                                    exclude_hosts_file=exclude_hosts_file,
                                    interesting_ports=self._masscan_config.tcp_interesting_ports,
                                    collector_name=collector_name)
