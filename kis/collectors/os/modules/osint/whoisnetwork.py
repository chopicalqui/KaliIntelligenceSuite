# -*- coding: utf-8 -*-
"""
run tool whois on all identified in- and out-of-scope global IPv4/IPv6 networks. depending on the number of networks
in the current workspace, it might be desired to limit the number of OS commands by using the optional argument
--filter. note that in order to reduce the number of whois requests, KIS only queries one IPv4/IPv6 address per network
range returned by whois and all remaining queries are ignored
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
from typing import List
from database.model import CollectorName
from database.model import Network
from collectors.os.modules.core import Ipv4NetworkCollector
from collectors.os.modules.core import BaseCollector
from collectors.os.modules.osint.core import BaseWhoisHostNetwork
from sqlalchemy.orm.session import Session

logger = logging.getLogger('whoisnetwork')


class CollectorClass(BaseWhoisHostNetwork, Ipv4NetworkCollector):
    """This class implements a collector module that is automatically incorporated into the application."""

    def __init__(self, **kwargs):
        super().__init__(priority=512,
                         **kwargs)

    @staticmethod
    def get_argparse_arguments():
        return {"help": __doc__, "action": "store_true"}

    def _get_commands(self,
                      session: Session,
                      network: Network,
                      collector_name: CollectorName,
                      command: str) -> List[BaseCollector]:
        """Returns a list of commands based on the provided information."""
        collectors = []
        os_command = [command, network.network]
        collector = self._get_or_create_command(session, os_command, collector_name, network=network)
        collectors.append(collector)
        return collectors

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
        collectors = []
        command = self._path_whois
        if network.ip_network.is_global and network.network != "0.0.0.0/0" and network.network != "::/0":
            tmp = self._get_commands(session, network, collector_name, command)
            collectors.extend(tmp)
        return collectors
