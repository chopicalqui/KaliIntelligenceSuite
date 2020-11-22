# -*- coding: utf-8 -*-
"""
run tool whois on all identified in- and out-of-scope global IPv4/IPv6 addresses. depending on the number of hosts
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
from database.model import Command
from database.model import CollectorName
from database.model import Host
from database.model import Workspace
from database.model import Network
from collectors.os.modules.core import HostCollector
from collectors.os.modules.core import BaseCollector
from collectors.os.modules.osint.core import BaseWhoisHostNetwork
from database.model import Source
from sqlalchemy.orm.session import Session

logger = logging.getLogger('whoishost')


class CollectorClass(BaseWhoisHostNetwork, HostCollector):
    """This class implements a collector module that is automatically incorporated into the application."""

    def __init__(self, **kwargs):
        super().__init__(priority=510,
                         **kwargs)

    @staticmethod
    def get_argparse_arguments():
        return {"help": __doc__, "action": "store_true"}

    def _get_commands(self,
                      session: Session,
                      host: Host,
                      collector_name: CollectorName,
                      command: str) -> List[BaseCollector]:
        """Returns a list of commands based on the provided information."""
        collectors = []
        address = host.address
        os_command = [command, address]
        collector = self._get_or_create_command(session, os_command, collector_name, host=host)
        collectors.append(collector)
        return collectors

    def create_host_commands(self,
                             session: Session,
                             host: Host,
                             collector_name: CollectorName) -> List[BaseCollector]:
        """This method creates and returns a list of commands based on the given service.

        This method determines whether the command exists already in the database. If it does, then it does nothing,
        else, it creates a new Collector entry in the database for each new command as well as it creates a corresponding
        operating system command and attaches it to the respective newly created Collector class.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param host: The host based on which commands shall be created.
        :param collector_name: The name of the collector as specified in table collector_name
        :return: List of Collector instances that shall be processed.
        """
        collectors = []
        command = self._path_whois
        source = session.query(Source)\
            .join((Host, Source.hosts)).filter(Source.name == collector_name.name, Host.id == host.id).one_or_none()
        if host.ip_address.is_global and not source:
            tmp = self._get_commands(session, host, collector_name, command)
            collectors.extend(tmp)
        return collectors

    def start_command_execution(self, session: Session, command: Command) -> bool:
        """
        This method allows the consumer threat to check whether the command should be executed. If this method returns
        false, then the command execution is not started. This is useful when another command of the same collector
        already identified the interesting information.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param command: The command instance to be executed
        :return: True, if the command should be executed, False if not.
        """
        # We only execute whois, if we have not obtained the same whois entry via an IP address located in the
        # same network
        count = session.query(Network)\
            .join((Workspace, Network.workspace))\
            .join((Host, Network.hosts))\
            .join((Command, Host.commands))\
            .join((CollectorName, Command.collector_name))\
            .join((Source, Network.sources))\
            .filter(Source.name == command.collector_name.name,
                    CollectorName.name == command.collector_name.name,
                    Network.id == command.host.ipv4_network_id,
                    Workspace.id == command.host.workspace_id).count()
        return count == 0
