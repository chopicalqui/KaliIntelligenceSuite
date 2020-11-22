# -*- coding: utf-8 -*-
"""
run tool host on all collected host names (e.g., www.megacorpone.com) and second-level domains (e.g.,
megacorpone.com) to resolve their IPv4/IPv6 addresses using the public DNS server 8.8.8.8. alternatively, you can use
a different DNS server by using optional argument --dns-server
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
from collectors.os.modules.core import DomainCollector
from collectors.os.modules.dns.core import BaseDnsHost
from collectors.os.modules.core import BaseCollector
from database.model import HostName
from database.model import CollectorName
from database.model import DnsResourceRecordType
from sqlalchemy.orm.session import Session

logger = logging.getLogger('dnshostpublic')


class CollectorClass(BaseDnsHost, DomainCollector):
    """This class implements a collector module that is automatically incorporated into the application."""

    def __init__(self, **kwargs):
        super().__init__(priority=312,
                         active_collector=False,
                         timeout=0,
                         delay_min=1,
                         **kwargs)

    @staticmethod
    def get_argparse_arguments():
        return {"help": __doc__, "action": "store_true"}

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
        if host_name:
            os_command = [self._path_host, host_name.full_name]
            if self._dns_server:
                os_command.append(self._dns_server)
            else:
                os_command.append(self._default_dns_server)
            collector = self._get_or_create_command(session, os_command, collector_name, host_name=host_name)
            collectors.append(collector)
        return collectors
