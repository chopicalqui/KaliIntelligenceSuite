# -*- coding: utf-8 -*-
"""
run tool host on each in-scope in-scope DNS service to test for DNS zone transfers for each in-scope domain name.
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
from collectors.os.modules.dns.core import BaseDnsAxfr
from collectors.os.modules.core import ServiceCollector
from collectors.os.modules.core import BaseCollector
from database.model import DomainName
from database.model import ScopeType
from database.model import Service
from database.model import CollectorName
from sqlalchemy import or_
from sqlalchemy.orm.session import Session

logger = logging.getLogger('dnsaxfrservice')


class CollectorClass(BaseDnsAxfr, ServiceCollector):
    """This class implements a collector module that is automatically incorporated into the application."""

    def __init__(self, **kwargs):
        super().__init__(priority=1306,
                         timeout=0,
                         **kwargs)

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
        if self.match_nmap_service_name(service) and not self._dns_server:
            domain_name = session.query(DomainName).filter(or_(DomainName.scope == ScopeType.all,
                                                               DomainName.scope == ScopeType.strict,
                                                               DomainName.scope == ScopeType.vhost)).all()
            for item in domain_name:
                os_command = [self._path_host,
                              "-{}".format(service.host.version),
                              "-t", "axfr",
                              "-p", service.port,
                              item.name,
                              service.address]
                collector = self._get_or_create_command(session, os_command, collector_name, service=service)
                collectors.append(collector)
        return collectors
