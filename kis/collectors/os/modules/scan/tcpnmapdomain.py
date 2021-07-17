# -*- coding: utf-8 -*-
"""
run tool nmap on all in-scope second-level domains and host names. valid parameters for this argument are: topX for
scanning top X TCP ports; interesting for scanning interesting TCP ports; all for scanning all TCP ports; or a list
of port numbers/ranges (e.g., 0-1024 8080) to scan just those TCP ports
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
from collectors.os.modules.scan.core import BaseNmap
from collectors.os.modules.core import BaseCollector
from collectors.os.modules.core import DomainCollector
from database.model import CollectorName
from database.model import CollectorType
from database.model import HostName
from database.model import DnsResourceRecordType
from sqlalchemy.orm.session import Session

logger = logging.getLogger('tcpnmapdomain')


class CollectorClass(BaseNmap, DomainCollector):
    """This class implements a collector module that is automatically incorporated into the application."""

    def __init__(self, **kwargs):
        super().__init__(priority=1150,
                         timeout=0,
                         exec_user="root",
                         **kwargs)

    @staticmethod
    def get_argparse_arguments():
        return {"help": __doc__, "type": str, "metavar": "TYPE", "nargs": "+"}

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
        # obtain list of in-scope host names
        ipv4_host_names = []
        exclude_ipv4_addresses = []
        ipv6_host_names = []
        exclude_ipv6_addresses = []
        ipv4_nmap_options = ["--resolve-all"]
        ipv6_nmap_options = ["--resolve-all"]
        results = []
        if host_name.name is None:
            # compile list of host names that are in scope and shall be scanned
            for item in host_name.domain_name.host_names:
                if item.name is not None:
                    if item.in_scope(CollectorType.vhost_service):
                        ipv4_host_names.append(item.full_name)
                        # compile list of IPv4 addresses to which the given host name resolves and which are out of scope
                        for mapping in item.get_host_host_name_mappings(types=[DnsResourceRecordType.a]):
                            if not mapping.host.in_scope:
                                exclude_ipv4_addresses.append(mapping.host.ipv4_address)
                    if item.in_scope_ipv6(CollectorType.vhost_service):
                        ipv6_host_names.append(item.full_name)
                        # compile list of IPv6 addresses to which the given host name resolves and which are out of scope
                        for mapping in item.get_host_host_name_mappings(types=[DnsResourceRecordType.aaaa]):
                            if not mapping.host.in_scope:
                                exclude_ipv6_addresses.append(mapping.host.ipv6_address)
            ipv4_nmap_options += list(self._nmap_config.nmap_tcp_options)
            ipv6_nmap_options += list(self._nmap_config.nmap_tcp_options)
            if exclude_ipv4_addresses:
                ipv4_nmap_options += ["--exclude", ",".join(exclude_ipv4_addresses)]
            if exclude_ipv6_addresses:
                ipv6_nmap_options += ["--exclude", ",".join(exclude_ipv6_addresses)]
            arguments = self.get_commandline_argument_value("tcpnmapdomain")
            results += self._create_domain_commands(session=session,
                                                    host_name=host_name,
                                                    host_names=ipv4_host_names,
                                                    collector_name=collector_name,
                                                    nmap_arguments=arguments,
                                                    nmap_options=ipv4_nmap_options,
                                                    nse_scripts=self._nmap_config.tcp_nse_scripts,
                                                    interesting_ports=self._nmap_config.tcp_interesting_ports,
                                                    ipv6=False)
            results += self._create_domain_commands(session=session,
                                                    host_name=host_name,
                                                    host_names=ipv6_host_names,
                                                    collector_name=collector_name,
                                                    nmap_arguments=arguments,
                                                    nmap_options=ipv6_nmap_options,
                                                    nse_scripts=self._nmap_config.tcp_nse_scripts,
                                                    interesting_ports=self._nmap_config.tcp_interesting_ports,
                                                    ipv6=True)
        return results
