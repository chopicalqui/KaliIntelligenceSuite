# -*- coding: utf-8 -*-
"""This module allows querying information about identified credentials (e.g., ftp or snmp)."""

__author__ = "Lukas Reiter"
__license__ = "GPL v3.0"
__copyright__ = """Copyright 2022 Lukas Reiter

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

import argparse
from typing import List
from database.model import Credentials
from database.model import CollectorType
from database.model import DnsResourceRecordType
from database.model import ReportScopeType
from database.report.core import BaseReport


class ReportClass(BaseReport):
    """
    this module allows querying information about identified credentials (e.g., ftp or snmp)
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(name="credential info",
                         title="Overview Identified Credentials",
                         description="The table provides an overview of all identified credentials.",
                         **kwargs)

    @staticmethod
    def get_add_argparse_arguments(parser_credential: argparse.ArgumentParser):
        """
        This method adds the report's specific command line arguments.
        """
        # setup credential parser
        parser_credential.add_argument("-w", "--workspaces",
                                       metavar="WORKSPACE",
                                       help="query the given workspaces",
                                       nargs="+",
                                       type=str)
        parser_credential.add_argument('--csv',
                                       default=True,
                                       action='store_true',
                                       help='returns gathered information in csv format')
        parser_credential.add_argument('--filter', metavar='IP|NETWORK|DOMAIN|HOSTNAME|EMAIL', type=str, nargs='*',
                                       help='list of IP addresses, IP networks, second-level domains (e.g., '
                                            'megacorpone.com), email address, or host names (e.g., www.megacorpone.com) '
                                            'whose information shall be returned.per default, mentioned items are. '
                                            'excluded add + in front of each item (e.g., +192.168.0.1) to return only '
                                            'these items')
        parser_credential.add_argument('--scope', choices=[item.name for item in ReportScopeType],
                                       help='return only information about in scope (within) or out of scope (outside) '
                                            'items. per default, all information is returned')

    def _filter(self, credentials: Credentials) -> bool:
        """
        Method determines whether the given item shall be included into the report
        """
        return credentials.is_processable(included_items=self._included_items,
                                          excluded_items=self._excluded_items,
                                          scope=self._scope)

    def get_csv(self) -> List[List[str]]:
        """
        This method returns all information as CSV.
        :return:
        """
        rows = [["DB ID",
                 "Workspace",
                 "Type",
                 "Network",
                 "In Scope",
                 "Address",
                 "Address Summary",
                 "Host Names",
                 "Service Summary",
                 "TCP/UDP",
                 "Port",
                 "Service",
                 "Type",
                 "Complete",
                 "User name",
                 "Password",
                 "Source"]]
        for workspace in self._workspaces:
            for domain in workspace.domain_names:
                for host_name in domain.host_names:
                    for service in host_name.services:
                        for credential in service.credentials:
                            if self._filter(credential):
                                rows.append([credential.id,
                                             workspace.name,
                                             "vhost",
                                             None,
                                             host_name.in_scope(CollectorType.vhost_service),
                                             service.address,
                                             service.address_summary,
                                             None,
                                             service.summary,
                                             service.protocol_str,
                                             service.port,
                                             service.protocol_port_str,
                                             credential.type_str,
                                             credential.complete,
                                             credential.username,
                                             credential.password,
                                             credential.sources_str])
            for host in workspace.hosts:
                host_names = host.get_host_host_name_mappings_str([DnsResourceRecordType.a,
                                                                   DnsResourceRecordType.aaaa,
                                                                   DnsResourceRecordType.ptr])
                if host.ipv4_network:
                    ipv4_network = host.ipv4_network.network
                else:
                    ipv4_network = None
                for service in host.services:
                    for credential in service.credentials:
                        if self._filter(credential):
                            rows.append([credential.id,
                                         workspace.name,
                                         "host",
                                         ipv4_network,
                                         host.in_scope,
                                         service.address,
                                         service.address_summary,
                                         host_names,
                                         service.summary,
                                         service.protocol_str,
                                         service.port,
                                         service.protocol_port_str,
                                         credential.type_str,
                                         credential.complete,
                                         credential.username,
                                         credential.password,
                                         credential.sources_str])
            for domain in workspace.domain_names:
                for host_name in domain.host_names:
                    for email in host_name.emails:
                        for credential in email.credentials:
                            if self._filter(credential):
                                rows.append([credential.id,
                                             workspace.name,
                                             "email",
                                             None,
                                             domain.in_scope,
                                             None,
                                             None,
                                             None,
                                             None,
                                             None,
                                             None,
                                             None,
                                             credential.type_str,
                                             credential.complete,
                                             email.email_address,
                                             credential.password,
                                             credential.sources_str])
        return rows
