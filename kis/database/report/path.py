# -*- coding: utf-8 -*-
"""This module allows querying information about identified paths (e.g., urls)."""

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
from database.model import Path
from database.model import PathType
from database.model import CollectorType
from database.model import ReportScopeType
from database.model import DnsResourceRecordType
from database.report.core import BaseReport


class ReportClass(BaseReport):
    """
    this module allows querying information about identified paths (e.g., urls)
    """

    def __init__(self, args, **kwargs) -> None:
        super().__init__(args=args,
                         name="path info",
                         title="Overview Identified Paths",
                         description="The table provides an overview of all identified URLs and network shares. You "
                                     "can use column 'Path Type' to filter for specific paths (e.g., URLs).",
                         **kwargs)
        self._path_types = []
        if "type" in args and args.type:
            self._path_types = [PathType[item] for item in args.type]

    @staticmethod
    def get_add_argparse_arguments(parser_path: argparse.ArgumentParser):
        """
        This method adds the report's specific command line arguments.
        """
        # setup path parser
        parser_path.add_argument("-w", "--workspaces",
                                 metavar="WORKSPACE",
                                 help="query the given workspaces",
                                 nargs="+",
                                 type=str)
        parser_path.add_argument('--csv',
                                 default=True,
                                 action='store_true',
                                 help='returns gathered information in csv format')
        parser_path.add_argument('--filter', metavar='IP|NETWORK|DOMAIN|HOSTNAME', type=str, nargs='*',
                                 help='list of IP addresses, IP networks, second-level domains (e.g., megacorpone.com), or '
                                      'host names (e.g., www.megacorpone.com) whose information shall be returned.'
                                      'per default, mentioned items are excluded. add + in front of each item '
                                      '(e.g., +192.168.0.1) to return only these items')
        parser_path.add_argument('--scope', choices=[item.name for item in ReportScopeType],
                                 help='return only information about in scope (within) or out of scope (outside) items. '
                                      'per default, all information is returned')
        parser_path.add_argument('--type',
                                 choices=[item.name for item in PathType],
                                 nargs="+",
                                 help='return only path items of the given type. per default, all information is returned')

    def _filter(self, path: Path) -> bool:
        """
        Method determines whether the given item shall be included into the report
        """
        return (not self._path_types or path.type in self._path_types) and \
               path.is_processable(included_items=self._included_items,
                                   excluded_items=self._excluded_items,
                                   scope=self._scope)

    def get_csv(self) -> List[List[str]]:
        """
        This method returns all information as CSV.
        :return:
        """
        rows = [["Workspace",
                 "Type",
                 "Network/Second-Level-Domain (NSLD)",
                 "Scope (NSLD)",
                 "Company (NSLD)",
                 "Address",
                 "In Scope (Address)",
                 "In Scope (Vhost)",
                 "Resolves To (RT)",
                 "Summary (IP/Vhost)",
                 "Summary (Service)",
                 "TCP/UDP",
                 "Port",
                 "Type (Path)",
                 "Status Code",
                 "Response Size [Bytes]",
                 "Full Path",
                 "Root Directory",
                 "Query",
                 "Sources (NSLD)",
                 "Sources (Service)",
                 "Sources (Path)",
                 "DB ID (Path)"]]
        for workspace in self._workspaces:
            for domain in workspace.domain_names:
                for host_name in domain.host_names:
                    hosts_str = host_name.get_host_host_name_mappings_str([DnsResourceRecordType.a,
                                                                           DnsResourceRecordType.aaaa])
                    sources = host_name.sources_str
                    for service in host_name.services:
                        sources_service = service.sources_str
                        for path in service.paths:
                            if self._filter(path):
                                if path.queries:
                                    for query in path.queries:
                                        rows.append([workspace.name, # Workspace
                                                     "vhost", # Type
                                                     host_name.domain_name.name, # Network/Second-Level-Domain (NSLD)
                                                     host_name.domain_name.scope_str, # Scope (NSLD)
                                                     host_name.domain_name.companies_str, # Company (NSLD)
                                                     host_name.full_name, # Address
                                                     host_name._in_scope, # In Scope (Address)
                                                     host_name.in_scope(CollectorType.vhost_service), # In Scope (Vhost)
                                                     hosts_str, # Resolves To (RT)
                                                     host_name.summary, # Summary (IP/Vhost)
                                                     service.summary, # Summary (Service)
                                                     service.protocol_str, # TCP/UDP
                                                     service.port, # Port
                                                     path.type_str, # Type (Path)
                                                     path.return_code, # Status Code
                                                     path.size_bytes, # Response Size [Bytes]
                                                     path.get_path(), # Full Path
                                                     path.name == "/", # Root Directory
                                                     query.query, # Query
                                                     sources, # Sources (NSLD)
                                                     sources_service, # Sources (Service)
                                                     path.sources_str, # Sources (Path)
                                                     path.id]) # DB ID (Path)
                                else:
                                    rows.append([workspace.name, # Workspace
                                                 "vhost", # Type
                                                 host_name.domain_name.name, # Network/Second-Level-Domain (NSLD)
                                                 host_name.domain_name.scope_str, # Scope (NSLD)
                                                 host_name.domain_name.companies_str, # Company (NSLD)
                                                 host_name.full_name, # Address
                                                 host_name._in_scope, # In Scope (Address)
                                                 host_name.in_scope(CollectorType.vhost_service), # In Scope (Vhost)
                                                 hosts_str, # Resolves To (RT)
                                                 host_name.summary, # Summary (IP/Vhost)
                                                 service.summary, # Summary (Service)
                                                 service.protocol_str, # TCP/UDP
                                                 service.port, # Port
                                                 path.type_str, # Type (Path)
                                                 path.return_code, # Status Code
                                                 path.size_bytes, # Response Size [Bytes]
                                                 path.get_path(), # Full Path
                                                 path.name == "/", # Root Directory
                                                 None, # Query
                                                 sources, # Sources (NSLD)
                                                 sources_service, # Sources (Service)
                                                 path.sources_str, # Sources (Path)
                                                 path.id]) # DB ID (Path)
            for host in workspace.hosts:
                host_names = host.get_host_host_name_mappings_str([DnsResourceRecordType.a,
                                                                   DnsResourceRecordType.aaaa])
                if host.ipv4_network:
                    ipv4_network = host.ipv4_network.network
                    scope = host.ipv4_network.scope_str
                    companies = host.ipv4_network.companies_str
                    sources = host.ipv4_network.sources_str
                else:
                    ipv4_network = None
                    scope = None
                    companies = None
                    sources = None
                for service in host.services:
                    sources_service = service.sources_str
                    for path in service.paths:
                        if self._filter(path):
                            if path.queries:
                                for query in path.queries:
                                    rows.append([workspace.name, # Workspace
                                                 "host", # Type
                                                 ipv4_network, # Network/Second-Level-Domain (NSLD)
                                                 scope, # Scope (NSLD)
                                                 companies, # Company (NSLD)
                                                 host.address, # Address
                                                 host.in_scope, # In Scope (Address)
                                                 None, # In Scope (Vhost)
                                                 host_names, # Resolves To (RT)
                                                 host.summary, # Summary (IP/Vhost)
                                                 service.summary, # Summary (Service)
                                                 service.protocol_str, # TCP/UDP
                                                 service.port, # Port
                                                 path.type_str, # Type (Path)
                                                 path.return_code, # Status Code
                                                 path.size_bytes, # Response Size [Bytes]
                                                 path.get_path(), # Full Path
                                                 path.name == "/", # Root Directory
                                                 query.query, # Query
                                                 sources, # Sources (NSLD)
                                                 sources_service, # Sources (Service)
                                                 path.sources_str, # Sources (Path)
                                                 path.id]) # DB ID (Path)
                            else:
                                rows.append([workspace.name, # Workspace
                                             "host", # Type
                                             ipv4_network, # Network/Second-Level-Domain (NSLD)
                                             scope, # Scope (NSLD)
                                             companies, # Company (NSLD)
                                             host.address, # Address
                                             host.in_scope, # In Scope (Address)
                                             None, # In Scope (Vhost)
                                             host_names, # Resolves To (RT)
                                             host.summary, # Summary (IP/Vhost)
                                             service.summary, # Summary (Service)
                                             service.protocol_str, # TCP/UDP
                                             service.port, # Port
                                             path.type_str, # Type (Path)
                                             path.return_code, # Status Code
                                             path.size_bytes, # Response Size [Bytes]
                                             path.get_path(), # Full Path
                                             path.name == "/", # Root Directory
                                             None, # Query
                                             sources, # Sources (NSLD)
                                             sources_service, # Sources (Service)
                                             path.sources_str, # Sources (Path)
                                             path.id]) # DB ID (Path)
        return rows
