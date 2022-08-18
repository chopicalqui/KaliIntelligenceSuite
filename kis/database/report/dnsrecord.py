# -*- coding: utf-8 -*-
"""
This module allows querying DNS record information.
"""

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
from database.model import Host
from database.model import HostName
from database.model import Workspace
from database.model import DomainName
from database.model import CollectorType
from database.model import ReportScopeType
from database.model import HostHostNameMapping
from database.model import HostNameHostNameMapping
from database.model import DnsResourceRecordType
from database.report.core import BaseReport


class ReportClass(BaseReport):
    """
    this module allows querying information about second-level domains
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(name="dns record info",
                         title="DNS Record Information",
                         description="The table provides an overview about extracted DNS record information ",
                         **kwargs)

    @staticmethod
    def get_add_argparse_arguments(parser: argparse.ArgumentParser):
        """
        This method adds the report's specific command line arguments.
        """
        # setup domain parser
        parser.add_argument("-w", "--workspaces",
                            metavar="WORKSPACE",
                            help="query the given workspaces",
                            nargs="+",
                            type=str)
        parser.add_argument('--csv',
                            default=True,
                            action='store_true',
                            help='returns gathered information in csv format')
        parser.add_argument('--scope', choices=[item.name for item in ReportScopeType],
                            help='return only second-level domains that are in scope (within) or out of scope '
                                 '(outside). per default, all information is returned')

    def _filter(self, item: object) -> bool:
        """
        Method determines whether the given item shall be included into the report
        """
        if isinstance(item, Host):
            result = item.is_processable(included_items=self._included_items,
                                         excluded_items=self._excluded_items,
                                         scope=self._scope,
                                         include_host_names=True)
        else:
            result = item.is_processable(included_items=self._included_items,
                                         excluded_items=self._excluded_items,
                                         collector_type=CollectorType.vhost_service,
                                         scope=self._scope,
                                         include_ip_address=True)
        return result

    def get_csv(self) -> List[List[str]]:
        """
        This method returns all information as CSV.
        :return:
        """
        result = [["Workspace",
                   "Type",
                   "Second-Level Domain (SLD)",
                   "Scope (SLD)",
                   "Host Name (HN)",
                   "In Scope (HN)",
                   "In Scope (HN or Host/HN)",
                   "Name Only (HN)",
                   "Company All (HN)",
                   "Company Verified (HN)",
                   "Environment (HN)",
                   "Record Type",
                   "IP Address/Host Name (Host/HN)",
                   "Version (Host)",
                   "Private IP",
                   "In Scope (Host/HN)",
                   "Name Only (HN)",
                   "Network/SLD (NW/SLD)",
                   "Scope (NW/SLD)",
                   "Company All (NW/SLD)",
                   "Company Verified (NW/SLD)",
                   "Environment (HN)",
                   "DB ID (SLD)",
                   "DB ID (HN)",
                   "DB ID (Mapping)",
                   "DB ID (Host/HN)",
                   "DB ID (NW/SLD)",
                   "Source (HN)",
                   "Source (Mapping)",
                   "Source (Host/HN)",
                   "Source (NW)"]]
        for workspace in self._workspaces:
            for mapping in self._session.query(HostHostNameMapping) \
                .join(Host) \
                .join(Workspace) \
                .filter(Workspace.id == workspace.id):
                for mapping_type in DnsResourceRecordType:
                    if (mapping.type & mapping_type) == mapping_type:
                        domain_name = mapping.host_name.domain_name.name
                        domain_name_id = mapping.host_name.domain_name.id
                        domain_name_scope = mapping.host_name.domain_name.scope_str
                        host_name = mapping.host_name.full_name
                        host_name_id = mapping.host_name.id
                        host_name_only = mapping.host_name.name
                        host_name_scope = mapping.host_name._in_scope
                        host_name_source = mapping.host_name.sources_str
                        host_name_companies = mapping.host_name.companies_str
                        host_name_companies_verified = mapping.host_name.companies_verified_str
                        host_name_environment = self._domain_config.get_environment(mapping.host_name)
                        host_or_host_name_scope = mapping.host_name._in_scope or mapping.host.in_scope
                        mapping_name = mapping_type.name.upper()
                        mapping_id = mapping.id
                        mapping_source = mapping.sources_str
                        host = mapping.host.address
                        host_id = mapping.host.id
                        host_version = mapping.host.version_str
                        host_private_ip = mapping.host.ip_address.is_private
                        host_scope = mapping.host.in_scope
                        host_source = mapping.host.sources_str
                        if mapping.host.ipv4_network:
                            network_id = mapping.host.ipv4_network.id
                            network_str = mapping.host.ipv4_network.network
                            network_scope = mapping.host.ipv4_network.scope_str
                            network_sources = mapping.host.ipv4_network.sources_str
                            network_companies = mapping.host.ipv4_network.companies_str
                            network_companies_verified = mapping.host.ipv4_network.companies_verified_str
                        else:
                            network_id = None
                            network_str = None
                            network_scope = None
                            network_sources = None
                            network_companies = None
                            network_companies_verified = None
                        result.append([workspace.name,  # Workspace
                                       "Domain to Host",  # Type
                                       domain_name,  # Second-Level Domain (SLD)
                                       domain_name_scope,  # Scope (SLD)
                                       host_name,  # Host Name (HN)
                                       host_name_scope,  # In Scope (HN)
                                       host_or_host_name_scope, # In Scope (HN or Host/HN)
                                       host_name_only,  # Name Only (HN)
                                       host_name_companies,  # Company All (HN)
                                       host_name_companies_verified,  # Company Verified (HN)
                                       host_name_environment,  # Environment (HN)
                                       mapping_name,  # Record Type
                                       host,  # IP Address/Host Name (Host/HN)
                                       host_version,  # Version (Host)
                                       host_private_ip,  # Private IP
                                       host_scope,  # In Scope (Host/HN)
                                       None,   # Name Only (HN)
                                       network_str,  # Network/SLD (NW/SLD)
                                       network_scope,  # Scope (NW/SLD)
                                       network_companies,  # Company All (NW/SLD)
                                       network_companies_verified,  # Company Verified (NW/SLD)
                                       None,  # Environment (HN)
                                       domain_name_id,  # DB ID (SLD)
                                       host_name_id,  # DB ID (HN)
                                       mapping_id,  # DB ID (Mapping)
                                       host_id,  # DB ID (Host/HN)
                                       network_id,  # DB ID (NW/SLD)
                                       host_name_source,  # Source (HN)
                                       mapping_source,  # Source (Mapping)
                                       host_source,  # Source (Host/HN)
                                       network_sources])  # Source (NW)
            for mapping in self._session.query(HostNameHostNameMapping) \
                .join(HostName, HostNameHostNameMapping.source_host_name) \
                .join(DomainName) \
                .join(Workspace) \
                .filter(Workspace.id == workspace.id):
                for mapping_type in DnsResourceRecordType:
                    if (mapping.type & mapping_type) == mapping_type:
                        domain_name = mapping.source_host_name.domain_name.name
                        domain_name_id = mapping.source_host_name.domain_name.id
                        domain_name_scope = mapping.source_host_name.domain_name.scope_str
                        host_name = mapping.source_host_name.full_name
                        host_name_id = mapping.source_host_name.id
                        host_name_only = mapping.source_host_name.name
                        host_name_scope = mapping.source_host_name._in_scope
                        host_name_source = mapping.source_host_name.sources_str
                        host_name_companies = mapping.source_host_name.companies_str
                        host_name_companies_verified = mapping.source_host_name.companies_verified_str
                        host_name_environment = self._domain_config.get_environment(mapping.source_host_name)
                        host_name_or_host_name_scope = mapping.source_host_name._in_scope or mapping.resolved_host_name._in_scope
                        mapping_name = mapping_type.name.upper()
                        mapping_id = mapping.id
                        mapping_source = mapping.sources_str
                        resolved_domain_name = mapping.resolved_host_name.domain_name.name
                        resolved_domain_name_id = mapping.resolved_host_name.domain_name.id
                        resolved_domain_name_scope = mapping.resolved_host_name.domain_name.scope_str
                        resolved_host_name = mapping.resolved_host_name.full_name
                        resolved_host_name_id = mapping.resolved_host_name.id
                        resolved_host_name_only = mapping.resolved_host_name.name
                        resolved_host_name_scope = mapping.resolved_host_name._in_scope
                        resolved_host_name_source = mapping.resolved_host_name.sources_str
                        resolved_host_name_companies = mapping.resolved_host_name.companies_str
                        resolved_host_name_companies_verified = mapping.resolved_host_name.companies_verified_str
                        resolved_host_name_environment = self._domain_config.get_environment(mapping.resolved_host_name)
                        result.append([workspace.name,  # Workspace
                                       "Domain to Domain",  # Type
                                       domain_name,  # Second-Level Domain (SLD)
                                       domain_name_scope,  # Scope (SLD)
                                       host_name,  # Host Name (HN)
                                       host_name_scope,  # In Scope (HN)
                                       host_name_or_host_name_scope,  # In Scope (HN or Host/HN)
                                       host_name_only,  # Name Only (HN)
                                       host_name_companies,  # Company All (HN)
                                       host_name_companies_verified,  # Company Verified (HN)
                                       host_name_environment,  # Environment (HN)
                                       mapping_name,  # Record Type
                                       resolved_host_name,  # IP Address/Host Name (Host/HN)
                                       None,  # Version (Host)
                                       None,  # Private IP
                                       resolved_host_name_scope,  # In Scope (Host/HN)
                                       resolved_host_name_only,  # Name Only (HN)
                                       resolved_domain_name,  # Network/SLD (NW/SLD)
                                       resolved_domain_name_scope,  # Scope (NW/SLD)
                                       resolved_host_name_companies,  # Company All (NW/SLD)
                                       resolved_host_name_companies_verified,  # Company Verified (NW/SLD)
                                       resolved_host_name_environment,  # Environment (HN)
                                       domain_name_id,  # DB ID (SLD)
                                       host_name_id,  # DB ID (HN)
                                       mapping_id,  # DB ID (Mapping)
                                       resolved_host_name_id,  # DB ID (Host/HN)
                                       resolved_domain_name_id,  # DB ID (NW/SLD)
                                       host_name_source,  # Source (HN)
                                       mapping_source,  # Source (Mapping)
                                       resolved_host_name_source,  # Source (Host/HN)
                                       None])  # Source (NW/SLD)
        return result
