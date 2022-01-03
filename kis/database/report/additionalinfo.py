# -*- coding: utf-8 -*-
"""This module allows querying additional information (e.g., HTTP headers)."""

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
from database.model import AdditionalInfo
from database.model import CollectorType
from database.model import DnsResourceRecordType
from collectors.apis.haveibeenpwned import HaveIBeenPwnedPasteAcccount
from collectors.apis.haveibeenpwned import HaveIBeenPwnedBreachedAcccount
from database.model import ReportScopeType
from database.report.core import BaseReport


class ReportClass(BaseReport):
    """
    this module allows querying additional information (e.g., HTTP headers).
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(name="additional info",
                         title="Overview Identified Additional Information",
                         description="The table provides an overview of all identified additional information like "
                                     "version information. Columns 'Name' and 'Value' are key value pairs and you "
                                     "can sort column 'Name' to determine which values exist for certain keys.",
                         **kwargs)

    @staticmethod
    def get_add_argparse_arguments(parser_additional_info: argparse.ArgumentParser):
        """
        This method adds the report's specific command line arguments.
        """
        # setup additional info parser
        parser_additional_info.add_argument("-w", "--workspaces",
                                            metavar="WORKSPACE",
                                            help="query the given workspaces",
                                            nargs="+",
                                            type=str)
        parser_additional_info.add_argument('--csv',
                                            default=True,
                                            action='store_true',
                                            help='returns gathered information in csv format')
        parser_additional_info.add_argument('--filter', metavar='IP|NETWORK|DOMAIN|HOSTNAME', type=str, nargs='*',
                                            help='list of IP addresses (e.g., 192.168.1.1), IP networks (e.g., '
                                                 '192.168.1.0/24), second-level domains (e.g., megacorpone.com), or '
                                                 'host names (e.g., www.megacorpone.com) whose information shall be '
                                                 'returned.per default, mentioned items are excluded. add + in front of '
                                                 'each item (e.g., +192.168.0.1) to return only these items')
        parser_additional_info.add_argument('--scope', choices=[item.name for item in ReportScopeType],
                                            help='return only information about in scope (within) or out of scope '
                                                 '(outside) items. per default, all information is returned')

    def _filter(self, additional_info: AdditionalInfo) -> bool:
        """
        Method determines whether the given item shall be included into the report
        """
        return additional_info.is_processable(included_items=self._included_items,
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
                 "Resolves to",
                 "Service Summary",
                 "TCP/UDP",
                 "Port",
                 "Service",
                 "Name",
                 "Value",
                 "Sources"]]
        for workspace in self._workspaces:
            for domain in workspace.domain_names:
                for host_name in domain.host_names:
                    ipv4_addresses = host_name.get_host_host_name_mappings_str(types=[DnsResourceRecordType.a,
                                                                                      DnsResourceRecordType.aaaa,
                                                                                      DnsResourceRecordType.ptr])
                    for service in host_name.services:
                        for additional_info in service.additional_info:
                            if additional_info.name not in ["CVEs",
                                                            HaveIBeenPwnedBreachedAcccount.NAME,
                                                            HaveIBeenPwnedPasteAcccount.NAME] and \
                                    self._filter(additional_info):
                                for value in additional_info.values:
                                    rows.append([additional_info.id,
                                                 workspace.name,
                                                 "vhost",
                                                 None,
                                                 host_name.in_scope(CollectorType.vhost_service),
                                                 service.address,
                                                 service.address_summary,
                                                 ipv4_addresses,
                                                 service.summary,
                                                 service.protocol_str,
                                                 service.port,
                                                 service.protocol_port_str,
                                                 additional_info.name,
                                                 value,
                                                 additional_info.sources_str])
            for host in workspace.hosts:
                host_names = host.get_host_host_name_mappings_str(types=[DnsResourceRecordType.a,
                                                                         DnsResourceRecordType.aaaa,
                                                                         DnsResourceRecordType.ptr])
                if host.ipv4_network:
                    ipv4_network = host.ipv4_network.network
                else:
                    ipv4_network = None
                for service in host.services:
                    for additional_info in service.additional_info:
                        if additional_info.name not in ["CVEs",
                                                        HaveIBeenPwnedBreachedAcccount.NAME,
                                                        HaveIBeenPwnedPasteAcccount.NAME] and \
                                self._filter(additional_info):
                            sources = additional_info.sources_str
                            for value in additional_info.values:
                                rows.append([additional_info.id,
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
                                             additional_info.name,
                                             value,
                                             sources])
            for domain in workspace.domain_names:
                for host_name in domain.host_names:
                    for additional_info in host_name.additional_info:
                        if additional_info.name not in ["CVEs",
                                                        HaveIBeenPwnedBreachedAcccount.NAME,
                                                        HaveIBeenPwnedPasteAcccount.NAME] \
                                and self._filter(additional_info):
                            sources = additional_info.sources_str
                            for value in additional_info.values:
                                rows.append([additional_info.id,
                                             workspace.name,
                                             "domain",
                                             None,
                                             host_name.in_scope(CollectorType.vhost_service),
                                             host_name.full_name,
                                             None,
                                             None,
                                             None,
                                             None,
                                             None,
                                             None,
                                             additional_info.name,
                                             value,
                                             sources])
            for domain in workspace.domain_names:
                for host_name in domain.host_names:
                    for email in host_name.emails:
                        for additional_info in email.additional_info:
                            if additional_info.name not in ["CVEs",
                                                            HaveIBeenPwnedBreachedAcccount.NAME,
                                                            HaveIBeenPwnedPasteAcccount.NAME] \
                                    and self._filter(additional_info):
                                sources = additional_info.sources_str
                                for value in additional_info.values:
                                    rows.append([additional_info.id,
                                                 workspace.name,
                                                 "email",
                                                 None,
                                                 domain.in_scope,
                                                 email.email_address,
                                                 None,
                                                 None,
                                                 None,
                                                 None,
                                                 None,
                                                 None,
                                                 additional_info.name,
                                                 value,
                                                 sources])
            for ipv4_network in workspace.ipv4_networks:
                for additional_info in ipv4_network.additional_info:
                    if additional_info.name not in ["CVEs",
                                                    HaveIBeenPwnedBreachedAcccount.NAME,
                                                    HaveIBeenPwnedPasteAcccount.NAME] and self._filter(additional_info):
                        sources = additional_info.sources_str
                        for value in additional_info.values:
                            rows.append([additional_info.id,
                                         workspace.name,
                                         "network",
                                         ipv4_network.network,
                                         ipv4_network.in_scope,
                                         ipv4_network.network,
                                         None,
                                         None,
                                         None,
                                         None,
                                         None,
                                         None,
                                         additional_info.name,
                                         value,
                                         sources])
            for company in workspace.companies:
                for additional_info in company.additional_info:
                    sources = additional_info.sources_str
                    for value in additional_info.values:
                        rows.append([additional_info.id,
                                     workspace.name,
                                     "company",
                                     None,
                                     company.in_scope,
                                     company.name,
                                     None,
                                     None,
                                     None,
                                     None,
                                     None,
                                     None,
                                     additional_info.name,
                                     value,
                                     sources])
        return rows
