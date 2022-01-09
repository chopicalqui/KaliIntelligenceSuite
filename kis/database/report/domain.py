# -*- coding: utf-8 -*-
"""
This module allows querying information about second-level domains.
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
from database.model import DomainName
from database.model import ServiceState
from database.model import ReportScopeType
from database.model import ReportVisibility
from database.model import TextReportDetails
from database.model import DnsResourceRecordType
from database.report.core import BaseReport


class ReportClass(BaseReport):
    """
    this module allows querying information about second-level domains
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(name="domain info",
                         title="Second-Level Domain Details",
                         description="The table provides an overview about all identified second-level domains "
                                     "(see column 'Second-Level Domain (SLD)').",
                         **kwargs)

    @staticmethod
    def get_add_argparse_arguments(parser_domain: argparse.ArgumentParser):
        """
        This method adds the report's specific command line arguments.
        """
        # setup domain parser
        parser_domain.add_argument("-w", "--workspaces",
                                   metavar="WORKSPACE",
                                   help="query the given workspaces",
                                   nargs="+",
                                   type=str)
        parser_domain_group = parser_domain.add_mutually_exclusive_group()
        parser_domain_group.add_argument('--text', action='store_true',
                                         help='returns gathered information including all collector outputs as text')
        parser_domain_group.add_argument('--csv', action='store_true', default=True,
                                         help='returns gathered information in csv format')
        parser_domain_group.add_argument('--igrep', type=str, nargs='+', metavar="REGEX",
                                         help="print command outputs that match the given string or Python3 regular "
                                              "expressions REGEX. matching is case insensitive. use named group 'output' "
                                              "to just capture the content of this named group")
        parser_domain_group.add_argument('--grep', type=str, nargs='+', metavar="REGEX",
                                         help="print command outputs that match the given string or Python3 regular "
                                              "expressions REGEX. matching is case sensitive. use named group 'output' "
                                              "to just capture the content of this named group")
        parser_domain.add_argument('--not', dest="grep_not", action='store_true',
                                   help='negate the filter logic and only show those domain names that do not match the '
                                        '--igrep or --grep argument.')
        parser_domain.add_argument('--filter', metavar='IP|DOMAIN', type=str, nargs='*',
                                   help='list of IP addresses or second-level domains (e.g., megacorpone.com) whose '
                                        'information shall be returned. per default, mentioned items are excluded. '
                                        'add + in front of each item (e.g., +megacorpone.com) to return only these items')
        parser_domain.add_argument('--scope', choices=[item.name for item in ReportScopeType],
                                   help='return only second-level domains that are in scope (within) or out of scope '
                                        '(outside). per default, all information is returned')
        parser_domain.add_argument('--visibility', choices=[item.name for item in ReportVisibility],
                                   help='return only relevant (relevant) or potentially irrelevant (irrelevant) '
                                        'information (e.g., executed commands that did not return any information) in text '
                                        'output (argument --text). per default, all information is returned')
        parser_domain.add_argument('-X', '--exclude', metavar='COLLECTOR', type=str, nargs='+', default=[],
                                   help='list of collector names (e.g., dnshost) whose outputs should not be returned in '
                                        'text mode (see argument --text). use argument value "all" to exclude all '
                                        'collectors. per default, no collectors are excluded')
        parser_domain.add_argument('-I', '--include', metavar='COLLECTOR', type=str, nargs='+', default=[],
                                   help='list of collector names whose outputs should be returned in text mode (see '
                                        'argument --text). per default, all collector information is returned')

    def _filter(self, domain_name: DomainName) -> bool:
        """
        Method determines whether the given item shall be included into the report
        """
        return domain_name.is_processable(included_items=self._included_items,
                                          excluded_items=self._excluded_items,
                                          scope=self._scope,
                                          include_ip_address=True)

    def _egrep_text(self, domain: DomainName) -> List[str]:
        """
        This method returns all lines matching the given list of regular expressions
        :param domain: The domain name whose text output shall be parsed
        :return:
        """
        result = self._egrep(domain.get_text(ident=0,
                                             exclude_collectors=self._excluded_collectors,
                                             include_collectors=self._included_collectors,
                                             scope=self._scope,
                                             details=TextReportDetails(TextReportDetails.item_info)))
        return result

    def get_text(self) -> List[str]:
        """
        This method returns all information as a list of text.
        :return:
        """
        rvalue = []
        for workspace in self._workspaces:
            for domain in workspace.domain_names:
                if self._filter(domain):
                    rvalue.extend(domain.get_text(ident=0,
                                                  exclude_collectors=self._excluded_collectors,
                                                  include_collectors=self._included_collectors,
                                                  scope=self._scope,
                                                  report_visibility=self._visibility,
                                                  color=self._color))
                    rvalue.append("")
        return rvalue

    def grep_text(self) -> List[List[str]]:
        """
        This method returns all information as a list of text.
        :return:
        """
        rows = [["DB ID (Domain)",
                 "DB ID (Hostname)",
                 "Second-Level Domain",
                 "Second-Level Domain Scope",
                 "Companies",
                 "Result"]]
        for workspace in self._workspaces:
            for domain in workspace.domain_names:
                if self._filter(domain):
                    results = self._egrep_text(domain)
                    if self._not_grep and not results:
                        rows.append([domain.id,
                                     workspace.name,
                                     domain.name,
                                     domain.scope_str,
                                     domain.companies_str,
                                     None])
                    elif not self._not_grep:
                        for result in results:
                            rows.append([domain.id,
                                         workspace.name,
                                         domain.name,
                                         domain.scope_str,
                                         domain.companies_str,
                                         result])
        return rows

    def get_csv(self) -> List[List[str]]:
        """
        This method returns all information as CSV.
        :return:
        """
        rows = [["Workspace",
                 "Second-Level Domain",
                 "Companies",
                 "Scope",
                 "In Scope (Company)",
                 "Sources",
                 "No. Subdomains",
                 "No. In-Scope Subdomains",
                 "No. Resolved IPs",
                 "No. Resolved Private IPs",
                 "No. Resolved In-Scope IPs",
                 "No. Open Services",
                 "No. Open In-Scope Services",
                 "No. Closed Services",
                 "No. Commands",
                 "DB ID"]]
        for workspace in self._workspaces:
            for domain in workspace.domain_names:
                if self._filter(domain):
                    # Calculate statistics
                    any_company_in_scope = any([item.in_scope for item in domain.companies])
                    domain_scope = domain.scope_str
                    companies = domain.companies_str
                    domain_sources = None
                    no_sub_domains = 0
                    no_in_scope_sub_domains = 0
                    no_resolved_ips = 0
                    no_resolved_private_ips = 0
                    no_resolved_in_scope_ips = 0
                    no_open_services = 0
                    no_open_in_scope_services = 0
                    no_closed_services = 0
                    no_commands = 0
                    # Obtain statistics about subdomains
                    for host_name in domain.host_names:
                        no_sub_domains += 1
                        no_commands += len(host_name.get_completed_commands())
                        if host_name.name is None:
                            domain_sources = host_name.sources_str
                        if host_name._in_scope:
                            no_in_scope_sub_domains += 1
                        # Obtain statistics about hosts
                        for mapping in host_name.get_host_host_name_mappings([DnsResourceRecordType.a,
                                                                              DnsResourceRecordType.aaaa]):
                            no_resolved_ips += 1
                            if mapping.host.ip_address.is_private:
                                no_resolved_private_ips += 1
                            if mapping.host.in_scope:
                                no_resolved_in_scope_ips += 1
                            # Obtain statistics about networks
                            for service in mapping.host.services:
                                if service.state == ServiceState.Open:
                                    no_open_services += 1
                                    if service.host.in_scope:
                                        no_open_in_scope_services += 1
                                else:
                                    no_closed_services += 1
                    rows.append([workspace.name,            # Workspace
                                 domain.name,               # Second-Level Domain
                                 companies,                 # Companies
                                 domain_scope,              # Scope
                                 any_company_in_scope,      # In Scope (Company)
                                 domain_sources,            # Sources
                                 no_sub_domains,            # No. Subdomains
                                 no_in_scope_sub_domains,   # No. In-Scope Subdomains
                                 no_resolved_ips,           # No. Resolved IPs
                                 no_resolved_private_ips,   # No. Resolved Private IPs
                                 no_resolved_in_scope_ips,  # No. Resolved In-Scope IPs
                                 no_open_services,          # No. Open Services
                                 no_open_in_scope_services, # No. Open In-Scope Services
                                 no_closed_services,        # No. Closed Services
                                 no_commands,               # No. Commands
                                 domain.id])                # DB ID (SLD)
        return rows
