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
from database.model import ProtocolType
from database.model import ReportScopeType
from database.model import ReportVisibility
from database.model import TextReportDetails
from database.model import DnsResourceRecordType
from database.report.core import BaseReport
from database.report.core import ServiceStatistics


class DomainNameStatistics:
    """
    This class maintains all statistics for a second-level domain
    """

    def __init__(self, protocols: list):
        self.service_stats = ServiceStatistics(protocols)
        self._protocols = protocols
        self.domain_sources = None
        self.no_sub_domains = 0
        self.no_in_scope_sub_domains = 0
        self.no_resolved_ips = 0
        self.no_resolved_in_scope_ips = 0
        self.no_resolved_private_ips = 0
        self.no_commands = 0

    @property
    def no_out_of_scope_sub_domains(self):
        return self.no_sub_domains - self.no_in_scope_sub_domains

    @property
    def no_resolved_out_of_scope_ips(self):
        return self.no_resolved_ips - self.no_resolved_in_scope_ips

    def compute(self, domain: DomainName):
        """
        Compute statistics for the given domain name.
        """
        # Obtain statistics about subdomains
        for host_name in domain.host_names:
            self.no_sub_domains += 1
            self.no_commands += len(host_name.get_completed_commands())
            if host_name.name is None:
                self.domain_sources = host_name.sources_str
            if host_name._in_scope:
                self.no_in_scope_sub_domains += 1
            # Obtain statistics about hosts
            for mapping in host_name.get_host_host_name_mappings([DnsResourceRecordType.a,
                                                                  DnsResourceRecordType.aaaa]):
                self.no_resolved_ips += 1
                if mapping.host.ip_address.is_private:
                    self.no_resolved_private_ips += 1
                if mapping.host.in_scope:
                    self.no_resolved_in_scope_ips += 1
                # Obtain statistics about networks
                self.service_stats.compute(mapping.host)


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
        parser_domain.add_argument('-p', '--protocol', nargs='+',
                                   choices=[item.name for item in ProtocolType],
                                   default=[item.name for item in ProtocolType],
                                   help="create the service statistics for the following ISO/OSI layer 4 protocols")

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
                 "Open Services",
                 "Open In-Scope Services",
                 "Open Web Services",
                 "Open In-Scope Web Services",
                 "Closed Services",
                 "Closed In-Scope Services",
                 "Closed Web Services",
                 "Closed In-Scope Web Services",
                 "Subdomains",
                 "In-Scope Subdomains",
                 "Out-of-Scope Subdomains",
                 "Resolved IPs",
                 "Resolved In-Scope IPs",
                 "Resolved Out-of-Scope IPs",
                 "Resolved Private IPs",
                 "Commands",
                 "Time Added",
                 "DB ID"]]
        for workspace in self._workspaces:
            for domain in workspace.domain_names:
                if self._filter(domain):
                    # Calculate statistics
                    stats = DomainNameStatistics(self._protocols)
                    stats.compute(domain)
                    any_company_in_scope = any([item.in_scope for item in domain.companies])
                    domain_scope = domain.scope_str
                    companies = domain.companies_str
                    rows.append([workspace.name,                         # Workspace
                                 domain.name,                            # Second-Level Domain
                                 companies,                              # Companies
                                 domain_scope,                           # Scope
                                 any_company_in_scope,                   # In Scope (Company)
                                 stats.domain_sources,                   # Sources
                                 stats.service_stats.no_open_services,   # Open Services
                                 stats.service_stats.no_open_in_scope_services,  # Open In-Scope Services
                                 stats.service_stats.no_open_web_services,  # Open Web Services
                                 stats.service_stats.no_open_in_scope_web_services,  # Open In-Scope Web Services
                                 stats.service_stats.no_closed_services,  # Closed Services
                                 stats.service_stats.no_closed_in_scope_services,  # Closed In-Scope Services
                                 stats.service_stats.no_closed_web_services,  # Closed Web Services
                                 stats.service_stats.no_closed_in_scope_web_services,  # Closed In-Scope Web Services
                                 stats.no_sub_domains,                   # Subdomains
                                 stats.no_in_scope_sub_domains,          # In-Scope Subdomains
                                 stats.no_out_of_scope_sub_domains,      # Out-of-Scope Subdomains
                                 stats.no_resolved_ips,                  # Resolved IPs
                                 stats.no_resolved_in_scope_ips,         # Resolved In-Scope IPs
                                 stats.no_resolved_out_of_scope_ips,     # Resolved Out-of-Scope IPs
                                 stats.no_resolved_private_ips,          # Resolved Private IPs
                                 stats.no_commands,                      # Commands
                                 domain.creation_date,                   # Time Added
                                 domain.id])                             # DB ID (SLD)
        return rows
