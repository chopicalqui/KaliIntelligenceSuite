# -*- coding: utf-8 -*-
"""
This module allows querying information about second-level domains and its sub-level domains.
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
from openpyxl import Workbook
from database.model import HostName
from database.model import ProtocolType
from database.model import ServiceState
from database.model import CollectorType
from database.model import ReportScopeType
from database.model import ReportVisibility
from database.model import TextReportDetails
from database.model import DnsResourceRecordType
from database.report.core import BaseReport
from database.report.core import ReportLanguage
from database.report.core import ServiceStatistics


class HostNameStatistics:
    """
    This class maintains all statistics for a host name
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

    def compute(self, host_name: HostName):
        """
        Compute statistics for the given host name
        """
        # Obtain statistics about subdomains
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
        super().__init__(name="host name info",
                         title="Overview about Identified Subdomain Details",
                         description="The table provides an overview about all identified second-level domains "
                                     "(see column 'Second-Level Domain (SLD)') and their sub-domains (see "
                                     "column 'Host Name (HN)')."
                                     ""
                                     "Note that column 'In Scope (HN)' is true, if the respective host name itself "
                                     "is in scope of the engagement. Column 'In Scope (VHost)' is true, if column "
                                     "'In Scope (HN)' is true and the respective host name resolves to at least one "
                                     "IP address, which is in scope of the engagement as well.",
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
                                   help='negate the filter logic and only show those host names that do not match the '
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

    def _filter(self, host_name: HostName) -> bool:
        """
        Method determines whether the given item shall be included into the report
        """
        return host_name.is_processable(included_items=self._included_items,
                                        excluded_items=self._excluded_items,
                                        collector_type=CollectorType.domain,
                                        scope=self._scope,
                                        include_ip_address=True)

    def _egrep_text(self, host_name: HostName) -> List[str]:
        """
        This method returns all lines matching the given list of regular expressions
        :param domain: The domain name whose text output shall be parsed
        :return:
        """
        result = self._egrep(host_name.get_text(ident=0,
                                                exclude_collectors=self._excluded_collectors,
                                                include_collectors=self._included_collectors,
                                                collector_type=CollectorType.domain,
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
                for host_name in domain.host_names:
                    if self._filter(host_name):
                        rvalue.extend(host_name.get_text(ident=0,
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
                 "Host Name",
                 "Host Name Scope",
                 "Companies",
                 "Result"]]
        for workspace in self._workspaces:
            for domain in workspace.domain_names:
                for host_name in domain.host_names:
                    if self._filter(host_name):
                        results = self._egrep_text(host_name)
                        if self._not_grep and not results:
                            rows.append([host_name.id,
                                         workspace.name,
                                         host_name.full_name,
                                         host_name._in_scope,
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
                 "Second-Level Domain (SLD)",
                 "Host Name (HN)",
                 "Companies All (SLD)",
                 "Companies Verified (SLD)",
                 "Scope (SLD)",
                 "In Scope (HN)",
                 "In Scope (Vhost)",
                 "In Scope (Company)",
                 "Subdomain Only (HN)",
                 "Environment (HN)",
                 "Sources (HN)",
                 "Open Services",
                 "Open In-Scope Services",
                 "Open Web Services",
                 "Open In-Scope Web Services",
                 "Closed Services",
                 "Closed In-Scope Services",
                 "Closed Web Services",
                 "Closed In-Scope Web Services",
                 "Resolved IPs",
                 "Resolved In-Scope IPs",
                 "Resolved Out-of-Scope IPs",
                 "Resolved Private IPs",
                 "Commands",
                 "Time Added",
                 "DB ID (SLD)",
                 "DB ID (HN)"]]
        for workspace in self._workspaces:
            for domain in workspace.domain_names:
                # Calculate statistics
                any_company_in_scope = any([item.in_scope for item in domain.companies])
                domain_scope = domain.scope_str
                companies = domain.companies_str
                companies_verified = domain.companies_verified_str
                # Obtain statistics about subdomains
                for host_name in domain.host_names:
                    stats = HostNameStatistics(self._protocols)
                    no_resolved_ips = 0
                    no_resolved_private_ips = 0
                    no_resolved_in_scope_ips = 0
                    no_open_services = 0
                    no_open_in_scope_services = 0
                    no_closed_services = 0
                    if self._filter(host_name):
                        sources = host_name.sources_str
                        environment = self._domain_config.get_environment(host_name)
                        # Compile list of A, AAAA hosts belonging to the host name
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
                        rows.append([workspace.name,                                    # Workspace
                                     domain.name,                                       # Second-Level Domain (SLD)
                                     host_name.full_name,                               # Host Name (HN)
                                     companies,                                         # Companies All (SLD)
                                     companies_verified,                                # Companies Verified (SLD)
                                     domain_scope,                                      # Scope (SLD)
                                     host_name._in_scope,                               # In Scope (HN)
                                     host_name.in_scope(CollectorType.vhost_service),   # In Scope (Vhost)
                                     any_company_in_scope,                              # In Scope (Company)
                                     host_name.name,                                    # Subdomain Only (HN)
                                     environment,                                       # Environment (HN)
                                     sources,                                           # Sources (HN)
                                     stats.service_stats.no_open_services,              # Open Services
                                     stats.service_stats.no_open_in_scope_services,     # Open In-Scope Services
                                     stats.service_stats.no_open_web_services,          # Open Web Services
                                     stats.service_stats.no_open_in_scope_web_services,  # Open In-Scope Web Services
                                     stats.service_stats.no_closed_services,            # Closed Services
                                     stats.service_stats.no_closed_in_scope_services,   # Closed In-Scope Services
                                     stats.service_stats.no_closed_web_services,        # Closed Web Services
                                     stats.service_stats.no_closed_in_scope_web_services,  # Closed In-Scope Web Services
                                     stats.no_resolved_ips,                             # Resolved IPs
                                     stats.no_resolved_in_scope_ips,                    # Resolved In-Scope IPs
                                     stats.no_resolved_out_of_scope_ips,                # Resolved Out-of-Scope IPs
                                     stats.no_resolved_private_ips,                     # Resolved Private IPs
                                     stats.no_commands,                                 # Commands
                                     host_name.creation_date,                           # Time Added
                                     domain.id,                                         # DB ID (SLD)
                                     host_name.id])                                     # DB ID (HN)
        return rows

    def final_report(self, workbook: Workbook):
        """
        This method creates all tables that are relevant to the final report.
        """
        result = [["Second-Level Domain",
                   "Host Name",
                   "Record\nType",
                   "Resolves To",
                   "Source\nHost Name"]]
        if self._args.language == ReportLanguage.de:
            result = [["Second-Level Domain",
                       "Hostname",
                       "DNS-\nTyp",
                       "Löst auf zu",
                       "Quelle\nHostname"]]
        for workspace in self._workspaces:
            for domain in workspace.domain_names:
                for host_name in domain.host_names:
                    if host_name._in_scope:
                        full_name = host_name.full_name
                        printed = False
                        for mapping in host_name.resolved_host_name_mappings:
                            printed = True
                            result.append([domain.name,
                                           full_name,
                                           mapping.type_str,
                                           mapping.resolved_host_name.full_name,
                                           host_name.sources_str])
                        for mapping in host_name.host_host_name_mappings:
                            printed = True
                            result.append([domain.name,
                                           full_name,
                                           mapping.type_str,
                                           mapping.host.address,
                                           host_name.sources_str])
                        if not printed:
                            result.append([domain.name,
                                           full_name,
                                           None,
                                           None,
                                           host_name.sources_str])
        if len(result) > 1:
            self.fill_excel_sheet(worksheet=workbook.create_sheet(),
                                  csv_list=result,
                                  name="Domain Results",
                                  title="",
                                  description="")
