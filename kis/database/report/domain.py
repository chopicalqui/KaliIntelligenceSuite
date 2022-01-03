# -*- coding: utf-8 -*-
"""
This module allows querying information about second-level domains and host names.
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
from database.model import DomainName
from database.model import ServiceState
from database.model import CollectorType
from database.model import ReportScopeType
from database.model import ReportVisibility
from database.report.core import BaseReport
from database.report.core import ReportLanguage


class ReportClass(BaseReport):
    """
    this module allows querying information about second-level domains and host names
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(name="domain info",
                         title="Domain name details",
                         description="The table provides an overview about all identified second-level domains "
                                     "(see column 'Second-Level Domain (SLD)') and their sub-domains (see "
                                     "column 'Host Name (HN)'). In addition, it documents to which IP addresses the "
                                     "respective sub-domains resolve. If no IP address is available, then either "
                                     "collector dnshostpublic or dnshost have not been executed or the sub-domain "
                                     "could not be resolved. "
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
                                             show_metadata=False))
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
                 "Second-Level Domain (SLD)",
                 "Scope (SLD)",
                 "Host Name (HN)",
                 "In Scope (HN)",
                 "In Scope (Vhost)",
                 "Companies (SLD)",
                 "Sources (HN)",
                 "Name Only (HN)",
                 "Environment (HN)",
                 "Record Type",
                 "Resolves To",
                 "Resolves To In Scope",
                 "Resolves to Network",
                 "Resolves to Companies",
                 "Number of Open Services",
                 "Number of Closed Services",
                 "DB ID (SLD)",
                 "DB ID (HN)"]]
        for workspace in self._workspaces:
            for domain in workspace.domain_names:
                if self._filter(domain):
                    for host_name in domain.host_names:
                        sources = host_name.sources_str
                        environment = self._domain_config.get_environment(host_name)
                        printed = False
                        for mapping in host_name.resolved_host_name_mappings:
                            printed = True
                            rows.append([workspace.name,
                                         domain.name,
                                         domain.scope_str,
                                         host_name.full_name,
                                         host_name._in_scope,
                                         host_name.in_scope(CollectorType.vhost_service),
                                         domain.companies_str,
                                         sources,
                                         host_name.name,
                                         environment,
                                         mapping.type_str,
                                         mapping.resolved_host_name.full_name,
                                         mapping.resolved_host_name.in_scope(CollectorType.vhost_service),
                                         None,
                                         mapping.resolved_host_name.domain_name.companies_str
                                         if mapping.resolved_host_name.domain_name else None,
                                         None,
                                         None,
                                         domain.id,
                                         host_name.id])
                        for mapping in host_name.host_host_name_mappings:
                            printed = True
                            open_services = len([service for service in mapping.host.services
                                                 if service.state == ServiceState.Open])
                            closed_services = len([service for service in mapping.host.services
                                                   if service.state == ServiceState.Closed])
                            rows.append([workspace.name,
                                         domain.name,
                                         domain.scope_str,
                                         host_name.full_name,
                                         host_name._in_scope,
                                         host_name.in_scope(CollectorType.vhost_service),
                                         domain.companies_str,
                                         sources,
                                         host_name.name,
                                         environment,
                                         mapping.type_str,
                                         mapping.host.address,
                                         mapping.host.in_scope,
                                         mapping.host.ipv4_network.network if mapping.host.ipv4_network else None,
                                         mapping.host.ipv4_network.companies_str
                                         if mapping.host.ipv4_network else None,
                                         open_services,
                                         closed_services,
                                         domain.id,
                                         host_name.id])
                        if not printed:
                            rows.append([workspace.name,
                                         domain.name,
                                         domain.scope_str,
                                         host_name.full_name,
                                         host_name._in_scope,
                                         host_name.in_scope(CollectorType.vhost_service),
                                         domain.companies_str,
                                         sources,
                                         host_name.name,
                                         environment,
                                         None,
                                         None,
                                         None,
                                         None,
                                         None,
                                         None,
                                         None,
                                         domain.id,
                                         host_name.id])
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
