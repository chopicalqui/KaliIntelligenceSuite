# -*- coding: utf-8 -*-
"""This module allows querying information about virtual hosts (vhost)."""

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
from database.model import HostName
from database.model import CollectorType
from database.model import ReportScopeType
from database.model import ReportVisibility
from database.model import DnsResourceRecordType
from database.report.core import BaseReport


class ReportClass(BaseReport):
    """
    This module allows querying information about virtual hosts (vhost)
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(name="host name info",
                         title="Host name details",
                         description="The table provides details about all identified host names (see column "
                                     "'Host Name (HN)') and their respective services (see columns 'UDP/TCP' and "
                                     "'Port'). "
                                     ""
                                     "Note that column 'In Scope (HN)' is true, if the respective host name itself "
                                     "is in scope of the engagement. Column 'In Scope (VHost)' is true, if column "
                                     "'In Scope (HN)' is true and the respective host name resolves to at least one "
                                     "IP address, which is in scope of the engagement as well.",
                         **kwargs)

    @staticmethod
    def get_add_argparse_arguments(parser_vhost: argparse.ArgumentParser):
        """
        This method adds the report's specific command line arguments.
        """

        # setup vhost parser
        parser_vhost.add_argument("-w", "--workspaces",
                                  metavar="WORKSPACE",
                                  help="query the given workspaces",
                                  nargs="+",
                                  type=str)
        parser_vhost_group = parser_vhost.add_mutually_exclusive_group()
        parser_vhost_group.add_argument('--text', action='store_true',
                                        help='returns gathered information including all collector outputs as text')
        parser_vhost_group.add_argument('--csv', action='store_true', default=True,
                                        help='returns gathered information in csv format')
        parser_vhost_group.add_argument('--igrep', type=str, nargs='+', metavar="REGEX",
                                        help="print command outputs that match the given string or Python3 regular "
                                             "expressions REGEX. matching is case insensitive. use named group 'output' "
                                             "to just capture the content of this named group")
        parser_vhost_group.add_argument('--grep', type=str, nargs='+', metavar="REGEX",
                                        help="print command outputs that match the given string or Python3 regular "
                                             "expressions REGEX. matching is case sensitive. use named group 'output' "
                                             "to just capture the content of this named group")
        parser_vhost.add_argument('--not', dest="grep_not", action='store_true',
                                  help='negate the filter logic and only show those vhost information that do not match '
                                       'the --igrep or --grep argument.')
        parser_vhost.add_argument('--filter', metavar='DOMAIN|HOSTNAME|IP', type=str, nargs='*',
                                  help='list of second-level domains (e.g., megacorpone.com), host names '
                                       '(e.g., www.megacorpone.com), or IP addresses whose information shall be returned.'
                                       'per default, mentioned items are excluded. add + in front of each item '
                                       '(e.g., +192.168.0.1) to return only these items')
        parser_vhost.add_argument('--scope', choices=[item.name for item in ReportScopeType],
                                  help='return only in scope (within) or out of scope (outside) items. per default, '
                                       'all information is returned')
        parser_vhost.add_argument('--visibility', choices=[item.name for item in ReportVisibility],
                                  help='return only relevant (relevant) or potentially irrelevant (irrelevant) information '
                                       'in text output (argument --text). examples of potentially irrelevant information '
                                       'are hosts with no open ports or operating system commands that did not return '
                                       'any results. per default, all information is returned')
        parser_vhost.add_argument('-X', '--exclude', metavar='COLLECTOR', type=str, nargs='+', default=[],
                                  help='list of collector names (e.g., httpnikto) whose outputs should not be returned in '
                                       'text mode (see argument --text). use argument value "all" to exclude all '
                                       'collectors. per default, no collectors are excluded')
        parser_vhost.add_argument('-I', '--include', metavar='COLLECTOR', type=str, nargs='+', default=[],
                                  help='list of collector names whose outputs should be returned in text mode (see '
                                       'argument --text). per default, all collector information is returned')

    def _filter(self, host_name: HostName) -> bool:
        """
        Method determines whether the given item shall be included into the report
        """
        return host_name.is_processable(included_items=self._included_items,
                                        excluded_items=self._excluded_items,
                                        collector_type=CollectorType.vhost_service,
                                        scope=self._scope,
                                        include_ip_address=True)

    def _egrep_text(self, host_name: HostName) -> List[str]:
        """
        This method returns all lines matching the given list of regular expressions
        :param host_name: The host_name name whose text output shall be parsed
        :return:
        """
        result = self._egrep(host_name.get_text(ident=0,
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
        companies = {}
        for item in self._session.query(HostName).filter(HostName.name.is_(None)).all():
            companies[item.domain_name.name] = item.companies_str
        for workspace in self._workspaces:
            for domain in workspace.domain_names:
                for item in domain.host_names:
                    if self._filter(item):
                        rvalue.extend(item.get_text(ident=0,
                                                    scope=self._scope,
                                                    companies=companies,
                                                    exclude_collectors=self._excluded_collectors,
                                                    include_collectors=self._included_collectors,
                                                    report_visibility=self._visibility,
                                                    color=self._color))
        return rvalue

    def grep_text(self) -> List[List[str]]:
        """
        This method returns all information as a list of text.
        :return:
        """
        rows = [["DB ID",
                 "Workspace",
                 "Domain Name",
                 "Companies",
                 "In Scope",
                 "Host Name",
                 "Host Name Summary",
                 "Result"]]
        companies = {}
        for item in self._session.query(HostName).filter(HostName.name.is_(None)).all():
            companies[item.domain_name.name] = item.companies_str
        for workspace in self._workspaces:
            for domain in workspace.domain_names:
                for host_name in domain.host_names:
                    if self._filter(host_name):
                        in_scope = host_name.in_scope(CollectorType.vhost_service)
                        results = self._egrep_text(host_name)
                        if self._not_grep and not results:
                            rows.append([host_name.id,
                                         workspace.name,
                                         domain.name,
                                         companies[host_name.domain_name.name],
                                         in_scope,
                                         host_name.full_name,
                                         host_name.summary,
                                         None])
                        elif not self._not_grep:
                            for row in results:
                                rows.append([host_name.id,
                                             workspace.name,
                                             domain.name,
                                             companies[host_name.domain_name.name],
                                             in_scope,
                                             host_name.full_name,
                                             host_name.summary,
                                             row])
        return rows

    def get_csv(self) -> List[List[str]]:
        """
        Method determines whether the given item shall be included into the report
        """
        rvalue = [["Workspace",
                   "Second-Level Domain (SLD)",
                   "Scope (SLD)",
                   "Companies (SLD)",
                   "Host Name (HN)",
                   "In Scope (HN)",
                   "In Scope (Vhost)",
                   "Name Only (HN)",
                   "Environment (HN)",
                   "Summary (HN)",
                   "IP Addresses",
                   "Service Summary",
                   "TCP/UDP",
                   "Port",
                   "Service (SRV)",
                   "State (SRV)",
                   "Sources (SRV)",
                   "TLS",
                   "Reason",
                   "Name (SRV)",
                   "Confidence (SRV)",
                   "NMap Service Name Original",
                   "Nmap Product",
                   "Version",
                   "Product Summary",
                   "SMB Message Signing",
                   "RDP NLA",
                   "Sources (Host Name)",
                   "Sources (Service)",
                   "No. Commands (Service)",
                   "No. Vulnerabilities (Service)",
                   "DB ID (SLD)",
                   "DB ID (HN)"]]
        for workspace in self._workspaces:
            for domain in workspace.domain_names:
                for host_name in domain.host_names:
                    if host_name.name and self._filter(host_name):
                        ipv4_addresses = host_name.get_host_host_name_mappings_str(types=[DnsResourceRecordType.a,
                                                                                          DnsResourceRecordType.aaaa])
                        host_name_sources = host_name.sources_str
                        in_scope = host_name.in_scope(CollectorType.vhost_service)
                        environment = self._domain_config.get_environment(host_name)
                        if host_name.services:
                            for service in host_name.services:
                                rvalue.append([workspace.name,
                                               domain.name,
                                               domain.scope_str,
                                               domain.companies_str,
                                               host_name.full_name,
                                               host_name._in_scope,
                                               in_scope,
                                               host_name.name,
                                               environment,
                                               host_name.summary,
                                               ipv4_addresses,
                                               service.summary,
                                               service.protocol_str,
                                               service.port,
                                               service.protocol_port_str,
                                               service.state_str,
                                               service.sources_str,
                                               service.nmap_tunnel,
                                               service.nmap_service_state_reason,
                                               service.service_name_with_confidence,
                                               service.service_confidence,
                                               service.nmap_service_name_original_with_confidence,
                                               service.nmap_product,
                                               service.nmap_version,
                                               service.nmap_product_version,
                                               service.smb_message_signing,
                                               service.rdp_nla,
                                               host_name_sources,
                                               service.sources_str,
                                               len(service.get_completed_commands()),
                                               len(service.vulnerabilities),
                                               domain.id,
                                               host_name.id])
                        else:
                            rvalue.append([workspace.name,
                                           domain.name,
                                           domain.scope_str,
                                           domain.companies_str,
                                           host_name.full_name,
                                           host_name._in_scope,
                                           in_scope,
                                           host_name.name,
                                           environment,
                                           host_name.summary,
                                           ipv4_addresses, None, None, None, None, None, None, None, None, None, None,
                                           None, None, None, None, None, None, host_name_sources, None, None, None,
                                           domain.id,
                                           host_name.id])
            return rvalue
