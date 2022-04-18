# -*- coding: utf-8 -*-
"""This module allows querying information about IPv4/IPv6 networks."""

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
from database.model import ProtocolType
from database.model import ReportScopeType
from database.model import ReportVisibility
from database.model import TextReportDetails
from database.model import DnsResourceRecordType
from database.report.core import BaseReport
from database.report.core import ServiceStatistics


class HostStatistics:
    """
    This class maintains all statistics for a host
    """

    def __init__(self, protocols: list):
        self.service_stats = ServiceStatistics(protocols)
        self.no_resolved_host_names = 0
        self.no_resolved_in_scope_host_names = 0
        self.no_commands = 0

    @property
    def no_resolved_out_of_scope_host_names(self):
        return self.no_resolved_host_names - self.no_resolved_in_scope_host_names

    def compute(self, host: Host):
        """
        Compute statistics for the given network.
        """
        # Obtain statistics about host names that resolve to IPs within the network
        self.service_stats.compute(host)
        self.no_commands += len(host.get_completed_commands())
        host_host_mappings = host.get_host_host_name_mappings([DnsResourceRecordType.a, DnsResourceRecordType.aaaa])
        for mapping in host_host_mappings:
            self.no_resolved_host_names += 1
            if mapping.host_name._in_scope:
                self.no_resolved_in_scope_host_names += 1


class ReportClass(BaseReport):
    """
    this module allows querying information about hosts
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(name="host info",
                         title="Overview Identified Hosts",
                         description="The table provides an overview of all identified networks. Note that the column "
                                     "'Number IPs' contains the number of hosts that were identified and are "
                                     "associated with this network. In other words, this column provides an indicator "
                                     "how extensive the identified network ranges are used.",
                         **kwargs)

    @staticmethod
    def get_add_argparse_arguments(parser: argparse.ArgumentParser):
        """
        This method adds the report's specific command line arguments.
        """
        # setup network parser
        parser.add_argument("-w", "--workspaces",
                            metavar="WORKSPACE",
                            help="query the given workspaces",
                            nargs="+",
                            type=str)
        parser_group = parser.add_mutually_exclusive_group()
        parser_group.add_argument('--text', action='store_true',
                                  help='returns gathered information including all collector outputs as text')
        parser_group.add_argument('--csv', action='store_true', default=True,
                                  help='returns gathered information in csv format')
        parser_group.add_argument('--igrep', type=str, nargs='+', metavar="REGEX",
                                  help="print command outputs that match the given string or Python3 regular "
                                       "expressions REGEX. matching is case insensitive. use named group 'output' "
                                       "to just capture the content of this named group")
        parser_group.add_argument('--grep', type=str, nargs='+', metavar="REGEX",
                                  help="print command outputs that match the given string or Python3 regular "
                                       "expressions REGEX. matching is case sensitive. use named group 'output' "
                                       "to just capture the content of this named group")
        parser.add_argument('--not', dest="grep_not", action='store_true',
                            help='negate the filter logic and only show those IP networks that do not match the '
                                 '--igrep or --grep argument.')
        parser.add_argument('--filter', metavar='NETWORK', type=str, nargs='*',
                            help='list of IPv4 networks (e.g., 192.168.0.0/24) whose information shall be '
                                 'returned. per default, mentioned items are excluded. add + in front of each '
                                 'item (e.g., +192.168.0.0/24) to return only these items')
        parser.add_argument('--scope', choices=[item.name for item in ReportScopeType],
                            help='return only networks that are in scope (within) or out of scope (outside). '
                                 'per default, all information is returned')
        parser.add_argument('--visibility', choices=[item.name for item in ReportVisibility],
                            help='return only relevant (relevant) or potentially irrelevant (irrelevant) '
                                 'information (e.g., executed commands that did not return any information) in '
                                 'text output (argument --text) per default, all information is returned')
        parser.add_argument('-X', '--exclude', metavar='COLLECTOR', type=str, nargs='+', default=[],
                            help='list of collector names (e.g., tcpnmap) whose outputs should not be returned in '
                                 'text mode (see argument --text). use argument value "all" to exclude all '
                                 'collectors. per default, no collectors are excluded')
        parser.add_argument('-I', '--include', metavar='COLLECTOR', type=str, nargs='+', default=[],
                            help='list of collector names whose outputs should be returned in text mode (see '
                                 'argument --text). per default, all collector information is returned')
        parser.add_argument('-p', '--protocol', nargs='+',
                            choices=[item.name for item in ProtocolType],
                            default=[item.name for item in ProtocolType],
                            help="create the service statistics for the following ISO/OSI layer 4 protocols")

    def _filter(self, host: Host) -> bool:
        """
        Method determines whether the given item shall be included into the report
        """
        result = host.is_processable(included_items=self._included_items,
                                     excluded_items=self._excluded_items,
                                     scope=self._scope,
                                     include_host_names=True)
        return result

    def _egrep_text(self, host: Host) -> List[str]:
        """
        This method returns all lines matching the given list of regular expressions
        :param domain: The domain name whose text output shall be parsed
        :return:
        """
        result = self._egrep(host.get_text(ident=0,
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
            for host in workspace.hosts:
                if self._filter(host):
                    rvalue.extend(host.get_text(ident=0,
                                                scope=self._scope,
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
                 "Network",
                 "Companies",
                 "In Scope",
                 "Address",
                 "Result"]]
        for workspace in self._workspaces:
            for host in workspace.hosts:
                if self._filter(host):
                    ipv4_network = None
                    companies = None
                    if host.ipv4_network:
                        ipv4_network = host.ipv4_network.network
                        companies = host.ipv4_network.companies_str
                    results = self._egrep_text(host)
                    if self._not_grep and not results:
                        rows.append([host.id,
                                     workspace.name,
                                     ipv4_network,
                                     companies,
                                     host.in_scope,
                                     host.ip,
                                     None])
                    elif not self._not_grep:
                        for result in results:
                            rows.append([host.id,
                                         workspace.name,
                                         ipv4_network,
                                         companies,
                                         host.in_scope,
                                         host.ip,
                                         result])
        return rows

    def get_csv(self) -> List[List[str]]:
        """
        This method returns all information as CSV.
        :return:
        """
        rows = [["Workspace",
                 "Network (NW)",
                 "IP Version",
                 "Netmask",
                 "IP Address (Host)",
                 "Private IP",
                 "Companies",
                 "Scope (NW)",
                 "In Scope (Host)",
                 "In Scope (Company)",
                 "Sources (NW)",
                 "Sources (Host)",
                 "Open Services",
                 "Open In-Scope Services",
                 "Open Web Services",
                 "Open In-Scope Web Services",
                 "Closed Services",
                 "Closed In-Scope Services",
                 "Closed Web Services",
                 "Closed In-Scope Web Services",
                 "Resolved Host Names",
                 "Resolved In-Scope Host Names",
                 "Resolved Out-of-Scope Host Names",
                 "Commands",
                 "Time Added",
                 "DB ID (NW)",
                 "DB ID (Host)"]]
        for workspace in self._workspaces:
            # Obtain statistics about IP addresses within the network
            for host in workspace.hosts:
                if host.ipv4_network:
                    network = host.ipv4_network.network
                    network_id = host.ipv4_network.id
                    network_prefixlen = host.ipv4_network.ip_network.prefixlen
                    network_version = host.ipv4_network.version_str
                    network_companies_str = host.ipv4_network.companies_str
                    network_scope_str = host.ipv4_network.scope_str
                    network_sources_str = host.ipv4_network.sources_str
                    any_company_in_scope = any([item.in_scope for item in host.ipv4_network.companies])
                else:
                    network = None
                    network_id = None
                    network_version = None
                    network_prefixlen = None
                    network_scope_str = None
                    network_sources_str = None
                    network_companies_str = None
                    any_company_in_scope = False
                if self._filter(host):
                    # Calculate statistics
                    stats = HostStatistics(self._protocols)
                    stats.compute(host)
                    rows.append([workspace.name,                                # Workspace
                                 network,                                       # Network (NW)
                                 network_version,                               # IP Version
                                 network_prefixlen,                             # Netmask
                                 host.address,                                  # IP Address (Host)
                                 host.ip_address.is_private,                    # Private IP
                                 network_companies_str,                         # Companies
                                 network_scope_str,                             # Scope (NW)
                                 host.in_scope,                                 # In Scope (Host)
                                 any_company_in_scope,                          # In Scope (Company)
                                 network_sources_str,                           # Sources (NW)
                                 host.sources_str,                              # Sources (Host)
                                 stats.service_stats.no_open_services,          # Open Services
                                 stats.service_stats.no_open_in_scope_services,  # Open In-Scope Services
                                 stats.service_stats.no_open_web_services,      # Open Web Services,
                                 stats.service_stats.no_open_in_scope_web_services, # Open In-Scope Web Services,
                                 stats.service_stats.no_closed_services,        # Closed Services
                                 stats.service_stats.no_closed_in_scope_services,  # Closed In-Scope Services
                                 stats.service_stats.no_closed_web_services,    # Closed Web Services
                                 stats.service_stats.no_closed_in_scope_web_services, # Closed In-Scope Web Services
                                 stats.no_resolved_host_names,                  # Resolved Host Names
                                 stats.no_resolved_in_scope_host_names,         # Resolved In-Scope Host Names
                                 stats.no_resolved_out_of_scope_host_names,     # Resolved Out-of-Scope Host Names
                                 stats.no_commands,                             # Commands
                                 host.creation_date,                            # Time Added
                                 network_id,                                    # DB ID (NW)
                                 host.id])                                      # DB ID (Host)
        return rows
