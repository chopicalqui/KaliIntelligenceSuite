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
from database.model import Network
from database.model import ScopeType
from database.model import ProtocolType
from database.model import ReportScopeType
from database.model import ReportVisibility
from database.model import TextReportDetails
from database.model import DnsResourceRecordType
from database.report.core import BaseReport
from database.report.core import ServiceStatistics
from sqlalchemy.orm import aliased
from sqlalchemy import and_


class NetworkStatistics:
    """
    This class maintains all statistics for a network
    """

    def __init__(self, protocols: list):
        self.service_stats = ServiceStatistics(protocols)
        self.prefix_length = 0
        self.no_hosts = 0
        self.no_allocated_ips = 0
        self.no_allocated_in_scope_ips = 0
        self.no_resolved_host_names = 0
        self.no_resolved_in_scope_host_names = 0
        self.no_commands = 0

    @property
    def no_resolved_out_of_scope_host_names(self):
        return self.no_resolved_host_names - self.no_resolved_in_scope_host_names

    def compute(self, network: Network):
        """
        Compute statistics for the given network.
        """
        ip_network = network.ip_network
        self.prefix_length = ip_network.prefixlen
        self.no_hosts = ip_network.num_addresses - 2
        self.no_commands = len(network.get_completed_commands())
        for host in network.hosts:
            self.service_stats.compute(host)
            self.no_allocated_ips += 1
            if host.in_scope:
                self.no_allocated_in_scope_ips += 1
            # Obtain statistics about host names that resolve to IPs within the network
            host_host_mappings = host.get_host_host_name_mappings([DnsResourceRecordType.a, DnsResourceRecordType.aaaa])
            for mapping in host_host_mappings:
                self.no_resolved_host_names += 1
                if mapping.host_name._in_scope:
                    self.no_resolved_in_scope_host_names += 1


class ReportClass(BaseReport):
    """
    this module allows querying information about IPv4/IPv6 networks
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(name="network info",
                         title="Overview Identified Networks",
                         description="The table provides an overview of all identified networks. Note that the column "
                                     "'Number IPs' contains the number of hosts that were identified and are "
                                     "associated with this network. In other words, this column provides an indicator "
                                     "how extensive the identified network ranges are used.",
                         **kwargs)

    @staticmethod
    def get_add_argparse_arguments(parser_network: argparse.ArgumentParser):
        """
        This method adds the report's specific command line arguments.
        """
        # setup network parser
        parser_network.add_argument("-w", "--workspaces",
                                    metavar="WORKSPACE",
                                    help="query the given workspaces",
                                    nargs="+",
                                    type=str)
        parser_network_group = parser_network.add_mutually_exclusive_group()
        parser_network_group.add_argument('--text', action='store_true',
                                          help='returns gathered information including all collector outputs as text')
        parser_network_group.add_argument('--csv', action='store_true', default=True,
                                          help='returns gathered information in csv format')
        parser_network_group.add_argument('--igrep', type=str, nargs='+', metavar="REGEX",
                                          help="print command outputs that match the given string or Python3 regular "
                                               "expressions REGEX. matching is case insensitive. use named group 'output' "
                                               "to just capture the content of this named group")
        parser_network_group.add_argument('--grep', type=str, nargs='+', metavar="REGEX",
                                          help="print command outputs that match the given string or Python3 regular "
                                               "expressions REGEX. matching is case sensitive. use named group 'output' "
                                               "to just capture the content of this named group")
        parser_network.add_argument('--not', dest="grep_not", action='store_true',
                                    help='negate the filter logic and only show those IP networks that do not match the '
                                         '--igrep or --grep argument.')
        parser_network.add_argument('--filter', metavar='NETWORK', type=str, nargs='*',
                                    help='list of IPv4 networks (e.g., 192.168.0.0/24) whose information shall be '
                                         'returned. per default, mentioned items are excluded. add + in front of each '
                                         'item (e.g., +192.168.0.0/24) to return only these items')
        parser_network.add_argument('--scope', choices=[item.name for item in ReportScopeType],
                                    help='return only networks that are in scope (within) or out of scope (outside). '
                                         'per default, all information is returned')
        parser_network.add_argument('--visibility', choices=[item.name for item in ReportVisibility],
                                    help='return only relevant (relevant) or potentially irrelevant (irrelevant) '
                                         'information (e.g., executed commands that did not return any information) in '
                                         'text output (argument --text) per default, all information is returned')
        parser_network.add_argument('-X', '--exclude', metavar='COLLECTOR', type=str, nargs='+', default=[],
                                    help='list of collector names (e.g., tcpnmap) whose outputs should not be returned in '
                                         'text mode (see argument --text). use argument value "all" to exclude all '
                                         'collectors. per default, no collectors are excluded')
        parser_network.add_argument('-I', '--include', metavar='COLLECTOR', type=str, nargs='+', default=[],
                                    help='list of collector names whose outputs should be returned in text mode (see '
                                         'argument --text). per default, all collector information is returned')
        parser_network.add_argument('--nosum', action='store_true',
                                    help="there are cases where an in-scope network contains several subnetworks."
                                         "per default, the network report summarizes the statistics into the largest "
                                         "in-scope network and does not show the corresponding subnetworks. if the "
                                         "subnetworks shall be displayed as well, then use this argument")
        parser_network.add_argument('-p', '--protocol', nargs='+',
                                    choices=[item.name for item in ProtocolType],
                                    default=[item.name for item in ProtocolType],
                                    help="create the service statistics for the following ISO/OSI layer 4 protocols")

    def _filter(self, network: Network) -> bool:
        """
        Method determines whether the given item shall be included into the report
        """
        return network.is_processable(included_items=self._included_items,
                                      excluded_items=self._excluded_items,
                                      scope=self._scope)

    def _egrep_text(self, ipv4_network: Network) -> List[str]:
        """
        This method returns all lines matching the given list of regular expressions
        :param ipv4_network: The network whose text output shall be parsed
        :return:
        """
        result = self._egrep(ipv4_network.get_text(ident=0,
                                                   exclude_collectors=self._excluded_collectors,
                                                   include_collectors=self._included_collectors,
                                                   scope=self._scope,
                                                   details=TextReportDetails(TextReportDetails.item_info)))
        return result

    def get_csv(self) -> List[List[str]]:
        """
        This method returns all information as CSV.
        :return:
        """
        rows = [["Workspace",
                 "Network",
                 "Version",
                 "Netmask",
                 "Parent Networks With Same Scope",
                 "Hosts",
                 "Companies",
                 "Scope",
                 "In Scope (Company)",
                 "Sources (NW)",
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
                 "Allocated IPs",
                 "Allocated In-Scope IPs",
                 "Commands",
                 "Time Added",
                 "DB ID"]]
        for workspace in self._workspaces:
            for network in workspace.ipv4_networks:
                if self._filter(network):
                    # Compute statistics
                    stats = NetworkStatistics(self._protocols)
                    stats.compute(network)
                    any_company_in_scope = any([item.in_scope for item in network.companies])
                    # Determine number of parent networks with same scope as current network
                    alias_current_network = aliased(Network)
                    alias_parent_network = aliased(Network)
                    parent_networks = self._session.query(alias_parent_network) \
                        .join(alias_current_network, and_(alias_current_network.workspace_id == alias_parent_network.workspace_id,
                                                          alias_current_network.id == network.id,
                                                          alias_current_network.scope == alias_parent_network.scope,
                                                          alias_current_network.network.op("<<")(alias_parent_network.network))).count()
                    # Summarize all satistics of in-scope subnetworks into the parent network
                    if not self._args.nosum and network.scope == ScopeType.all:
                        alias_child_network = aliased(Network)
                        child_networks = self._session.query(alias_child_network) \
                            .join(alias_current_network,
                                  and_(alias_current_network.workspace_id == alias_child_network.workspace_id,
                                       alias_current_network.id == network.id,
                                       alias_current_network.scope == alias_child_network.scope,
                                       alias_current_network.network.op(">>")(alias_child_network.network))).all()
                        for child_network in child_networks:
                            stats.compute(child_network)
                    if self._args.nosum or network.scope != ScopeType.all or (network.scope == ScopeType.all and parent_networks == 0):
                        rows.append([workspace.name,                             # Workspace
                                     network.network,                            # Network (NW)
                                     network.version_str,                        # Version
                                     stats.prefix_length,                        # Netmask
                                     parent_networks,                            # Parent Networks With Same Scope
                                     stats.no_hosts,                             # Hosts
                                     network.companies_str,                      # Companies
                                     network.scope_str,                          # Scope (NW)
                                     any_company_in_scope,                       # In Scope (Company)
                                     network.sources_str,                        # Sources (NW)
                                     stats.service_stats.no_open_services,       # Open Services
                                     stats.service_stats.no_open_in_scope_services,  # Open In-Scope Services
                                     stats.service_stats.no_open_web_services,   # Open Web Services,
                                     stats.service_stats.no_open_in_scope_web_services,  # Open In-Scope Web Services,
                                     stats.service_stats.no_closed_services,     # Closed Services
                                     stats.service_stats.no_closed_in_scope_services,  # Closed In-Scope Services
                                     stats.service_stats.no_closed_web_services, # Closed Web Services
                                     stats.service_stats.no_closed_in_scope_web_services,  # Closed In-Scope Web Services
                                     stats.no_resolved_host_names,               # Resolved Host Names
                                     stats.no_resolved_in_scope_host_names,      # Resolved In-Scope Host Names
                                     stats.no_resolved_out_of_scope_host_names,  # Resolved Out-of-Scope Host Names
                                     stats.no_allocated_ips,                     # Allocated IPs
                                     stats.no_allocated_in_scope_ips,            # Allocated In-Scope IPs
                                     stats.no_commands,                          # Commands
                                     network.creation_date,                      # Time Added
                                     network.id])                                # DB ID
                    else:
                        pass
        return rows

    def get_text(self) -> List[str]:
        """
        This method returns all information as a list of text.
        :return:
        """
        rvalue = []
        for workspace in self._workspaces:
            for ipv4_network in workspace.ipv4_networks:
                if self._filter(ipv4_network):
                    rvalue.extend(ipv4_network.get_text(ident=0,
                                                        scope=self.scope,
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
        rows = [["DB ID", "Workspace", "Network", "Companies", "In Scope", "Result"]]
        for workspace in self._workspaces:
            for ipv4_network in workspace.ipv4_networks:
                if self._filter(ipv4_network):
                    results = self._egrep_text(ipv4_network)
                    if self._not_grep and not results:
                        rows.append([ipv4_network.id,
                                     workspace.name,
                                     ipv4_network.network,
                                     ipv4_network.companies_str,
                                     ipv4_network.in_scope,
                                     None])
                    elif not self._not_grep:
                        for row in results:
                            rows.append([ipv4_network.id,
                                         workspace.name,
                                         ipv4_network.network,
                                         ipv4_network.companies_str,
                                         ipv4_network.in_scope,
                                         row])
        return rows
