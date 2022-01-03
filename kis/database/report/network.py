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
from database.model import ReportScopeType
from database.model import ReportVisibility
from database.report.core import BaseReport


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
                                                   show_metadata=False))
        return result

    def get_csv(self) -> List[List[str]]:
        """
        This method returns all information as CSV.
        :return:
        """
        rows = [["DB ID", "Workspace", "Network", "Version", "Companies", "Scope", "Sources", "Number IPs"]]
        for workspace in self._workspaces:
            for network in workspace.ipv4_networks:
                if self._filter(network):
                    rows.append([network.id,
                                 workspace.name,
                                 network.network,
                                 network.version_str,
                                 network.companies_str,
                                 network.scope_str,
                                 network.sources_str,
                                 len(network.hosts)])
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
