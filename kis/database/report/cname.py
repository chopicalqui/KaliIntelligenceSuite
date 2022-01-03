# -*- coding: utf-8 -*-
"""
This module allows querying DNS canonical names (CNAMES). this report can be used to identify potential subdomain takeovers
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
from database.model import Workspace
from database.model import HostName
from database.model import DomainName
from database.model import CollectorType
from database.model import ReportScopeType
from database.report.core import BaseReport


class ReportClass(BaseReport):
    """
    This module allows querying DNS canonical names (CNAMES). this report can be used to identify potential subdomain takeovers
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(name="DNS cname records",
                         title="Overview Canonical Name Records",
                         description="This table summarizes how host names are resolved. Use column 'Resolves to "
                                     "IP' to identify host names that do not resolve to an IP address.",
                         **kwargs)

    @staticmethod
    def get_add_argparse_arguments(parser_cname: argparse.ArgumentParser):
        """
        This method adds the report's specific command line arguments.
        """
        # setup cname parser
        parser_cname.add_argument("-w", "--workspaces",
                                  metavar="WORKSPACE",
                                  help="query the given workspaces",
                                  nargs="+",
                                  type=str)
        parser_cname.add_argument('--csv',
                                  default=True,
                                  action='store_true',
                                  help='returns gathered information in csv format')
        parser_cname.add_argument('--filter', metavar='IP|DOMAIN', type=str, nargs='*',
                                  help='list of IP addresses or second-level domains (e.g., megacorpone.com) whose '
                                       'information shall be returned. per default, mentioned items are excluded. '
                                       'add + in front of each item (e.g., +megacorpone.com) to return only these items')
        parser_cname.add_argument('--scope', choices=[item.name for item in ReportScopeType],
                                  help='return only second-level domains that are in scope (within) or out of scope '
                                       '(outside). per default, all information is returned')

    def _filter(self, domain_name: DomainName) -> bool:
        """
        Method determines whether the given item shall be included into the report
        """
        return domain_name.is_processable(included_items=self._included_items,
                                          excluded_items=self._excluded_items,
                                          scope=self._scope,
                                          include_ip_address=True)

    def get_csv(self) -> List[List[str]]:
        """
        This method returns all information as CSV.
        :return:
        """
        rows = [["DB ID (Domain)",
                 "DB ID (Hostname)",
                 "Workspace",
                 "Second-Level Domain",
                 "Second-Level Domain Scope",
                 "Host Name",
                 "Host Name In Scope",
                 "Vhost In-Scope",
                 "CNAME Records",
                 "Resolves to IPv4",
                 "Resolves to IPv6",
                 "Resolves to IP"]]
        for workspace in self._workspaces:
            for host_name in self._session.query(HostName) \
                    .join(DomainName) \
                    .join(Workspace) \
                    .filter(Workspace.name == workspace.name).all():
                if self._filter(host_name.domain_name) and not host_name.source_host_name_mappings:
                    resolves_to_ipv4 = False
                    resolves_to_ipv6 = False
                    cnames = host_name.canonical_name_records
                    if len(cnames) > 1:
                        for item in cnames[-1].host_host_name_mappings:
                            resolves_to_ipv4 |= item.resolves_to_ipv4_address()
                            resolves_to_ipv6 |= item.resolves_to_ipv6_address()
                        rows.append([host_name.domain_name.id,
                                     host_name.id,
                                     workspace.name,
                                     host_name.domain_name.name,
                                     host_name.domain_name.scope_str,
                                     host_name.full_name,
                                     host_name._in_scope,
                                     host_name.in_scope(CollectorType.vhost_service),
                                     " -> ".join([item.summary for item in cnames]),
                                     resolves_to_ipv4,
                                     resolves_to_ipv6,
                                     resolves_to_ipv6 or resolves_to_ipv4])
        return rows
