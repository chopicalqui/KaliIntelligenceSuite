# -*- coding: utf-8 -*-
"""This module allows querying information about companies."""

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
from database.model import Company
from database.model import ReportScopeType
from database.model import ReportVisibility
from database.report.core import BaseReport


class ReportClass(BaseReport):
    """
    this module allows querying information about companies
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(name="company info",
                         title="Overview Identified Company Names",
                         description="The table provides an overview about all identified companies.",
                         **kwargs)

    @staticmethod
    def get_add_argparse_arguments(parser_company: argparse.ArgumentParser):
        """
        This method adds the report's specific command line arguments.
        """
        # setup company parser
        parser_company.add_argument("-w", "--workspaces",
                                    metavar="WORKSPACE",
                                    help="query the given workspaces",
                                    nargs="+",
                                    type=str)
        parser_company_group = parser_company.add_mutually_exclusive_group()
        parser_company_group.add_argument('--text', action='store_true',
                                          help='returns gathered information including all collector outputs as text')
        parser_company_group.add_argument('--csv', action='store_true', default=True,
                                          help='returns gathered information in csv format')
        parser_company.add_argument('--filter', metavar='COMPANY', type=str, nargs='*',
                                    help='list of company names whose information shall be returned. '
                                         'per default, mentioned items are excluded. add + in front of each item '
                                         '(e.g., +"test llc") to return only these items')
        parser_company.add_argument('--scope', choices=[item.name for item in ReportScopeType],
                                    help='return only in scope (within) or out of scope (outside) items. '
                                         'per default, all information is returned')
        parser_company.add_argument('--visibility', choices=[item.name for item in ReportVisibility],
                                    help='return only relevant (relevant) or potentially irrelevant (irrelevant) '
                                         'information (e.g., executed commands that did not return any information) in '
                                         'text output (argument --text). per default, all information is returned')
        parser_company.add_argument('-X', '--exclude', metavar='COLLECTOR', type=str, nargs='+', default=[],
                                    help='list of collector names (e.g., reversewhois) whose outputs should not be '
                                         'returned in text mode (see argument --text). use argument value "all" to '
                                         'exclude all collectors. per default, no collectors are excluded')
        parser_company.add_argument('-I', '--include', metavar='COLLECTOR', type=str, nargs='+', default=[],
                                    help='list of collector names whose outputs should be returned in text mode (see '
                                         'argument --text). per default, all collector information is returned')

    def _filter(self, company: Company) -> bool:
        """
        Method determines whether the given item shall be included into the report
        """
        return company.is_processable(included_items=self._included_items,
                                      excluded_items=self._excluded_items,
                                      scope=self._scope)

    def get_csv(self) -> List[List[str]]:
        """
        This method returns all information as CSV.
        :return:
        """
        rows = [["Workspace",
                 "Company",
                 "In Scope",
                 "Verified",
                 "Owns",
                 "Owns Type",
                 "Owns Scope",
                 "Sources (Company)",
                 "Sources (Mappings)",
                 "DB ID (Company)",
                 "DB ID (Mapping)"]]
        for workspace in self._workspaces:
            results = self._session.query(Company)\
                .join(Workspace)\
                .filter(Workspace.id == workspace.id).order_by(Company.name).all()
            for company in results:
                if self._filter(company):
                    has_results = False
                    in_scope = company.in_scope
                    sources_companies = company.sources_str
                    for mapping in company.company_network_mappings:
                        has_results = True
                        sources_mappings = mapping.sources_str
                        row = [company.workspace.name,  # Workspace
                               company.name,  # Company
                               in_scope,  # In Scope
                               mapping.verified,  # Verified
                               mapping.network.network,  # Owns
                               "network",  # Owns Type
                               mapping.network.scope_str,  # Owns Scope
                               sources_companies,  # Sources (Company)
                               sources_mappings,  # Sources (Mappings)
                               company.id,  # DB ID (Company)
                               mapping.id]  # DB ID (Mapping)
                        rows.append(row)
                    for mapping in company.company_domain_name_mappings:
                        has_results = True
                        sources_mappings = mapping.sources_str
                        row = [company.workspace.name,  # Workspace
                               company.name,  # Company
                               in_scope,  # In Scope
                               mapping.verified,  # Verified
                               mapping.domain_name.name,  # Owns
                               "domain",  # Owns Type
                               mapping.domain_name.scope_str,  # Owns Scope
                               sources_companies,  # Sources (Company)
                               sources_mappings,  # Sources (Mappings)
                               company.id,  # DB ID (Company)
                               mapping.id]  # DB ID (Mapping)
                        rows.append(row)
                    if not has_results:
                        row = [company.workspace.name,  # Workspace
                               company.name,  # Company
                               in_scope,  # In Scope
                               None,  # Verified
                               None,  # Owns
                               "domain",  # Owns Type
                               None,  # Owns Scope
                               sources_companies,  # Sources (Company)
                               None,  # Sources (Mappings)
                               company.id,  # DB ID (Company)
                               None]  # DB ID (Mapping)
                        rows.append(row)
        return rows

    def get_text(self) -> List[str]:
        """
        This method returns all information as a list of text.
        :return:
        """
        rvalue = []
        for workspace in self._workspaces:
            results = self._session.query(Company) \
                .join(Workspace) \
                .filter(Workspace.id == workspace.id).all()
            for company in results:
                if self._filter(company):
                    rvalue.extend(company.get_text(ident=0,
                                                   scope=self.scope,
                                                   report_visibility=self._visibility,
                                                   exclude_collectors=self._excluded_collectors,
                                                   include_collectors=self._included_collectors,
                                                   color=self._color))
        return rvalue
