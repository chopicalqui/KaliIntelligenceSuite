# -*- coding: utf-8 -*-
"""This module allows querying information about emails."""

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
from database.model import Email
from database.model import ReportScopeType
from database.model import ReportVisibility
from database.report.core import BaseReport


class ReportClass(BaseReport):
    """
    this module allows querying information about emails
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(name="email info",
                         title="Overview Identified Email Addresses",
                         description="The table provides an overview of all identified email addresses.",
                         **kwargs)

    @staticmethod
    def get_add_argparse_arguments(parser_email: argparse.ArgumentParser):
        """
        This method adds the report's specific command line arguments.
        """
        # setup email parser
        parser_email.add_argument("-w", "--workspaces",
                                  metavar="WORKSPACE",
                                  help="query the given workspaces",
                                  nargs="+",
                                  type=str)
        parser_email_group = parser_email.add_mutually_exclusive_group()
        parser_email_group.add_argument('--text', action='store_true',
                                        help='returns gathered information including all collector outputs as text')
        parser_email_group.add_argument('--csv', action='store_true', default=True,
                                        help='returns gathered information in csv format')
        parser_email.add_argument('--filter', metavar='DOMAIN|HOSTNAME|EMAIL', type=str, nargs='*',
                                  help='list of second-level domains (e.g., megacorpone.com), host names (e.g., '
                                       'www.megacorpone.com), or email addresses whose information shall be returned. '
                                       'per default, mentioned items are excluded. add + in front of each item '
                                       '(e.g., +megacorpone.com) to return only these items')
        parser_email.add_argument('--scope', choices=[item.name for item in ReportScopeType],
                                  help='return only in scope (within) or out of scope (outside) items. '
                                       'per default, all information is returned')
        parser_email.add_argument('--visibility', choices=[item.name for item in ReportVisibility],
                                  help='return only relevant (relevant) or potentially irrelevant (irrelevant) '
                                       'information (e.g., executed commands that did not return any information) in text '
                                       'output (argument --text). per default, all information is returned')
        parser_email.add_argument('-X', '--exclude', metavar='COLLECTOR', type=str, nargs='+', default=[],
                                   help='list of collector names (e.g., haveibeenbreach) whose outputs should not be '
                                        'returned in text mode (see argument --text). use argument value "all" to '
                                        'exclude all collectors. per default, no collectors are excluded')
        parser_email.add_argument('-I', '--include', metavar='COLLECTOR', type=str, nargs='+', default=[],
                                   help='list of collector names whose outputs should be returned in text mode (see '
                                        'argument --text). per default, all collector information is returned')

    def _filter(self, email: Email) -> bool:
        """
        Method determines whether the given item shall be included into the report
        """
        return email.is_processable(included_items=self._included_items,
                                    excluded_items=self._excluded_items,
                                    scope=self._scope)

    def get_csv(self) -> List[List[str]]:
        """
        This method returns all information as CSV.
        :return:
        """
        rows = [["DB ID", "Workspace", "Email", "Domain", "In Scope", "Sources"]]
        for workspace in self._workspaces:
            email_addresses = self._session.query(Email)\
                .join(HostName)\
                .join(DomainName)\
                .join(Workspace)\
                .filter(Workspace.id == workspace.id).all()
            for email_address in email_addresses:
                if self._filter(email_address):
                    row = [email_address.id,
                           workspace.name,
                           email_address.email_address,
                           email_address.host_name.full_name,
                           email_address.host_name.domain_name.in_scope,
                           email_address.sources_str]
                    rows.append(row)
        return rows

    def get_text(self) -> List[str]:
        """
        This method returns all information as a list of text.
        :return:
        """
        rvalue = []
        for workspace in self._workspaces:
            email_addresses = self._session.query(Email) \
                .join(HostName) \
                .join(DomainName) \
                .join(Workspace) \
                .filter(Workspace.id == workspace.id).all()
            for email in email_addresses:
                if self._filter(email):
                    rvalue.extend(email.get_text(ident=0,
                                                 scope=self.scope,
                                                 report_visibility=self._visibility,
                                                 exclude_collectors=self._excluded_collectors,
                                                 include_collectors=self._included_collectors,
                                                 color=self._color))
        return rvalue
