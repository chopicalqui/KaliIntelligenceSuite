#!/usr/bin/python3
"""
this file implements unittests for testing the scope
"""

__author__ = "Lukas Reiter"
__license__ = "GPL v3.0"
__copyright__ = """Copyright 2018 Lukas Reiter

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

from unittests.tests.core import BaseKisTestCase
from database.model import Workspace
from database.model import HostName
from database.model import DomainName
from database.model import ScopeType


class HostNameScopingTestCases(BaseKisTestCase):
    """
    This class implements functionalities for testing the host name scope
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def _check_data(self, workspace_str: str, host_name: str, second_level_domain: str, in_scope: bool):
        with self._engine.session_scope() as session:
            result = session.query(HostName) \
                .join(DomainName) \
                .join(Workspace) \
                .filter(HostName.name == host_name,
                        DomainName.name == second_level_domain,
                        Workspace.name == workspace_str).one()
            self.assertEqual(in_scope, result._in_scope)

    def test_host_name_scope_strict(self):
        """
        check trigger: if network's scope is set to strict, then host scope is set to false
        """
        # set up database
        self.init_db()
        host_names = ["www.unittest.com", "mail.unittest.com", "vpn.unittest.com"]
        for workspace in self._workspaces:
            for item in host_names:
                with self._engine.session_scope() as session:
                    self.create_hostname(session=session,
                                         workspace_str=workspace,
                                         host_name=item,
                                         scope=ScopeType.strict)
        # check database
        for workspace in self._workspaces:
            self._check_data(workspace_str=workspace,
                             host_name=None,
                             second_level_domain="unittest.com",
                             in_scope=True)
            for item in host_names:
                host_name = self.query_hostname(session=session,
                                                workspace_str=workspace,
                                                host_name=item)
                self.assertEqual(False, host_name._in_scope)
        # update host name scope
        with self._engine.session_scope() as session:
            host_name = self.query_hostname(session=session,
                                            workspace_str=self._workspaces[0],
                                            host_name=host_names[0])
            host_name._in_scope = True
        # check database
        for workspace in self._workspaces:
            host_name = self.query_hostname(session=session,
                                            workspace_str=workspace,
                                            host_name=host_names[0])
            self.assertEqual(self._workspaces[0] == workspace, host_name._in_scope)
        # update scope of domain name to all
        for workspace in self._workspaces:
            with self._engine.session_scope() as session:
                domain_name = self.query_domainname(session=session,
                                                    workspace_str=workspace,domain_name="unittest.com")
                domain_name.scope = ScopeType.all
        # check database
        for workspace in self._workspaces:
            self._check_data(workspace_str=workspace,
                             host_name=None,
                             second_level_domain="unittest.com",
                             in_scope=True)
            for item in host_names:
                host_name = self.query_hostname(session=session,
                                                workspace_str=workspace,
                                                host_name=item)
                self.assertEqual(True, host_name._in_scope)
        # update scope of domain name to exclude
        for workspace in self._workspaces:
            with self._engine.session_scope() as session:
                domain_name = self.query_domainname(session=session,
                                                    workspace_str=workspace,domain_name="unittest.com")
                domain_name.scope = ScopeType.exclude
        # check database
        for workspace in self._workspaces:
            self._check_data(workspace_str=workspace,
                             host_name=None,
                             second_level_domain="unittest.com",
                             in_scope=False)
            for item in host_names:
                host_name = self.query_hostname(session=session,
                                                workspace_str=workspace,
                                                host_name=item)
                self.assertEqual(False, host_name._in_scope)
