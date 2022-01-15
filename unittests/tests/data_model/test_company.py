#!/usr/bin/python3
"""
this file implements unittests for the data model
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

from database.model import Company
from database.model import DomainName
from database.model import ScopeType
from unittests.tests.core import BaseDataModelTestCase


class TestCompany(BaseDataModelTestCase):
    """
    Test data model for company
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, Company)

    def test_unique_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = self.create_workspace(session=session, workspace=self._workspaces[0])
            self._test_unique_constraint(session, name="test ag", workspace=workspace)

    def test_not_null_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = self.create_workspace(session=session, workspace=self._workspaces[0])
            self._test_not_null_constraint(session)
            self._test_not_null_constraint(session, name="test ag")
            self._test_not_null_constraint(session, workspace=workspace)

    def test_success(self):
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = self.create_workspace(session=session, workspace=self._workspaces[0])
            self._test_success(session, name="test ag", workspace=workspace)

    def test_set_domain_in_scope(self):
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_hostname(session=session,
                                 workspace_str="unittest",
                                 host_name="www.test.com",
                                 scope=ScopeType.all)
            self.create_email(session=session,
                              workspace_str="unittest",
                              email_address="test@test.com",
                              scope=ScopeType.exclude)
        with self._engine.session_scope() as session:
            domain = session.query(DomainName).all()
            self.assertEqual(1, len(domain))
            self.assertTrue(domain[0].in_scope)