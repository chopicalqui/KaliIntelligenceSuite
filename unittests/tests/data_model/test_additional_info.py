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

from database.model import AdditionalInfo
from unittests.tests.core import BaseDataModelTestCase


class TestAdditionalInfo(BaseDataModelTestCase):
    """
    Test data model for additional info
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, model=AdditionalInfo)

    def test_unique_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            host_name = self.create_hostname(session, workspace_str=self._workspaces[0])
            service = self.create_service(session, workspace_str=self._workspaces[0])
            self._test_unique_constraint(session,
                                         name="key",
                                         host_name=host_name)
            self._test_unique_constraint(session,
                                         name="key",
                                         service=service)

    def test_not_null_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            host_name = self.create_hostname(session, workspace_str=self._workspaces[0])
            service = self.create_service(session, workspace_str=self._workspaces[0])
            self._test_not_null_constraint(session)
            self._test_not_null_constraint(session,
                                           host_name=host_name)
            self._test_not_null_constraint(session,
                                           service=service)

    def test_check_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            host_name = self.create_hostname(session, workspace_str=self._workspaces[0])
            service = self.create_service(session, workspace_str=self._workspaces[0])
            self._test_check_constraint(session, name="unittest")
            self._test_check_constraint(session,
                                        name="unittest",
                                        host_name=host_name,
                                        service=service)
            self._test_check_constraint(session,
                                        name="unittest",
                                        host_name=host_name,
                                        service=service)

    def test_success(self):
        self.init_db()
        with self._engine.session_scope() as session:
            host_name = self.create_hostname(session, workspace_str=self._workspaces[0])
            service = self.create_service(session, workspace_str=self._workspaces[0])
            self._test_success(session,
                               name="key",
                               host_name=host_name)
            self._test_success(session,
                               name="key",
                               service=service)
