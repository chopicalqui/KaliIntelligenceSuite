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

from database.model import HostNameHostNameMapping
from unittests.tests.core import BaseDataModelTestCase


class TestHostNameHostNameMapping(BaseDataModelTestCase):
    """
    Test data model for HostNameHostNameMapping
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, HostNameHostNameMapping)

    def test_unique_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            source_host_name = self.create_hostname(session=session,
                                                    workspace_str=self._workspaces[0],
                                                    host_name="www.unittest1.com")
            resolved_host_name = self.create_hostname(session=session,
                                                      workspace_str=self._workspaces[0],
                                                      host_name="www.unittest2.com")
            self._test_unique_constraint(session,
                                         source_host_name=source_host_name,
                                         resolved_host_name=resolved_host_name)
            self._test_unique_constraint(session,
                                         source_host_name=source_host_name,
                                         resolved_host_name=resolved_host_name)

    def test_not_null_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            source_host_name = self.create_hostname(session=session,
                                                    workspace_str=self._workspaces[0],
                                                    host_name="www.unittest1.com")
            self._test_not_null_constraint(session)
            self._test_not_null_constraint(session,
                                           source_host_name=source_host_name)
            self._test_not_null_constraint(session,
                                           resolved_host_name=source_host_name)

    def test_check_constraint(self):
        pass

    def test_success(self):
        self.init_db()
        with self._engine.session_scope() as session:
            source_host_name = self.create_hostname(session=session,
                                                    workspace_str=self._workspaces[0],
                                                    host_name="www.unittest1.com")
            resolved_host_name = self.create_hostname(session=session,
                                                      workspace_str=self._workspaces[0],
                                                      host_name="www.unittest2.com")
            self._test_success(session, source_host_name=source_host_name, resolved_host_name=resolved_host_name)
