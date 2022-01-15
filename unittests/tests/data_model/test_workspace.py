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

from database.model import Workspace
from unittests.tests.core import BaseDataModelTestCase


class TestWorkspace(BaseDataModelTestCase):
    """
    Test data model for workspace
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, Workspace)

    def test_unique_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            self._test_unique_constraint(session, name="unittest")

    def test_not_null_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            self._test_not_null_constraint(session)

    def test_check_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            pass

    def test_success(self):
        self.init_db()
        with self._engine.session_scope() as session:
            self._test_success(session, name="unittest")
