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

from database.model import Version
from database.model import DatabaseVersionMismatchError
from database.model import DatabaseUninitializationError
from unittests.tests.core import BaseDataModelTestCase


class TestVersion(BaseDataModelTestCase):
    """
    Test data model for version
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, model=Version)

    def test_unique_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            self._test_unique_constraint(session, version="1.0.0")

    def test_success(self):
        self.init_db()
        with self._engine.session_scope() as session:
            self._test_success(session, version="1.0.0")
            self._test_success(session, version="1.1")

    def test_invalid_version(self):
        self.init_db()
        with self.assertRaises(ValueError):
            with self._engine.session_scope() as session:
                session.add(Version(version="1"))
            with self._engine.session_scope() as session:
                session.add(Version(version="1.1.1.1"))
            with self._engine.session_scope() as session:
                session.add(Version(version="a.b"))
            with self._engine.session_scope() as session:
                session.add(Version(version="-1.0"))
            with self._engine.session_scope() as session:
                session.add(Version(version="1.-1"))
            with self._engine.session_scope() as session:
                session.add(Version(version="1.1.-1"))

    def test_valid_version(self):
        self.init_db()
        with self._engine.session_scope() as session:
            session.add(Version(version="1.0"))
            session.add(Version(version="1.1"))
            session.add(Version(version="1.1.1"))


class TestVersionComparison(BaseDataModelTestCase):
    """
    Test data model for version
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, model=Version)

    def test_equal(self):
        self.assertTrue(Version("1.1") == Version("1.1"))
        self.assertTrue(Version("1.1.1") == Version("1.1.1"))
        self.assertFalse(Version("1.1") == Version("1.0"))
        self.assertFalse(Version("1.1.1") == Version("1.1.0"))

    def test_smaller(self):
        self.assertFalse(Version("1.1") < Version("1.1"))
        self.assertFalse(Version("1.1.1") < Version("1.1.1"))
        self.assertFalse(Version("2.1") < Version("1.1"))
        self.assertFalse(Version("1.2") < Version("1.1"))
        self.assertFalse(Version("1.1.2") < Version("1.1.1"))
        self.assertTrue(Version("1.1") < Version("2.1"))
        self.assertTrue(Version("2.1") < Version("2.2"))
        self.assertTrue(Version("2.2.1") < Version("2.2.2"))
        self.assertTrue(Version("1.1.1") < Version("2.2.2"))

    def test_greater(self):
        self.assertFalse(Version("1.1") > Version("1.1"))
        self.assertFalse(Version("1.1.1") > Version("1.1.1"))
        self.assertTrue(Version("2.1") > Version("1.1"))
        self.assertTrue(Version("1.2") > Version("1.1"))
        self.assertTrue(Version("1.1.2") > Version("1.1.1"))
        self.assertFalse(Version("1.1") > Version("2.1"))
        self.assertFalse(Version("2.1") > Version("2.2"))
        self.assertFalse(Version("2.2.1") > Version("2.2.2"))
        self.assertFalse(Version("1.1.1") > Version("2.2.2"))


class TestPreFlightCheck(BaseDataModelTestCase):
    """
    Test KIS' preflight check
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, model=Version)

    def test_preflight_check(self):
        self.init_db()
        with self.assertRaises(DatabaseVersionMismatchError,
                               msg="the database model version in the postgresql database is newer than the one of "
                                   "KIS's current source code version."):
            self._engine.perform_preflight_check("0.0")
        with self.assertRaises(DatabaseVersionMismatchError,
                               msg="the database model version in the postgresql database is outdated and is not supported by " \
                                   "KIS anymore. Before you can continue, you have to update KIS' postgresql database model. " \
                                   "For more information, refer to the following Wiki page (see Option 2): " \
                                   "https://github.com/chopicalqui/KaliIntelligenceSuite/wiki/Updating-the-KIS-database"):
            self._engine.perform_preflight_check("9999999.0")

    def test_uninitialized_exception(self):
        """If the database is not initialized, then the preflight check throws an self._engine.perform_preflight_check("""
        self._engine.drop()
        with self.assertRaises(DatabaseUninitializationError):
            self._engine.perform_preflight_check()
