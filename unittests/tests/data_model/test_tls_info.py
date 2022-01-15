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

from database.model import TlsInfo
from database.model import TlsVersion
from database.model import TlsPreference
from unittests.tests.core import BaseDataModelTestCase


class TestTlsInfo(BaseDataModelTestCase):
    """
    Test data model for CipherSuite
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, TlsInfo)

    def test_unique_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            service = self.create_service(session=session)
            self._test_unique_constraint(session,
                                         version=TlsVersion.tls13,
                                         service=service,
                                         compressors=[],
                                         preference=TlsPreference.client)

    def test_not_null_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            service = self.create_service(session=session)
            self._test_not_null_constraint(session,
                                           service=service)
            self._test_not_null_constraint(session,
                                           version=TlsVersion.tls13)

    def test_check_constraint(self):
        pass

    def test_success(self):
        self.init_db()
        with self._engine.session_scope() as session:
            service = self.create_service(session=session)
            self._test_success(session,
                               version=TlsVersion.tls13,
                               service=service,
                               compressors=[],
                               preference=TlsPreference.client)
