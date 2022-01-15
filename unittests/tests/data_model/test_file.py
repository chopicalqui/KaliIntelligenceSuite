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
from database.model import Host
from database.model import Service
from database.model import ServiceMethod
from database.model import ServiceState
from database.model import ProtocolType
from database.model import Credentials
from database.model import CredentialType
from database.model import Email
from database.model import Network
from database.model import Source
from database.model import Company
from database.model import HostName
from database.model import DomainName
from database.model import Path
from database.model import PathType
from database.model import AdditionalInfo
from database.model import Command
from database.model import CipherSuiteSecurity
from database.model import ScopeType
from database.model import CollectorName
from database.model import CollectorType
from database.model import FileType
from database.model import File
from database.model import HostHostNameMapping
from database.model import HostNameHostNameMapping
from database.model import CipherSuite
from database.model import KeyExchangeAlgorithm
from database.model import HashAlgorithm
from database.model import TlsInfo
from database.model import TlsVersion
from database.model import TlsPreference
from database.model import TlsInfoCipherSuiteMapping
from database.model import CertInfo
from database.model import AsymmetricAlgorithm
from database.model import CertType
from database.model import DnsResourceRecordType
from database.model import VHostNameMapping
from datetime import datetime
from unittests.tests.core import BaseKisTestCase
from unittests.tests.core import BaseDataModelTestCase


class TestPath(BaseDataModelTestCase):
    """
    Test data model for path
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, Path)

    def test_unique_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            service = self.create_service(session)
            self._test_unique_constraint(session, name="/tmp", type=PathType.http, service=service)

    def test_not_null_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            service = self.create_service(session)
            self._test_not_null_constraint(session)
            self._test_not_null_constraint(session, name="/tmp")
            self._test_not_null_constraint(session, name="/tmp", type=PathType.http)
            self._test_not_null_constraint(session, name="/tmp", service=service)
            self._test_not_null_constraint(session, type=PathType.http, service=service)

    def test_check_constraint(self):
        pass

    def test_success(self):
        self.init_db()
        with self._engine.session_scope() as session:
            service = self.create_service(session)
            self._test_success(session, name="/tmp", type=PathType.http, service=service)
