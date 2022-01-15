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
from unittests.tests.data_model.core import BaseTestServiceSyncTriggersTestCase
from unittests.tests.collectors.kali.modules.core import BaseKaliCollectorTestCase


class TestHostHostNameMapping(BaseDataModelTestCase):
    """
    Test data model for HostHostNameMapping
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, HostHostNameMapping)

    def test_unique_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            host_name = self.create_hostname(session=session, workspace_str=self._workspaces[0])
            host = self.create_host(session=session, workspace_str=self._workspaces[0])
            self._test_unique_constraint(session, host=host, host_name=host_name, type=DnsResourceRecordType.a)
            self._test_unique_constraint(session, host=host, host_name=host_name, type=DnsResourceRecordType.a)

    def test_not_null_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            host_name = self.create_hostname(session=session, workspace_str=self._workspaces[0])
            host = self.create_host(session=session, workspace_str=self._workspaces[0])
            self._test_not_null_constraint(session)
            self._test_not_null_constraint(session, host=host)
            self._test_not_null_constraint(session, host_name=host_name)
            self._test_not_null_constraint(session, type=DnsResourceRecordType.a, host=host)
            self._test_not_null_constraint(session, host_name=host_name, type=DnsResourceRecordType.a)

    def test_check_constraint(self):
        pass

    def test_success(self):
        self.init_db()
        with self._engine.session_scope() as session:
            host_name = self.create_hostname(session=session, workspace_str=self._workspaces[0])
            host = self.create_host(session=session, workspace_str=self._workspaces[0])
            self._test_success(session, host=host, host_name=host_name, type=DnsResourceRecordType.a)


class TestServiceSyncTriggers(BaseTestServiceSyncTriggersTestCase):
    """
    Test trigger:
    - assign_services_to_host_name
    - add_services_to_host_name
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def test_new_host_host_name_mapping(self):
        self.init_db()
        # test insert
        with self._engine.session_scope() as session:
            self._create_test_data(session=session)
            results_host_name_service = session.query(Service)\
                .join(HostName).one()
            results_host_service = session.query(Service)\
                .join(Host).filter(Host.address == "192.168.1.1").one()
            self.assertIsNone(results_host_name_service.host_id)
            self.assertIsNone(results_host_service.host_name_id)
            self._compare_service(results_host_service, results_host_name_service)
        # test update
        with self._engine.session_scope() as session:
            results_host_name_service = session.query(Service).join(HostName).one()
            results_host_name_service.state = ServiceState.Closed
            results_host_name_service.nmap_service_name = "https"
            results_host_name_service.nmap_service_confidence = 1
            results_host_name_service.nmap_service_name_original = "nmap_service_name_original"
            results_host_name_service.nmap_service_state_reason = "nmap_service_state_reason"
            results_host_name_service.nmap_product = "nmap_product"
            results_host_name_service.nmap_version = "nmap_version"
            results_host_name_service.nmap_extra_info = "nmap_extra_info"
            results_host_name_service.nmap_os_type = "nmap_os_type"
            results_host_name_service.nmap_tunnel = "nmap_tunnel"
            results_host_name_service.nessus_service_name = "nessus_service_name"
            results_host_name_service.nessus_service_confidence = 1
        with self._engine.session_scope() as session:
            results_host_name_service = session.query(Service).join(HostName).one()
            results_host_service = session.query(Service).join(Host).filter(Host.address == "192.168.1.1").one()
            self.assertEqual(ServiceState.Closed, results_host_name_service.state)
            self.assertEqual("https", results_host_name_service.nmap_service_name)
            self.assertEqual(1, results_host_name_service.nessus_service_confidence)
            self.assertEqual("nmap_service_name_original", results_host_name_service.nmap_service_name_original)
            self.assertEqual("nmap_service_state_reason", results_host_name_service.nmap_service_state_reason)
            self.assertEqual("nmap_product", results_host_name_service.nmap_product)
            self.assertEqual("nmap_version", results_host_name_service.nmap_version)
            self.assertEqual("nmap_extra_info", results_host_name_service.nmap_extra_info)
            self.assertEqual("nmap_os_type", results_host_name_service.nmap_os_type)
            self.assertEqual("nmap_tunnel", results_host_name_service.nmap_tunnel)
            self.assertEqual("nessus_service_name", results_host_name_service.nessus_service_name)
            self.assertEqual(1, results_host_name_service.nmap_service_confidence)
            self._compare_service(results_host_service, results_host_name_service)

    def test_update_host_host_name_mapping(self):
        self.init_db()
        # create database and update data
        with self._engine.session_scope() as session:
            self._create_test_data(session=session)
            host = self.query_host(session=session, workspace_str="unittest", ipv4_address="192.168.1.2")
            host_name = self.query_hostname(session=session, workspace_str="unittest", host_name="www.test.com")
            host_host_name_mapping = session.query(HostHostNameMapping) \
                .filter_by(host_name_id=host_name.id, host_id=host.id).one()
            self.assertEqual(DnsResourceRecordType.ptr, host_host_name_mapping.type)
            self.assertEqual(0, len(host_name.services))
            host_host_name_mapping.type |= DnsResourceRecordType.aaaa
        # check database
        with self._engine.session_scope() as session:
            host = self.query_host(session=session, workspace_str="unittest", ipv4_address="192.168.1.2")
            host_name = self.query_hostname(session=session, workspace_str="unittest", host_name="www.test.com")
            host_host_name_mapping = session.query(HostHostNameMapping) \
                .filter_by(host_name_id=host_name.id, host_id=host.id).one()
            self.assertEqual(DnsResourceRecordType.ptr | DnsResourceRecordType.aaaa, host_host_name_mapping.type)
            self.assertEqual(1, len(host_name.services))
            self.assertEqual(1, len(host.services))
            self.assertEqual(ProtocolType.tcp, host_name.services[0].protocol)
            self.assertEqual(80, host_name.services[0].port)
            self._compare_service(host_name.services[0], host.services[0])
