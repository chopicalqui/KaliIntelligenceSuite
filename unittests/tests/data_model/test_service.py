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

from database.model import Host
from database.model import Service
from database.model import HostName
from database.model import DomainName
from database.model import ScopeType
from database.model import ServiceState
from database.model import ProtocolType
from database.model import DnsResourceRecordType
from unittests.tests.core import BaseDataModelTestCase
from unittests.tests.data_model.core import BaseTestServiceSyncTriggersTestCase


class TestService(BaseDataModelTestCase):
    """
    Test data model for service
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, model=Service)

    def test_unique_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            host_name = self.create_hostname(session, workspace_str=self._workspaces[0])
            host = self.create_host(session, workspace_str=self._workspaces[0])
            self._test_unique_constraint(session,
                                         port=80,
                                         protocol=ProtocolType.tcp,
                                         host=host,
                                         state=ServiceState.Open)
            self._test_unique_constraint(session,
                                         port=80,
                                         protocol=ProtocolType.tcp,
                                         host_name=host_name,
                                         state=ServiceState.Open)

    def test_not_null_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            host = self.create_host(session)
            self._test_not_null_constraint(session)
            self._test_not_null_constraint(session,
                                           port=80,
                                           protocol=ProtocolType.tcp,
                                           host=host)
            self._test_not_null_constraint(session,
                                           port=80,
                                           host=host,
                                           state=ServiceState.Open)
            self._test_not_null_constraint(session,
                                           port=80,
                                           protocol=ProtocolType.tcp,
                                           host=host)

    def test_check_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            host_name = self.create_hostname(session, workspace_str=self._workspaces[0])
            host = self.create_host(session, workspace_str=self._workspaces[0])
            self._test_check_constraint(session,
                                        port=80,
                                        protocol=ProtocolType.tcp,
                                        state=ServiceState.Open)
            self._test_check_constraint(session,
                                        port=80,
                                        protocol=ProtocolType.tcp,
                                        state=ServiceState.Open,
                                        host=host,
                                        host_name=host_name)

    def test_success(self):
        self.init_db()
        with self._engine.session_scope() as session:
            host_name = self.create_hostname(session, workspace_str=self._workspaces[0])
            host = self.create_host(session, workspace_str=self._workspaces[0])
            self._test_success(session,
                               port=80,
                               protocol=ProtocolType.tcp,
                               host=host,
                               state=ServiceState.Open)
            self._test_success(session,
                               port=80,
                               protocol=ProtocolType.tcp,
                               host_name=host_name,
                               state=ServiceState.Open)


class TestServiceSyncTriggers(BaseTestServiceSyncTriggersTestCase):
    """
    Test trigger:
    - assign_services_to_host_name
    - add_services_to_host_name
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def test_sync_service_from_host_name_to_host(self):
        self.init_db()
        workspace_str = "unittest"
        # Set up database
        with self._engine.session_scope() as session:
            host1 = self.create_host(session=session, workspace_str=workspace_str, address="192.168.1.1")
            host2 = self.create_host(session=session, workspace_str=workspace_str, address="::1")
            host_name1 = self.create_hostname(session=session,
                                              workspace_str=workspace_str,
                                              host_name="www.test1.com", scope=ScopeType.all)
            host_name2 = self.create_hostname(session=session,
                                              workspace_str=workspace_str,
                                              host_name="www.test.com", scope=ScopeType.all)
            session.add(Service(host_name=host_name1, protocol=ProtocolType.tcp, port=80, state=ServiceState.Open))
            session.add(Service(host_name=host_name2, protocol=ProtocolType.tcp, port=80, state=ServiceState.Open))
            self._domain_utils.add_host_host_name_mapping(session=session,
                                                          host=host1,
                                                          host_name=host_name1,
                                                          mapping_type=DnsResourceRecordType.a | DnsResourceRecordType.ns)
            self._domain_utils.add_host_host_name_mapping(session=session,
                                                          host=host2,
                                                          host_name=host_name2,
                                                          mapping_type=DnsResourceRecordType.aaaa | DnsResourceRecordType.ptr)
        with self._engine.session_scope() as session:
            result = session.query(Host).filter_by(address="192.168.1.1").one()
            self.assertEqual(1, len(result.services))
            self.assertEqual(ProtocolType.tcp, result.services[0].protocol)
            self.assertEqual(80, result.services[0].port)
            result = session.query(Host).filter_by(address="::1").one()
            self.assertEqual(1, len(result.services))
            self.assertEqual(ProtocolType.tcp, result.services[0].protocol)
            self.assertEqual(80, result.services[0].port)

    def test_service_update(self):
        """
        Updating service
        """
        self.init_db()
        # test insert
        with self._engine.session_scope() as session:
            self._create_test_data(session=session)
            results_host_name_service = session.query(Service)\
                .join(HostName).one_or_none()
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

    def test_new_service_for_host(self):
        self.init_db()
        workspace_str = "unittest"
        # setup database
        with self._engine.session_scope() as session:
            source = self.create_source(session=session, source_str="dnshost")
            self.create_service(session=session, workspace_str=workspace_str, address="192.168.10.1", port=80)
            self.create_service(session=session, workspace_str=workspace_str, address="192.168.10.2", port=80)
            host = self.create_host(session=session, workspace_str=workspace_str, address="192.168.1.1")
            host_name = self.create_hostname(session=session,
                                             workspace_str=workspace_str,
                                             host_name="www.test1.com", scope=ScopeType.all)
            host_name_id = host_name.id
            self._domain_utils.add_host_host_name_mapping(session=session,
                                                          host=host,
                                                          host_name=host_name,
                                                          source=source,
                                                          mapping_type=DnsResourceRecordType.a)
        # test trigger
        with self._engine.session_scope() as session:
            service = self.create_service(session=session,
                                          workspace_str=workspace_str,
                                          address="192.168.1.1", port=443,
                                          protocol_type=ProtocolType.tcp)
            # verify trigger
            results = session.query(Service).join(HostName).filter(Service.port == 443).one()
            self.assertEqual(host_name_id, results.host_name_id)
            self.assertIsNone(results.host_id)
            self._compare_service(service, results)
        # test service update
        with self._engine.session_scope() as session:
            results = session.query(Service).join(Host).filter(Service.port == 443).one()
            results.state = ServiceState.Closed
            results.nmap_service_name = "https"
            results.nmap_service_confidence = 1
            results.nmap_service_name_original = "nmap_service_name_original"
            results.nmap_service_state_reason = "nmap_service_state_reason"
            results.nmap_product = "nmap_product"
            results.nmap_version = "nmap_version"
            results.nmap_extra_info = "nmap_extra_info"
            results.nmap_os_type = "nmap_os_type"
            results.nmap_tunnel = "nmap_tunnel"
            results.nessus_service_name = "nessus_service_name"
            results.nessus_service_confidence = 1
        with self._engine.session_scope() as session:
            results_host_name_service = session.query(Service) \
                .join(Host).filter(Service.port == 443).one()
            results_host_service = session.query(Service) \
                .join(HostName).one()
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

    def test_new_service_for_host_name(self):
        self.init_db()
        workspace_str = "unittest"
        # setup database
        with self._engine.session_scope() as session:
            source = self.create_source(session=session, source_str="dnshost")
            self.create_service(session=session, workspace_str=workspace_str, address="192.168.10.1", port=80)
            self.create_service(session=session, workspace_str=workspace_str, address="192.168.10.2", port=80)
            host = self.create_host(session=session, workspace_str=workspace_str, address="192.168.1.1")
            host_name = self.create_hostname(session=session,
                                             workspace_str=workspace_str,
                                             host_name="www.test1.com", scope=ScopeType.all)
            host_id = host.id
            self._domain_utils.add_host_host_name_mapping(session=session,
                                                          host=host,
                                                          host_name=host_name,
                                                          source=source,
                                                          mapping_type=DnsResourceRecordType.a)
        # test trigger
        with self._engine.session_scope() as session:
            service = self.create_service(session=session,
                                          workspace_str=workspace_str,
                                          host_name_str="www.test1.com",
                                          port=443)
            # verify trigger
            results = session.query(Service).join(Host).filter(Service.port == 443).one()
            self.assertEqual(host_id, results.host_id)
            self.assertIsNone(results.host_name_id)
            self._compare_service(service, results)
        # test service update
        with self._engine.session_scope() as session:
            results = session.query(Service).join(HostName).filter(Service.port == 443).one()
            results.state = ServiceState.Closed
            results.nmap_service_name = "https"
            results.nmap_service_confidence = 1
            results.nmap_service_name_original = "nmap_service_name_original"
            results.nmap_service_state_reason = "nmap_service_state_reason"
            results.nmap_product = "nmap_product"
            results.nmap_version = "nmap_version"
            results.nmap_extra_info = "nmap_extra_info"
            results.nmap_os_type = "nmap_os_type"
            results.nmap_tunnel = "nmap_tunnel"
            results.nessus_service_name = "nessus_service_name"
            results.nessus_service_confidence = 1
        with self._engine.session_scope() as session:
            results_host_name_service = session.query(Service) \
                .join(HostName).one_or_none()
            results_host_service = session.query(Service) \
                .join(Host).filter(Host.address == "192.168.1.1").one_or_none()
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

    def test_delete_service(self):
        self.init_db()
        workspace_str = "unittest"
        # Set up database
        with self._engine.session_scope() as session:
            host1 = self.create_host(session=session, workspace_str=workspace_str, address="192.168.1.1")
            host2 = self.create_host(session=session, workspace_str=workspace_str, address="::1")
            self.create_service(session=session, workspace_str=workspace_str, address="10.0.0.1", port=443)
            host_name1 = self.create_hostname(session=session,
                                              workspace_str=workspace_str,
                                              host_name="www.test1.com", scope=ScopeType.all)
            host_name2 = self.create_hostname(session=session,
                                              workspace_str=workspace_str,
                                              host_name="www.test.com", scope=ScopeType.all)
            session.add(Service(host_name=host_name1, protocol=ProtocolType.tcp, port=80, state=ServiceState.Open))
            session.add(Service(host=host2, protocol=ProtocolType.tcp, port=8080, state=ServiceState.Open))
            self._domain_utils.add_host_host_name_mapping(session=session,
                                                          host=host1,
                                                          host_name=host_name1,
                                                          mapping_type=DnsResourceRecordType.a | DnsResourceRecordType.ns)
            self._domain_utils.add_host_host_name_mapping(session=session,
                                                          host=host2,
                                                          host_name=host_name2,
                                                          mapping_type=DnsResourceRecordType.aaaa | DnsResourceRecordType.ptr)
        # Delete services
        with self._engine.session_scope() as session:
            result = session.query(Service) \
                .join(Host) \
                .filter(Host.address == "192.168.1.1").one()
            session.delete(result)
            result = session.query(Service) \
                .join((HostName, Service.host_name)) \
                .join((DomainName, HostName.domain_name)) \
                .filter(HostName.name == "www").filter(DomainName.name == "test.com").filter(Service.port == 8080).one()
            session.delete(result)
        # Check database
        with self._engine.session_scope() as session:
            result = session.query(Service).all()
            self.assertEqual(1, len(result))
            self.assertEqual(443, result[0].port)
            self.assertIsNotNone(result[0].host)
            self.assertEqual("10.0.0.1", result[0].host.address)
