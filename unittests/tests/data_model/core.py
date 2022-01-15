#!/usr/bin/python3
"""
this file implements core functionality to test KIS' data model
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

from database.model import Host
from database.model import Service
from database.model import ScopeType
from database.model import ServiceState
from database.model import ProtocolType
from database.model import DnsResourceRecordType
from unittests.tests.collectors.kali.modules.core import BaseKisTestCase
from sqlalchemy.orm.session import Session


class BaseTestServiceSyncTriggersTestCase(BaseKisTestCase):
    """
    Test trigger:
    - assign_services_to_host_name
    - add_services_to_host_name
    """

    def _create_test_data(self,
                          session: Session,
                          workspace_str: str = "unittest") -> Host:
        source = self.create_source(session=session, source_str="dnshost")
        self.create_network(session=session,
                            network="192.168.1.0/24",
                            scope=ScopeType.all,
                            workspace_str=workspace_str)
        host1 = self.create_host(session=session, workspace_str=workspace_str, address="192.168.1.1")
        host2 = self.create_host(session=session, workspace_str=workspace_str, address="192.168.1.2")
        session.add(Service(host=host1, protocol=ProtocolType.tcp, port=80, state=ServiceState.Open))
        session.add(Service(host=host2, protocol=ProtocolType.tcp, port=80, state=ServiceState.Open))
        # self.create_service(session=session, workspace_str=workspace_str, address="192.168.1.1", port=80)
        host_name1 = self.create_hostname(session=session,
                                          workspace_str=workspace_str,
                                          host_name="www.test1.com", scope=ScopeType.all)
        host_name2 = self.create_hostname(session=session,
                                          workspace_str=workspace_str,
                                          host_name="www.test.com", scope=ScopeType.all)
        self._domain_utils.add_host_host_name_mapping(session=session,
                                                      host=host1,
                                                      host_name=host_name1,
                                                      source=source,
                                                      mapping_type=DnsResourceRecordType.a | DnsResourceRecordType.ns)
        self._domain_utils.add_host_host_name_mapping(session=session,
                                                      host=host2,
                                                      host_name=host_name2,
                                                      source=source,
                                                      mapping_type=DnsResourceRecordType.ptr)

    def _compare_service(self, expected: Service, actual: Service):
        self.assertEqual(expected.protocol, actual.protocol)
        self.assertEqual(expected.port, actual.port)
        self.assertEqual(expected.nmap_service_name, actual.nmap_service_name)
        self.assertEqual(expected.nessus_service_name, actual.nessus_service_name)
        self.assertEqual(expected.nmap_service_confidence, actual.nmap_service_confidence)
        self.assertEqual(expected.nessus_service_confidence, actual.nessus_service_confidence)
        self.assertEqual(expected.nmap_service_name_original, actual.nmap_service_name_original)
        self.assertEqual(expected.state, actual.state)
        self.assertEqual(expected.nmap_service_state_reason, actual.nmap_service_state_reason)
        self.assertEqual(expected.nmap_extra_info, actual.nmap_extra_info)
        self.assertEqual(expected.nmap_product, actual.nmap_product)
        self.assertEqual(expected.nmap_version, actual.nmap_version)
        self.assertEqual(expected.nmap_tunnel, actual.nmap_tunnel)
        self.assertEqual(expected.nmap_os_type, actual.nmap_os_type)
