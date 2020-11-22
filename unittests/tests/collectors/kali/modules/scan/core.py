#!/usr/bin/python3
"""
this file implements core functionalities to test os nmap collectors
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

import tempfile
from typing import List
from unittests.tests.collectors.core import CollectorProducerTestSuite
from unittests.tests.collectors.kali.modules.core import BaseKaliCollectorTestCase
from collectors.os.collector import VhostChoice
from database.model import Command
from database.model import Network
from database.model import HostName
from database.model import DnsResourceRecordType
from database.model import ScopeType


class BaseNmapCollectorTestCase(BaseKaliCollectorTestCase):
    """
    This class represents the base class for all os collector tests
    """

    def __init__(self,
                 test_name: str,
                 collector_name: str = None,
                 collector_class: type = None):
        super().__init__(test_name, collector_name=collector_name, collector_class=collector_class)

    def _create_data_for_command_creation(self) -> None:
        """
        This method creates test data in the database in order to be able to create commands
        :return
        """
        self.init_db()
        with self._engine.session_scope() as session:
            for workspace_str in self._workspaces:
                source_dnshost = self.create_source(session=session, source_str="dnshost")
                # Case host name and IPv4 address in scope and source is dnshost
                self.create_network(session=session,
                                    workspace_str=workspace_str,
                                    network="192.168.1.0/24",
                                    scope=ScopeType.all)
                mapping = self.create_host_host_name_mapping(session=session,
                                                             workspace_str=workspace_str,
                                                             ipv4_address="192.168.1.1",
                                                             host_name_str="www.unittest1.com",
                                                             mapping_type=DnsResourceRecordType.a,
                                                             host_name_scope=ScopeType.all)
                # Case host name and IPv6 address in scope and source is dnshost
                self.create_network(session=session,
                                    workspace_str=workspace_str,
                                    network="2001:0D88:AC10:FE01::/64",
                                    scope=ScopeType.all)
                mapping = self.create_host_host_name_mapping(session=session,
                                                             workspace_str=workspace_str,
                                                             ipv4_address="2001:0D88:AC10:FE01::1",
                                                             host_name_str="www.unittest1.com",
                                                             mapping_type=DnsResourceRecordType.aaaa,
                                                             host_name_scope=ScopeType.all)
                mapping.source = source_dnshost
                # Case host name in scope and IP address out of scope and source is dnsnmap
                self.create_network(session=session,
                                    workspace_str=workspace_str,
                                    network="192.168.10.0/24",
                                    scope=ScopeType.exclude)
                mapping = self.create_host_host_name_mapping(session=session,
                                                             workspace_str=workspace_str,
                                                             ipv4_address="192.168.10.1",
                                                             host_name_str="www.unittest10.com",
                                                             mapping_type=DnsResourceRecordType.a,
                                                             host_name_scope=ScopeType.all)
                mapping.source = source_dnshost
                # Case host name in scope and IPv6 address out of scope and source is dnsnmap
                self.create_network(session=session,
                                    workspace_str=workspace_str,
                                    network="2001:0D88:AC10:FE02::/64",
                                    scope=ScopeType.exclude)
                mapping = self.create_host_host_name_mapping(session=session,
                                                             workspace_str=workspace_str,
                                                             ipv4_address="2001:0D88:AC10:FE02::1",
                                                             host_name_str="ipv6.unittest10.com",
                                                             mapping_type=DnsResourceRecordType.aaaa,
                                                             host_name_scope=ScopeType.all)
                mapping.source = source_dnshost
                # Case host name out of scope and IP address in scope and source is dnsnmap
                self.create_network(session=session,
                                    workspace_str=workspace_str,
                                    network="192.168.20.0/24",
                                    scope=ScopeType.all)
                mapping = self.create_host_host_name_mapping(session=session,
                                                             workspace_str=workspace_str,
                                                             ipv4_address="192.168.20.1",
                                                             host_name_str="www.unittest20.com",
                                                             mapping_type=DnsResourceRecordType.a,
                                                             host_name_scope=ScopeType.exclude)
                mapping.source = source_dnshost
                # Case host name out of scope and IPv6 address in scope and source is dnsnmap
                self.create_network(session=session,
                                    workspace_str=workspace_str,
                                    network="2001:0D88:AC10:FE03::/64",
                                    scope=ScopeType.all)
                mapping = self.create_host_host_name_mapping(session=session,
                                                             workspace_str=workspace_str,
                                                             ipv4_address="2001:0D88:AC10:FE03::1",
                                                             host_name_str="ipv6.unittest20.com",
                                                             mapping_type=DnsResourceRecordType.aaaa,
                                                             host_name_scope=ScopeType.exclude)
                mapping.source = source_dnshost
                # Case host name and IP address in scope and source is other
                self.create_network(session=session,
                                    workspace_str=workspace_str,
                                    network="192.168.30.0/24",
                                    scope=ScopeType.all)
                mapping = self.create_host_host_name_mapping(session=session,
                                                             workspace_str=workspace_str,
                                                             ipv4_address="192.168.30.1",
                                                             host_name_str="www.unittest30.com",
                                                             mapping_type=DnsResourceRecordType.ptr,
                                                             host_name_scope=ScopeType.all)
                mapping.source = source_dnshost
                # Case host name and IPv6 address in scope and source is other
                self.create_network(session=session,
                                    workspace_str=workspace_str,
                                    network="2001:0D88:AC10:FE04::/64",
                                    scope=ScopeType.all)
                mapping = self.create_host_host_name_mapping(session=session,
                                                             workspace_str=workspace_str,
                                                             ipv4_address="2001:0D88:AC10:FE04::1",
                                                             host_name_str="www.unittest30.com",
                                                             mapping_type=DnsResourceRecordType.ptr,
                                                             host_name_scope=ScopeType.all)
                mapping.source = source_dnshost

    def _unittest_command_creation_vhost(self,
                                         vhost: VhostChoice = None,
                                         expected_host_name_commands: List[str] = [],
                                         expected_ipv4_network_command_results: List[str] = []):
        """
        This method tests the correct creation of Nmap scans based on host_names and IPv4 addresses
        :return:
        """
        self._create_data_for_command_creation()
        with tempfile.TemporaryDirectory() as temp_dir:
            arguments = {"workspace": self._workspaces[0],
                         "output_dir": temp_dir,
                         self._collector_name: ["all"]}
            if vhost:
                arguments["vhost"] = vhost
            test_suite = CollectorProducerTestSuite(engine=self._engine,
                                                    arguments=arguments)
            test_suite.create_commands([self._arg_parse_module])
        with self._engine.session_scope() as session:
            ipv4_network_command_results = [item.network for item in session.query(Network)\
                                                .join(Command).all()]
            host_name_command_results = [item.full_name for item in session.query(HostName).join(Command).all()]
            ipv4_network_command_results.sort()
            host_name_command_results.sort()
            self.assertListEqual(expected_ipv4_network_command_results, ipv4_network_command_results)
            self.assertListEqual(expected_host_name_commands, host_name_command_results)

