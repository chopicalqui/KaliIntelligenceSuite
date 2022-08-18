#!/usr/bin/python3
"""
this file implements unittests for reporting host information
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

from database.model import ScopeType
from database.model import ServiceState
from database.model import ProtocolType
from database.model import DnsResourceRecordType
from unittests.tests.report.core import BaseReportTestCase


class TestHostReport(BaseReportTestCase):
    """
    Test host report
    """

    def __init__(self, test_name: str):
        super().__init__(test_name=test_name)

    def _create_host_host_name_mapping(self,
                                       session,
                                       workspace: str,
                                       ip_address: str,
                                       host_names: list = [],
                                       service_ports: list = []):
        host = self.create_host(session=session, workspace_str=workspace, address=ip_address)
        for host_name in host_names:
            host_name = self.create_hostname(session=session,
                                             workspace_str=workspace,
                                             host_name=host_name,
                                             scope=ScopeType.strict)
            self._domain_utils.add_host_host_name_mapping(session=session,
                                                          host=host,
                                                          host_name=host_name,
                                                          mapping_type=DnsResourceRecordType.a)
            for port in service_ports:
                self._domain_utils.add_service(session=session,
                                               port=port,
                                               protocol_type=ProtocolType.tcp,
                                               state=ServiceState.Open,
                                               host=host)

    def create_data_for_filter_test(self) -> None:
        workspace = self._workspaces[0]
        with self._engine.session_scope() as session:
            self.create_network(session,
                                workspace_str=workspace,
                                network="192.168.0.0/24",
                                scope=ScopeType.all)
            self.create_network(session,
                                workspace_str=workspace,
                                network="192.168.10.0/24",
                                scope=ScopeType.exclude)
            self.create_host(session, workspace_str=workspace, address="192.168.0.1")
            self.create_host(session, workspace_str=workspace, address="192.168.0.2")
            host = self.create_host(session, workspace_str=workspace, address="192.168.0.3")
            self._domain_utils.add_service(session=session,
                                           port=443,
                                           protocol_type=ProtocolType.tcp,
                                           state=ServiceState.Open,
                                           host=host)
            self._create_host_host_name_mapping(session=session,
                                                workspace=workspace,
                                                ip_address="192.168.0.10",
                                                host_names=["www.test10.com", "ftp.test10.com", "www1.test10.com"],
                                                service_ports=[21, 80, 443])
            self._create_host_host_name_mapping(session=session,
                                                workspace=workspace,
                                                ip_address="192.168.0.20",
                                                host_names=["www.test20.com", "ftp.test20.com", "www1.test20.com"],
                                                service_ports=[21, 80, 443])

    def test_csv_all(self):
        self.init_db()
        self.create_data_for_filter_test()
        with self._engine.session_scope() as session:
            workspace = self._workspaces[0]
            results = self._get_csv_report(session=session,
                                           workspace_str=workspace,
                                           argument_list=["service", "-w", workspace, "--csv", "-r", "all"])
            self.assertEqual(28, len(results))
