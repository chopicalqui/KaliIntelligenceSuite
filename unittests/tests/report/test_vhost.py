#!/usr/bin/python3
"""
this file implements unittests for reporting domain and host name information
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
from database.model import DnsResourceRecordType
from sqlalchemy.orm.session import Session
from unittests.tests.report.core import BaseReportTestCase


class TestHostNameReport(BaseReportTestCase):
    """
    Test host name report
    """

    def __init__(self, test_name: str):
        super().__init__(test_name=test_name)

    def create_data_for_filter_test(self, session: Session) -> None:
        workspace = self._workspaces[0]
        self.create_network(session=session,
                            workspace_str=workspace,
                            network="192.168.1.0/24",
                            scope=ScopeType.all)
        self.create_network(session=session,
                            workspace_str=workspace,
                            network="192.168.0.0/24",
                            scope=ScopeType.exclude)
        # host name in scope
        self.create_host_host_name_mapping(session=session,
                                           workspace_str=workspace,
                                           ipv4_address="192.168.1.1",
                                           host_name_str="inscope.test1.com",
                                           mapping_type=DnsResourceRecordType.a,
                                           host_name_scope=ScopeType.all, source_str="dnshost")
        self.create_host_host_name_mapping(session=session,
                                           workspace_str=workspace,
                                           ipv4_address="192.168.1.1",
                                           host_name_str="outofscope1.test2.com",
                                           mapping_type=DnsResourceRecordType.a,
                                           host_name_scope=ScopeType.exclude, source_str="test")
        self.create_host_host_name_mapping(session=session,
                                           workspace_str=workspace,
                                           ipv4_address="192.168.1.1",
                                           host_name_str="outofscope2.test1.com",
                                           mapping_type=DnsResourceRecordType.ptr,
                                           host_name_scope=ScopeType.all, source_str="dnshost")
        self.create_host_host_name_mapping(session=session,
                                           workspace_str=workspace,
                                           ipv4_address="192.168.0.1",
                                           host_name_str="outofscope3.test1.com",
                                           mapping_type=DnsResourceRecordType.a,
                                           host_name_scope=ScopeType.all, source_str="dnshost")
        self.create_hostname(session, workspace_str=workspace, host_name="ftp.test1.com", scope=ScopeType.all)
        self.create_hostname(session, workspace_str=workspace, host_name="www.test2.com", scope=ScopeType.exclude)
        self.create_hostname(session, workspace_str=workspace, host_name="ftp.test2.com", scope=ScopeType.exclude)
        workspace = self._workspaces[1]
        self.create_hostname(session, workspace_str=workspace, host_name="www.test1.com", scope=ScopeType.exclude)
        self.create_hostname(session, workspace_str=workspace, host_name="ftp.test1.com", scope=ScopeType.exclude)
        self.create_hostname(session, workspace_str=workspace, host_name="www.test2.com", scope=ScopeType.all)
        self.create_hostname(session, workspace_str=workspace, host_name="ftp.test2.com", scope=ScopeType.all)

    def test_filter_in_scope_I(self):
        """
        Unittests for _HostNameReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
        with self._engine.session_scope() as session:
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["service", "-w", workspace, "--csv", "--scope", "within", "-r", "domain"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="inscope.test1.com"),
                              expected_result=True)

    def test_filter_in_scope_II(self):
        """
        Unittests for _HostNameReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
        with self._engine.session_scope() as session:
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["service", "-w", workspace, "--csv", "--scope", "within", "-r", "domain"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="test1.com"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["service", "-w", workspace, "--csv", "--scope", "within", "-r", "domain"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="ftp.test1.com"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["service", "-w", workspace, "--csv", "--scope", "within", "-r", "domain"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="www.test2.com"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["service", "-w", workspace, "--csv", "--scope", "within", "-r", "domain"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="outofscope1.test2.com"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["service", "-w", workspace, "--csv", "--scope", "within", "-r", "domain"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="outofscope2.test1.com"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["service", "-w", workspace, "--csv", "--scope", "within", "-r", "domain"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="outofscope3.test1.com"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["service", "-w", workspace, "--csv", "--scope", "within", "-r", "domain"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="test2.com"),
                              expected_result=False)

    def test_filter_out_of_scope(self):
        """
        Unittests for _HostNameReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
        with self._engine.session_scope() as session:
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["service", "-w", workspace, "--csv", "--scope", "outside", "-r", "domain"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="test1.com"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["service", "-w", workspace, "--csv", "--scope", "outside", "-r", "domain"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="ftp.test1.com"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["service", "-w", workspace, "--csv", "--scope", "outside", "-r", "domain"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="www.test2.com"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["service", "-w", workspace, "--csv", "--scope", "outside", "-r", "domain"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="outofscope1.test2.com"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["service", "-w", workspace, "--csv", "--scope", "outside", "-r", "domain"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="outofscope2.test1.com"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["service", "-w", workspace, "--csv", "--scope", "outside", "-r", "domain"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="outofscope3.test1.com"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["service", "-w", workspace, "--csv", "--scope", "outside", "-r", "domain"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="test2.com"),
                              expected_result=True)

    def test_filter_include(self):
        """
        Unittests for _HostNameReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["service", "-w", workspace,
                                             "--csv", "--filter", "+inscope.test1.com", "-r", "domain"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="inscope.test1.com"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["service", "-w", workspace,
                                             "--csv", "--filter", "+test1.com", "-r", "domain"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="inscope.test1.com"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["service", "-w", workspace,
                                             "--csv", "--filter", "+inscope.test1.com", "-r", "domain"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="www.test2.com"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["service", "-w", workspace,
                                             "--csv", "--filter", "+test1.com", "-r", "domain"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="www.test2.com"),
                              expected_result=False)

    def test_filter_exclude(self):
        """
        Unittests for _HostNameReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["service", "-w", workspace,
                                             "--csv", "--filter", "inscope.test1.com", "-r", "domain"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="inscope.test1.com"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["service", "-w", workspace,
                                             "--csv", "--filter", "test1.com", "-r", "domain"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="inscope.test1.com"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["service", "-w", workspace,
                                             "--csv", "--filter", "inscope.test1.com", "-r", "domain"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="www.test2.com"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["service", "-w", workspace,
                                             "--csv", "--filter", "test1.com", "-r", "domain"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="www.test2.com"),
                              expected_result=True)

    def test_filter_mixed(self):
        """
        Unittests for _HostNameReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["service", "-w", workspace, "--csv",
                                             "--filter", "+inscope.test1.com", "--scope", "within", "-r", "domain"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="inscope.test1.com"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["service", "-w", workspace, "--csv",
                                             "--filter", "+inscope.test1.com", "--scope", "within", "-r", "domain"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="www.test2.com"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["service", "-w", workspace, "--csv",
                                             "--filter", "test2.com", "--scope", "within", "-r", "domain"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="inscope.test1.com"),
                              expected_result=True)