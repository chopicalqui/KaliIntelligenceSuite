#!/usr/bin/python3
"""
this file implements unittests for the reporting functionality
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
import os
from unittests.tests.core import BaseReportTestCase
from database.model import PathType
from database.model import Workspace
from database.model import DnsResourceRecordType
from database.model import ScopeType
from database.report import _HostNameReportGenerator
from database.report import _HostReportGenerator
from database.report import _NetworkReportGenerator
from database.report import _CollectorReportGenerator
from database.report import _CredentialReportGenerator
from database.report import _DomainNameReportGenerator
from database.report import _EmailReportGenerator
from database.report import _CompanyReportGenerator
from database.report import _PathReportGenerator
from database.report import ReportGenerator
from sqlalchemy.orm.session import Session


class TestHostReport(BaseReportTestCase):
    """
    Test host report
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, report_class=_HostReportGenerator)

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
            self.create_host(session, workspace_str=workspace, address="192.168.10.1")
            self.create_host(session, workspace_str=workspace, address="192.168.10.2")
            workspace = self._workspaces[1]
            self.create_network(session,
                                workspace_str=workspace,
                                network="192.168.0.0/24",
                                scope=ScopeType.exclude)
            self.create_network(session,
                                workspace_str=workspace,
                                network="192.168.10.0/24",
                                scope=ScopeType.all)
            self.create_host(session, workspace_str=workspace, address="192.168.0.1")
            self.create_host(session, workspace_str=workspace, address="192.168.0.2")
            self.create_host(session, workspace_str=workspace, address="192.168.10.1")
            self.create_host(session, workspace_str=workspace, address="192.168.10.2")

    def test_filter_in_scope(self):
        """
        Unittests for _HostReportGenerator.filter
        :return:
        """
        self.init_db()
        self.create_data_for_filter_test()
        with self._engine.session_scope() as session:
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["host", "-w", workspace, "--csv", "--scope", "within"],
                              item=self.query_host(session=session,
                                                   workspace_str=workspace,
                                                   ipv4_address="192.168.0.1"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["host", "-w", workspace, "--csv", "--scope", "within"],
                              item=self.query_host(session=session,
                                                   workspace_str=workspace,
                                                   ipv4_address="192.168.10.1"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["host", "-w", workspace, "--csv", "--scope", "within"],
                              item=self.create_host(session=session,
                                                    workspace_str=workspace,
                                                    address="192.168.100.1",
                                                    in_scope=False),
                              expected_result=False)

    def test_filter_include(self):
        """
        Unittests for _HostNameReportGenerator.filter
        :return:
        """
        self.init_db()
        self.create_data_for_filter_test()
        with self._engine.session_scope() as session:
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["host", "-w", workspace, "--csv", "--filter", "+192.168.0.1"],
                              item=self.create_host(session=session,
                                                    workspace_str=workspace,
                                                    address="192.168.0.1"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["host", "-w", workspace, "--csv", "--filter", "+192.168.0.0/24"],
                              item=self.create_host(session=session,
                                                    workspace_str=workspace,
                                                    address="192.168.0.1"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["host", "-w", workspace, "--csv", "--filter", "+192.168.1.1"],
                              item=self.create_host(session=session,
                                                    workspace_str=workspace,
                                                    address="192.168.0.1"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["host", "-w", workspace, "--csv", "--filter", "+192.168.1.0/24"],
                              item=self.create_host(session=session,
                                                    workspace_str=workspace,
                                                    address="192.168.0.1"),
                              expected_result=False)

    def test_filter_exclude(self):
        """
        Unittests for _HostNameReportGenerator.filter
        :return:
        """
        self.init_db()
        self.create_data_for_filter_test()
        with self._engine.session_scope() as session:
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["host", "-w", workspace, "--csv", "--filter", "192.168.0.1"],
                              item=self.create_host(session=session,
                                                    workspace_str=workspace,
                                                    address="192.168.0.1"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["host", "-w", workspace, "--csv", "--filter", "192.168.0.0/24"],
                              item=self.create_host(session=session,
                                                    workspace_str=workspace,
                                                    address="192.168.0.1"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["host", "-w", workspace, "--csv", "--filter", "192.168.0.1"],
                              item=self.create_host(session=session,
                                                    workspace_str=workspace,
                                                    address="192.168.1.1"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["host", "-w", workspace, "--csv", "--filter", "192.168.0.0/24"],
                              item=self.create_host(session=session,
                                                    workspace_str=workspace,
                                                    address="192.168.1.1"),
                              expected_result=True)

    def test_filter_mixed(self):
        """
        Unittests for _HostNameReportGenerator.filter
        :return:
        """
        self.init_db()
        self.create_data_for_filter_test()
        with self._engine.session_scope() as session:
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["host", "-w", workspace, "--csv", "--filter", "+192.168.0.1",
                                             "--scope", "within"],
                              item=self.query_host(session=session,
                                                    workspace_str=workspace,
                                                    ipv4_address="192.168.0.1"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["host", "-w", workspace, "--csv", "--filter", "192.168.0.1",
                                             "--scope", "within"],
                              item=self.create_host(session=session,
                                                    workspace_str=workspace,
                                                    address="192.168.1.1",
                                                    in_scope=False),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["host", "-w", workspace, "--csv", "--filter", "192.168.1.0/24",
                                             "--scope", "within"],
                              item=self.query_host(session=session,
                                                   workspace_str=workspace,
                                                   ipv4_address="192.168.0.1"),
                              expected_result=True)


class TestHostNameReport(BaseReportTestCase):
    """
    Test host name report
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, report_class=_HostNameReportGenerator)

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
                              argument_list=["vhost", "-w", workspace, "--csv", "--scope", "within"],
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
                              argument_list=["vhost", "-w", workspace, "--csv", "--scope", "within"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="test1.com"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["vhost", "-w", workspace, "--csv", "--scope", "within"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="ftp.test1.com"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["vhost", "-w", workspace, "--csv", "--scope", "within"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="www.test2.com"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["vhost", "-w", workspace, "--csv", "--scope", "within"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="outofscope1.test2.com"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["vhost", "-w", workspace, "--csv", "--scope", "within"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="outofscope2.test1.com"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["vhost", "-w", workspace, "--csv", "--scope", "within"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="outofscope3.test1.com"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["vhost", "-w", workspace, "--csv", "--scope", "within"],
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
                              argument_list=["vhost", "-w", workspace, "--csv", "--scope", "outside"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="test1.com"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["vhost", "-w", workspace, "--csv", "--scope", "outside"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="ftp.test1.com"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["vhost", "-w", workspace, "--csv", "--scope", "outside"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="www.test2.com"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["vhost", "-w", workspace, "--csv", "--scope", "outside"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="outofscope1.test2.com"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["vhost", "-w", workspace, "--csv", "--scope", "outside"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="outofscope2.test1.com"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["vhost", "-w", workspace, "--csv", "--scope", "outside"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="outofscope3.test1.com"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["vhost", "-w", workspace, "--csv", "--scope", "outside"],
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
                              argument_list=["vhost", "-w", workspace, "--csv", "--filter", "+inscope.test1.com"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="inscope.test1.com"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["vhost", "-w", workspace, "--csv", "--filter", "+test1.com"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="inscope.test1.com"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["vhost", "-w", workspace, "--csv", "--filter", "+inscope.test1.com"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="www.test2.com"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["vhost", "-w", workspace, "--csv", "--filter", "+test1.com"],
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
                              argument_list=["vhost", "-w", workspace, "--csv", "--filter", "inscope.test1.com"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="inscope.test1.com"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["vhost", "-w", workspace, "--csv", "--filter", "test1.com"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="inscope.test1.com"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["vhost", "-w", workspace, "--csv", "--filter", "inscope.test1.com"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="www.test2.com"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["vhost", "-w", workspace, "--csv", "--filter", "test1.com"],
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
                              argument_list=["vhost", "-w", workspace, "--csv",
                                             "--filter", "+inscope.test1.com", "--scope", "within"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="inscope.test1.com"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["vhost", "-w", workspace, "--csv",
                                             "--filter", "+inscope.test1.com", "--scope", "within"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="www.test2.com"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["vhost", "-w", workspace, "--csv",
                                             "--filter", "test2.com", "--scope", "within"],
                              item=self.query_hostname(session=session,
                                                       workspace_str=workspace,
                                                       host_name="inscope.test1.com"),
                              expected_result=True)


class TestCompanyReport(BaseReportTestCase):
    """
    Test email report
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, report_class=_CompanyReportGenerator)

    def create_data_for_filter_test(self, session: Session) -> None:
        workspace_str = self._workspaces[0]
        workspace = self._domain_utils.add_workspace(session, workspace_str)
        excluded_network = self._ip_utils.add_network(session=session,
                                                      workspace=workspace,
                                                      network="192.168.1.0/24",
                                                      scope=ScopeType.exclude)
        included_network = self._ip_utils.add_network(session=session,
                                                      workspace=workspace,
                                                      network="192.168.10.0/24",
                                                      scope=ScopeType.all)
        excluded_domain = self._domain_utils.add_domain_name(session=session,
                                                             workspace=workspace,
                                                             item="www.excluded.com",
                                                             scope=ScopeType.exclude)
        included_domain = self._domain_utils.add_domain_name(session=session,
                                                             workspace=workspace,
                                                             item="www.excluded.com",
                                                             scope=ScopeType.all)
        self._domain_utils.add_company(session=session,
                                       workspace=workspace,
                                       name="Included Network LLC",
                                       in_scope=True,
                                       network=included_network)
        self._domain_utils.add_company(session=session,
                                       workspace=workspace,
                                       name="Excluded Network LLC",
                                       network=excluded_network)
        self._domain_utils.add_company(session=session,
                                       workspace=workspace,
                                       name="Included Domain LLC",
                                       in_scope=True,
                                       domain_name=included_domain)
        self._domain_utils.add_company(session=session,
                                       workspace=workspace,
                                       name="Excluded Domain LLC",
                                       domain_name=excluded_domain)
        self._domain_utils.add_company(session=session,
                                       workspace=workspace,
                                       name="Included All LLC",
                                       in_scope=True,
                                       domain_name=included_domain,
                                       network=included_network, )
        self._domain_utils.add_company(session=session,
                                       workspace=workspace,
                                       name="Excluded Domain LLC",
                                       domain_name=excluded_domain,
                                       network=excluded_network)

    def test_filter_within_scope_I(self):
        """
        Unittests for _CompanyReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["company",
                                             "-w", workspace,
                                             "--csv",
                                             "--scope", "within",
                                             "--filter", '+included all llc'],
                              item=self.query_company(session=session,
                                                      workspace_str=workspace,
                                                      name="included all llc"),
                              expected_result=True)

    def test_filter_within_scope_II(self):
        """
        Unittests for _CompanyReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["company",
                                             "-w", workspace,
                                             "--csv",
                                             "--scope", "within",
                                             "--filter", '+exclude network llc'],
                              item=self.query_company(session=session,
                                                      workspace_str=workspace,
                                                      name="excluded network llc"),
                              expected_result=False)

    def test_filter_outside_scope(self):
        """
        Unittests for _CompanyReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["company",
                                             "-w", workspace,
                                             "--csv",
                                             "--scope", "outside",
                                             "--filter", '+included all llc'],
                              item=self.query_company(session=session,
                                                      workspace_str=workspace,
                                                      name="included all llc"),
                              expected_result=False)


class TestEmailReport(BaseReportTestCase):
    """
    Test email report
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, report_class=_EmailReportGenerator)

    def create_data_for_filter_test(self, session: Session) -> None:
        workspace = self._workspaces[0]
        self.create_hostname(session, workspace_str=workspace, host_name="test1.com", scope=ScopeType.all)
        self.create_email(session, workspace_str=workspace, email_address="user1@test1.com")
        self.create_email(session, workspace_str=workspace, email_address="user1@department.test1.com")
        self.create_email(session, workspace_str=workspace, email_address="user2@test1.com")
        self.create_email(session, workspace_str=workspace, email_address="user2@department.test1.com")
        self.create_hostname(session, workspace_str=workspace, host_name="test2.com", scope=ScopeType.exclude)
        self.create_email(session, workspace_str=workspace, email_address="user1@test2.com")
        self.create_email(session, workspace_str=workspace, email_address="user1@department.test2.com")
        self.create_email(session, workspace_str=workspace, email_address="user2@test2.com")
        self.create_email(session, workspace_str=workspace, email_address="user2@department.test2.com")
        workspace = self._workspaces[1]
        self.create_hostname(session, workspace_str=workspace, host_name="test1.com", scope=ScopeType.exclude)
        self.create_email(session, workspace_str=workspace, email_address="user1@test1.com")
        self.create_email(session, workspace_str=workspace, email_address="user1@department.test1.com")
        self.create_email(session, workspace_str=workspace, email_address="user2@test1.com")
        self.create_email(session, workspace_str=workspace, email_address="user2@department.test1.com")
        self.create_hostname(session, workspace_str=workspace, host_name="test2.com", scope=ScopeType.all)
        self.create_email(session, workspace_str=workspace, email_address="user1@test2.com")
        self.create_email(session, workspace_str=workspace, email_address="user1@department.test2.com")
        self.create_email(session, workspace_str=workspace, email_address="user2@test2.com")
        self.create_email(session, workspace_str=workspace, email_address="user2@department.test2.com")

    def test_filter_in_scope(self):
        """
        Unittests for _EmailReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["email", "-w", workspace, "--csv", "--scope", "within"],
                              item=self.query_email(session=session,
                                                    workspace_str=workspace,
                                                    email_address="user1@test1.com"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["email", "-w", workspace, "--csv", "--scope", "within"],
                              item=self.query_email(session=session,
                                                    workspace_str=workspace,
                                                    email_address="user1@test2.com"),
                              expected_result=False)

    def test_filter_include(self):
        """
        Unittests for _EmailReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["email", "-w", workspace, "--csv", "--filter", "+user1@test1.com"],
                              item=self.query_email(session=session,
                                                    workspace_str=workspace,
                                                    email_address="user1@test1.com"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["email", "-w", workspace, "--csv", "--filter", "+department.test1.com"],
                              item=self.query_email(session=session,
                                                    workspace_str=workspace,
                                                    email_address="user1@department.test1.com"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["email", "-w", workspace, "--csv",
                                             "--filter", "+user1@department.test1.com"],
                              item=self.query_email(session=session,
                                                    workspace_str=workspace,
                                                    email_address="user2@department.test1.com"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["email", "-w", workspace, "--csv", "--filter", "+department.test1.com"],
                              item=self.query_email(session=session,
                                                    workspace_str=workspace,
                                                    email_address="user1@department.test2.com"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["email", "-w", workspace, "--csv", "--filter", "+test1.com"],
                              item=self.query_email(session=session,
                                                    workspace_str=workspace,
                                                    email_address="user1@department.test2.com"),
                              expected_result=False)

    def test_filter_exclude(self):
        """
        Unittests for _EmailReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["email", "-w", workspace, "--csv", "--filter", "user1@test1.com"],
                              item=self.query_email(session=session,
                                                    workspace_str=workspace,
                                                    email_address="user1@test1.com"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["email", "-w", workspace, "--csv", "--filter", "department.test1.com"],
                              item=self.query_email(session=session,
                                                    workspace_str=workspace,
                                                    email_address="user1@department.test1.com"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["email", "-w", workspace, "--csv",
                                             "--filter", "user1@department.test1.com"],
                              item=self.query_email(session=session,
                                                    workspace_str=workspace,
                                                    email_address="user2@department.test1.com"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["email", "-w", workspace, "--csv", "--filter", "department.test1.com"],
                              item=self.query_email(session=session,
                                                    workspace_str=workspace,
                                                    email_address="user1@department.test2.com"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["email", "-w", workspace, "--csv", "--filter", "test1.com"],
                              item=self.query_email(session=session,
                                                    workspace_str=workspace,
                                                    email_address="user1@department.test2.com"),
                              expected_result=True)

    def test_filter_mixed(self):
        """
        Unittests for _EmailReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["email", "-w", workspace, "--csv",
                                             "--filter", "+user1@test1.com", "--scope", "within"],
                              item=self.query_email(session=session,
                                                    workspace_str=workspace,
                                                    email_address="user1@test1.com"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["email", "-w", workspace, "--csv",
                                             "--filter", "+department.test1.com", "--scope", "within"],
                              item=self.query_email(session=session,
                                                    workspace_str=workspace,
                                                    email_address="user1@department.test1.com"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["email", "-w", workspace, "--csv",
                                             "--filter", "+test1.com", "--scope", "within"],
                              item=self.query_email(session=session,
                                                    workspace_str=workspace,
                                                    email_address="user1@test1.com"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["email", "-w", workspace, "--csv",
                                             "--filter", "+user1@test2.com", "--scope", "within"],
                              item=self.query_email(session=session,
                                                    workspace_str=workspace,
                                                    email_address="user1@test2.com"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["email", "-w", workspace, "--csv",
                                             "--filter", "test2.com", "--scope", "within"],
                              item=self.query_email(session=session,
                                                    workspace_str=workspace,
                                                    email_address="user1@test1.com"),
                              expected_result=True)


class TestDomainReport(BaseReportTestCase):
    """
    Test domain name report
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, report_class=_DomainNameReportGenerator)

    def create_data_for_filter_test(self, session: Session) -> None:
        workspace = self._workspaces[0]
        self.create_hostname(session, workspace_str=workspace, host_name="test1.com", scope=ScopeType.all)
        self.create_hostname(session, workspace_str=workspace, host_name="test2.com", scope=ScopeType.exclude)
        workspace = self._workspaces[1]
        self.create_hostname(session, workspace_str=workspace, host_name="test1.com", scope=ScopeType.exclude)
        self.create_hostname(session, workspace_str=workspace, host_name="test2.com", scope=ScopeType.all)

    def test_filter_in_scope(self):
        """
        Unittests for _DomainReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["domain", "-w", workspace, "--csv", "--scope", "within"],
                              item=self.query_domainname(session=session,
                                                         workspace_str=workspace,
                                                         domain_name="test1.com"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["domain", "-w", workspace, "--csv", "--scope", "within"],
                              item=self.query_domainname(session=session,
                                                         workspace_str=workspace,
                                                         domain_name="test2.com"),
                              expected_result=False)

    def test_filter_include(self):
        """
        Unittests for _DomainReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["domain", "-w", workspace, "--csv", "--filter", "+test1.com"],
                              item=self.query_domainname(session=session,
                                                         workspace_str=workspace,
                                                         domain_name="test1.com"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["domain", "-w", workspace, "--csv", "--filter", "+department.test1.com"],
                              item=self.query_domainname(session=session,
                                                         workspace_str=workspace,
                                                         domain_name="test1.com"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["domain", "-w", workspace, "--csv", "--filter", "+test1.com"],
                              item=self.query_domainname(session=session,
                                                         workspace_str=workspace,
                                                         domain_name="test2.com"),
                              expected_result=False)

    def test_filter_exclude(self):
        """
        Unittests for _DomainReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["domain", "-w", workspace, "--csv", "--filter", "test1.com"],
                              item=self.query_domainname(session=session,
                                                         workspace_str=workspace,
                                                         domain_name="test1.com"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["domain", "-w", workspace, "--csv", "--filter", "department.test1.com"],
                              item=self.query_domainname(session=session,
                                                         workspace_str=workspace,
                                                         domain_name="test1.com"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["domain", "-w", workspace, "--csv", "--filter", "test1.com"],
                              item=self.query_domainname(session=session,
                                                         workspace_str=workspace,
                                                         domain_name="test2.com"),
                              expected_result=True)

    def test_filter_mixed(self):
        """
        Unittests for _DomainReportGenerator.filter
        :return:
        """
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["domain", "-w", workspace, "--csv", "--filter", "test1.com"],
                              item=self.query_domainname(session=session,
                                                         workspace_str=workspace,
                                                         domain_name="test1.com"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["domain", "-w", workspace, "--csv",
                                             "--filter", "test1.com", "--scope", "within"],
                              item=self.query_domainname(session=session,
                                                         workspace_str=workspace,
                                                         domain_name="test1.com"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["domain", "-w", workspace, "--csv", "--filter", "department.test1.com"],
                              item=self.query_domainname(session=session,
                                                         workspace_str=workspace,
                                                         domain_name="test1.com"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["domain", "-w", workspace, "--csv",
                                             "--filter", "department.test1.com", "--scope", "within"],
                              item=self.query_domainname(session=session,
                                                         workspace_str=workspace,
                                                         domain_name="test1.com"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["domain", "-w", workspace, "--csv", "--filter", "test1.com"],
                              item=self.query_domainname(session=session,
                                                         workspace_str=workspace,
                                                         domain_name="test2.com"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["domain", "-w", workspace, "--csv",
                                             "--filter", "test1.com", "--scope", "within"],
                              item=self.query_domainname(session=session,
                                                         workspace_str=workspace,
                                                         domain_name="test2.com"),
                              expected_result=False)


class TestIpv4NetworkReport(BaseReportTestCase):
    """
    Test IPv4 network report
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, report_class=_NetworkReportGenerator)

    def create_data_for_filter_test(self, session: Session) -> None:
        workspace = self._workspaces[0]
        self.create_network(session, workspace_str=workspace, network="192.168.0.0/24", scope=ScopeType.all)
        self.create_network(session,
                            workspace_str=workspace,
                            network="192.168.10.0/24",
                            scope=ScopeType.exclude)
        workspace = self._workspaces[1]
        self.create_network(session,
                            workspace_str=workspace,
                            network="192.168.0.0/24",
                            scope=ScopeType.exclude)
        self.create_network(session, workspace_str=workspace, network="192.168.10.0/24", scope=ScopeType.all)

    def test_filter_in_scope(self):
        """
        Unittests for _Ipv4NetworkReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["network", "-w", workspace, "--csv", "--scope", "within"],
                              item=self.query_ipv4network(session=session,
                                                          workspace_str=workspace,
                                                          ipv4_network="192.168.0.0/24"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["network", "-w", workspace, "--csv", "--scope", "within"],
                              item=self.query_ipv4network(session=session,
                                                          workspace_str=workspace,
                                                          ipv4_network="192.168.10.0/24"),
                              expected_result=False)

    def test_filter_include(self):
        """
        Unittests for _Ipv4NetworkReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["network", "-w", workspace, "--csv", "--filter", "+192.168.0.0/24"],
                              item=self.query_ipv4network(session=session,
                                                          workspace_str=workspace,
                                                          ipv4_network="192.168.0.0/24"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["network", "-w", workspace, "--csv", "--filter", "+192.168.0.0/24"],
                              item=self.query_ipv4network(session=session,
                                                          workspace_str=workspace,
                                                          ipv4_network="192.168.10.0/24"),
                              expected_result=False)

    def test_filter_exclude(self):
        """
        Unittests for _Ipv4NetworkReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["network", "-w", workspace, "--csv", "--filter", "192.168.0.0/24"],
                              item=self.query_ipv4network(session=session,
                                                          workspace_str=workspace,
                                                          ipv4_network="192.168.0.0/24"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["network", "-w", workspace, "--csv", "--filter", "192.168.10.0/24"],
                              item=self.query_ipv4network(session=session,
                                                          workspace_str=workspace,
                                                          ipv4_network="192.168.0.0/24"),
                              expected_result=True)

    def test_filter_mixed(self):
        """
        Unittests for _Ipv4NetworkReportGenerator.filter
        :return:
        """
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["network", "-w", workspace, "--csv",
                                             "--filter", "192.168.0.0/24", "--scope", "within"],
                              item=self.query_ipv4network(session=session,
                                                          workspace_str=workspace,
                                                          ipv4_network="192.168.0.0/24"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["network", "-w", workspace, "--csv",
                                             "--filter", "+192.168.0.0/24", "--scope", "within"],
                              item=self.query_ipv4network(session=session,
                                                          workspace_str=workspace,
                                                          ipv4_network="192.168.0.0/24"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["network", "-w", workspace, "--csv",
                                             "--filter", "192.168.0.0/24", "--scope", "within"],
                              item=self.query_ipv4network(session=session,
                                                          workspace_str=workspace,
                                                          ipv4_network="192.168.10.0/24"),
                              expected_result=False)


class TestPathReport(BaseReportTestCase):
    """
    Test path report
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, report_class=_PathReportGenerator)

    def create_data_for_filter_test(self, session: Session) -> None:
        workspace = self._workspaces[0]
        self.create_network(session, workspace_str=workspace, network="192.168.0.0/24", scope=ScopeType.all)
        self.create_path(session,
                         workspace_str=workspace,
                         path="/path1",
                         path_type=PathType.Http,
                         service=self.create_service(session,
                                                     workspace_str=workspace,
                                                     address="192.168.0.1"))
        self.create_path(session,
                         workspace_str=workspace,
                         path="/path1",
                         path_type=PathType.Http,
                         service=self.create_service(session,
                                                     workspace_str=workspace,
                                                     address="192.168.0.10"))
        self.create_network(session,
                            workspace_str=workspace,
                            network="192.168.10.0/24",
                            scope=ScopeType.exclude)
        self.create_path(session,
                         workspace_str=workspace,
                         path="/path1",
                         path_type=PathType.Http,
                         service=self.create_service(session,
                                                     workspace_str=workspace,
                                                     address="192.168.10.1"))
        self.create_path(session,
                         workspace_str=workspace,
                         path="/path1",
                         path_type=PathType.Http,
                         service=self.create_service(session,
                                                     workspace_str=workspace,
                                                     address="192.168.10.10"))
        self.create_host_host_name_mapping(session=session,
                                           workspace_str=workspace,
                                           ipv4_address="192.168.0.100",
                                           host_name_str="inscope.test1.com",
                                           mapping_type=DnsResourceRecordType.a,
                                           host_name_scope=ScopeType.all, source_str="dnshost")
        self.create_path(session,
                         workspace_str=workspace,
                         path="/path1",
                         path_type=PathType.Http,
                         service=self.create_service(session,
                                                     workspace_str=workspace,
                                                     host_name_str="inscope.test1.com",
                                                     scope=ScopeType.all))
        self.create_path(session,
                         workspace_str=workspace,
                         path="/path1",
                         path_type=PathType.Http,
                         service=self.create_service(session,
                                                     workspace_str=workspace,
                                                     host_name_str="ftp.test1.com",
                                                     scope=ScopeType.all))
        self.create_path(session,
                         workspace_str=workspace,
                         path="/path1",
                         path_type=PathType.Http,
                         service=self.create_service(session,
                                                     workspace_str=workspace,
                                                     host_name_str="www.test2.com",
                                                     scope=ScopeType.exclude))
        self.create_path(session,
                         workspace_str=workspace,
                         path="/path1",
                         path_type=PathType.Http,
                         service=self.create_service(session,
                                                     workspace_str=workspace,
                                                     host_name_str="ftp.test2.com",
                                                     scope=ScopeType.exclude))
        workspace = self._workspaces[1]
        self.create_network(session,
                            workspace_str=workspace,
                            network="192.168.0.0/24",
                            scope=ScopeType.exclude)
        self.create_path(session,
                         workspace_str=workspace,
                         path="/path1",
                         path_type=PathType.Http,
                         service=self.create_service(session,
                                                     workspace_str=workspace,
                                                     address="192.168.0.1"))
        self.create_path(session,
                         workspace_str=workspace,
                         path="/path1",
                         path_type=PathType.Http,
                         service=self.create_service(session,
                                                     workspace_str=workspace,
                                                     address="192.168.0.10"))
        self.create_network(session, workspace_str=workspace, network="192.168.10.0/24", scope=ScopeType.all)
        self.create_path(session,
                         workspace_str=workspace,
                         path="/path1",
                         path_type=PathType.Http,
                         service=self.create_service(session,
                                                     workspace_str=workspace,
                                                     address="192.168.10.1"))
        self.create_path(session,
                         workspace_str=workspace,
                         path="/path1",
                         path_type=PathType.Http,
                         service=self.create_service(session,
                                                     workspace_str=workspace,
                                                     address="192.168.10.10"))
        self.create_path(session,
                         workspace_str=workspace,
                         path="/path1",
                         path_type=PathType.Http,
                         service=self.create_service(session,
                                                     workspace_str=workspace,
                                                     host_name_str="www.test1.com",
                                                     scope=ScopeType.exclude))
        self.create_path(session,
                         workspace_str=workspace,
                         path="/path1",
                         path_type=PathType.Http,
                         service=self.create_service(session,
                                                     workspace_str=workspace,
                                                     host_name_str="ftp.test1.com",
                                                     scope=ScopeType.exclude))
        self.create_path(session,
                         workspace_str=workspace,
                         path="/path1",
                         path_type=PathType.Http,
                         service=self.create_service(session,
                                                     workspace_str=workspace,
                                                     host_name_str="www.test2.com",
                                                     scope=ScopeType.all))
        self.create_path(session,
                         workspace_str=workspace,
                         path="/path1",
                         path_type=PathType.Http,
                         service=self.create_service(session,
                                                     workspace_str=workspace,
                                                     host_name_str="ftp.test2.com",
                                                     scope=ScopeType.all))

    def test_filter_host_in_scope(self):
        """
        Unittests for _PathReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["path", "-w", workspace, "--csv", "--scope", "within"],
                              item=self.query_path(session=session,
                                                   workspace_str=workspace,
                                                   ipv4_address="192.168.0.1",
                                                   path="/path1"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["path", "-w", workspace, "--csv", "--scope", "within"],
                              item=self.query_path(session=session,
                                                   workspace_str=workspace,
                                                   ipv4_address="192.168.10.1",
                                                   path="/path1"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["path", "-w", workspace, "--csv", "--scope", "within", "--type", "Http"],
                              item=self.query_path(session=session,
                                                   workspace_str=workspace,
                                                   ipv4_address="192.168.0.1",
                                                   path="/path1"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["path", "-w", workspace, "--csv", "--scope", "within", "--type",
                                             "Smb_Share"],
                              item=self.query_path(session=session,
                                                   workspace_str=workspace,
                                                   ipv4_address="192.168.0.1",
                                                   path="/path1"),
                              expected_result=False)

    def test_filter_hostname_in_scope(self):
        """
        Unittests for _PathReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["path", "-w", workspace, "--csv", "--scope", "within"],
                              item=self.query_path(session=session,
                                                   workspace_str=workspace,
                                                   host_name="inscope.test1.com",
                                                   path="/path1"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["path", "-w", workspace, "--csv", "--scope", "within"],
                              item=self.query_path(session=session,
                                                   workspace_str=workspace,
                                                   host_name="www.test2.com",
                                                   path="/path1"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["path", "-w", workspace, "--csv", "--scope", "within", "--type", "Http"],
                              item=self.query_path(session=session,
                                                   workspace_str=workspace,
                                                   host_name="inscope.test1.com",
                                                   path="/path1"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["path", "-w", workspace, "--csv", "--scope", "within", "--type",
                                             "Smb_Share"],
                              item=self.query_path(session=session,
                                                   workspace_str=workspace,
                                                   host_name="www.test2.com",
                                                   path="/path1"),
                              expected_result=False)


class TestCredentialReport(BaseReportTestCase):
    """
    Test credential report
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, report_class=_CredentialReportGenerator)

    def create_data_for_filter_test(self, session: Session) -> None:
        workspace = self._workspaces[0]
        self.create_network(session, workspace_str=workspace, network="192.168.0.0/24", scope=ScopeType.all)
        self.create_credential(session,
                               workspace_str=workspace,
                               username="testuser",
                               service=self.create_service(session,
                                                           workspace_str=workspace,
                                                           address="192.168.0.1"))
        self.create_credential(session,
                               workspace_str=workspace,
                               username="testuser",
                               service=self.create_service(session,
                                                           workspace_str=workspace,
                                                           address="192.168.0.10"))
        self.create_network(session,
                            workspace_str=workspace,
                            network="192.168.10.0/24",
                            scope=ScopeType.exclude)
        self.create_credential(session,
                               workspace_str=workspace,
                               username="testuser",
                               service=self.create_service(session,
                                                           workspace_str=workspace,
                                                           address="192.168.10.1"))
        self.create_credential(session,
                               workspace_str=workspace,
                               username="testuser",
                               service=self.create_service(session,
                                                           workspace_str=workspace,
                                                           address="192.168.10.10"))
        self.create_credential(session,
                               workspace_str=workspace,
                               username="testuser",
                               service=self.create_service(session,
                                                           workspace_str=workspace,
                                                           address=None,
                                                           host_name_str="www.test1.com",
                                                           scope=ScopeType.all))
        self.create_host_host_name_mapping(session,
                                           workspace_str=workspace,
                                           ipv4_address="192.168.0.1",
                                           host_name_str="www.test1.com",
                                           mapping_type=DnsResourceRecordType.a,
                                           source_str="dnshost")
        self.create_credential(session,
                               workspace_str=workspace,
                               username="testuser",
                               service=self.create_service(session,
                                                           workspace_str=workspace,
                                                           address=None,
                                                           host_name_str="ftp.test1.com",
                                                           scope=ScopeType.all))
        self.create_credential(session,
                               workspace_str=workspace,
                               username="testuser",
                               service=self.create_service(session,
                                                           workspace_str=workspace,
                                                           address=None,
                                                           host_name_str="www.test2.com",
                                                           scope=ScopeType.exclude))
        self.create_credential(session,
                               workspace_str=workspace,
                               service=self.create_service(session,
                                                           workspace_str=workspace,
                                                           address=None,
                                                           host_name_str="ftp.test2.com",
                                                           scope=ScopeType.exclude))
        self.create_credential(session,
                               workspace_str=workspace,
                               email=self.create_email(session,
                                                       workspace_str=workspace,
                                                       email_address="user1@test1.com"))
        self.create_credential(session,
                               workspace_str=workspace,
                               email=self.create_email(session,
                                                       workspace_str=workspace,
                                                       email_address="user2@test1.com"))
        self.create_credential(session,
                               workspace_str=workspace,
                               email=self.create_email(session,
                                                       workspace_str=workspace,
                                                       email_address="user1@test2.com"))
        self.create_credential(session,
                               workspace_str=workspace,
                               email=self.create_email(session,
                                                       workspace_str=workspace,
                                                       email_address="user2@test2.com"))

    def test_filter_host_in_scope(self):
        """
        Unittests for _PathReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["credential", "-w", workspace, "--csv", "--scope", "within"],
                              item=self.query_credential(session=session,
                                                         workspace_str=workspace,
                                                         username="testuser",
                                                         ipv4_address="192.168.0.1"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["credential", "-w", workspace, "--csv", "--scope", "within"],
                              item=self.query_credential(session=session,
                                                         workspace_str=workspace,
                                                         username="testuser",
                                                         ipv4_address="192.168.10.1"),
                              expected_result=False)

    def test_filter_hostname_in_scope(self):
        """
        Unittests for _PathReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
        with self._engine.session_scope() as session:
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["credential", "-w", workspace, "--csv", "--scope", "within"],
                              item=self.query_credential(session=session,
                                                         workspace_str=workspace,
                                                         username="testuser",
                                                         host_name="www.test1.com"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["credential", "-w", workspace, "--csv", "--scope", "within"],
                              item=self.query_credential(session=session,
                                                         workspace_str=workspace,
                                                         username="testuser",
                                                         host_name="www.test2.com"),
                              expected_result=False)

    def test_filter_email_in_scope(self):
        """
        Unittests for _PathReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["credential", "-w", workspace, "--csv", "--scope", "within"],
                              item=self.query_email(session=session,
                                                    workspace_str=workspace,
                                                    email_address="user1@test1.com"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["credential", "-w", workspace, "--csv", "--scope", "within"],
                              item=self.query_email(session=session,
                                                    workspace_str=workspace,
                                                    email_address="user1@test2.com"),
                              expected_result=False)


class TestCollectorReport(BaseReportTestCase):
    """
    Test collector report
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, report_class=_CollectorReportGenerator)

    def create_ipv4_network_data(self, session: Session) -> None:
        workspace = self._workspaces[0]
        self.create_command(session,
                            workspace_str=workspace,
                            command=["nmap", "-sS", "192.168.0.0/24"],
                            collector_name_str="tcpnmap",
                            ipv4_network_str="192.168.0.0/24",
                            scope=ScopeType.all)
        self.create_command(session,
                            workspace_str=workspace,
                            command=["nmap", "-sU", "192.168.0.0/24"],
                            collector_name_str="udpnmap",
                            ipv4_network_str="192.168.0.0/24",
                            scope=ScopeType.all)
        self.create_command(session,
                            workspace_str=workspace,
                            command=["nmap", "-sS", "192.168.10.0/24"],
                            collector_name_str="tcpnmap",
                            ipv4_network_str="192.168.10.0/24",
                            scope=ScopeType.exclude)
        self.create_command(session,
                            workspace_str=workspace,
                            command=["nmap", "-sU", "192.168.10.0/24"],
                            collector_name_str="udpnmap",
                            ipv4_network_str="192.168.10.0/24",
                            scope=ScopeType.exclude)

    def create_data_for_filter_test(self, session: Session) -> None:
        self.create_ipv4_network_data(session)

    def test_filter_ipv4_network_in_scope(self):
        """
        Unittests for _CollectorReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["command", "-w", workspace, "--csv", "--scope", "within"],
                              item=self.query_command(session=session,
                                                      workspace_str=workspace,
                                                      command_str=["nmap", "-sS", "192.168.0.0/24"],
                                                      collector_name="tcpnmap",
                                                      ipv4_network="192.168.0.0/24"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["command", "-w", workspace, "--csv", "--scope", "within"],
                              item=self.query_command(session=session,
                                                      workspace_str=workspace,
                                                      command_str=["nmap", "-sS", "192.168.10.0/24"],
                                                      collector_name="tcpnmap",
                                                      ipv4_network="192.168.10.0/24"),
                              expected_result=False)

    def test_filter_ipv4_network_include_collector(self):
        """
        Unittests for _CollectorReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["command", "-w", workspace, "--csv", "-I", "tcpnmap"],
                              item=self.query_command(session=session,
                                                      workspace_str=workspace,
                                                      command_str=["nmap", "-sS", "192.168.0.0/24"],
                                                      collector_name="tcpnmap",
                                                      ipv4_network="192.168.0.0/24"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["command", "-w", workspace, "--csv", "-X", "tcpnmap"],
                              item=self.query_command(session=session,
                                                      workspace_str=workspace,
                                                      command_str=["nmap", "-sS", "192.168.0.0/24"],
                                                      collector_name="tcpnmap",
                                                      ipv4_network="192.168.0.0/24"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["command", "-w", workspace, "--csv", "-X", "tcpnmap"],
                              item=self.query_command(session=session,
                                                      workspace_str=workspace,
                                                      command_str=["nmap", "-sU", "192.168.0.0/24"],
                                                      collector_name="udpnmap",
                                                      ipv4_network="192.168.0.0/24"),
                              expected_result=True)

    def test_filter_ipv4_network_exclude_collector(self):
        """
        Unittests for _CollectorReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["command", "-w", workspace, "--csv", "-X", "tcpnmap"],
                              item=self.query_command(session=session,
                                                      workspace_str=workspace,
                                                      command_str=["nmap", "-sS", "192.168.0.0/24"],
                                                      collector_name="tcpnmap",
                                                      ipv4_network="192.168.0.0/24"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["command", "-w", workspace, "--csv", "-X", "tcpnmap"],
                              item=self.query_command(session=session,
                                                      workspace_str=workspace,
                                                      command_str=["nmap", "-sU", "192.168.0.0/24"],
                                                      collector_name="udpnmap",
                                                      ipv4_network="192.168.0.0/24"),
                              expected_result=True)

    def test_filter_ipv4_network_include_network(self):
        """
        Unittests for _CollectorReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["command", "-w", workspace, "--csv", "--filter", "+192.168.0.0/24"],
                              item=self.query_command(session=session,
                                                      workspace_str=workspace,
                                                      command_str=["nmap", "-sS", "192.168.0.0/24"],
                                                      collector_name="tcpnmap",
                                                      ipv4_network="192.168.0.0/24"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["command", "-w", workspace, "--csv", "--filter", "+192.168.0.0/24"],
                              item=self.query_command(session=session,
                                                      workspace_str=workspace,
                                                      command_str=["nmap", "-sS", "192.168.10.0/24"],
                                                      collector_name="tcpnmap",
                                                      ipv4_network="192.168.10.0/24"),
                              expected_result=False)

    def test_filter_ipv4_network_mixed(self):
        """
        Unittests for _CollectorReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["command", "-w", workspace, "--csv",
                                             "--filter", "+192.168.0.0/24", "-I", "tcpnmap", "--scope", "within"],
                              item=self.query_command(session=session,
                                                      workspace_str=workspace,
                                                      command_str=["nmap", "-sU", "192.168.0.0/24"],
                                                      collector_name="udpnmap",
                                                      ipv4_network="192.168.0.0/24"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["command", "-w", workspace, "--csv",
                                             "--filter", "+192.168.0.0/24", "-I", "udpnmap", "--scope", "within"],
                              item=self.query_command(session=session,
                                                      workspace_str=workspace,
                                                      command_str=["nmap", "-sU", "192.168.0.0/24"],
                                                      collector_name="udpnmap",
                                                      ipv4_network="192.168.0.0/24"),
                              expected_result=True)


class TestReportCreation(BaseReportTestCase):
    """
    Test collector report
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, report_class=_CollectorReportGenerator)

    def test_excel_creation(self):
        self.init_db(load_cipher_suites=True)
        # create database
        with self._engine.session_scope() as session:
            for workspace_str in self._workspaces:
                self._populate_all_tables(session, workspace_str)
        # create report
        with self._engine.session_scope() as session:
            with tempfile.TemporaryDirectory() as temp_dir:
                excel_file = os.path.join(temp_dir, "excel.xlsx")
                arguments = ["excel", excel_file, "-w"]
                arguments.extend(self._workspaces)
                args = self.arg_parse(arguments)
                workspaces = [session.query(Workspace).filter_by(name=item).one() for item in self._workspaces]
                generator = ReportGenerator(args=args, session=session, workspaces=workspaces)
                generator.run()

    def test_text_creation(self):
        self.init_db(load_cipher_suites=True)
        # create database
        with self._engine.session_scope() as session:
            for workspace_str in self._workspaces:
                self._populate_all_tables(session, workspace_str)
        # create reports
        with self._engine.session_scope() as session:
            workspaces = [session.query(Workspace).filter_by(name=item).one() for item in self._workspaces]
            generator = ReportGenerator(args=self.arg_parse([]), session=session, workspaces=workspaces)
            for item in generator._generators.values():
                try:
                    item(args=self.arg_parse([]), session=session, workspaces=workspaces).get_text()
                except NotImplementedError:
                    pass

    def test_csv_check_column_count(self):
        self.init_db(load_cipher_suites=True)
        # create database
        with self._engine.session_scope() as session:
            for workspace_str in self._workspaces:
                self._populate_all_tables(session, workspace_str)
        # create reports
        with self._engine.session_scope() as session:
            workspaces = [session.query(Workspace).filter_by(name=item).one() for item in self._workspaces]
            generator = ReportGenerator(args=self.arg_parse([]), session=session, workspaces=workspaces)
            for key, item in generator._generators.items():
                try:
                    rows = item(args=self.arg_parse([]), session=session, workspaces=workspaces).get_csv()
                    if len(rows) > 1:
                        header_count = len(rows[0])
                        for row in rows[1:]:
                            row_count = len(row)
                            if row_count != header_count:
                                self.fail("In report '{}' row count mismatch between "
                                          "header ({}) and content columns ({})".format(key,
                                                                                        header_count,
                                                                                        row_count))
                except NotImplementedError:
                    pass
