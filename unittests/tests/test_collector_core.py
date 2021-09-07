#!/usr/bin/python3
"""
this file implements unittests for core functionalities
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

import unittest
import tempfile
import time
import subprocess
from urllib.parse import urlparse
from typing import List
from typing import Dict
from unittests.tests.core import BaseKisTestCase
from database.model import Workspace
from database.model import Host
from database.model import Service
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
from database.model import ServiceMethod
from database.model import CommandStatus
from database.model import CollectorName
from database.model import CollectorType
from database.model import FileType
from database.model import File
from database.model import HttpQuery
from database.model import DnsResourceRecordType
from database.model import HostHostNameMapping
from database.model import TlsVersion
from database.model import TlsPreference
from database.model import TlsInfo
from database.model import AsymmetricAlgorithm
from database.model import HashAlgorithm
from database.model import CertInfo
from database.model import KeyExchangeAlgorithm
from database.model import CertType
from database.model import TlsInfoCipherSuiteMapping
from database.model import ScopeType
from database.model import ExecutionInfoType
from database.model import DomainNameNotFound
from collectors.os.core import PopenCommand
from collectors.os.core import PopenCommandOpenSsl
from collectors.core import IpUtils
from datetime import datetime
from view.core import ReportItem
from collectors.os.modules.core import Delay
from sqlalchemy.orm.session import Session


class TestDelayMethods(unittest.TestCase):
    """
    This class implements checks for testing delay functionality
    """

    def test_sleep_active(self):
        self.assertFalse(Delay(0, 0, False, False).sleep_active())
        self.assertFalse(Delay(0, 0).sleep_active())
        self.assertTrue(Delay(5, 10, False, False).sleep_active())
        self.assertFalse(Delay(5, 10, True, False).sleep_active())
        self.assertFalse(Delay(5, 10, False, True).sleep_active())
        self.assertFalse(Delay(5, 10, True, True).sleep_active())
        self.assertFalse(Delay(-5, 10, True, True).sleep_active())
        self.assertTrue(Delay(None, 10, False, False).sleep_active())
        self.assertTrue(Delay(5, None, False, False).sleep_active())
        self.assertFalse(Delay(None, None, False, False).sleep_active())

    def test_sleep_time(self):
        self.assertEqual(0, Delay(0, 0, False, False).sleep_time)
        self.assertEqual(5, Delay(5, 0, False, False).sleep_time)
        self.assertEqual(5, Delay(5, 5, False, False).sleep_time)
        self.assertEqual(5, Delay(0, 5, False, False).sleep_time)
        self.assertEqual(0, Delay(0, 0, True, False).sleep_time)
        self.assertEqual(0, Delay(5, 0, True, False).sleep_time)
        self.assertEqual(0, Delay(5, 5, True, False).sleep_time)
        self.assertEqual(0, Delay(0, 5, True, False).sleep_time)
        self.assertEqual(0, Delay(0, 0, False, True).sleep_time)
        self.assertEqual(0, Delay(5, 0, False, True).sleep_time)
        self.assertEqual(0, Delay(5, 5, False, True).sleep_time)
        self.assertEqual(0, Delay(0, 5, False, True).sleep_time)
        self.assertTrue(1 <= Delay(1, 3, False, False).sleep_time <= 3)
        self.assertTrue(1 <= Delay(1, 3, False, False).sleep_time <= 3)
        self.assertTrue(1 <= Delay(1, 3, False, False).sleep_time <= 3)
        self.assertTrue(1 <= Delay(1, 3, False, False).sleep_time <= 3)
        self.assertTrue(1 <= Delay(1, 3, False, False).sleep_time <= 3)


class TestCommandExecution(BaseKisTestCase):
    """
    This class tests OS command executions via library collectors.os.core
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def test_terminate(self):
        process = PopenCommand(os_command=["sleep", "10"],
                               cwd="/tmp",
                               timeout=1,
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
        process.start()
        process.join()
        self.assertIsNone(process.stdout_list)
        self.assertIsNone(process.stderr_list)
        self.assertTrue(process.killed)

    def test_stdout_queue_only(self):
        """
        This unittest checks whether PopenCommand correctly reads the entire subprocess.PIPE data for stdout only.
        """
        iterations = 5
        process = PopenCommand(os_command=["python3",
                                           "-c",
                                           "import sys; import time; [str(time.sleep(1)) + str(print(item, file=sys.stdout)) + str(time.sleep(1)) for item in range(0, {})]; time.sleep(5)".format(iterations)],
                               cwd="/tmp",
                               stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL)
        process.start()
        process.join()
        self.assertEqual(0, process.return_code)
        self.assertIsNone(process.stderr_list)
        self.assertIsNotNone(process.stdout_list)
        self.assertEqual(iterations, len(process.stdout_list))
        for i in range(0, iterations):
            self.assertEqual(str(i), process.stdout_list[i])

    def test_stderr_queue_only(self):
        """
        This unittest checks whether PopenCommand correctly reads the entire subprocess.PIPE data for stderr only.
        """
        iterations = 5
        process = PopenCommand(os_command=["python3",
                                           "-c",
                                           "import sys; import time; [str(time.sleep(1)) + str(print(item, file=sys.stderr)) + str(time.sleep(1)) for item in range(0, {})]; time.sleep(5)".format(iterations)],
                               cwd="/tmp",
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.PIPE)
        process.start()
        process.join()
        self.assertEqual(0, process.return_code)
        self.assertIsNone(process.stdout_list)
        self.assertIsNotNone(process.stderr_list)
        self.assertEqual(iterations, len(process.stderr_list))
        for i in range(0, iterations):
            self.assertEqual(str(i), process.stderr_list[i])

    def test_stdout_and_stderr_queue(self):
        """
        This unittest checks whether PopenCommand correctly reads the entire subprocess.PIPE data for stdout and stderr.
        """
        iterations = 5
        process = PopenCommand(os_command=["python3",
                                           "-c",
                                           "import sys; import time; [str(time.sleep(1)) + str(print(item, file=sys.stdout)) + str(print(item, file=sys.stderr)) + str(time.sleep(1)) for item in range(0, {})]; time.sleep(5)".format(iterations)],
                               cwd="/tmp",
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        process.start()
        process.join()
        self.assertEqual(0, process.return_code)
        self.assertIsNotNone(process.stdout_list)
        self.assertIsNotNone(process.stderr_list)
        self.assertEqual(iterations, len(process.stdout_list))
        self.assertEqual(iterations, len(process.stderr_list))
        for i in range(0, iterations):
            self.assertEqual(str(i), process.stdout_list[i])
            self.assertEqual(str(i), process.stderr_list[i])


class TestDatabaseVerificationMethods(BaseKisTestCase):
    """
    This class implements checks for testing the methods, which check validation methods
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def test_valid_domains(self):
        """
        Unittests for DomainUtils.is_valid_domain
        :return:
        """
        self.assertTrue(self._domain_utils.is_valid_domain("test.com"))
        self.assertTrue(self._domain_utils.is_valid_domain("www.test.com"))
        self.assertTrue(self._domain_utils.is_valid_domain("test.local"))
        self.assertTrue(self._domain_utils.is_valid_domain("test-1.local"))
        self.assertFalse(self._domain_utils.is_valid_domain(" test-1.local"))
        self.assertFalse(self._domain_utils.is_valid_domain("test-1.local "))
        self.assertFalse(self._domain_utils.is_valid_domain(" test-1.local "))
        self.assertFalse(self._domain_utils.is_valid_domain("127.0.0.1"))
        self.assertFalse(self._domain_utils.is_valid_domain("192.168.1.1"))
        self.assertFalse(self._domain_utils.is_valid_domain("0.1"))
        self.assertFalse(self._domain_utils.is_valid_domain("test"))

    def test_extract_domains(self):
        """
        Unittests for DomainUtils.extract_domains
        """
        self.assertListEqual([],
                             self._domain_utils.extract_domains("Did not follow redirect to https://test"))
        self.assertListEqual(["test.local"],
                             self._domain_utils.extract_domains("Did not follow redirect to https://test.local/"))
        self.assertListEqual(["test.local"],
                             self._domain_utils.extract_domains("Did not follow redirect to https://test.local"))
        self.assertListEqual(["test.local"],
                             self._domain_utils.extract_domains("Did not follow redirect to https://test.local:8080/"))
        self.assertListEqual(["test.local"],
                             self._domain_utils.extract_domains("Did not follow redirect to https://test.local:8080"))
        self.assertListEqual(["www.test.local"],
                             self._domain_utils.extract_domains("Did not follow redirect to https://www.test.local/"))
        self.assertListEqual(["www.test.local"],
                             self._domain_utils.extract_domains("Did not follow redirect to https://www.test.local"))
        self.assertListEqual(["www.test.local"],
                             self._domain_utils.extract_domains("Did not follow redirect to https://www.test.local:8080/"))
        self.assertListEqual(["www.test.local"],
                             self._domain_utils.extract_domains("Did not follow redirect to https://www.test.local:8080"))

    def test_match_tld(self):
        """
        Unittest for BaseUtils.match_tld
        :return:
        """
        self.assertEqual("local", self._domain_utils.matches_tld("www.test.local"))
        self.assertEqual("local", self._domain_utils.matches_tld("www.test.local."))
        self.assertEqual("com", self._domain_utils.matches_tld("www.test.com"))
        self.assertEqual("com", self._domain_utils.matches_tld("www.test.com."))
        self.assertEqual("公司.hk", self._domain_utils.matches_tld("www.test.公司.hk"))
        self.assertEqual("公司.hk", self._domain_utils.matches_tld("www.test.公司.hk"))
        self.assertEqual("konyvelo.hu", self._domain_utils.matches_tld("www.test.konyvelo.hu"))
        self.assertEqual("konyvelo.hu", self._domain_utils.matches_tld("www.test.konyvelo.hu"))
        self.assertIsNone(self._domain_utils.matches_tld("www.test.konyvelo.thisisnotatld"))

    def test_split_host_name(self):
        """
        Unittest for BaseUtils.split_host_name
        :return:
        """
        self.assertIsNone(self._domain_utils.split_host_name("."))
        self.assertIsNone(self._domain_utils.split_host_name("...."))
        self.assertIsNone(self._domain_utils.split_host_name("www.test.konyvelo.thisisnotatld"))
        self.assertListEqual(["test"], self._domain_utils.split_host_name("test"))
        self.assertListEqual(["www", "test", "local"], self._domain_utils.split_host_name("www.test.local"))
        self.assertListEqual(["www", "test", "local"], self._domain_utils.split_host_name("www.test.local."))
        self.assertListEqual(["test", "local"], self._domain_utils.split_host_name("test.local"))
        self.assertListEqual(["test", "com"], self._domain_utils.split_host_name("test.com"))
        self.assertListEqual(["ns-1697", "awsdns-20", "uk"], self._domain_utils.split_host_name("ns-1697.awsdns-20.uk."))
        self.assertListEqual(["www", "test", "local"], self._domain_utils.split_host_name("*.www.test.local"))
        self.assertListEqual(["www", "test", "konyvelo.hu"], self._domain_utils.split_host_name("www.test.konyvelo.hu"))
        self.assertListEqual(["www", "test", "公司.hk"], self._domain_utils.split_host_name("www.test.公司.hk"))

    def test_valid_email(self):
        """
        Unittests for DomainUtils.is_valid_email
        :return:
        """
        self.assertTrue(self._domain_utils.is_valid_email("admin@test.com"))
        self.assertTrue(self._domain_utils.is_valid_email("admin@www.test.com"))
        self.assertTrue(self._domain_utils.is_valid_email("admin@test.local"))
        self.assertFalse(self._domain_utils.is_valid_email("admin@127.0.0.1"))
        self.assertFalse(self._domain_utils.is_valid_email("127.0.0.1"))
        self.assertFalse(self._domain_utils.is_valid_email("admin@0.1"))
        self.assertFalse(self._domain_utils.is_valid_email("admin@test"))
        self.assertFalse(self._domain_utils.is_valid_email("admin@test.com "))
        self.assertFalse(self._domain_utils.is_valid_email(" admin@test.com"))
        self.assertFalse(self._domain_utils.is_valid_email(" admin@test.com "))

    def test_valid_address(self):
        """
        Unittests for Ipv4Utils.is_valid_address
        :return:
        """
        self.assertTrue(self._ip_utils.is_valid_address("192.168.0.1"))
        self.assertTrue(self._ip_utils.is_valid_address("255.255.255.0"))
        self.assertTrue(self._ip_utils.is_valid_address("255.255.255.255"))
        self.assertTrue(self._ip_utils.is_valid_address("0.0.0.0"))
        self.assertFalse(self._ip_utils.is_valid_address("192.168.0.1/24"))
        self.assertFalse(self._ip_utils.is_valid_address("192.168.0.1.1"))
        self.assertFalse(self._ip_utils.is_valid_address("256.255.255.255"))
        self.assertFalse(self._ip_utils.is_valid_address("255.256.255.255"))
        self.assertFalse(self._ip_utils.is_valid_address("255.255.256.255"))
        self.assertFalse(self._ip_utils.is_valid_address("255.255.255.256"))
        self.assertFalse(self._ip_utils.is_valid_address(" 255.255.255.255"))
        self.assertFalse(self._ip_utils.is_valid_address("255.255.255.255 "))
        self.assertFalse(self._ip_utils.is_valid_address(" 255.255.255.255 "))
        self.assertFalse(self._ip_utils.is_valid_address("a.a.a.a"))
        self.assertFalse(self._ip_utils.is_valid_address("-1.-1.-1.-1"))

    def test_valid_ipv4_cidr_range(self):
        """
        Unittests for Ipv4Utils.is_valid_ipv4_cidr_range
        :return:
        """
        self.assertTrue(self._ip_utils.is_valid_cidr_range("192.168.0.0/24"))
        self.assertTrue(self._ip_utils.is_valid_cidr_range("192.168.0.0/32"))
        self.assertTrue(self._ip_utils.is_valid_cidr_range("0.0.0.0/0"))
        self.assertFalse(self._ip_utils.is_valid_cidr_range("192.168.0.0/33"))

    def test_verified_company_name(self):
        """
        Unittests for BaseUtils.is_verified_company_name
        :return:
        """
        self.assertEqual("test ag", self._domain_utils.is_verified_company_name("test ag"))
        self.assertEqual("Test AG", self._domain_utils.is_verified_company_name("Test AG"))
        self.assertEqual("Test AG", self._domain_utils.is_verified_company_name("Test AG    "))
        self.assertEqual("Test AG", self._domain_utils.is_verified_company_name("   Test AG"))
        self.assertEqual("Test AG", self._domain_utils.is_verified_company_name("   Test AG    "))
        self.assertEqual("Test GmbH", self._domain_utils.is_verified_company_name("Test GmbH"))
        self.assertEqual("test gmbH", self._domain_utils.is_verified_company_name("test gmbH"))
        self.assertEqual("Test LP", self._domain_utils.is_verified_company_name("Test LP"))
        self.assertEqual("Test LP.", self._domain_utils.is_verified_company_name("Test LP."))
        self.assertEqual("Test LP.", self._domain_utils.is_verified_company_name("Test LP.."))
        self.assertEqual("Test Corporation", self._domain_utils.is_verified_company_name("Test Corporation"))
        self.assertEqual("Test Corporation", self._domain_utils.is_verified_company_name("Test Corporation (random)"))


class TestAddHost(BaseKisTestCase):
    """
    This test case tests Ipv4Utils.add_host
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def _test_add_host(self,
                       session: Session,
                       address: str,
                       valid: bool,
                       source: Source = None,
                       report_item: ReportItem = None):
        """
        This is a helper method for testing IpUtils.add_host
        :return:
        """
        report_item = self._reset_report_item(report_item)
        for item in self._workspaces:
            workspace = self._engine.get_or_create(session, Workspace, name=item)
            result = self._ip_utils.add_host(session=session,
                                             workspace=workspace,
                                             address=address,
                                             source=source,
                                             report_item=report_item)
            if valid:
                self.assertIsNotNone(result)
                self.assertEqual(item, result.workspace.name)
                self.assertEqual(workspace.id, result.workspace_id)
                self.assertEqual(address, result.address)
                results = session.query(Host) \
                    .join(Workspace).filter(Host.address == address,
                                            Workspace.name == item).count()
                self.assertEqual(1, results)
                # check source correctly set
                if source:
                    results = session.query(Source) \
                        .join((Host.sources, Source)) \
                        .join(Workspace) \
                        .filter(Host.address == address,
                                Workspace.name == item).count()
                    self.assertEqual(1, results)
                if report_item:
                    self.assertIn("potentially new host: {}".format(address),
                                  report_item.get_report())
            else:
                self.assertIsNone(result)
        # we should have the same address in different workspaces
        if valid:
            results = session.query(Host).filter_by(address=address).count()
            self.assertEqual(len(self._workspaces), results)
        else:
            results = session.query(Host).count()
            self.assertEqual(0, results)

    def _unittest_add_host(self,
                           address: str,
                           valid: bool):
        """
        This is a helper method for testing IpUtils.add_host
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            source = self.create_source(session)
            # without source and report item
            self._test_add_host(session=session,
                                address=address,
                                valid=valid)
            # with source
            self._test_add_host(session=session,
                                address=address,
                                valid=valid,
                                source=source)
            # with report item
            self._test_add_host(session=session,
                                address=address,
                                valid=valid,
                                report_item=self._report_item)
            # with source and report item
            self._test_add_host(session=session,
                                address=address,
                                valid=valid,
                                source=source,
                                report_item=self._report_item)

    def test_valid_address(self):
        """
        Unittests for valid IPv4/IPv6 addresses
        :return:
        """
        valid = True
        self._unittest_add_host(address="192.168.0.1", valid=valid)
        self._unittest_add_host(address="10.10.10.10", valid=valid)
        self._unittest_add_host(address="0.0.0.0", valid=valid)
        self._unittest_add_host(address="255.255.255.255", valid=valid)
        self._unittest_add_host(address="fe80::a00:27ff:fe05:eadc", valid=valid)
        self._unittest_add_host(address="::1", valid=valid)
        self._unittest_add_host(address="::", valid=valid)

    def test_invalid_ip_address(self):
        """
        Unittests for invalid IPv4/IPv6 addresses
        :return:
        """
        valid = False
        self._unittest_add_host(address="256.0.0.0", valid=valid)
        self._unittest_add_host(address="0.256.0.0", valid=valid)
        self._unittest_add_host(address="0.0.256.0", valid=valid)
        self._unittest_add_host(address="0.0.0.256", valid=valid)
        self._unittest_add_host(address="a.b.c.d", valid=valid)
        self._unittest_add_host(address="10.10.10.10.1/24", valid=valid)
        self._unittest_add_host(address="-1.-1.-1.-1", valid=valid)
        self._unittest_add_host(address="::1/24", valid=valid)


class TestAddNetwork(BaseKisTestCase):
    """
    This test case tests Ipv4Utils.add_network
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def _test_add_network(self,
                          session: Session,
                          network: str,
                          valid: bool,
                          source: Source = None,
                          report_item: ReportItem = None):
        """
        This is a helper method for testing IpUtils.add_network
        :return:
        """
        i = 0
        report_item = self._reset_report_item(report_item)
        for item in self._workspaces:
            scope = ScopeType.all if ((i % 2) == 0) else ScopeType.exclude
            workspace = self._engine.get_or_create(session, Workspace, name=item)
            result = self._ip_utils.add_network(session=session,
                                                workspace=workspace,
                                                network=network,
                                                scope=scope,
                                                source=source,
                                                report_item=report_item)
            if valid:
                self.assertIsNotNone(result)
                self.assertEqual(item, result.workspace.name)
                self.assertEqual(network, result.network)
                self.assertEqual(scope, result.scope)
                self.assertEqual(workspace.id, result.workspace_id)
                results = session.query(Network) \
                     .join(Workspace).filter(Network.network == network,
                                             Workspace.name == item).count()
                self.assertEqual(1, results)
                # check source correctly set
                if source:
                    results = session.query(Source) \
                        .join((Network, Source.ipv4_networks)) \
                        .join(Workspace) \
                        .filter(Network.network == network,
                                Workspace.name == item).count()
                    self.assertEqual(1, results)
                if report_item:
                    self.assertIn("potentially new IP network: {}".format(network),
                                  report_item.get_report())
            else:
                self.assertIsNone(result)
        # we should have the same address in different workspaces
        if valid:
            results = session.query(Network).filter_by(network=network).count()
            self.assertEqual(len(self._workspaces), results)
        else:
            results = session.query(Network).count()
            self.assertEqual(0, results)

    def _unittest_add_network(self,
                              ip_network: str,
                              valid: bool):
        """
        This is a helper method for testing IpUtils.add_network
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            source = self.create_source(session)
            # without source and report item
            self._test_add_network(session=session,
                                   network=ip_network,
                                   valid=valid)
            # with source
            self._test_add_network(session=session,
                                   network=ip_network,
                                   valid=valid,
                                   source=source)
            # with report item
            self._test_add_network(session=session,
                                   network=ip_network,
                                   valid=valid,
                                   report_item=self._report_item)
            # with source and report item
            self._test_add_network(session=session,
                                   network=ip_network,
                                   valid=valid,
                                   source=source,
                                   report_item=self._report_item)

    def test_valid_network(self):
        """
        Unittests for IpUtils.add_network
        :return:
        """
        self.init_db()
        valid = True
        self._unittest_add_network(ip_network="192.168.0.0/24", valid=valid)
        self._unittest_add_network(ip_network="0.0.0.0/0", valid=valid)
        self._unittest_add_network(ip_network="10.0.0.0/16", valid=valid)
        self._unittest_add_network(ip_network="2a00:1450:4000::/37", valid=valid)
        self._unittest_add_network(ip_network="fe80::a00:27ff:fe05:eadc", valid=valid)

    def test_invalid_network(self):
        """
        Unittests for Ipv4Utils.add_network
        :return:
        """
        self.init_db()
        valid = False
        self._unittest_add_network(ip_network="192.168.0.0/33", valid=valid)
        self._unittest_add_network(ip_network="192.168.0.0/-1", valid=valid)
        self._unittest_add_network(ip_network="256.0.0.0/0", valid=valid)
        self._unittest_add_network(ip_network="0.256.0.0/0", valid=valid)
        self._unittest_add_network(ip_network="0.0.256.0/0", valid=valid)
        self._unittest_add_network(ip_network="0.0.0.256/0", valid=valid)
        self._unittest_add_network(ip_network=" 0.0.0.0/0", valid=valid)
        self._unittest_add_network(ip_network="0.0.0.0/0 ", valid=valid)
        self._unittest_add_network(ip_network=" 0.0.0.0/0 ", valid=valid)
        self._unittest_add_network(ip_network="a.b.c.d/16", valid=valid)
        self._unittest_add_network(ip_network="192.168.0.1/24", valid=valid)
        self._unittest_add_network(ip_network="::1/24", valid=valid)

    def _initial_setup_scope_tests(self,
                                   workspace1: str = "workspace1",
                                   workspace2: str = "workspace2",
                                   ipv4_address1a: str = "192.168.1.1",
                                   ipv4_address1b: str = "192.168.1.254",
                                   ipv4_network1: str = "192.168.1.0/24",
                                   ipv4_network1_scope: ScopeType = ScopeType.all,
                                   ipv4_address2a: str = "192.168.2.1",
                                   ipv4_address2b: str = "192.168.2.254",
                                   ipv4_network2: str = "192.168.2.0/24",
                                   ipv4_network2_scope: ScopeType = ScopeType.exclude,
                                   check: bool = False):
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_host(session=session, workspace_str=workspace1, address=ipv4_address1a)
            self.create_host(session=session, workspace_str=workspace1, address=ipv4_address1b)
            self.create_host(session=session, workspace_str=workspace1, address=ipv4_address2a)
            self.create_host(session=session, workspace_str=workspace1, address=ipv4_address2b)
            self.create_host(session=session, workspace_str=workspace2, address=ipv4_address1a)
            self.create_host(session=session, workspace_str=workspace2, address=ipv4_address1b)
            self.create_host(session=session, workspace_str=workspace2, address=ipv4_address2a)
            self.create_host(session=session, workspace_str=workspace2, address=ipv4_address2b)
            self.create_network(session=session,
                                workspace_str=workspace1,
                                network=ipv4_network1,
                                scope=ipv4_network1_scope)
            self.create_network(session=session,
                                workspace_str=workspace1,
                                network=ipv4_network2,
                                scope=ipv4_network2_scope)
            self.create_network(session=session,
                                workspace_str=workspace2,
                                network=ipv4_network1,
                                scope=ipv4_network1_scope)
            self.create_network(session=session,
                                workspace_str=workspace2,
                                network=ipv4_network2,
                                scope=ipv4_network2_scope)
        # Check database
        if check:
            self._initial_setup_scope_tests_check(workspace1=workspace1,
                                                  workspace2=workspace2,
                                                  ipv4_address1a=ipv4_address1a,
                                                  ipv4_address1b=ipv4_address1b,
                                                  ipv4_network1=ipv4_network1,
                                                  ipv4_network1_scope=ipv4_network1_scope,
                                                  ipv4_address2a=ipv4_address2a,
                                                  ipv4_address2b=ipv4_address2b,
                                                  ipv4_network2=ipv4_network2,
                                                  ipv4_network2_scope=ipv4_network2_scope)

    def _initial_setup_scope_tests_check(self,
                                         workspace1: str = "workspace1",
                                         workspace2: str = "workspace2",
                                         ipv4_address1a: str = "192.168.1.1",
                                         ipv4_address1b: str = "192.168.1.254",
                                         ipv4_network1: str = "192.168.1.0/24",
                                         ipv4_network1_scope: ScopeType = ScopeType.all,
                                         ipv4_address2a: str = "192.168.2.1",
                                         ipv4_address2b: str = "192.168.2.254",
                                         ipv4_network2: str = "192.168.2.0/24",
                                         ipv4_network2_scope: ScopeType = ScopeType.exclude):
        with self._engine.session_scope() as session:
            result = session.query(Host) \
                .join(Network) \
                .join(Workspace) \
                .filter(Host.address == ipv4_address1a,
                        Network.scope == ipv4_network1_scope,
                        Workspace.name == workspace1).count()
            self.assertEqual(1, result)
            result = session.query(Host) \
                .join(Network) \
                .join(Workspace) \
                .filter(Host.address == ipv4_address2a,
                        Network.scope == ipv4_network2_scope,
                        Workspace.name == workspace1).count()
            self.assertEqual(1, result)

    def test_basic_insert_network_trigger(self):
        self._initial_setup_scope_tests(check=True)

    def test_insert_larger_inscope_network(self):
        self._initial_setup_scope_tests(check=False,
                                        workspace1=self._workspaces[0],
                                        workspace2=self._workspaces[1])
        network = "0.0.0.0/0"
        # insert new network
        with self._engine.session_scope() as session:
            self.create_network(session=session,
                                workspace_str=self._workspaces[0],
                                network=network,
                                scope=ScopeType.all)
        # check database
        with self._engine.session_scope() as session:
            result = session.query(Network) \
                .join(Workspace) \
                .filter(Workspace.name == self._workspaces[0],
                        Network.scope == ScopeType.all).all()
            self.assertEqual(3, len(result))
            for item in result:
                self.assertEqual(0 if item.network == "0.0.0.0/0" else 2, len(item.hosts))

    def test_trigger_insert_small_network_after(self):
        self.init_db()
        network = "0.0.0.0/0"
        # insert new network
        with self._engine.session_scope() as session:
            self.create_network(session=session,
                                workspace_str=self._workspaces[0],
                                network=network,
                                scope=ScopeType.all)
        network = "192.168.1.0/24"
        # insert new network
        with self._engine.session_scope() as session:
            self.create_network(session=session,
                                workspace_str=self._workspaces[0],
                                network=network,
                                scope=ScopeType.all)
        # check database
        with self._engine.session_scope() as session:
            session.query(Network).filter_by(network="0.0.0.0/0", scope=ScopeType.all).one()
            session.query(Network).filter_by(network="192.168.1.0/24", scope=ScopeType.all).one()

    def test_trigger_insert_large_network_after(self):
        self.init_db()
        ipv4_network = "192.168.1.0/24"
        # insert new network
        with self._engine.session_scope() as session:
            self.create_network(session=session,
                                workspace_str=self._workspaces[0],
                                network=ipv4_network,
                                scope=ScopeType.all)
        ipv4_network = "0.0.0.0/0"
        # insert new network
        with self._engine.session_scope() as session:
            self.create_network(session=session,
                                workspace_str=self._workspaces[0],
                                network=ipv4_network,
                                scope=ScopeType.all)
        # check database
        with self._engine.session_scope() as session:
            session.query(Network).filter_by(network="0.0.0.0/0", scope=ScopeType.all).one()
            session.query(Network).filter_by(network="192.168.1.0/24", scope=ScopeType.all).one()

    def test_delete_network(self):
        self._initial_setup_scope_tests(check=False,
                                        workspace1=self._workspaces[0],
                                        workspace2=self._workspaces[1])
        ipv4_network = "0.0.0.0/0"
        # insert new network
        with self._engine.session_scope() as session:
            self.create_network(session=session,
                                workspace_str=self._workspaces[0],
                                network=ipv4_network,
                                scope=ScopeType.all)
        # delete new network
        with self._engine.session_scope() as session:
            result = session.query(Network)\
                .join(Workspace)\
                .filter(Network.network == ipv4_network,
                        Workspace.name == self._workspaces[0]).one()
            session.delete(result)
        # check database
        self._initial_setup_scope_tests_check(workspace1=self._workspaces[0],
                                              workspace2=self._workspaces[1],
                                              ipv4_network2_scope=ScopeType.all)


class TestAddCompany(BaseKisTestCase):
    """
    This test case tests BaseUtils.add_company
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def _test_add_company(self,
                          session: Session,
                          company_name: str,
                          valid: bool,
                          ipv4_network: str = None,
                          domain_name: str = None,
                          verify: bool = False,
                          source: Source = None,
                          report_item: ReportItem = None,
                          ex_message: str = None) -> None:
        """
        This is a helper method for testing BaseUtils.add_company
        :return:
        """
        network = None
        domain = None
        self._reset_report_item(report_item)
        for item in self._workspaces:
            workspace = self.create_workspace(session, item)
            if ipv4_network:
                network = self.create_network(session=session,
                                              workspace_str=item,
                                              network=ipv4_network)
            if domain_name:
                domain = self.create_domain_name(session=session, workspace_str=item, host_name=domain_name)
            try:
                result = self._domain_utils.add_company(session=session,
                                                        workspace=workspace,
                                                        name=company_name,
                                                        network=network,
                                                        domain_name=domain,
                                                        source=source,
                                                        report_item=report_item,
                                                        verify=verify)
            except Exception as ex:
                if ex_message:
                    self.assertEqual(ex_message, str(ex))
                    return
                raise ex
            self.assertIsNone(ex_message)
            if valid:
                self.assertIsNotNone(result)
                self.assertEqual(company_name, result.name)
                if ipv4_network:
                    self.assertEqual(ipv4_network, result.networks[0].network)
                    results = session.query(Company) \
                        .join((Workspace, Company.workspace)) \
                        .join((Network, Company.networks)) \
                        .filter(Company.name == company_name,
                                Network.network == ipv4_network,
                                Workspace.name == item).count()
                    self.assertEqual(1, results)
                    if source:
                        results = session.query(Source) \
                            .join((Company, Source.companies)) \
                            .join((Network, Company.networks)) \
                            .join((Workspace, Company.workspace)) \
                            .filter(Company.name == company_name,
                                    Network.network == ipv4_network,
                                    Workspace.name == item).count()
                        self.assertEqual(1, results)
                    if report_item:
                        self.assertIn("potentially new company for network {}: {}".format(ipv4_network, company_name),
                                      report_item.get_report())
                if domain_name:
                    self.assertEqual(domain_name, result.domain_names[0].name)
                    results = session.query(Company) \
                        .join((Workspace, Company.workspace)) \
                        .join((DomainName, Company.domain_names)) \
                        .filter(Company.name == company_name,
                                DomainName.name == domain_name,
                                Workspace.name == item).count()
                    self.assertEqual(1, results)
                    if source:
                        results = session.query(Source) \
                            .join((Company, Source.companies)) \
                            .join(Workspace) \
                            .join((DomainName, Company.domain_names)) \
                            .filter(Company.name == company_name,
                                DomainName.name == domain_name,
                                Workspace.name == item).count()
                        self.assertEqual(1, results)
                    if report_item:
                        self.assertIn("potentially new company for domain {}: {}".format(domain_name, company_name),
                                      report_item.get_report())
        # we should have the same address in different workspaces
        if valid or not verify:
            self.assertEqual(len(self._workspaces), session.query(Company).filter_by(name=company_name).count())
        else:
            self.assertEqual(0, session.query(Company).count())

    def _unittest_add_company(self,
                              company_name: str,
                              valid: bool,
                              verify: bool,
                              ipv4_network: str = None,
                              domain_name: str = None,
                              ex_message: str = None):
        """
        Unittests for BaseUtils.add_company
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            source = self.create_source(session=session)
            # without report item
            self._test_add_company(session=session,
                                   company_name=company_name,
                                   valid=valid,
                                   ipv4_network=ipv4_network,
                                   domain_name=domain_name,
                                   verify=verify,
                                   ex_message=ex_message)
            # with source
            self._test_add_company(session=session,
                                   company_name=company_name,
                                   valid=valid,
                                   ipv4_network=ipv4_network,
                                   domain_name=domain_name,
                                   verify=verify,
                                   ex_message=ex_message,
                                   source=source)
            # with report item
            self._test_add_company(session=session,
                                   company_name=company_name,
                                   valid=valid,
                                   ipv4_network=ipv4_network,
                                   domain_name=domain_name,
                                   verify=verify,
                                   ex_message=ex_message,
                                   report_item=self._report_item)
            # with source and report item
            self._test_add_company(session=session,
                                   company_name=company_name,
                                   valid=valid,
                                   ipv4_network=ipv4_network,
                                   domain_name=domain_name,
                                   verify=verify,
                                   ex_message=ex_message,
                                   source=source,
                                   report_item=self._report_item)

    def test_add_invalid_company_verify_true(self):
        """
        Unittests for BaseUtils.add_company
        :return:
        """
        verify = True
        valid = False
        company_name = "test"
        self._unittest_add_company(company_name, valid=valid, verify=verify, ipv4_network="192.168.0.0/24")
        self._unittest_add_company(company_name, valid=valid, verify=verify, domain_name="test.com")

    def test_add_invalid_company_verify_false(self):
        """
        Unittests for BaseUtils.add_company
        :return:
        """
        verify = False
        valid = False
        self._unittest_add_company("test", valid=valid, verify=verify, ipv4_network="192.168.0.0/24")
        self._unittest_add_company("test", valid=valid, verify=verify, domain_name="test.com")

    def test_add_valid_company_verify_true(self):
        """
        Unittests for BaseUtils.add_company
        :return:
        """
        verify = True
        valid = True
        self._unittest_add_company("test gmbh", valid=valid, verify=verify, ipv4_network="192.168.0.0/24")
        self._unittest_add_company("test ag", valid=valid, verify=verify, domain_name="test.com")

    def test_add_valid_company_verify_false(self):
        """
        Unittests for BaseUtils.add_company
        :return:
        """
        verify = False
        valid = True
        self._unittest_add_company("test gmbh", valid=valid, verify=verify, ipv4_network="192.168.0.0/24")
        self._unittest_add_company("test ag", valid=valid, verify=verify, domain_name="www.test.com")


class TestAddCredential(BaseKisTestCase):
    """
    This test case tests BaseUtils.add_credential
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def _test_add_credential(self,
                             session: Session,
                             user_name: str,
                             password: str,
                             credential_type: CredentialType,
                             domain: str = None,
                             source: Source = None,
                             service_port: int = None,
                             email_address: str = None,
                             report_item: ReportItem = None,
                             ex_message: str = None) -> None:
        """
        This is a helper method for testing BaseUtils.add_credential
        :return:
        """
        service = None
        email = None
        self._reset_report_item(report_item)
        for item in self._workspaces:
            if service_port:
                service = self.create_service(session=session,
                                              workspace_str=item,
                                              port=service_port)
            if email_address:
                email = self.create_email(session=session,
                                          workspace_str=item,
                                          email_address=email_address)
            try:
                result = self._domain_utils.add_credential(session=session,
                                                           username=user_name,
                                                           password=password,
                                                           credential_type=credential_type,
                                                           domain=domain,
                                                           service=service,
                                                           email=email,
                                                           source=source,
                                                           report_item=report_item)
                self.assertIsNotNone(result)
            except Exception as ex:
                if ex_message:
                    self.assertEqual(ex_message, str(ex))
                    return
                raise ex
            self.assertIsNone(ex_message)
            self.assertEqual(user_name, result.username)
            self.assertEqual(password, result.password)
            self.assertEqual(credential_type, result.type)
            self.assertEqual(domain, result.domain)
            self.assertEqual(password is not None, result.complete)
            if service_port:
                self.assertIsNotNone(result.service)
                self.assertIsNone(result.email)
                self.assertEqual(service.id, result.service_id)
                self.assertEqual(service_port, result.service.port)
                results = session.query(Credentials) \
                    .join(Service) \
                    .join(Host) \
                    .join(Workspace) \
                    .filter(Credentials.username == user_name,
                            Credentials.type == credential_type,
                            Credentials.domain == domain,
                            Credentials.password == password,
                            Service.port == service_port,
                            Workspace.name == item).count()
                self.assertEqual(1, results)
                if source:
                    results = session.query(Source) \
                        .join((Credentials, Source.credentials)) \
                        .join(Service) \
                        .join(Host) \
                        .join(Workspace) \
                        .filter(Credentials.username == user_name,
                                Credentials.type == credential_type,
                                Credentials.domain == domain,
                                Credentials.password == password,
                                Service.port == service_port,
                                Workspace.name == item).count()
                    self.assertEqual(1, results)
                if report_item:
                    if user_name and password:
                        self.assertIn("potentially new user {} with password {}".format(user_name, password),
                                      report_item.get_report())
                    elif user_name and not password:
                        self.assertIn("potentially new user {}".format(user_name), report_item.get_report())
                    elif not user_name and password:
                        self.assertIn("potentially new password {}".format(password), report_item.get_report())
            if email:
                name_part, host_part, domain_part = self.split_email(email_address)
                self.assertIsNotNone(result.email)
                self.assertIsNone(result.service)
                self.assertEqual(email.id, result.email_id)
                self.assertEqual(email_address, result.email.email_address)
                results = session.query(Credentials) \
                    .join(Email) \
                    .join(HostName) \
                    .join(DomainName) \
                    .join(Workspace) \
                    .filter(Credentials.username == user_name,
                            Credentials.type == credential_type,
                            Credentials.domain == domain,
                            Credentials.password == password,
                            Email.address == name_part,
                            HostName.name == host_part,
                            DomainName.name == domain_part,
                            Workspace.name == item).count()
                self.assertEqual(1, results)
                if source:
                    results = session.query(Source) \
                        .join((Credentials, Source.credentials)) \
                        .join(Email) \
                        .join(HostName) \
                        .join(DomainName) \
                        .join(Workspace) \
                        .filter(Credentials.username == user_name,
                                Credentials.type == credential_type,
                                Credentials.domain == domain,
                                Credentials.password == password,
                                Email.address == name_part,
                                HostName.name == host_part,
                                DomainName.name == domain_part,
                                Workspace.name == item).count()
                    self.assertEqual(1, results)
                if report_item:
                    self.assertIn("potentially new user {} with password {}".format(email_address,
                                                                                    password if password else ""),
                                  report_item.get_report())
        # we should have the same company name in different workspaces
        results = session.query(Credentials) \
            .filter_by(username=user_name,
                       type=credential_type,
                       domain=domain,
                       password=password).count()
        self.assertEqual(len(self._workspaces), results)

    def _unittest_add_credential(self,
                                 user_name: str = None,
                                 password: str = None,
                                 credential_type: CredentialType = None,
                                 domain: str = None,
                                 service_port: int = None,
                                 email_address: str = None,
                                 ex_message: str = None) -> None:
        """
        Unittests for BaseUtils.add_credential
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            source = self.create_source(session)
            # without source and report item
            self._test_add_credential(session=session,
                                      user_name=user_name,
                                      password=password,
                                      credential_type=credential_type,
                                      domain=domain,
                                      service_port=service_port,
                                      email_address=email_address,
                                      ex_message=ex_message)
            # with source
            self._test_add_credential(session=session,
                                      user_name=user_name,
                                      password=password,
                                      credential_type=credential_type,
                                      domain=domain,
                                      service_port=service_port,
                                      email_address=email_address,
                                      ex_message=ex_message,
                                      source=source)
            # with report item
            self._test_add_credential(session=session,
                                      user_name=user_name,
                                      password=password,
                                      credential_type=credential_type,
                                      domain=domain,
                                      service_port=service_port,
                                      email_address=email_address,
                                      ex_message=ex_message,
                                      report_item=self._report_item)
            # with source and report item
            self._test_add_credential(session=session,
                                      user_name=user_name,
                                      password=password,
                                      credential_type=credential_type,
                                      domain=domain,
                                      service_port=service_port,
                                      email_address=email_address,
                                      ex_message=ex_message,
                                      source=source,
                                      report_item=self._report_item)

    def test_service_and_email_exception(self):
        """
        Unittests for BaseUtils.add_credential
        :return:
        """
        self._unittest_add_credential(user_name="username",
                                      password="password",
                                      credential_type=CredentialType.cleartext,
                                      service_port=None,
                                      email_address=None,
                                      ex_message='credential must be assigned to an email address or service')
        self._unittest_add_credential(user_name=None,
                                      password="password",
                                      credential_type=CredentialType.cleartext,
                                      service_port=80,
                                      email_address="test@test.com",
                                      ex_message='credential must either be assigned to an email address or a service')
        self._unittest_add_credential(user_name="username",
                                      password="password",
                                      credential_type=CredentialType.cleartext,
                                      service_port=80,
                                      email_address="test@test.com",
                                      ex_message='user name must not be specified together with an email address')
        self._unittest_add_credential(user_name="username",
                                      password="password",
                                      service_port=80,
                                      ex_message="password type is missing for password")

    def test_incomplete_credential(self):
        """
        Unittests for BaseUtils.add_company
        :return:
        """
        self._unittest_add_credential(user_name="username", service_port=80)
        self._unittest_add_credential(email_address="test@test.com")

    def test_password_only(self):
        """
        Unittests for BaseUtils.add_credential
        :return:
        """
        self._unittest_add_credential(password="password", credential_type=CredentialType.cleartext, service_port=80)

    def test_username_and_password(self):
        """
        Unittests for BaseUtils.add_credential
        :return:
        """
        self._unittest_add_credential(user_name="username",
                                      password="password",
                                      credential_type=CredentialType.cleartext,
                                      service_port=80)

    def test_username_domain_and_password(self):
        """
        Unittests for BaseUtils.add_credential
        :return:
        """
        self._unittest_add_credential(user_name="username",
                                      domain="domain",
                                      password="password",
                                      credential_type=CredentialType.cleartext,
                                      service_port=80)


class TestAddServiceMethod(BaseKisTestCase):
    """
    This test case tests BaseUtils.add_service_method
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def _test_add_service_method(self,
                                 session: Session,
                                 method: str,
                                 service_port: int = None,
                                 source: Source = None,
                                 report_item: ReportItem = None) -> None:
        """
        This is a helper method for testing BaseUtils.add_service_method
        :return:
        """
        self._reset_report_item(report_item)
        for item in self._workspaces:
            service = self.create_service(session=session,
                                          workspace_str=item,
                                          port=service_port)
            result = self._domain_utils.add_service_method(session=session,
                                                           name=method,
                                                           service=service,
                                                           source=source,
                                                           report_item=report_item)
            self.assertIsNotNone(result)
            self.assertIsNotNone(result.service)
            self.assertEqual(service.id, result.service_id)
            self.assertEqual(service_port, result.service.port)
            self.assertEqual(method, result.name)
            results = session.query(ServiceMethod) \
                .join(Service) \
                .join(Host) \
                .join(Workspace).filter(ServiceMethod.name == method,
                                        ServiceMethod.service_id == service.id,
                                        Workspace.name == item).all()
            self.assertEqual(1, len(results))
            if source:
                results = session.query(Source) \
                    .join((ServiceMethod, Source.service_methods)) \
                    .join(Service) \
                    .join(Host) \
                    .join(Workspace) \
                    .filter(ServiceMethod.name == method,
                            ServiceMethod.service_id == service.id,
                            Service.port == service_port,
                            Workspace.name == item).count()
                self.assertEqual(1, results)
            if report_item:
                    self.assertIn("add potentially dangerous service method {}".format(method),
                                  report_item.get_report())
        # we should have the same company name in different workspaces
        results = session.query(ServiceMethod).filter(ServiceMethod.name == method).count()
        self.assertEqual(len(self._workspaces), results)

    def _unittest_add_service_method(self, method: str = None, service_port: int = None) -> None:
        """
        Unittests for BaseUtils.add_service_method
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            source = self.create_source(session)
            # without source and report item
            self._test_add_service_method(session=session,
                                          method=method,
                                          service_port=service_port)
            # with source
            self._test_add_service_method(session=session,
                                          method=method,
                                          service_port=service_port,
                                          source=source)
            # with report item
            self._test_add_service_method(session=session,
                                          method=method,
                                          service_port=service_port,
                                          report_item=self._report_item)
            # with source and report item
            self._test_add_service_method(session=session,
                                          method=method,
                                          service_port=service_port,
                                          source=source,
                                          report_item=self._report_item)

    def test_add_service_method(self):
        """
        Unittests for BaseUtils.add_service_method
        :return:
        """
        self._unittest_add_service_method(method="PUT", service_port=80)


class TestAddPath(BaseKisTestCase):
    """
    This test case tests BaseUtils.add_path
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def _test_add_path(self,
                       session: Session,
                       path: str,
                       path_type: PathType,
                       size_bytes: int = None,
                       return_code: int = None,
                       service_port: int = None,
                       source: Source = None,
                       report_item: ReportItem = None) -> None:
        """
        This is a helper method for testing BaseUtils.add_path
        :return:
        """
        self._reset_report_item(report_item)
        for item in self._workspaces:
            service = self.create_service(session=session,
                                          workspace_str=item,
                                          port=service_port)
            result = self._domain_utils.add_path(session=session,
                                                 service=service,
                                                 path=path,
                                                 path_type=path_type,
                                                 size_bytes=size_bytes,
                                                 return_code=return_code,
                                                 source=source,
                                                 report_item=report_item)
            self.assertIsNotNone(result)
            self.assertIsNotNone(result.service)
            self.assertEqual(service.id, result.service_id)
            self.assertEqual(service_port, result.service.port)
            self.assertEqual(path, result.name)
            self.assertEqual(path_type, result.type)
            self.assertEqual(size_bytes, result.size_bytes)
            self.assertEqual(return_code, result.return_code)
            results = session.query(Path) \
                .join(Service) \
                .join(Host) \
                .join(Workspace).filter(Path.name == path,
                                        Path.type == path_type,
                                        Path.service_id == service.id,
                                        Workspace.name == item).all()
            self.assertEqual(1, len(results))
            if source:
                results = session.query(Source) \
                    .join((Path, Source.paths)) \
                    .join(Service) \
                    .join(Host) \
                    .join(Workspace) \
                    .filter(Path.name == path,
                            Path.type == path_type,
                            Path.service_id == service.id,
                            Service.port == service_port,
                            Workspace.name == item).count()
                self.assertEqual(1, results)
            if report_item:
                if size_bytes and return_code:
                    self.assertIn("potentially new path/file: {} (status: {}, size: {})".format(path,
                                                                                                return_code,
                                                                                                size_bytes),
                                  report_item.get_report())
                elif not size_bytes and return_code:
                    self.assertIn("potentially new path/file: {} (status: {})".format(path, return_code),
                                  report_item.get_report())
                elif size_bytes and not return_code:
                    self.assertIn("potentially new path/file: {} (size: {})".format(path, size_bytes),
                                  report_item.get_report())
                else:
                    self.assertTrue("potentially new path/file: {}".format(path) in report_item.get_report())
        # we should have the same company name in different workspaces
        results = session.query(Path).filter(Path.name == path,
                                             Path.type == path_type).count()
        self.assertEqual(len(self._workspaces), results)

    def _unittest_add_path(self,
                           path: str = None,
                           path_type: PathType = None,
                           size_bytes: int = None,
                           return_code: int = None,
                           service_port: int = None) -> None:
        """
        Unittests for BaseUtils.add_path
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            source = self.create_source(session)
            # without source and report item
            self._test_add_path(session=session,
                                path=path,
                                path_type=path_type,
                                size_bytes=size_bytes,
                                return_code=return_code,
                                service_port=service_port)
            # with source
            self._test_add_path(session=session,
                                path=path,
                                path_type=path_type,
                                size_bytes=size_bytes,
                                return_code=return_code,
                                service_port=service_port,
                                source=source)
            # with report item
            self._test_add_path(session=session,
                                path=path,
                                path_type=path_type,
                                size_bytes=size_bytes,
                                return_code=return_code,
                                service_port=service_port,
                                report_item=self._report_item)
            # with source and report item
            self._test_add_path(session=session,
                                path=path,
                                path_type=path_type,
                                size_bytes=size_bytes,
                                return_code=return_code,
                                service_port=service_port,
                                source=source,
                                report_item=self._report_item)

    def test_add_path(self):
        """
        Unittests for BaseUtils.add_path
        :return:
        """
        self._unittest_add_path(path="/test/admin",
                                path_type=PathType.http,
                                service_port=80)
        self._unittest_add_path(path="test/admin",
                                path_type=PathType.http,
                                service_port=80,
                                size_bytes=10)
        self._unittest_add_path(path="test/admin",
                                path_type=PathType.http,
                                service_port=80,
                                return_code=200)
        self._unittest_add_path(path="test/admin",
                                path_type=PathType.http,
                                service_port=80,
                                size_bytes=20,
                                return_code=200)


class TestCertInfo(BaseKisTestCase):
    """
    This test case tests BaseUtils.add_cert_info
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def _test_add_cert_info(self,
                            session: Session,
                            service_port: int,
                            host_name_str: str,
                            company_name_str: str,
                            serial_number: int,
                            common_name: str,
                            issuer_name: str,
                            signature_asym_algorithm: AsymmetricAlgorithm,
                            signature_bits: int,
                            hash_algorithm: HashAlgorithm,
                            cert_type: CertType,
                            valid_from: datetime,
                            valid_until: datetime,
                            subject_alt_names: List[str] = [],
                            extension_info: Dict[str, str] = {},
                            source: Source = None,
                            ex_message: str = None) -> None:
        """
        This is a helper method for testing BaseUtils.add_cert_info
        :return:
        """
        serial_number = str(serial_number)
        extension_info = dict(extension_info)
        if subject_alt_names:
            if "subject_alt_name" in extension_info:
                extension_info["subject_alt_name"].extend(subject_alt_names)
            else:
                extension_info["subject_alt_name"] = subject_alt_names
        for item in self._workspaces:
            service = None
            host_name = None
            company = None
            if service_port:
                service = self.create_service(session=session,
                                              workspace_str=item,
                                              port=service_port)
            if host_name_str:
                host_name = self.create_hostname(session=session,
                                                 workspace_str=item,
                                                 host_name=host_name_str)
            if company_name_str:
                company = self.create_company(session=session,
                                              workspace_str=item,
                                              name_str=company_name_str)
                company_name_str = company_name_str.lower()
            try:
                result = self._domain_utils.add_cert_info(session=session,
                                                          service=service,
                                                          host_name=host_name,
                                                          company=company,
                                                          serial_number=serial_number,
                                                          common_name=common_name,
                                                          issuer_name=issuer_name,
                                                          signature_asym_algorithm=signature_asym_algorithm,
                                                          signature_bits=signature_bits,
                                                          hash_algorithm=hash_algorithm,
                                                          cert_type=cert_type,
                                                          valid_until=valid_until,
                                                          valid_from=valid_from,
                                                          subject_alt_names=subject_alt_names,
                                                          extension_info=extension_info,
                                                          source=source)
                self.assertIsNotNone(result)
                session.commit()
            except Exception as ex:
                if ex_message:
                    self.assertEqual(ex_message, str(ex))
                    return
                raise ex
            self.assertIsNone(ex_message)
            if service_port:
                self.assertIsNotNone(result.service)
                self.assertEqual(service.id, result.service_id)
                self.assertEqual(service_port, result.service.port)
                results = session.query(CertInfo) \
                    .join(Service) \
                    .join(Host) \
                    .join(Workspace).filter(CertInfo.serial_number == serial_number,
                                            CertInfo.service_id == service.id,
                                            Workspace.name == item).all()
                self.assertEqual(1, len(results))
                if source:
                    results = session.query(Source) \
                        .join((CertInfo, Source.cert_info)) \
                        .join(Service) \
                        .join(Host) \
                        .join(Workspace) \
                        .filter(CertInfo.serial_number == serial_number,
                                CertInfo.service_id == service.id,
                                Workspace.name == item).count()
                    self.assertEqual(1, results)
            if host_name_str:
                self.assertIsNotNone(result.host_name)
                self.assertEqual(host_name.id, result.host_name_id)
                self.assertEqual(host_name_str, result.host_name.full_name)
                results = session.query(CertInfo) \
                    .join(HostName) \
                    .join(DomainName) \
                    .join(Workspace).filter(CertInfo.serial_number == serial_number,
                                            CertInfo.host_name_id == host_name.id,
                                            Workspace.name == item).all()
                self.assertEqual(1, len(results))
                if source:
                    results = session.query(Source) \
                        .join((CertInfo, Source.cert_info)) \
                        .join(HostName) \
                        .join(DomainName) \
                        .join(Workspace) \
                        .filter(CertInfo.serial_number == serial_number,
                                CertInfo.host_name_id == host_name.id,
                                Workspace.name == item).count()
                    self.assertEqual(1, results)
            if company_name_str:
                self.assertIsNotNone(result.company)
                self.assertEqual(company.id, result.company_id)
                self.assertEqual(company_name_str, result.company.name)
                results = session.query(CertInfo) \
                    .join(Company) \
                    .join(Workspace).filter(CertInfo.serial_number == serial_number,
                                            CertInfo.company_id == company.id,
                                            Workspace.name == item).all()
                self.assertEqual(1, len(results))
                if source:
                    results = session.query(Source) \
                        .join((CertInfo, Source.cert_info)) \
                        .join(Company) \
                        .join(Workspace) \
                        .filter(CertInfo.serial_number == serial_number,
                                CertInfo.company_id == company.id,
                                Workspace.name == item).count()
                    self.assertEqual(1, results)
            self.assertEqual(serial_number, result.serial_number)
            self.assertEqual(common_name, result.common_name)
            self.assertEqual(issuer_name, result.issuer_name)
            self.assertEqual(signature_asym_algorithm, result.signature_asym_algorithm)
            self.assertEqual(hash_algorithm, result.hash_algorithm)
            self.assertEqual(cert_type, result.cert_type)
            self.assertEqual(valid_from, result.valid_from)
            self.assertEqual(valid_until, result.valid_until)
            self.assertEqual(subject_alt_names, result.subject_alt_names)
            self.assertDictEqual(extension_info, result.extension_info)
        # we should have the same company name in different workspaces
        results = session.query(CertInfo).count()
        self.assertEqual(len(self._workspaces), results)

    def _unittest_add_cert_info(self,
                                service_port: int,
                                host_name_str: str,
                                company_name_str: str,
                                serial_number: int,
                                common_name: str,
                                issuer_name: str,
                                signature_asym_algorithm: AsymmetricAlgorithm,
                                signature_bits: int,
                                hash_algorithm: HashAlgorithm,
                                cert_type: CertType,
                                valid_from: datetime,
                                valid_until: datetime,
                                subject_alt_names: List[str] = [],
                                extension_info: Dict[str, str] = {},
                                source: Source = None,
                                ex_message: str = None) -> None:
        """
        Unittests for BaseUtils.add_cert_info
        :return:
        """
        self.init_db(load_cipher_suites=True)
        with self._engine.session_scope() as session:
            source = self.create_source(session)
            #  source
            self._test_add_cert_info(session=session,
                                     service_port=service_port,
                                     host_name_str=host_name_str,
                                     company_name_str=company_name_str,
                                     serial_number=serial_number,
                                     common_name=common_name,
                                     issuer_name=issuer_name,
                                     signature_asym_algorithm=signature_asym_algorithm,
                                     signature_bits=signature_bits,
                                     hash_algorithm=hash_algorithm,
                                     cert_type=cert_type,
                                     valid_from=valid_from,
                                     valid_until=valid_until,
                                     subject_alt_names=subject_alt_names,
                                     extension_info=extension_info,
                                     source=source,
                                     ex_message=ex_message)
        self.init_db(load_cipher_suites=True)
        with self._engine.session_scope() as session:
            # without source
            self._test_add_cert_info(session=session,
                                     service_port=service_port,
                                     host_name_str=host_name_str,
                                     company_name_str=company_name_str,
                                     serial_number=serial_number,
                                     common_name=common_name,
                                     issuer_name=issuer_name,
                                     signature_asym_algorithm=signature_asym_algorithm,
                                     signature_bits=signature_bits,
                                     hash_algorithm=hash_algorithm,
                                     cert_type=cert_type,
                                     valid_from=valid_from,
                                     valid_until=valid_until,
                                     subject_alt_names=subject_alt_names,
                                     extension_info=extension_info,
                                     ex_message=ex_message)

    def test_service_host_name_company_exception(self):
        """
        Unittests for BaseUtils.add_cert_info
        :return:
        """
        self._unittest_add_cert_info(service_port=80,
                                     host_name_str="www.test.com",
                                     company_name_str=None,
                                     serial_number=1,
                                     common_name="www.test.com",
                                     issuer_name="www.test.com",
                                     signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                     signature_bits=2048,
                                     hash_algorithm=HashAlgorithm.sha256,
                                     cert_type=CertType.identity,
                                     valid_from=datetime.now(),
                                     valid_until=datetime.now(),
                                     subject_alt_names=["web.test.com", "owa.test.com", "dev.test.com"],
                                     extension_info={"test": ["test", "test"]},
                                     ex_message="cert info must either be assigned to a service, host name, or company")
        self._unittest_add_cert_info(service_port=80,
                                     host_name_str=None,
                                     company_name_str="Test LLC",
                                     serial_number=1,
                                     common_name="www.test.com",
                                     issuer_name="www.test.com",
                                     signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                     signature_bits=2048,
                                     hash_algorithm=HashAlgorithm.sha256,
                                     cert_type=CertType.identity,
                                     valid_from=datetime.now(),
                                     valid_until=datetime.now(),
                                     subject_alt_names=["web.test.com", "owa.test.com", "dev.test.com"],
                                     extension_info={"test": ["test", "test"]},
                                     ex_message="cert info must either be assigned to a service, host name, or company")
        self._unittest_add_cert_info(service_port=None,
                                     host_name_str="www.test.com",
                                     company_name_str="Test LLC",
                                     serial_number=1,
                                     common_name="www.test.com",
                                     issuer_name="www.test.com",
                                     signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                     signature_bits=2048,
                                     hash_algorithm=HashAlgorithm.sha256,
                                     cert_type=CertType.identity,
                                     valid_from=datetime.now(),
                                     valid_until=datetime.now(),
                                     subject_alt_names=["web.test.com", "owa.test.com", "dev.test.com"],
                                     extension_info={"test": ["test", "test"]},
                                     ex_message="cert info must either be assigned to a service, host name, or company")

    def test_service_add_cert_info(self):
        """
        Unittests for BaseUtils.add_cert_info
        :return:
        """
        self._unittest_add_cert_info(service_port=80,
                                     host_name_str=None,
                                     company_name_str=None,
                                     serial_number=1,
                                     common_name="www.test.com",
                                     issuer_name="www.test.com",
                                     signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                     signature_bits=2048,
                                     hash_algorithm=HashAlgorithm.sha256,
                                     cert_type=CertType.identity,
                                     valid_from=datetime.now(),
                                     valid_until=datetime.now(),
                                     subject_alt_names=["web.test.com", "owa.test.com", "dev.test.com"],
                                     extension_info={"test": ["test", "test"]})
        self._unittest_add_cert_info(service_port=80,
                                     host_name_str=None,
                                     company_name_str=None,
                                     serial_number=1,
                                     common_name="www.test.com",
                                     issuer_name="www.test.com",
                                     signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                     signature_bits=2048,
                                     hash_algorithm=HashAlgorithm.sha256,
                                     cert_type=CertType.identity,
                                     valid_from=datetime.now(),
                                     valid_until=datetime.now(),
                                     extension_info={"test": ["test", "test"]})
        self._unittest_add_cert_info(service_port=80,
                                     host_name_str=None,
                                     company_name_str=None,
                                     serial_number=1,
                                     common_name="www.test.com",
                                     issuer_name="www.test.com",
                                     signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                     signature_bits=2048,
                                     hash_algorithm=HashAlgorithm.sha256,
                                     cert_type=CertType.identity,
                                     valid_from=datetime.now(),
                                     valid_until=datetime.now(),
                                     subject_alt_names=["web.test.com", "owa.test.com", "dev.test.com"])

    def test_host_name_add_cert_info(self):
        """
        Unittests for BaseUtils.add_cert_info
        :return:
        """
        self._unittest_add_cert_info(service_port=None,
                                     host_name_str="www.test.com",
                                     company_name_str=None,
                                     serial_number=1,
                                     common_name="www.test.com",
                                     issuer_name="www.test.com",
                                     signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                     signature_bits=2048,
                                     hash_algorithm=HashAlgorithm.sha256,
                                     cert_type=CertType.identity,
                                     valid_from=datetime.now(),
                                     valid_until=datetime.now(),
                                     subject_alt_names=["web.test.com", "owa.test.com", "dev.test.com"],
                                     extension_info={"test": ["test", "test"]})
        self._unittest_add_cert_info(service_port=None,
                                     host_name_str="www.test.com",
                                     company_name_str=None,
                                     serial_number=1,
                                     common_name="www.test.com",
                                     issuer_name="www.test.com",
                                     signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                     signature_bits=2048,
                                     hash_algorithm=HashAlgorithm.sha256,
                                     cert_type=CertType.identity,
                                     valid_from=datetime.now(),
                                     valid_until=datetime.now(),
                                     extension_info={"test": ["test", "test"]})
        self._unittest_add_cert_info(service_port=None,
                                     host_name_str="www.test.com",
                                     company_name_str=None,
                                     serial_number=1,
                                     common_name="www.test.com",
                                     issuer_name="www.test.com",
                                     signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                     signature_bits=2048,
                                     hash_algorithm=HashAlgorithm.sha256,
                                     cert_type=CertType.identity,
                                     valid_from=datetime.now(),
                                     valid_until=datetime.now(),
                                     subject_alt_names=["web.test.com", "owa.test.com", "dev.test.com"])

    def test_company_add_cert_info(self):
        """
        Unittests for BaseUtils.add_cert_info
        :return:
        """
        self._unittest_add_cert_info(service_port=None,
                                     host_name_str=None,
                                     company_name_str="Test LLC",
                                     serial_number=1,
                                     common_name="www.test.com",
                                     issuer_name="www.test.com",
                                     signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                     signature_bits=2048,
                                     hash_algorithm=HashAlgorithm.sha256,
                                     cert_type=CertType.identity,
                                     valid_from=datetime.now(),
                                     valid_until=datetime.now(),
                                     subject_alt_names=["web.test.com", "owa.test.com", "dev.test.com"],
                                     extension_info={"test": ["test", "test"]})
        self._unittest_add_cert_info(service_port=None,
                                     host_name_str=None,
                                     company_name_str="Test LLC",
                                     serial_number=1,
                                     common_name="www.test.com",
                                     issuer_name="www.test.com",
                                     signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                     signature_bits=2048,
                                     hash_algorithm=HashAlgorithm.sha256,
                                     cert_type=CertType.identity,
                                     valid_from=datetime.now(),
                                     valid_until=datetime.now(),
                                     extension_info={"test": ["test", "test"]})
        self._unittest_add_cert_info(service_port=None,
                                     host_name_str=None,
                                     company_name_str="Test LLC",
                                     serial_number=1,
                                     common_name="www.test.com",
                                     issuer_name="www.test.com",
                                     signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                     signature_bits=2048,
                                     hash_algorithm=HashAlgorithm.sha256,
                                     cert_type=CertType.identity,
                                     valid_from=datetime.now(),
                                     valid_until=datetime.now(),
                                     subject_alt_names=["web.test.com", "owa.test.com", "dev.test.com"])


class TestAddTlsInfo(BaseKisTestCase):
    """
    This test case tests BaseUtils.add_tls_info
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def _test_add_tls_info(self,
                           session: Session,
                           service_port: int,
                           version: TlsVersion,
                           preference: TlsPreference,
                           heartbleed: bool = None,
                           compressors: List[str] = []) -> None:
        """
        This is a helper method for testing BaseUtils.add_path
        :return:
        """
        for item in self._workspaces:
            service = self.create_service(session=session,
                                          workspace_str=item,
                                          port=service_port)
            result = self._domain_utils.add_tls_info(session=session,
                                                     service=service,
                                                     version=version,
                                                     preference=preference,
                                                     compressors=compressors,
                                                     heartbleed=heartbleed)
            self.assertIsNotNone(result)
            self.assertIsNotNone(result.service)
            self.assertEqual(service.id, result.service_id)
            self.assertEqual(service_port, result.service.port)
            self.assertEqual(version, result.version)
            self.assertEqual(preference, result.preference)
            self.assertEqual(heartbleed, result.heartbleed)
            self.assertListEqual(compressors, result.compressors)
            results = session.query(TlsInfo) \
                .join(Service) \
                .join(Host) \
                .join(Workspace).filter(TlsInfo.version == result.version,
                                        TlsInfo.service_id == service.id,
                                        Workspace.name == item).all()
            self.assertEqual(1, len(results))
        # we should have the same company name in different workspaces
        results = session.query(TlsInfo).count()
        self.assertEqual(len(self._workspaces), results)

    def _unittest_add_tls_info(self,
                               service_port: int,
                               version: TlsVersion,
                               preference: TlsPreference,
                               heartbleed: bool = None,
                               compressors: List[str] = []) -> None:
        """
        Unittests for BaseUtils.add_tls_info
        :return:
        """
        self.init_db(load_cipher_suites=True)
        with self._engine.session_scope() as session:
            self._test_add_tls_info(session=session,
                                    service_port=service_port,
                                    version=version,
                                    preference=preference,
                                    heartbleed=heartbleed,
                                    compressors=compressors)

    def test_add_tls_info(self):
        """
        Unittests for BaseUtils.add_tls_info
        :return:
        """
        self._unittest_add_tls_info(service_port=80,
                                    version=TlsVersion.tls13,
                                    preference=TlsPreference.client)
        self._unittest_add_tls_info(service_port=80,
                                    version=TlsVersion.tls13,
                                    preference=TlsPreference.client,
                                    compressors=["1", "2"])
        self._unittest_add_tls_info(service_port=80,
                                    version=TlsVersion.tls13,
                                    preference=TlsPreference.client,
                                    heartbleed=False)
        self._unittest_add_tls_info(service_port=80,
                                    version=TlsVersion.tls13,
                                    preference=TlsPreference.client,
                                    heartbleed=False,
                                    compressors=["1", "2"])


class TestTlsInfoCipherSuiteMapping(BaseKisTestCase):
    """
    This test case tests BaseUtils.add_tls_info_cipher_suite_mapping
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def _test_add_tls_info_cipher_suite_mapping(self,
                                                session: Session,
                                                tls_info_version: TlsVersion,
                                                iana_name: str,
                                                order: int,
                                                prefered: bool,
                                                kex_algorithm_details: KeyExchangeAlgorithm,
                                                source: Source = None) -> None:
        """
        This is a helper method for testing BaseUtils.add_tls_info_cipher_suite_mapping
        :return:
        """
        for item in self._workspaces:
            service = self.create_service(session=session, workspace_str=item)
            tls_info = self.create_tls_info(session=session, version=tls_info_version, service=service)
            cipher_suite = self.query_cipher_suite(session=session, iana_name=iana_name)
            result = self._domain_utils.add_tls_info_cipher_suite_mapping(session=session,
                                                                          tls_info=tls_info,
                                                                          cipher_suite=cipher_suite,
                                                                          order=order,
                                                                          prefered=prefered,
                                                                          kex_algorithm_details=kex_algorithm_details,
                                                                          source=source)
            self.assertIsNotNone(result)
            self.assertIsNotNone(result.tls_info)
            self.assertIsNotNone(result.cipher_suite)
            self.assertEqual(tls_info_version, result.tls_info.version)
            self.assertEqual(iana_name, result.cipher_suite.iana_name)
            self.assertEqual(order, result.order)
            self.assertEqual(prefered, result.prefered)
            self.assertEqual(kex_algorithm_details, result.kex_algorithm_details)
            results = session.query(TlsInfoCipherSuiteMapping) \
                .join(TlsInfo) \
                .join(Service) \
                .join(Host) \
                .join(Workspace).filter(Workspace.name == item).all()
            self.assertEqual(1, len(results))
            if source:
                results = session.query(Source) \
                    .join((TlsInfoCipherSuiteMapping, Source.tls_info_cipher_suite_mappings)) \
                    .join(TlsInfo) \
                    .join(Service) \
                    .join(Host) \
                    .join(Workspace) \
                    .filter(Workspace.name == item).count()
                self.assertEqual(1, results)
        # we should have the same company name in different workspaces
        results = session.query(TlsInfoCipherSuiteMapping).count()
        self.assertEqual(len(self._workspaces), results)

    def _unittest_add_tls_info_cipher_suite_mapping(self,
                                                    tls_info_version: TlsVersion,
                                                    iana_name: str,
                                                    order: int,
                                                    prefered: bool,
                                                    kex_algorithm_details: KeyExchangeAlgorithm) -> None:
        """
        Unittests for BaseUtils.add_tls_info_cipher_suite_mapping
        :return:
        """
        self.init_db(load_cipher_suites=True)
        with self._engine.session_scope() as session:
            source = self.create_source(session)
            # with source
            self._test_add_tls_info_cipher_suite_mapping(session=session,
                                                         tls_info_version=tls_info_version,
                                                         iana_name=iana_name,
                                                         order=order,
                                                         prefered=prefered,
                                                         kex_algorithm_details=kex_algorithm_details,
                                                         source=source)
        self.init_db(load_cipher_suites=True)
        with self._engine.session_scope() as session:
            # without source
            self._test_add_tls_info_cipher_suite_mapping(session=session,
                                                         tls_info_version=tls_info_version,
                                                         iana_name=iana_name,
                                                         order=order,
                                                         prefered=prefered,
                                                         kex_algorithm_details=kex_algorithm_details)

    def test_add_tls_info_cipher_suite_mapping(self):
        """
        Unittests for BaseUtils.add_tls_info_cipher_suite_mapping
        :return:
        """
        self._unittest_add_tls_info_cipher_suite_mapping(tls_info_version=TlsVersion.tls13,
                                                         iana_name="TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                                                         order=1,
                                                         prefered=True,
                                                         kex_algorithm_details=KeyExchangeAlgorithm.ecdh_x25519)


class TestAddService(BaseKisTestCase):
    """
    This test case tests BaseUtils.add_service
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def _test_add_service(self,
                          session: Session,
                          port: int,
                          protocol_type: ProtocolType,
                          state: ServiceState,
                          host_name_str: str = None,
                          address: str = None,
                          source: Source = None,
                          report_item: ReportItem = None,
                          ex_message: str = None) -> None:
        """
        This is a helper method for testing BaseUtils.add_service
        :return:
        """
        host = None
        host_name = None
        self._reset_report_item(report_item)
        for item in self._workspaces:
            if address:
                host = self.create_host(session=session, workspace_str=item, address=address)
            if host_name_str:
                host_name = self.create_hostname(session=session,
                                                 workspace_str=item,
                                                 host_name=host_name_str)
            try:
                result = self._domain_utils.add_service(session=session,
                                                        port=port,
                                                        protocol_type=protocol_type,
                                                        state=state,
                                                        host=host,
                                                        host_name=host_name,
                                                        source=source,
                                                        report_item=report_item)
                self.assertIsNotNone(result)
            except Exception as ex:
                if ex_message:
                    self.assertEqual(ex_message, str(ex))
                    return
                raise ex
            self.assertIsNone(ex_message)
            self.assertEqual(port, result.port)
            self.assertEqual(protocol_type, result.protocol)
            if address:
                self.assertIsNotNone(result.host)
                self.assertIsNone(result.host_name)
                self.assertEqual(host.id, result.host_id)
                self.assertEqual(address, result.host.address)
                results = session.query(Service) \
                     .join(Host) \
                     .join(Workspace) \
                     .filter(Service.port == port,
                             Service.protocol == protocol_type,
                             Host.address == address,
                             Workspace.name == item).count()
                self.assertEqual(1, results)
                if source:
                    results = session.query(Source) \
                        .join((Service, Source.services)) \
                        .join(Host) \
                        .join(Workspace) \
                        .filter(Service.port == port,
                                Service.protocol == protocol_type,
                                Host.address == address,
                                Workspace.name == item).count()
                    self.assertEqual(1, results)
            if host_name_str:
                host_part, domain_part = self.split_domain_name(host_name_str)
                self.assertIsNotNone(result.host_name)
                self.assertIsNone(result.host)
                self.assertEqual(host_name.id, result.host_name_id)
                self.assertEqual(host_name_str, result.host_name.full_name)
                results = session.query(Service) \
                                 .join(HostName) \
                                 .join(DomainName) \
                                 .join(Workspace) \
                                 .filter(Service.port == port,
                                         Service.protocol == protocol_type,
                                         HostName.name == host_part,
                                         DomainName.name == domain_part,
                                         Workspace.name == item).count()
                self.assertEqual(1, results)
                if source:
                    results = session.query(Source) \
                        .join((Service, Source.services)) \
                        .join(HostName) \
                        .join(DomainName) \
                        .join(Workspace) \
                        .filter(Service.port == port,
                                Service.protocol == protocol_type,
                                HostName.name == host_part,
                                DomainName.name == domain_part,
                                Workspace.name == item).count()
                    self.assertEqual(1, results)
            if report_item:
                self.assertIn("potentially new service: {}/{}".format(protocol_type.name.lower(), port),
                              report_item.get_report())
        results = session.query(Service) \
            .filter(Service.port == port,
                    Service.protocol == protocol_type).count()
        self.assertEqual(len(self._workspaces), results)

    def _unittest_add_service(self,
                              port: int,
                              protocol_type: ProtocolType,
                              state: ServiceState,
                              host_name_str: str = None,
                              address: str = None,
                              ex_message: str = None) -> None:
        """
        Unittests for BaseUtils.add_service
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            source = self.create_source(session)
            # without source and report item
            self._test_add_service(session=session,
                                   port=port,
                                   protocol_type=protocol_type,
                                   state=state,
                                   host_name_str=host_name_str,
                                   address=address,
                                   ex_message=ex_message)
            # with source
            self._test_add_service(session=session,
                                   port=port,
                                   protocol_type=protocol_type,
                                   state=state,
                                   host_name_str=host_name_str,
                                   address=address,
                                   ex_message=ex_message,
                                   source=source)
            # with report item
            self._test_add_service(session=session,
                                   port=port,
                                   protocol_type=protocol_type,
                                   state=state,
                                   host_name_str=host_name_str,
                                   address=address,
                                   ex_message=ex_message,
                                   report_item=self._report_item)
            # with source and report item
            self._test_add_service(session=session,
                                   port=port,
                                   protocol_type=protocol_type,
                                   state=state,
                                   host_name_str=host_name_str,
                                   address=address,
                                   ex_message=ex_message,
                                   source=source,
                                   report_item=self._report_item)

    def test_host_and_hostname_exception(self):
        """
        Unittests for BaseUtils.add_service
        :return:
        """
        self._unittest_add_service(port=80,
                                   protocol_type=ProtocolType.tcp,
                                   state=ServiceState.Open,
                                   address="192.168.1.1",
                                   host_name_str="www.test.com",
                                   ex_message="service must either be assigned to a host or a host name")
        self._unittest_add_service(port=80,
                                   protocol_type=ProtocolType.tcp,
                                   state=ServiceState.Open,
                                   host_name_str=None,
                                   address=None,
                                   ex_message="service must be assigned to host or host name")

    def test_add_service(self):
        """
        Unittests for BaseUtils.add_service
        :return:
        """
        self._unittest_add_service(port=80,
                                   protocol_type=ProtocolType.udp,
                                   state=ServiceState.Open,
                                   address="172.168.1.1")
        self._unittest_add_service(port=80,
                                   protocol_type=ProtocolType.udp,
                                   state=ServiceState.Open,
                                   host_name_str="www.test.com")

    def test_add_service_and_path(self):
        """
        If a web service is added, then the database trigger add_services_to_host_name automatically adds the default
        path / to table path.
        """
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = self._domain_utils.add_workspace(session=session, name=self._workspaces[0])
            host = IpUtils.add_host(session=session,
                                    workspace=workspace,
                                    address="192.168.1.1")
            # Test Nmap Service Names
            IpUtils.add_service(session=session,
                                port=1,
                                protocol_type=ProtocolType.tcp,
                                state=ServiceState.Open,
                                host=host,
                                nmap_service_name='ssl|http')
            IpUtils.add_service(session=session,
                                port=2,
                                protocol_type=ProtocolType.tcp,
                                state=ServiceState.Open,
                                host=host,
                                nmap_service_name='http')
            IpUtils.add_service(session=session,
                                port=3,
                                protocol_type=ProtocolType.tcp,
                                state=ServiceState.Open,
                                host=host,
                                nmap_service_name='http-alt')
            IpUtils.add_service(session=session,
                                port=4,
                                protocol_type=ProtocolType.tcp,
                                state=ServiceState.Open,
                                host=host,
                                nmap_service_name='https')
            IpUtils.add_service(session=session,
                                port=5,
                                protocol_type=ProtocolType.tcp,
                                state=ServiceState.Open,
                                host=host,
                                nmap_service_name='http-proxy')
            IpUtils.add_service(session=session,
                                port=6,
                                protocol_type=ProtocolType.tcp,
                                state=ServiceState.Open,
                                host=host,
                                nmap_service_name='sgi-soap')
            IpUtils.add_service(session=session,
                                port=7,
                                protocol_type=ProtocolType.tcp,
                                state=ServiceState.Open,
                                host=host,
                                nmap_service_name='caldav')
            # Test Nessus Service Names
            IpUtils.add_service(session=session,
                                port=11,
                                protocol_type=ProtocolType.tcp,
                                state=ServiceState.Open,
                                host=host,
                                nessus_service_name='www')
            IpUtils.add_service(session=session,
                                port=12,
                                protocol_type=ProtocolType.tcp,
                                state=ServiceState.Open,
                                host=host,
                                nessus_service_name='http-alt')
            IpUtils.add_service(session=session,
                                port=13,
                                protocol_type=ProtocolType.tcp,
                                state=ServiceState.Open,
                                host=host,
                                nessus_service_name='http')
            IpUtils.add_service(session=session,
                                port=14,
                                protocol_type=ProtocolType.tcp,
                                state=ServiceState.Open,
                                host=host,
                                nessus_service_name='https')
            IpUtils.add_service(session=session,
                                port=15,
                                protocol_type=ProtocolType.tcp,
                                state=ServiceState.Open,
                                host=host,
                                nessus_service_name='pcsync-https')
            IpUtils.add_service(session=session,
                                port=16,
                                protocol_type=ProtocolType.tcp,
                                state=ServiceState.Open,
                                host=host,
                                nessus_service_name='homepage')
            IpUtils.add_service(session=session,
                                port=17,
                                protocol_type=ProtocolType.tcp,
                                state=ServiceState.Open,
                                host=host,
                                nessus_service_name='greenbone-administrator')
            IpUtils.add_service(session=session,
                                port=18,
                                protocol_type=ProtocolType.tcp,
                                state=ServiceState.Open,
                                host=host,
                                nessus_service_name='openvas-administrator')
            # Negative Test
            IpUtils.add_service(session=session,
                                port=100,
                                protocol_type=ProtocolType.tcp,
                                state=ServiceState.Open,
                                host=host,
                                nmap_service_name='ssh')
            IpUtils.add_service(session=session,
                                port=101,
                                protocol_type=ProtocolType.tcp,
                                state=ServiceState.Open,
                                host=host,
                                nmap_service_name=None)
        with self._engine.session_scope() as session:
            for item in session.query(Service).all():
                if item.port < 100:
                    self.assertEqual(1, len(item.paths))
                    self.assertEqual('/', item.paths[0].name)
                else:
                    self.assertEqual(0, len(item.paths))


class TestAddDomainName(BaseKisTestCase):
    """
    This test case tests DomainUtils.add_domain_name
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def _test_add_domain(self,
                         session: Session,
                         host_name_str: str,
                         valid: bool,
                         verify: bool = False,
                         address: str = None,
                         source: Source = None,
                         mapping_type: DnsResourceRecordType = DnsResourceRecordType.a,
                         report_item: ReportItem = None) -> None:
        """
        This is a helper method for testing DomainUtils.add_domain_name
        :return:
        """
        host = None
        self._reset_report_item(report_item)
        i = 0
        for item in self._workspaces:
            scope = ScopeType.all if ((i % 2) == 0) else ScopeType.exclude
            workspace = self.create_workspace(session=session, workspace=item)
            if address:
                host = self.create_host(session=session, workspace_str=item, address=address)
            result = self._domain_utils.add_domain_name(session=session,
                                                        workspace=workspace,
                                                        item=host_name_str,
                                                        source=source,
                                                        scope=scope,
                                                        verify=verify,
                                                        report_item=report_item)
            if result and host:
                self._domain_utils.add_host_host_name_mapping(session=session,
                                                              host=host,
                                                              host_name=result,
                                                              mapping_type=mapping_type,
                                                              source=source,
                                                              report_item=report_item)
            session.commit()
            if valid or not verify:
                host_part, domain_part = self.split_domain_name(host_name_str)
                self.assertIsNotNone(result)
                self.assertEqual((scope == ScopeType.all), result.in_scope(CollectorType.domain))
                results = session.query(DomainName) \
                    .join(HostName) \
                    .join((Workspace, DomainName.workspace)) \
                    .filter(DomainName.name == domain_part,
                            HostName.name == host_part,
                            Workspace.name == item).count()
                self.assertEqual(1, results)
                if address:
                    results = session.query(DomainName) \
                        .join(HostName) \
                        .join((Host, HostName.hosts)) \
                        .join((Workspace, DomainName.workspace)) \
                        .filter(DomainName.name == domain_part,
                                HostName.name == host_part,
                                Host.address == address,
                                Workspace.name == item).count()
                    self.assertEqual(1, results)
                else:
                    self.assertEqual(0, len(result.hosts))
                if source:
                    results = session.query(Source)\
                        .join((HostName, Source.host_names))\
                        .join(DomainName)\
                        .join(Workspace)\
                        .filter(DomainName.name == domain_part,
                                HostName.name == host_part,
                                Workspace.name == item).count()
                    self.assertEqual(1, results)
                if report_item and host_name_str and address:
                    self.assertIn("add potentially new link (A) between {} and {}".format(address, host_name_str),
                                  report_item.get_report())
                elif report_item:
                    self.assertIn("potentially new host name {}".format(host_name_str), report_item.get_report())
            else:
                self.assertIsNone(result)
            i += 1
        # we should have the same address in different workspaces
        if valid or not verify:
            host_part, domain_part = self.split_domain_name(host_name_str)
            results = session.query(DomainName) \
                .join(HostName) \
                .filter(DomainName.name == domain_part,
                        HostName.name == host_part).count()
            self.assertEqual(len(self._workspaces), results)
        else:
            self.assertEqual(0, session.query(DomainName).join(HostName).count())

    def _unittest_add_domain(self,
                             host_name_str: str,
                             valid: bool,
                             verify: bool = False,
                             address: str = None) -> None:
        """
        Unittests for BaseUtils.add_domain_name
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            source = self.create_source(session)
            # without source and report item
            self._test_add_domain(session=session,
                                  host_name_str=host_name_str,
                                  valid=valid,
                                  verify=verify,
                                  address=address)
            # with source
            self._test_add_domain(session=session,
                                  host_name_str=host_name_str,
                                  valid=valid,
                                  verify=verify,
                                  address=address,
                                  source=source)
            # with report item
            self._test_add_domain(session=session,
                                  host_name_str=host_name_str,
                                  valid=valid,
                                  verify=verify,
                                  address=address,
                                  report_item=self._report_item)
            # with source and report item
            self._test_add_domain(session=session,
                                  host_name_str=host_name_str,
                                  valid=valid,
                                  verify=verify,
                                  address=address,
                                  source=source,
                                  report_item=self._report_item)

    def test_add_valid_domainname_with_verify(self):
        """
        Unittests for BaseUtils.add_service
        :return:
        """
        valid = True
        verify = True
        self._unittest_add_domain(host_name_str="www.test.com", valid=valid, verify=verify, address="192.168.1.1")
        self._unittest_add_domain(host_name_str="www.test.com", valid=valid, verify=verify)
        self._unittest_add_domain(host_name_str="test.com", valid=valid, verify=verify, address="192.168.1.1")
        self._unittest_add_domain(host_name_str="test.com", valid=valid, verify=verify)
        self._unittest_add_domain(host_name_str="ftptest.gov.com",
                                  valid=valid,
                                  verify=verify,
                                  address="192.168.1.1")
        self._unittest_add_domain(host_name_str="ftptest.gov.com",
                                  valid=valid,
                                  verify=verify)

    def test_add_valid_domainname_without_verify(self):
        """
        Unittests for BaseUtils.add_service
        :return:
        """
        valid = True
        verify = False
        self._unittest_add_domain(host_name_str="www.test.com", valid=valid, verify=verify, address="192.168.1.1")
        self._unittest_add_domain(host_name_str="www.test.com", valid=valid, verify=verify)
        self._unittest_add_domain(host_name_str="test.com", valid=valid, verify=verify, address="192.168.1.1")
        self._unittest_add_domain(host_name_str="test.com", valid=valid, verify=verify)
        self._unittest_add_domain(host_name_str="ftptest.gov.com",
                                  valid=valid,
                                  verify=verify,
                                  address="192.168.1.1")
        self._unittest_add_domain(host_name_str="ftptest.gov.com",
                                  valid=valid,
                                  verify=verify)
        self._unittest_add_domain(host_name_str="ip6-localhost", valid=True, verify=False)

    def test_add_invalid_domainname_with_verify(self):
        """
        Unittests for BaseUtils.add_service
        :return:
        """
        valid = False
        verify = True
        self._unittest_add_domain(host_name_str=" www.test.com", valid=valid, verify=verify, address="192.168.1.1")
        self._unittest_add_domain(host_name_str=" www.test.com", valid=valid, verify=verify)
        self._unittest_add_domain(host_name_str="www.test.com ", valid=valid, verify=verify, address="192.168.1.1")
        self._unittest_add_domain(host_name_str="www.test.com ", valid=valid, verify=verify)
        self._unittest_add_domain(host_name_str=" www.test.com ",
                                  valid=valid,
                                  verify=verify,
                                  address="192.168.1.1")
        self._unittest_add_domain(host_name_str=" www.test.com ",
                                  valid=valid,
                                  verify=verify)
        self._unittest_add_domain(host_name_str="com", valid=valid, verify=verify, address="192.168.1.1")
        self._unittest_add_domain(host_name_str="com", valid=valid, verify=verify)
        self._unittest_add_domain(host_name_str="test.asdf", valid=valid, verify=verify, address="192.168.1.1")
        self._unittest_add_domain(host_name_str="test.asdf", valid=valid, verify=verify)

    def test_special_cases(self):
        """
        Unittests for BaseUtils.add_service
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            source = self.create_source(session, source_str="unittest")
            workspace = self._domain_utils.add_workspace(session, self._workspaces[0])
            host_name = self._domain_utils.add_domain_name(session=session,
                                                           workspace=workspace,
                                                           item=".*.www.test.unittest.com",
                                                           scope=ScopeType.all,
                                                           verify=True,
                                                           source=source)
            self._domain_utils.add_host_host_name_mapping(session=session,
                                                          host=self._ip_utils.add_host(session=session,
                                                                                       workspace=workspace,
                                                                                       address="192.168.1.1",
                                                                                       source=source),
                                                          host_name=host_name,
                                                          mapping_type=DnsResourceRecordType.a,
                                                          source=source)
            rvalue = self._domain_utils.add_domain_name(session=session,
                                                        workspace=workspace,
                                                        item="test..test.unittest.com",
                                                        source=source,
                                                        scope=ScopeType.all,
                                                        verify=True)
            self.assertIsNone(rvalue)
            if rvalue:
                self._domain_utils.add_host_host_name_mapping(session=session,
                                                              host=self._ip_utils.add_host(session=session,
                                                                                           workspace=workspace,
                                                                                           address="192.168.1.1",
                                                                                           source=source),
                                                              host_name=rvalue,
                                                              mapping_type=DnsResourceRecordType.a,
                                                              source=source)
        with self._engine.session_scope() as session:
            host_names = session.query(HostName)\
                .join(DomainName).join(Workspace)\
                .filter(Workspace.name == self._workspaces[0]).all()
            host_names_str = [item.full_name for item in host_names]
            self.assertListEqual(["test.unittest.com", "www.test.unittest.com", "unittest.com"], host_names_str)
            for host_name in host_names:
                self.assertEqual("unittest", host_name.sources[0].name)
                if host_name.name is not None and host_name.full_name == "www.test.unittest.com":
                    self.assertEqual("192.168.1.1", host_name.host_host_name_mappings[0].host.address)
                else:
                    self.assertListEqual([], host_name.host_host_name_mappings)


class TestAddSecondLevelDomain(BaseKisTestCase):
    """
    This test case tests DomainUtils.add_sld
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def test_add_sld_simple(self):
        self.init_db()
        with self._engine.session_scope() as session:
            source = self._domain_utils.add_source(session=session, name="user")
            workspace = self._domain_utils.add_workspace(session=session, name=self._workspaces[0])
            domain_name = self._domain_utils.add_sld(session=session,
                                                     workspace=workspace,
                                                     name="test.local",
                                                     scope=ScopeType.all,
                                                     source=source)
        with self._engine.session_scope() as session:
            result = session.query(DomainName).filter_by(name="test.local").one()
            self.assertEqual(ScopeType.all, result.scope)
            self.assertIsNone(result.host_names[0].name)
            self.assertTrue(result.host_names[0]._in_scope)
            self.assertEqual(1, len(result.host_names[0].sources))

    def test_add_sld_simple_02(self):
        self.init_db()
        with self._engine.session_scope() as session:
            source = self._domain_utils.add_source(session=session, name="user")
            workspace = self._domain_utils.add_workspace(session=session, name=self._workspaces[0])
            domain_name = self._domain_utils.add_sld(session=session,
                                                     workspace=workspace,
                                                     name="test.co.kr",
                                                     scope=ScopeType.all,
                                                     source=source)
        with self._engine.session_scope() as session:
            result = session.query(DomainName).filter_by(name="test.co.kr").one()
            self.assertEqual(ScopeType.all, result.scope)
            self.assertIsNone(result.host_names[0].name)
            self.assertTrue(result.host_names[0]._in_scope)
            self.assertEqual(1, len(result.host_names[0].sources))

    def test_add_sld_invalid(self):
        self.init_db()
        with self._engine.session_scope() as session:
            try:
                source = self.create_source(session)
                workspace = self._domain_utils.add_workspace(session=session, name=self._workspaces[0])
                domain_name = self._domain_utils.add_sld(session=session,
                                                         workspace=workspace,
                                                         name="www.test.local",
                                                         scope=ScopeType.all,
                                                         source=source)
                self.assertIsNone(domain_name)
            except ValueError as ex:
                self.assertEqual("www.test.local is not a second-level domain", str(ex))

    def test_update_sld_simple_01(self):
        self.test_add_sld_simple()
        with self._engine.session_scope() as session:
            workspace = self._domain_utils.add_workspace(session=session, name=self._workspaces[0])
            source = self._domain_utils.add_source(session=session, name="user")
            self._domain_utils.add_sld(session=session,
                                       workspace=workspace,
                                       name="test.local",
                                       source=source,
                                       scope=ScopeType.strict)
        with self._engine.session_scope() as session:
            result = session.query(DomainName).filter_by(name="test.local").one()
            self.assertEqual(ScopeType.strict, result.scope)
            self.assertIsNone(result.host_names[0].name)
            self.assertTrue(result.host_names[0]._in_scope)
            self.assertEqual(1, len(result.host_names[0].sources))

    def test_update_sld_simple_02(self):
        self.test_add_sld_simple()
        with self._engine.session_scope() as session:
            workspace = self._domain_utils.add_workspace(session=session, name=self._workspaces[0])
            source = self._domain_utils.add_source(session=session, name="user1")
            self._domain_utils.add_sld(session=session,
                                       workspace=workspace,
                                       name="test.local",
                                       source=source,
                                       scope=ScopeType.strict)
        with self._engine.session_scope() as session:
            result = session.query(DomainName).filter_by(name="test.local").one()
            self.assertEqual(ScopeType.strict, result.scope)
            self.assertIsNone(result.host_names[0].name)
            self.assertTrue(result.host_names[0]._in_scope)
            self.assertEqual(2, len(result.host_names[0].sources))


class TestAddHostName(BaseKisTestCase):
    """
    This test case tests DomainUtils.add_host_name
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def test_add_invalid_host_name(self):
        self.init_db()
        with self._engine.session_scope() as session:
            try:
                source = self._domain_utils.add_source(session=session, name="user")
                workspace = self._domain_utils.add_workspace(session=session, name=self._workspaces[0])
                domain_name = self._domain_utils.add_host_name(session=session,
                                                               workspace=workspace,
                                                               name="local",
                                                               in_scope=True,
                                                               source=source)
                self.assertIsNotNone(domain_name)
            except ValueError as ex:
                self.assertEqual("local is not a valid sub-domain", str(ex))

    def test_add_without_second_level_domain(self):
        self.init_db()
        with self._engine.session_scope() as session:
            try:
                source = self._domain_utils.add_source(session=session, name="user")
                workspace = self._domain_utils.add_workspace(session=session, name=self._workspaces[0])
                domain_name = self._domain_utils.add_host_name(session=session,
                                                               workspace=workspace,
                                                               name="www.test.local",
                                                               in_scope=True,
                                                               source=source)
                self.assertIsNotNone(domain_name)
            except DomainNameNotFound as ex:
                self.assertEqual("second-level domain name 'test.local' does not exist in database", str(ex))

    def test_add_second_level_domain_in_scope(self):
        self.init_db()
        with self._engine.session_scope() as session:
            source = self._domain_utils.add_source(session=session, name="user")
            workspace = self._domain_utils.add_workspace(session=session, name=self._workspaces[0])
            self._domain_utils.add_sld(session=session,
                                       workspace=workspace,
                                       name="test.local",
                                       source=source,
                                       scope=ScopeType.strict)
        with self._engine.session_scope() as session:
            source = self._domain_utils.add_source(session=session, name="user1")
            workspace = self._domain_utils.get_workspace(session=session, name=self._workspaces[0])
            result = session.query(DomainName).filter_by(name="test.local").one()
            self.assertEqual(ScopeType.strict, result.scope)
            self.assertIsNone(result.host_names[0].name)
            self.assertFalse(result.host_names[0]._in_scope)
            self._domain_utils.add_host_name(session=session,
                                             workspace=workspace,
                                             name="test.local",
                                             in_scope=True,
                                             source=source)
        with self._engine.session_scope() as session:
            result = session.query(DomainName).filter_by(name="test.local").one()
            self.assertEqual(ScopeType.strict, result.scope)
            self.assertIsNone(result.host_names[0].name)
            self.assertTrue(result.host_names[0]._in_scope)
            self.assertEqual(2, len(result.host_names[0].sources))


class TestAddEmail(BaseKisTestCase):
    """
    This test case tests DomainUtils.add_email
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def _test_add_email(self,
                        session: Session,
                        email_address: str,
                        valid: bool,
                        verify: bool = False,
                        source: Source = None,
                        report_item: ReportItem = None) -> None:
        """
        This is a helper method for testing DomainUtils.add_email
        :return:
        """
        self._reset_report_item(report_item)
        for item in self._workspaces:
            workspace = self.create_workspace(session=session, workspace=item)
            result = self._domain_utils.add_email(session=session,
                                                  workspace=workspace,
                                                  text=email_address,
                                                  verify=verify,
                                                  source=source,
                                                  report_item=report_item)
            if valid or not verify:
                self.assertIsNotNone(result)
                name, host, domain = self.split_email(email_address)
                results = session.query(DomainName) \
                    .join(HostName) \
                    .join(Email) \
                    .join((Workspace, DomainName.workspace)) \
                    .filter(DomainName.name == domain,
                            HostName.name == host,
                            Email.address == name,
                            Workspace.name == item).count()
                self.assertEqual(1, results)
                if source:
                    results = session.query(Source) \
                        .join((Email, Source.emails)) \
                        .join(HostName) \
                        .join(DomainName) \
                        .join(Workspace) \
                        .filter(DomainName.name == domain,
                                HostName.name == host,
                                Email.address == name,
                                Workspace.name == item).count()
                    self.assertEqual(1, results)
                if report_item:
                    self.assertIn("potentially new email address {}".format(email_address), report_item.get_report())
            else:
                self.assertIsNone(result)
        # we should have the same address in different workspaces
        if valid or not verify:
            name, host, domain = self.split_email(email_address)
            results = session.query(DomainName) \
                .join(HostName) \
                .join(Email) \
                .filter(DomainName.name == domain,
                        HostName.name == host,
                        Email.address == name).count()
            self.assertEqual(len(self._workspaces), results)
        else:
            self.assertEqual(0, session.query(DomainName).join(HostName).join(Email).count())

    def _unittest_add_email(self,
                            email_address: str,
                            valid: bool,
                            verify: bool = False) -> None:
        """
        Unittests for BaseUtils.add_email
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            source = self.create_source(session)
            # without source and report item
            self._test_add_email(session=session,
                                 email_address=email_address,
                                 valid=valid,
                                 verify=verify)
            # with source
            self._test_add_email(session=session,
                                 email_address=email_address,
                                 valid=valid,
                                 verify=verify,
                                 source=source)
            # with report item
            self._test_add_email(session=session,
                                 email_address=email_address,
                                 valid=valid,
                                 verify=verify,
                                 report_item=self._report_item)
            # with source and report item
            self._test_add_email(session=session,
                                 email_address=email_address,
                                 valid=valid,
                                 verify=verify,
                                 source=source,
                                 report_item=self._report_item)

    def test_add_valid_email_with_verify(self):
        """
        Unittests for BaseUtils.add_email
        :return:
        """
        valid = True
        verify = True
        self._unittest_add_email(email_address="user.name@a.test.com", valid=valid, verify=verify)
        self._unittest_add_email(email_address="user.name@test.com", valid=valid, verify=verify)
        self._unittest_add_email(email_address="user.name@ftptest.gov.com", valid=valid, verify=verify)

    def test_add_valid_email_without_verify(self):
        """
        Unittests for BaseUtils.add_email
        :return:
        """
        valid = True
        verify = False
        self._unittest_add_email(email_address="user.name@a.test.com", valid=valid, verify=verify)
        self._unittest_add_email(email_address="user.name@test.com", valid=valid, verify=verify)
        self._unittest_add_email(email_address="user.name@ftptest.gov.com", valid=valid, verify=verify)

    def test_add_invalid_email_with_verify(self):
        """
        Unittests for BaseUtils.add_email
        :return:
        """
        valid = False
        verify = True
        self._unittest_add_email(email_address="www.test.com", valid=valid, verify=verify)
        self._unittest_add_email(email_address=" user.name@www.test.com", valid=valid, verify=verify)
        self._unittest_add_email(email_address="user.name@www.test.com ", valid=valid, verify=verify)
        self._unittest_add_email(email_address=" user.name@www.test.com ", valid=valid, verify=verify)
        self._unittest_add_email(email_address="user.name@com", valid=valid, verify=verify)
        self._unittest_add_email(email_address="user.name@test.asdf", valid=valid, verify=verify)


class TestAdditionalInfo(BaseKisTestCase):
    """
    This test case tests BaseUtils.add_additional_info
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def _test_add_additional_info(self,
                                  session: Session,
                                  name: str,
                                  values: List[str],
                                  service_port: int,
                                  host_name_str: str,
                                  source: Source = None,
                                  report_item: ReportItem = None,
                                  ex_message: str = None) -> None:
        """
        This is a helper method for testing BaseUtils.add_additional_info
        :return:
        """
        cmp_value = values if isinstance(values, list) else [values]
        cmp_value2 = [str(item) for item in cmp_value]
        service = None
        host_name = None
        self._reset_report_item(report_item)
        for item in self._workspaces:
            if service_port:
                service = self.create_service(session=session, workspace_str=item, port=service_port)
            if host_name_str:
                host_name = self.create_hostname(session=session, workspace_str=item, host_name=host_name_str)
            try:
                result = self._domain_utils.add_additional_info(session=session,
                                                                name=name,
                                                                values=values,
                                                                source=source,
                                                                service=service,
                                                                host_name=host_name,
                                                                report_item=report_item)
            except Exception as ex:
                if ex_message:
                    self.assertEqual(ex_message, str(ex))
                    return
                raise ex
            self.assertIsNone(ex_message)
            if values:
                self.assertIsNotNone(result)
            else:
                self.assertIsNone(result)
                return
            self.assertEqual(name, result.name)
            self.assertListEqual(cmp_value, result.values)
            if service:
                self.assertIsNotNone(result.service)
                self.assertIsNone(result.host_name)
                results = session.query(AdditionalInfo)\
                    .join(Service)\
                    .join(Host)\
                    .join(Workspace)\
                    .filter(AdditionalInfo.name == name,
                            AdditionalInfo._values.op('=')(cmp_value2),
                            Service.port == service_port,
                            Workspace.name == item).count()
                self.assertEqual(1, results)
                if source:
                    results = session.query(Source) \
                        .join((AdditionalInfo, Source.additional_info)) \
                        .join(Service) \
                        .join(Host) \
                        .join(Workspace) \
                        .filter(AdditionalInfo.name == name,
                                AdditionalInfo._values.op('=')(cmp_value2),
                                Service.port == service_port,
                                Workspace.name == item).count()
                    self.assertEqual(1, results)
            if host_name:
                info, domain = self.split_domain_name(host_name_str)
                self.assertIsNotNone(result.host_name)
                self.assertIsNone(result.service)
                results = session.query(AdditionalInfo) \
                    .join(HostName) \
                    .join(DomainName) \
                    .join(Workspace) \
                    .filter(AdditionalInfo.name == name,
                            AdditionalInfo._values.op('=')(cmp_value2),
                            HostName.name == info,
                            DomainName.name == domain,
                            Workspace.name == item).count()
                self.assertEqual(1, results)
                if source:
                    results = session.query(Source) \
                        .join((AdditionalInfo, Source.additional_info)) \
                        .join(HostName) \
                        .join(DomainName) \
                        .join(Workspace) \
                        .filter(AdditionalInfo.name == name,
                                AdditionalInfo._values.op('=')(cmp_value2),
                                HostName.name == info,
                                DomainName.name == domain,
                                Workspace.name == item).count()
                    self.assertEqual(1, results)
            if report_item:
                self.assertIn("{}: {}".format(name, ", ".join(values)), report_item.get_report())
        # we should have the same address in different workspaces
        results = session.query(AdditionalInfo)\
            .filter(AdditionalInfo.name == name,
                    AdditionalInfo._values.op('=')(cmp_value2)).count()
        self.assertEqual(len(self._workspaces), results)

    def _unittest_add_additional_info(self,
                                      name: str,
                                      values: List[str],
                                      service_port: int = None,
                                      host_name_str: str = None,
                                      ex_message: str = None) -> None:
        """
        Unittests for BaseUtils.add_additional_info
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            source = self.create_source(session)
            # without source and report item
            self._test_add_additional_info(session=session,
                                           name=name,
                                           values=values,
                                           service_port=service_port,
                                           host_name_str=host_name_str,
                                           ex_message=ex_message)
            self._test_add_additional_info(session=session,
                                           name=name,
                                           values=values,
                                           service_port=service_port,
                                           host_name_str=host_name_str,
                                           ex_message=ex_message,
                                           source=source)
            self._test_add_additional_info(session=session,
                                           name=name,
                                           values=values,
                                           service_port=service_port,
                                           host_name_str=host_name_str,
                                           ex_message=ex_message,
                                           report_item=self._report_item)
            self._test_add_additional_info(session=session,
                                           name=name,
                                           values=values,
                                           service_port=service_port,
                                           host_name_str=host_name_str,
                                           ex_message=ex_message,
                                           source=source,
                                           report_item=self._report_item)

    def test_add_additional_info_for_service(self):
        """
        Unittests for BaseUtils.add_additional_info
        :return
        """
        self._unittest_add_additional_info(name="test",
                                           values='1',
                                           service_port=443,
                                           host_name_str=None)
        self._unittest_add_additional_info(name="test",
                                           values=['1', '2'],
                                           service_port=443,
                                           host_name_str=None)
        self._unittest_add_additional_info(name="test",
                                           values=[],
                                           service_port=443,
                                           host_name_str=None)

    def test_add_additional_info_for_hostname(self):
        """
        Unittests for BaseUtils.add_additional_info
        :return
        """
        self._unittest_add_additional_info(name="test",
                                           values='1',
                                           service_port=None,
                                           host_name_str="www.test.com")
        self._unittest_add_additional_info(name="test",
                                           values=['1', '2'],
                                           service_port=None,
                                           host_name_str="www.test.com")
        self._unittest_add_additional_info(name="test",
                                           values=[],
                                           service_port=None,
                                           host_name_str="www.test.com")


class TestAddCommand(BaseKisTestCase):
    """
    This test case tests BaseUtils.add_command
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def _test_add_command(self,
                          session: Session,
                          command_str: List[str],
                          service_port: int,
                          network_str: str,
                          address: str,
                          host_name_str: str,
                          xml_file: str = None,
                          json_file: str = None,
                          output_path: str = None,
                          input_file: str = None,
                          binary_file: str = None,
                          ex_message: str = None) -> None:
        """
        This is a helper method for testing BaseUtils.add_command
        :return:
        """
        service = None
        network = None
        host = None
        host_name = None
        collector_name = None
        for item in self._workspaces:
            if service_port:
                collector_name = self.create_collector_name(session=session, type=CollectorType.host_service)
                service = self.create_service(session=session,
                                              workspace_str=item,
                                              port=service_port)
            if address:
                collector_name = self.create_collector_name(session=session, type=CollectorType.host)
                host = self.create_host(session=session,
                                        address=address,
                                        workspace_str=item)
            if network_str:
                collector_name = self.create_collector_name(session=session, type=CollectorType.network)
                network = self.create_network(session=session,
                                              network=network_str,
                                              workspace_str=item)
            if host_name_str:
                collector_name = self.create_collector_name(session=session, type=CollectorType.vhost_service)
                host_name = self.create_hostname(session=session,
                                                 workspace_str=item,
                                                 host_name=host_name_str)
            try:
                result = self._domain_utils.add_command(session=session,
                                                        os_command=command_str,
                                                        collector_name=collector_name,
                                                        service=service,
                                                        network=network,
                                                        host=host,
                                                        host_name=host_name,
                                                        xml_file=xml_file,
                                                        json_file=json_file,
                                                        output_path=output_path,
                                                        input_file=input_file,
                                                        binary_file=binary_file)
                self.assertIsNotNone(result)
            except Exception as ex:
                if ex_message:
                    self.assertEqual(ex_message, str(ex))
                    return
                raise ex
            self.assertIsNone(ex_message)
            self.assertListEqual(command_str, result.os_command)
            self.assertEqual(CommandStatus.pending, result.status)
            if xml_file:
                self.assertEqual(xml_file, result.execution_info[ExecutionInfoType.xml_output_file.name])
            if json_file:
                self.assertEqual(json_file, result.execution_info[ExecutionInfoType.json_output_file.name])
            if output_path:
                self.assertEqual(output_path, result.execution_info[ExecutionInfoType.output_path.name])
            if input_file:
                self.assertEqual(input_file, result.execution_info[ExecutionInfoType.input_file.name])
            if binary_file:
                self.assertEqual(binary_file, result.execution_info[ExecutionInfoType.binary_output_file.name])
            if service_port:
                self.assertIsNotNone(result.service)
                self.assertIsNotNone(result.host)
                self.assertIsNone(result.host_name)
                self.assertIsNone(result.ipv4_network)
                self.assertEqual(service_port, result.service.port)
                results = session.query(Command)\
                                .join((CollectorName, Command.collector_name))\
                                .join((Service, Command.service))\
                                .join((Host, Service.host))\
                                .join((Workspace, Host.workspace))\
                                .filter(Command.os_command.op("=")(command_str),
                                        Service.port == service_port,
                                        Workspace.name == item).all()
                self.assertEqual(1, len(results))
            if address:
                self.assertIsNone(result.service)
                self.assertIsNotNone(result.host)
                self.assertIsNone(result.host_name)
                self.assertIsNone(result.ipv4_network)
                self.assertEqual(address, result.host.address)
                results = session.query(Command) \
                    .join((CollectorName, Command.collector_name)) \
                    .join((Host, Command.host)) \
                    .join((Workspace, Host.workspace)) \
                    .filter(Command.os_command.op("=")(command_str),
                            Host.address == address,
                            Workspace.name == item).all()
                self.assertEqual(1, len(results))
            if network_str:
                self.assertIsNone(result.service)
                self.assertIsNone(result.host)
                self.assertIsNone(result.host_name)
                self.assertIsNotNone(result.ipv4_network)
                self.assertEqual(network_str, result.ipv4_network.network)
                results = session.query(Command) \
                    .join((CollectorName, Command.collector_name)) \
                    .join((Network, Command.ipv4_network)) \
                    .join((Workspace, Network.workspace)) \
                    .filter(Command.os_command.op("=")(command_str),
                            Network.network == network_str,
                            Workspace.name == item).all()
                self.assertEqual(1, len(results))
            if host_name_str:
                host_info, domain_info = self.split_domain_name(host_name_str)
                self.assertIsNone(result.service)
                self.assertIsNone(result.host)
                self.assertIsNotNone(result.host_name)
                self.assertIsNone(result.ipv4_network)
                self.assertEqual(host_name_str, result.host_name.full_name)
                results = session.query(Command) \
                    .join((HostName, Command.host_name)) \
                    .join(DomainName) \
                    .join(Workspace) \
                    .filter(Command.os_command.op("=")(command_str),
                            HostName.name == host_info,
                            DomainName.name == domain_info,
                            Workspace.name == item).all()
                self.assertEqual(1, len(results))
        # we should have the same address in different workspaces
        results = session.query(Command) \
            .join(CollectorName) \
            .filter(Command.os_command.op("=")(command_str)).count()
        self.assertEqual(len(self._workspaces), results)

    def _unittest_add_command(self,
                              command_str: List[str],
                              service_port: int = None,
                              network_str: str = None,
                              address: str = None,
                              host_name_str: str = None,
                              xml_file: str = None,
                              json_file: str = None,
                              output_path: str = None,
                              input_file: str = None,
                              binary_file: str = None,
                              ex_message: str = None) -> None:
        """
        Unittests for BaseUtils.add_command
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            # without source and report item
            self._test_add_command(session=session,
                                   command_str=command_str,
                                   service_port=service_port,
                                   network_str=network_str,
                                   address=address,
                                   host_name_str=host_name_str,
                                   xml_file=xml_file,
                                   json_file=json_file,
                                   output_path=output_path,
                                   input_file=input_file,
                                   binary_file=binary_file,
                                   ex_message=ex_message)
            self._test_add_command(session=session,
                                   command_str=command_str,
                                   service_port=service_port,
                                   network_str=network_str,
                                   address=address,
                                   host_name_str=host_name_str,
                                   xml_file=xml_file,
                                   json_file=json_file,
                                   output_path=output_path,
                                   input_file=input_file,
                                   binary_file=binary_file,
                                   ex_message=ex_message)

    def test_missing_service_host_host_name_ipv4network_exception(self):
        """
        Unittests for BaseUtils.add_command
        :return:
        """
        self._unittest_add_command(command_str=["sleep", "10"],
                                   service_port=80,
                                   address="192.168.1.1",
                                   ex_message="command must be assigned either to a service, host, host name or "
                                              "to an IPv4 network")
        self._unittest_add_command(command_str=["sleep", "10"],
                                   service_port=80,
                                   network_str="192.168.1.0/24",
                                   ex_message="command must be assigned either to a service, host, host name or "
                                              "to an IPv4 network")
        self._unittest_add_command(command_str=["sleep", "10"],
                                   service_port=80,
                                   host_name_str="www.test.com",
                                   ex_message="command must be assigned either to a service, host, host name or "
                                              "to an IPv4 network")
        self._unittest_add_command(command_str=["sleep", "10"],
                                   address="192.168.1.1",
                                   network_str="192.168.1.0/24",
                                   ex_message="command must be assigned either to a service, host, host name or "
                                              "to an IPv4 network")
        self._unittest_add_command(command_str=["sleep", "10"],
                                   address="192.168.1.1",
                                   host_name_str="www.test.com",
                                   ex_message="command must be assigned either to a service, host, host name or "
                                              "to an IPv4 network")
        self._unittest_add_command(command_str=["sleep", "10"],
                                   service_port=80,
                                   address="192.168.1.1",
                                   host_name_str="www.test.com",
                                   network_str="192.168.1.0/24",
                                   ex_message="command must be assigned either to a service, host, host name or "
                                              "to an IPv4 network")

    def test_add_command_service(self):
        """
        Unittests for BaseUtils.add_command
        :return
        """
        self._unittest_add_command(command_str=["sleep", "10"],
                                   service_port=80)
        self._unittest_add_command(command_str=["sleep", "10"],
                                   service_port=80,
                                   xml_file="/tmp/test.xml")
        self._unittest_add_command(command_str=["sleep", "10"],
                                   service_port=80,
                                   json_file="/tmp/test.json")
        self._unittest_add_command(command_str=["sleep", "10"],
                                   service_port=80,
                                   output_path="/tmp")
        self._unittest_add_command(command_str=["sleep", "10"],
                                   service_port=80,
                                   output_path="/doesnotexist")
        self._unittest_add_command(command_str=["sleep", "10"],
                                   service_port=80,
                                   input_file="/tmp/doesnotexist",
                                   ex_message="input file '/tmp/doesnotexist' does not exist")
        self._unittest_add_command(command_str=["sleep", "10"],
                                   service_port=80,
                                   input_file="/proc/version")
        self._unittest_add_command(command_str=["sleep", "10"],
                                   service_port=80,
                                   xml_file="/tmp/test.xml",
                                   json_file="/tmp/test.json",
                                   binary_file="/tmp/test.bin",
                                   output_path="/doesnotexist",
                                   input_file="/proc/version")

    def test_add_command_ipv4network(self):
        """
        Unittests for BaseUtils.add_command
        :return
        """
        self._unittest_add_command(command_str=["sleep", "10"],
                                   network_str="192.168.1.0/24")
        self._unittest_add_command(command_str=["sleep", "10"],
                                   network_str="192.168.1.0/24",
                                   xml_file="/tmp/test.xml")
        self._unittest_add_command(command_str=["sleep", "10"],
                                   network_str="192.168.1.0/24",
                                   json_file="/tmp/test.json")
        self._unittest_add_command(command_str=["sleep", "10"],
                                   network_str="192.168.1.0/24",
                                   binary_file="/tmp/test.bin")
        self._unittest_add_command(command_str=["sleep", "10"],
                                   network_str="192.168.1.0/24",
                                   output_path="/tmp")
        self._unittest_add_command(command_str=["sleep", "10"],
                                   network_str="192.168.1.0/24",
                                   output_path="/doesnotexist")
        self._unittest_add_command(command_str=["sleep", "10"],
                                   network_str="192.168.1.0/24",
                                   input_file="/tmp/doesnotexist",
                                   ex_message="input file '/tmp/doesnotexist' does not exist")
        self._unittest_add_command(command_str=["sleep", "10"],
                                   network_str="192.168.1.0/24",
                                   input_file="/proc/version")
        self._unittest_add_command(command_str=["sleep", "10"],
                                   network_str="192.168.1.0/24",
                                   xml_file="/tmp/test.xml",
                                   json_file="/tmp/test.json",
                                   output_path="/doesnotexist",
                                   input_file="/proc/version")

    def test_add_command_host(self):
        """
        Unittests for BaseUtils.add_command
        :return
        """
        self._unittest_add_command(command_str=["sleep", "10"],
                                   address="192.168.1.1")
        self._unittest_add_command(command_str=["sleep", "10"],
                                   address="192.168.1.1",
                                   xml_file="/tmp/test.xml")
        self._unittest_add_command(command_str=["sleep", "10"],
                                   address="192.168.1.1",
                                   json_file="/tmp/test.json")
        self._unittest_add_command(command_str=["sleep", "10"],
                                   address="192.168.1.1",
                                   output_path="/tmp")
        self._unittest_add_command(command_str=["sleep", "10"],
                                   address="192.168.1.1",
                                   output_path="/doesnotexist")
        self._unittest_add_command(command_str=["sleep", "10"],
                                   address="192.168.1.1",
                                   input_file="/tmp/doesnotexist",
                                   ex_message="input file '/tmp/doesnotexist' does not exist")
        self._unittest_add_command(command_str=["sleep", "10"],
                                   address="192.168.1.1",
                                   input_file="/proc/version")
        self._unittest_add_command(command_str=["sleep", "10"],
                                   address="192.168.1.1",
                                   xml_file="/tmp/test.xml",
                                   json_file="/tmp/test.json",
                                   output_path="/doesnotexist",
                                   input_file="/proc/version")

    def test_add_command_host_name(self):
        """
        Unittests for BaseUtils.add_command
        :return
        """
        self._unittest_add_command(command_str=["sleep", "10"],
                                   host_name_str="www.test.com")
        self._unittest_add_command(command_str=["sleep", "10"],
                                   host_name_str="www.test.com",
                                   xml_file="/tmp/test.xml")
        self._unittest_add_command(command_str=["sleep", "10"],
                                   host_name_str="www.test.com",
                                   json_file="/tmp/test.json")
        self._unittest_add_command(command_str=["sleep", "10"],
                                   host_name_str="www.test.com",
                                   output_path="/tmp")
        self._unittest_add_command(command_str=["sleep", "10"],
                                   host_name_str="www.test.com",
                                   output_path="/doesnotexist")
        self._unittest_add_command(command_str=["sleep", "10"],
                                   host_name_str="www.test.com",
                                   input_file="/tmp/doesnotexist",
                                   ex_message="input file '/tmp/doesnotexist' does not exist")
        self._unittest_add_command(command_str=["sleep", "10"],
                                   host_name_str="www.test.com",
                                   input_file="/proc/version")
        self._unittest_add_command(command_str=["sleep", "10"],
                                   host_name_str="www.test.com",
                                   xml_file="/tmp/test.xml",
                                   json_file="/tmp/test.json",
                                   output_path="/doesnotexist",
                                   input_file="/proc/version")


class TestAddHint(BaseKisTestCase):
    """
    This test case tests BaseUtils.add_hint
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def _test_add_hint(self,
                       session: Session,
                       hint: str,
                       expected_count: int,
                       report_item: ReportItem = None) -> None:
        """
        This is a helper method for testing BaseUtils.add_hint
        :return:
        """
        self._reset_report_item(report_item)
        for item in self._workspaces:
            command = self.create_command(session=session,
                                          workspace_str=item)
            self._domain_utils.add_hint(command=command,
                                        hint=hint,
                                        report_item=report_item)
            self.assertEqual(expected_count, len(command.hint))
            if report_item:
                self.assertEqual(hint, report_item.details)

    def _unittest_add_hint(self,
                           hint: str = None,
                           expected_count: int = 0) -> None:
        """
        Unittests for BaseUtils.add_command
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self._test_add_hint(session=session,
                                hint=hint,
                                expected_count=expected_count)
            self._test_add_hint(session=session,
                                hint=hint,
                                expected_count=expected_count,
                                report_item=self._report_item)

    def test_add_hint(self) -> None:
        """
        Unittests for BaseUtils.add_command
        :return:
        """
        self._unittest_add_hint(hint=None, expected_count=0)
        self._unittest_add_hint(hint="test hint", expected_count=2)


class TestAddJsonResults(BaseKisTestCase):
    """
    This test case tests BaseUtils.add_json_results
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def _test_add_json_results(self,
                               session: Session,
                               json_objects: Dict[str, str],
                               expected_count: int) -> None:
        """
        This is a helper method for testing BaseUtils.add_json_results
        :return:
        """
        for item in self._workspaces:
            command = self.create_command(session=session,
                                          workspace_str=item)

            self._domain_utils.add_json_results(command=command,
                                                json_objects=json_objects)
            self.assertEqual(expected_count, len(command.json_output))

    def _unittest_add_json_results(self,
                                   json_objects: Dict[str, str],
                                   expected_count: int) -> None:
        """
        Unittests for BaseUtils.add_json_results
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self._test_add_json_results(session=session,
                                        json_objects=json_objects,
                                        expected_count=expected_count)
            self._test_add_json_results(session=session,
                                        json_objects=json_objects,
                                        expected_count=expected_count)

    def test_add_json_results(self) -> None:
        """
        Unittests for BaseUtils.add_json_results
        :return:
        """
        json_object = {'test': [{'blob1': {'a': 1, 'b': 2}}, {'blob2': [3, 4, 5], 'b': 4}], 'mac': 'abcdef'}
        self._unittest_add_json_results(json_objects=None, expected_count=0)
        self._unittest_add_json_results(json_objects=json_object, expected_count=1)
        self._unittest_add_json_results(json_objects=[json_object, json_object], expected_count=1)
        self._unittest_add_json_results(json_objects=[json_object, {}], expected_count=1)
        self._unittest_add_json_results(json_objects=[json_object, {}, {"a": 1}], expected_count=2)


class TestAddFile(BaseKisTestCase):
    """
    This test case tests BaseUtils.add_file
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def _test_add_file(self,
                       session: Session,
                       file_path: str,
                       file_type: FileType = None,
                       file_content: bytes = None,
                       sha256_value: str = None,
                       ex_message: str = None) -> None:
        """
        This is a helper method for testing BaseUtils.add_file
        :return:
        """
        for item in self._workspaces:
            workspace = self.create_workspace(session=session,
                                              workspace=item)
            command = self.create_command(session=session,
                                          workspace_str=item)
            try:
                file = self._domain_utils.add_file(session=session,
                                                   command=command,
                                                   workspace=workspace,
                                                   file_path=file_path,
                                                   file_type=file_type)
                self.assertIsNotNone(file)
                self.assertEqual(sha256_value, file.sha256_value)
                self.assertEqual(file_type, file.type)
                self.assertEqual(file_content, file.content)
            except FileNotFoundError as ex:
                if ex_message:
                    self.assertEqual(ex_message, str(ex))
                    return
                raise ex
        self.assertEqual(2, session.query(File).count())
        for item in self._workspaces:
            results = session.query(File) \
                            .join(Workspace) \
                            .filter(File.sha256_value == sha256_value,
                                    File.type == file_type,
                                    Workspace.name == item).all()
            self.assertEqual(1, len(results))

    def _unittest_add_file(self,
                           file_path: str,
                           file_type: FileType = None,
                           file_content: bytes = None,
                           sha256_value: str = None,
                           ex_message: str = None) -> None:
        """
        Unittests for BaseUtils.add_file
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self._test_add_file(session=session,
                                file_path=file_path,
                                file_type=file_type,
                                file_content=file_content,
                                sha256_value=sha256_value,
                                ex_message=ex_message)
            self._test_add_file(session=session,
                                file_path=file_path,
                                file_type=file_type,
                                file_content=file_content,
                                sha256_value=sha256_value,
                                ex_message=ex_message)

    def test_add_hint(self) -> None:
        """
        Unittests for BaseUtils.add_file
        :return:
        """
        with tempfile.NamedTemporaryFile(mode="wb") as file:
            file_content = "test".encode()
            sha256_sum = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
            file.write(file_content)
            file.flush()
            self._unittest_add_file(file_path=file.name,
                                    file_type=FileType.screenshot,
                                    file_content=file_content,
                                    sha256_value=sha256_sum)
        self._unittest_add_file(file_path="/tmp",
                                file_type=FileType.screenshot,
                                ex_message="file '/tmp' does not exist")


class TestAddUrl(BaseKisTestCase):
    """
    This test case tests BaseUtils.add_url
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def _test_add_url(self,
                      session: Session,
                      service_port: int = None,
                      url_str: str = None,
                      expected_url_str: str = None,
                      status_code: int = None,
                      size_bytes: int = None,
                      source: Source = None,
                      report_item: ReportItem = None) -> None:
        """
        This is a helper method for testing BaseUtils.add_url
        :return:
        """
        url = urlparse(expected_url_str)
        report_item = self._reset_report_item(report_item)
        for item in self._workspaces:
            service = self.create_service(session=session,
                                          workspace_str=item,
                                          port=service_port)
            result = self._domain_utils.add_url(session=session,
                                                service=service,
                                                url=url_str,
                                                status_code=status_code,
                                                size_bytes=size_bytes,
                                                source=source,
                                                report_item=report_item)
            if url.path:
                self.assertIsNotNone(result)
                self.assertIsNotNone(result.service)
                self.assertEqual(service.id, result.service_id)
                # Check path settings
                results = session.query(Path) \
                    .join(Service) \
                    .join(Host) \
                    .join(Workspace) \
                    .filter(Path.name == url.path,
                            Path.size_bytes == size_bytes,
                            Path.return_code == status_code,
                            Service.port == service_port,
                            Workspace.name == item).count()
                self.assertEqual(1, results)
            else:
                self.assertIsNone(result)
            if url.query:
                # Check query settings
                results = session.query(HttpQuery) \
                    .join(Path) \
                    .join(Service) \
                    .join(Host) \
                    .join(Workspace) \
                    .filter(HttpQuery.query == url.query,
                            Path.name == url.path,
                            Path.size_bytes == size_bytes,
                            Path.return_code == status_code,
                            Service.port == service_port,
                            Workspace.name == item).count()
                self.assertEqual(1, results)
            if source:
                # Check source settings
                results = session.query(Source) \
                    .join((Path, Source.paths)) \
                    .join(Service) \
                    .join(Host) \
                    .join(Workspace) \
                    .filter(Path.name == url.path,
                            Path.size_bytes == size_bytes,
                            Path.return_code == status_code,
                            Service.port == service_port,
                            Source.name == source.name,
                            Workspace.name == item).count()
                self.assertEqual(1 if url.path else 0, results)
            if report_item and result:
                if size_bytes and status_code:
                    self.assertIn("potentially new path/file: {} (status: {}, size: {})".format(url.path,
                                                                                                status_code,
                                                                                                size_bytes),
                                  report_item.get_report())
                elif not size_bytes and status_code:
                    self.assertIn("potentially new path/file: {} (status: {})".format(url.path, status_code),
                                  report_item.get_report())
                elif size_bytes and not status_code:
                    self.assertIn("potentially new path/file: {} (size: {})".format(url.path, size_bytes),
                                  report_item.get_report())
                else:
                    self.assertTrue("potentially new path/file: {}".format(url.path) in report_item.get_report())
        results = session.query(Path) \
            .join(Service) \
            .filter(Path.name == url.path,
                    Path.size_bytes == size_bytes,
                    Path.return_code == status_code,
                    Service.port == service_port).count()
        self.assertEqual(len(self._workspaces) if url.path else 0, results)

    def _unittest_add_url(self,
                          service_port: int = None,
                          url_str: str = None,
                          expected_url_str: str = None,
                          status_code: int = None,
                          size_bytes: int = None) -> None:
        """
        Unittests for BaseUtils.add_url
        :return:
        """
        expected_url_str = expected_url_str if expected_url_str else url_str
        self.init_db()
        with self._engine.session_scope() as session:
            source = self.create_source(session)
            # without source and report item
            self._test_add_url(session=session,
                               service_port=service_port,
                               url_str=url_str,
                               expected_url_str=expected_url_str,
                               status_code=status_code,
                               size_bytes=size_bytes)
            # with source
            self._test_add_url(session=session,
                               service_port=service_port,
                               url_str=url_str,
                               expected_url_str=expected_url_str,
                               status_code=status_code,
                               size_bytes=size_bytes,
                               source=source)
            # with report item
            self._test_add_url(session=session,
                               service_port=service_port,
                               url_str=url_str,
                               expected_url_str=expected_url_str,
                               status_code=status_code,
                               size_bytes=size_bytes,
                               source=source,
                               report_item=self._report_item)
            # with source and report item
            self._test_add_url(session=session,
                               service_port=service_port,
                               url_str=url_str,
                               expected_url_str=expected_url_str,
                               status_code=status_code,
                               size_bytes=size_bytes,
                               source=source)

    def test_add_url_path(self):
        """
        Unittests for BaseUtils.add_url
        :return
        """
        self._unittest_add_url(service_port=80,
                               url_str="https://192.168.1.1",)
        self._unittest_add_url(service_port=80,
                               url_str="https://192.168.1.1/manager/status",)
        self._unittest_add_url(service_port=80,
                               url_str="https://192.168.1.1/manager/status",
                               status_code=200)
        self._unittest_add_url(service_port=80,
                               url_str="https://192.168.1.1/manager/status",
                               size_bytes=1024)
        self._unittest_add_url(service_port=80,
                               url_str="https://192.168.1.1/manager/status",
                               status_code=200,
                               size_bytes=1024)

    def test_add_url_query(self):
        """
        Unittests for BaseUtils.add_url
        :return
        """
        self._unittest_add_url(service_port=80,
                               url_str="https://192.168.1.1/manager/status?a=b&c=d")
        self._unittest_add_url(service_port=80,
                               url_str="https://192.168.1.1/?a=b&c=d")
        self._unittest_add_url(service_port=80,
                               url_str="https://192.168.1.1?a=b&c=d",
                               expected_url_str="https://192.168.1.1/?a=b&c=d")
        self._unittest_add_url(service_port=80,
                               url_str="https://192.168.1.1?a=b&c=d",
                               expected_url_str="https://192.168.1.1/?a=b&c=d",
                               status_code=200)
        self._unittest_add_url(service_port=80,
                               url_str="https://192.168.1.1?a=b&c=d",
                               expected_url_str="https://192.168.1.1/?a=b&c=d",
                               size_bytes=2048)
        self._unittest_add_url(service_port=80,
                               url_str="https://192.168.1.1?a=b&c=d",
                               expected_url_str="https://192.168.1.1/?a=b&c=d",
                               status_code=100,
                               size_bytes=2048)


class TestAddHostHostNameMapping(BaseKisTestCase):
    """
    This test case tests BaseUtils.add_host_host_name_mapping
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def _test_host_host_name_mapping(self,
                                     session: Session,
                                     address: str = None,
                                     host_name_str: str = None,
                                     mapping_type: DnsResourceRecordType = None,
                                     source: Source = None,
                                     report_item: ReportItem = None,
                                     ex_message: str = None) -> None:
        """
        This is a helper method for testing BaseUtils.add_host_host_name_mapping
        :return:
        """
        host = None
        host_name = None
        if host_name_str:
            host_name = self.create_hostname(session=session, host_name=host_name_str)
        if address:
            host = self.create_host(session=session, address=address)
        try:
            result = self._domain_utils.add_host_host_name_mapping(session=session,
                                                                   host=host,
                                                                   host_name=host_name,
                                                                   source=source,
                                                                   mapping_type=mapping_type,
                                                                   report_item=report_item)
            self.assertIsNotNone(result)
            session.commit()
        except Exception as ex:
            if ex_message:
                self.assertEqual(ex_message, str(ex))
                return
            raise ex
        self.assertIsNotNone(result.host_name)
        self.assertEqual(host_name_str, result.host_name.full_name)
        self.assertIsNotNone(result.host)
        self.assertEqual(address, result.host.address)
        if mapping_type:
            self.assertIsNotNone(mapping_type, result.type)
            self.assertEqual(mapping_type, host.host_host_name_mappings[0].type)
            self.assertEqual(mapping_type, host_name.host_host_name_mappings[0].type)
        else:
            self.assertEqual(DnsResourceRecordType(0), result.type)
        if source:
            self.assertEqual(source.name, host.host_host_name_mappings[0].sources[0].name)
            self.assertEqual(source.name, host_name.host_host_name_mappings[0].sources[0].name)
        else:
            self.assertEqual(0, len(result.sources))
        if report_item:
            self.assertIn("add potentially new link (A) between {} and {}".format(host.address,
                                                                                  host_name.full_name),
                          report_item.get_report())

    def _unittest_add_host_host_name_mapping(self,
                                             address: str = None,
                                             host_name_str: str = None,
                                             mapping_type: DnsResourceRecordType = DnsResourceRecordType.a,
                                             ex_message: str = None) -> None:
        """
        Unittests for BaseUtils.add_host_host_name_mapping
        :return:
        """
        # Without source and report item
        self.init_db()
        with self._engine.session_scope() as session:
            self._test_host_host_name_mapping(session=session,
                                              address=address,
                                              host_name_str=host_name_str,
                                              mapping_type=mapping_type,
                                              ex_message=ex_message)
        # With source
        self.init_db()
        with self._engine.session_scope() as session:
            source = self.create_source(session)
            self._test_host_host_name_mapping(session=session,
                                              address=address,
                                              host_name_str=host_name_str,
                                              mapping_type=mapping_type,
                                              source=source,
                                              ex_message=ex_message)
        # With report item
        self.init_db()
        with self._engine.session_scope() as session:
            self._test_host_host_name_mapping(session=session,
                                              address=address,
                                              host_name_str=host_name_str,
                                              mapping_type=mapping_type,
                                              report_item=self._report_item,
                                              ex_message=ex_message)
        # With source and report item
        self.init_db()
        with self._engine.session_scope() as session:
            source = self.create_source(session)
            self._test_host_host_name_mapping(session=session,
                                              address=address,
                                              host_name_str=host_name_str,
                                              mapping_type=mapping_type,
                                              source=source,
                                              report_item=self._report_item,
                                              ex_message=ex_message)

    def test_without_host_and_host_name_exception(self):
        """
        Unittests for BaseUtils.add_host_host_name_mapping
        :return:
        """
        self._unittest_add_host_host_name_mapping(ex_message="host and host name are mandatory")
        self._unittest_add_host_host_name_mapping(address="192.168.1.1",
                                                  ex_message="host and host name are mandatory")
        self._unittest_add_host_host_name_mapping(host_name_str="www.unittest.com",
                                                  ex_message="host and host name are mandatory")

    def test_host_and_host_name(self):
        """
        Unittests for BaseUtils.add_host_host_name_mapping
        :return:
        """
        self._unittest_add_host_host_name_mapping(address="192.168.1.1",
                                                  host_name_str="www.unittest.com")
        self._unittest_add_host_host_name_mapping(address="192.168.1.1",
                                                  host_name_str="www.unittest.com",
                                                  mapping_type=DnsResourceRecordType.a)

    def _test_type_update(self,
                          type_first_update: DnsResourceRecordType,
                          type_second_update: DnsResourceRecordType,
                          host_scope: ScopeType,
                          host_name_scope: ScopeType):
        self.init_db()
        # setup database
        with self._engine.session_scope() as session:
            self.create_network(session=session,
                                workspace_str=self._workspaces[0],
                                network="192.168.1.0/24",
                                scope=host_scope)
            host_name = self.create_hostname(session=session,
                                             workspace_str=self._workspaces[0],
                                             host_name="www.test.com",
                                             scope=host_name_scope)
            host = self.create_host(session=session,
                                    workspace_str=self._workspaces[0],
                                    address="192.168.1.0")
            source = self.create_source(session=session, source_str="test")
            result = self._domain_utils.add_host_host_name_mapping(session=session,
                                                                   host=host,
                                                                   host_name=host_name,
                                                                   source=source,
                                                                   mapping_type=type_first_update)
            self.assertIsNotNone(result)
            self.assertTrue(bool(result.type & type_first_update))
        # check database
        with self._engine.session_scope() as session:
            result = session.query(HostHostNameMapping).one()
            if bool(type_first_update & DnsResourceRecordType.a):
                self.assertEqual((host_scope == ScopeType.all),
                                 result.resolves_to_in_scope_ipv4_address())
                self.assertEqual((host_scope == ScopeType.all) and (host_name_scope == ScopeType.all),
                                 result.host_name.in_scope(CollectorType.vhost_service))
            else:
                self.assertFalse(result.resolves_to_in_scope_ipv4_address())
                self.assertFalse(result.host_name.in_scope(CollectorType.vhost_service))
            self.assertEqual((host_name_scope == ScopeType.all),
                             result.host_name.in_scope(CollectorType.domain))
            # update mapping
            host_name = self.create_hostname(session=session,
                                             workspace_str=self._workspaces[0],
                                             host_name="www.test.com",
                                             scope=host_name_scope)
            host = self.create_host(session=session,
                                    workspace_str=self._workspaces[0],
                                    address="192.168.1.0")
            result = self._domain_utils.add_host_host_name_mapping(session=session,
                                                                   host=host,
                                                                   host_name=host_name,
                                                                   mapping_type=type_second_update)
            session.flush()
            self.assertIsNotNone(result)
        # check database
        with self._engine.session_scope() as session:
            result = session.query(HostHostNameMapping).one()
            self.assertEqual((host_scope == ScopeType.all),
                             result.resolves_to_in_scope_ipv4_address())
            self.assertEqual((host_scope == ScopeType.all and host_name_scope == ScopeType.all),
                             result.host_name.in_scope(CollectorType.vhost_service))
            self.assertEqual((host_name_scope == ScopeType.all),
                             result.host_name.in_scope(CollectorType.domain))

    def test_type_update_ptr_and_then_a(self):
        # Without source and report item
        self._test_type_update(type_first_update=DnsResourceRecordType.ptr,
                               type_second_update=DnsResourceRecordType.a,
                               host_name_scope=ScopeType.all,
                               host_scope=ScopeType.all)
        self._test_type_update(type_first_update=DnsResourceRecordType.ptr,
                               type_second_update=DnsResourceRecordType.a,
                               host_name_scope=ScopeType.exclude,
                               host_scope=ScopeType.all)
        self._test_type_update(type_first_update=DnsResourceRecordType.ptr,
                               type_second_update=DnsResourceRecordType.a,
                               host_name_scope=ScopeType.all,
                               host_scope=ScopeType.exclude)
        self._test_type_update(type_first_update=DnsResourceRecordType.ptr,
                               type_second_update=DnsResourceRecordType.a,
                               host_name_scope=ScopeType.exclude,
                               host_scope=ScopeType.exclude)

    def test_type_update_a_and_then_ptr(self):
        # Without source and report item
        self._test_type_update(type_first_update=DnsResourceRecordType.a,
                               type_second_update=DnsResourceRecordType.ptr,
                               host_name_scope=ScopeType.all,
                               host_scope=ScopeType.all)
        self._test_type_update(type_first_update=DnsResourceRecordType.a,
                               type_second_update=DnsResourceRecordType.ptr,
                               host_name_scope=ScopeType.exclude,
                               host_scope=ScopeType.all)
        self._test_type_update(type_first_update=DnsResourceRecordType.a,
                               type_second_update=DnsResourceRecordType.ptr,
                               host_name_scope=ScopeType.all,
                               host_scope=ScopeType.exclude)
        self._test_type_update(type_first_update=DnsResourceRecordType.a,
                               type_second_update=DnsResourceRecordType.ptr,
                               host_name_scope=ScopeType.exclude,
                               host_scope=ScopeType.exclude)

    def test_mixed_types(self):
        self.init_db()
        # initialize database
        with self._engine.session_scope() as session:
            workspace = self._domain_utils.add_workspace(session, self._workspaces[0])
            host = self._ip_utils.add_host(session=session,
                                           workspace=workspace,
                                           address="192.168.1.1")
            host_name = self._domain_utils.add_domain_name(session=session,
                                                           workspace=workspace,
                                                           item="www.unittest.com",
                                                           scope=ScopeType.all)
            self._domain_utils.add_host_host_name_mapping(session=session,
                                                          host=host,
                                                          host_name=host_name,
                                                          mapping_type=(DnsResourceRecordType.a |
                                                                         DnsResourceRecordType.ptr))
        # check database
        with self._engine.session_scope() as session:
            host_name = session.query(HostName).filter(HostName.name.isnot(None)).one()
            results = host_name.get_host_host_name_mappings(types=[DnsResourceRecordType.a, DnsResourceRecordType.ptr])
            self.assertEqual(1, len(results))
            self.assertEqual("A, PTR", results[0].type_str)
            host = host_name.host_host_name_mappings[0].host
            results = host.get_host_host_name_mappings(types=[DnsResourceRecordType.a, DnsResourceRecordType.ptr])
            self.assertEqual(1, len(results))
            self.assertEqual("A, PTR", results[0].type_str)


class TestAddHostNameHostNameMapping(BaseKisTestCase):
    """
    This test case tests BaseUtils.add_host_name_host_name_mapping
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def _test_host_name_host_name_mapping(self,
                                          session: Session,
                                          source_host_name_str: str = None,
                                          resolved_host_name_str: str = None,
                                          mapping_type: DnsResourceRecordType = None,
                                          source: Source = None,
                                          report_item: ReportItem = None,
                                          ex_message: str = None) -> None:
        """
        This is a helper method for testing BaseUtils.add_host_name_host_name_mapping
        :return:
        """
        source_host_name = None
        resolved_host_name = None
        if source_host_name_str:
            source_host_name = self.create_hostname(session=session, host_name=source_host_name_str)
        if resolved_host_name_str:
            resolved_host_name = self.create_hostname(session=session, host_name=resolved_host_name_str)
        try:
            result = self._domain_utils.add_host_name_host_name_mapping(session=session,
                                                                        source_host_name=source_host_name,
                                                                        resolved_host_name=resolved_host_name,
                                                                        source=source,
                                                                        mapping_type=mapping_type,
                                                                        report_item=report_item)
            self.assertIsNotNone(result)
            session.commit()
        except Exception as ex:
            if ex_message:
                self.assertEqual(ex_message, str(ex))
                return
            raise ex
        self.assertIsNotNone(result.source_host_name)
        self.assertEqual(source_host_name_str, result.source_host_name.full_name)
        self.assertIsNotNone(result.resolved_host_name)
        self.assertEqual(resolved_host_name_str, result.resolved_host_name.full_name)
        if mapping_type:
            self.assertIsNotNone(mapping_type, result.type)
            self.assertEqual(mapping_type, source_host_name.resolved_host_name_mappings[0].type)
            self.assertEqual(mapping_type, resolved_host_name.source_host_name_mappings[0].type)
        else:
            self.assertEqual(DnsResourceRecordType(0), result.type)
        if source:
            self.assertEqual(source.name, source_host_name.resolved_host_name_mappings[0].sources[0].name)
            self.assertEqual(source.name, resolved_host_name.source_host_name_mappings[0].sources[0].name)
        else:
            self.assertEqual(0, len(result.sources))
        if report_item:
            self.assertIn("add potentially new link between {} and {}".format(source_host_name.full_name,
                                                                              resolved_host_name.full_name),
                          report_item.get_report())

    def _unittest_add_host_name_host_name_mapping(self,
                                                  source_host_name_str: str = None,
                                                  resolved_host_name_str: str = None,
                                                  mapping_type: DnsResourceRecordType = None,
                                                  ex_message: str = None) -> None:
        """
        Unittests for BaseUtils.add_host_host_name_mapping
        :return:
        """
        # Without source and report item
        self.init_db()
        with self._engine.session_scope() as session:
            self._test_host_name_host_name_mapping(session=session,
                                                   source_host_name_str=source_host_name_str,
                                                   resolved_host_name_str=resolved_host_name_str,
                                                   mapping_type=mapping_type,
                                                   ex_message=ex_message)
        # With source
        self.init_db()
        with self._engine.session_scope() as session:
            source = self.create_source(session)
            self._test_host_name_host_name_mapping(session=session,
                                                   source_host_name_str=source_host_name_str,
                                                   resolved_host_name_str=resolved_host_name_str,
                                                   mapping_type=mapping_type,
                                                   source=source,
                                                   ex_message=ex_message)
        # With report item
        self.init_db()
        with self._engine.session_scope() as session:
            self._test_host_name_host_name_mapping(session=session,
                                                   source_host_name_str=source_host_name_str,
                                                   resolved_host_name_str=resolved_host_name_str,
                                                   mapping_type=mapping_type,
                                                   report_item=self._report_item,
                                                   ex_message=ex_message)
        # With source and report item
        self.init_db()
        with self._engine.session_scope() as session:
            source = self.create_source(session)
            self._test_host_name_host_name_mapping(session=session,
                                                   source_host_name_str=source_host_name_str,
                                                   resolved_host_name_str=resolved_host_name_str,
                                                   mapping_type=mapping_type,
                                                   source=source,
                                                   report_item=self._report_item,
                                                   ex_message=ex_message)

    def test_without_host_name_and_host_name_exception(self):
        """
        Unittests for BaseUtils.add_host_host_name_mapping
        :return:
        """
        self._unittest_add_host_name_host_name_mapping(ex_message="source and resolved host names are mandatory")
        self._unittest_add_host_name_host_name_mapping(source_host_name_str="www.unittest.com",
                                                       ex_message="source and resolved host names are mandatory")
        self._unittest_add_host_name_host_name_mapping(resolved_host_name_str="www.unittest.com",
                                                       ex_message="source and resolved host names are mandatory")

    def test_host_name_and_host_name(self):
        """
        Unittests for BaseUtils.add_host_host_name_mapping
        :return:
        """
        self._unittest_add_host_name_host_name_mapping(source_host_name_str="www.unittest1.com",
                                                       resolved_host_name_str="www.unittest2.com")
        self._unittest_add_host_name_host_name_mapping(source_host_name_str="www.unittest1.com",
                                                       resolved_host_name_str="www.unittest2.com",
                                                       mapping_type=DnsResourceRecordType.a)


class TestAddCertificate(BaseKisTestCase):
    """
    This test case tests BaseUtils.add_certificate
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)
        self._certificate = """-----BEGIN CERTIFICATE-----
MIIEvjCCA6agAwIBAgIQAaeKf167t7oCAAAAAEL/7TANBgkqhkiG9w0BAQsFADBC
MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVR29vZ2xlIFRydXN0IFNlcnZpY2VzMRMw
EQYDVQQDEwpHVFMgQ0EgMU8xMB4XDTE5MDkwNTIwMjEyNFoXDTE5MTEyODIwMjEy
NFowaDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcT
DU1vdW50YWluIFZpZXcxEzARBgNVBAoTCkdvb2dsZSBMTEMxFzAVBgNVBAMTDnd3
dy5nb29nbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFozpcPL0RPFq
PdxpYCEudxkn/IWJU5JU81Dqp1psOvVqWHB8TcvLlscPbx04BNsJZsZaSSQF5Ky0
SeJchxHrL6OCAlMwggJPMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEF
BQcDATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBSvLWUz0DGNZtkyyKkyvQ6rfHKS
TDAfBgNVHSMEGDAWgBSY0fhuEOvPm+xgnxiQG6DrfQn9KzBkBggrBgEFBQcBAQRY
MFYwJwYIKwYBBQUHMAGGG2h0dHA6Ly9vY3NwLnBraS5nb29nL2d0czFvMTArBggr
BgEFBQcwAoYfaHR0cDovL3BraS5nb29nL2dzcjIvR1RTMU8xLmNydDAZBgNVHREE
EjAQgg53d3cuZ29vZ2xlLmNvbTAhBgNVHSAEGjAYMAgGBmeBDAECAjAMBgorBgEE
AdZ5AgUDMC8GA1UdHwQoMCYwJKAioCCGHmh0dHA6Ly9jcmwucGtpLmdvb2cvR1RT
MU8xLmNybDCCAQMGCisGAQQB1nkCBAIEgfQEgfEA7wB2AGPy283oO8wszwtyhCdX
azOkjWF3j711pjixx2hUS9iNAAABbQNNrJ0AAAQDAEcwRQIgTSJms2pYhhK9fqeT
FxFez+JhDdItCIQQWgzaBPkJv/oCIQCLfR4jtnTlM4Q+3DsnJkUpOLyVGe1+szyo
3iGIVKtrnwB1AHR+2oMxrTMQkSGcziVPQnDCv/1eQiAIxjc1eeYQe8xWAAABbQNN
rLoAAAQDAEYwRAIgTz5ZYxnof80pqG73hkNRX8ypL7Zhawts2vNE/rhOHIQCIAfn
IxrHwf9Jx0DyD7A4cjtgaunpuAy8ICUjysICyQ16MA0GCSqGSIb3DQEBCwUAA4IB
AQBEKhT92shr4RdM4Yc26VkNOxR4FjbDJHRltJkrxIu/VwFdyrsRfA3WtawRl7xM
27C99PvwS2Z6XzqKM+GuxfS5qBRxV3RTQVFDeJYgXqkXwCT1YnpRo98cDcBcOlac
rXz+3KzDWrz323xG8NyYSoqDtDUvUF5B0JttNYh2UuxVh3yqOmYjEQvH0kxp+Elc
LV7Xq47alFBvD8nLARX9mqLFXjaiMNLPihX/Oo3AJd+kXuDeJz6igUsf9UeIcbRc
4ZOLQk5ysB/+k9B8w3B2DIXMyy+UWt3XNX7pKMDVEhLm2esXAsjgMziu0n3UwLKG
1KJj8WrPtP2Xvq/dixvp08ui
-----END CERTIFICATE-----"""

    def _test_add_certificate(self,
                              session: Session,
                              type: CertType,
                              content: str,
                              service_port: int = None,
                              host_name_str: str = None,
                              company_name_str: str = None,
                              source: Source = None,
                              report_item: ReportItem = None) -> None:
        """
        This is a helper method for testing BaseUtils.add_certificate
        :return:
        """
        self._reset_report_item(report_item)
        for item in self._workspaces:
            if service_port:
                command = self.create_command(session=session,
                                              workspace_str=item,
                                              command=["nikto", "https://127.0.0.1"],
                                              collector_name_str="nikto",
                                              collector_name_type=CollectorType.host_service,
                                              service_port=service_port)
            elif host_name_str:
                command = self.create_command(session=session,
                                              workspace_str=item,
                                              host_name_str=host_name_str)
            else:
                command = self.create_command(session=session,
                                              workspace_str=item,
                                              company_name_str=company_name_str)
                company_name_str = company_name_str.lower()
            result = self._domain_utils.add_certificate(session=session,
                                                        command=command,
                                                        content=content,
                                                        type=type,
                                                        source=source,
                                                        report_item=report_item)
            self.assertIsNotNone(result)
            session.commit()
            if service_port:
                result = session.query(CertInfo) \
                    .filter(CertInfo.serial_number == "2199150634980703004737029206949691373",
                            CertInfo.service_id == command.service.id).one()
                self.assertIsNotNone(result)
            elif host_name_str:
                result = session.query(CertInfo) \
                    .filter(CertInfo.serial_number == "2199150634980703004737029206949691373",
                            CertInfo.host_name_id == command.host_name.id).one()
                self.assertIsNotNone(result)
            elif company_name_str:
                result = session.query(CertInfo) \
                    .filter(CertInfo.serial_number == "2199150634980703004737029206949691373",
                            CertInfo.company_id == command.company.id).one()
                self.assertIsNotNone(result)

    def _unittest_add_certificate(self,
                                  type: CertType,
                                  content: str,
                                  service_port: int = None,
                                  host_name_str: str = None,
                                  company_name_str: str = None) -> None:
        """
        Unittests for BaseUtils.add_certificate
        :return:
        """
        # without source and report item
        self.init_db()
        with self._engine.session_scope() as session:
            self._test_add_certificate(session=session,
                                       type=type,
                                       content=content,
                                       service_port=service_port,
                                       host_name_str=host_name_str,
                                       company_name_str=company_name_str)
        # with source
        self.init_db()
        with self._engine.session_scope() as session:
            source = self.create_source(session)
            self._test_add_certificate(session=session,
                                       type=type,
                                       content=content,
                                       service_port=service_port,
                                       host_name_str=host_name_str,
                                       company_name_str=company_name_str,
                                       source=source)
        # with report item
        self.init_db()
        with self._engine.session_scope() as session:
            self._test_add_certificate(session=session,
                                       type=type,
                                       content=content,
                                       service_port=service_port,
                                       host_name_str=host_name_str,
                                       company_name_str=company_name_str,
                                       report_item=self._report_item)
        # with source and report item
        self.init_db()
        with self._engine.session_scope() as session:
            source = self.create_source(session)
            self._test_add_certificate(session=session,
                                       type=type,
                                       content=content,
                                       service_port=service_port,
                                       host_name_str=host_name_str,
                                       company_name_str=company_name_str,
                                       source=source,
                                       report_item=self._report_item)

    def test_service_add_certificate(self):
        """
        Unittests for BaseUtils.add_certificate
        :return:
        """
        self._unittest_add_certificate(type=CertType.identity,
                                       content=self._certificate,
                                       service_port=80,
                                       host_name_str=None,
                                       company_name_str=None)

    def test_host_name_add_certificate(self):
        """
        Unittests for BaseUtils.add_certificate
        :return:
        """
        self._unittest_add_certificate(type=CertType.identity,
                                       content=self._certificate,
                                       service_port=None,
                                       host_name_str="www.test.com",
                                       company_name_str=None)

    def test_company_add_certificate(self):
        """
        Unittests for BaseUtils.add_certificate
        :return:
        """
        self._unittest_add_certificate(type=CertType.identity,
                                       content=self._certificate,
                                       service_port=None,
                                       host_name_str=None,
                                       company_name_str="Test LLC")


class TestIpv4NetworkExcludedHosts(BaseKisTestCase):
    """
    This test case tests Ipv4Utils.get_excluded_ipv4_addresses
    """

    def test_scopetype_all(self):
        self.init_db()
        ipv4_network = "192.168.1.0/29"
        workspace = self._workspaces[0]
        # setup database
        with self._engine.session_scope() as session:
            self.create_network(session=session,
                                workspace_str=workspace,
                                network=ipv4_network,
                                scope=ScopeType.all)
            self.create_host(session=session,
                             workspace_str=workspace,
                             address="192.168.1.1",
                             in_scope=False)
        # verify results
        with self._engine.session_scope() as session:
            result = session.query(Network).all()
            self.assertEqual(1, len(result))
            results = IpUtils.get_excluded_hosts(session=session, network=result[0])
            self.assertListEqual([], results)

    def test_scopetype_exclude(self):
        self.init_db()
        ipv4_network = "192.168.1.0/29"
        workspace = self._workspaces[0]
        # setup database
        with self._engine.session_scope() as session:
            self.create_network(session=session,
                                workspace_str=workspace,
                                network=ipv4_network,
                                scope=ScopeType.exclude)
            self.create_host(session=session,
                             workspace_str=workspace,
                             address="192.168.1.1",
                             in_scope=False)
        # verify results
        with self._engine.session_scope() as session:
            expected_results = ["192.168.1.{}".format(i) for i in range(0, 8)]
            result = session.query(Network).all()
            self.assertEqual(1, len(result))
            results = IpUtils.get_excluded_hosts(session=session, network=result[0])
            self.assertListEqual(expected_results, results)

    def test_scopetype_strict(self):
        self.init_db()
        ipv4_network = "192.168.1.0/29"
        workspace = self._workspaces[0]
        # setup database
        with self._engine.session_scope() as session:
            self.create_network(session=session,
                                workspace_str=workspace,
                                network=ipv4_network,
                                scope=ScopeType.strict)
            self.create_host(session=session,
                             workspace_str=workspace,
                             address="192.168.1.0",
                             in_scope=False)
            self.create_host(session=session,
                             workspace_str=workspace,
                             address="192.168.1.1",
                             in_scope=True)
            self.create_host(session=session,
                             workspace_str=workspace,
                             address="192.168.1.2",
                             in_scope=True)
        # verify results
        with self._engine.session_scope() as session:
            expected_results = ["192.168.1.{}".format(i) for i in range(0, 8) if i not in [1, 2]]
            result = session.query(Network).all()
            self.assertEqual(1, len(result))
            results = IpUtils.get_excluded_hosts(session=session, network=result[0])
            self.assertListEqual(expected_results, results)

