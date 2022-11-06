#!/usr/bin/python3
"""
this file implements all unittests for collector httpnuclei
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

import os
import tempfile
from typing import List
from unittests.tests.collectors.kali.modules.http.core import BaseKaliHttpCollectorTestCase
from unittests.tests.collectors.kali.modules.core import BaseKaliCollectorTestCase
from unittests.tests.collectors.core import CollectorProducerTestSuite
from collectors.os.modules.http.httpnuclei import CollectorClass as HttpNucleiCollector
from database.model import Host
from database.model import Command
from database.model import CollectorType
from database.model import ScopeType
from database.model import DomainName
from database.model import HostName
from database.model import Service
from database.model import ProtocolType
from database.model import VhostChoice
from database.model import DnsResourceRecordType
from database.model import VHostNameMapping


class BaseVhostGobusterCollectorTestCase(BaseKaliHttpCollectorTestCase):
    """
    This class implements all unittestss for the given collector
    """
    def __init__(self, test_name: str, **kwargs):
        super().__init__(test_name,
                         collector_name="httpnuclei",
                         collector_class=HttpNucleiCollector)

    @staticmethod
    def get_command_text_outputs() -> List[str]:
        """
        This method returns example outputs of the respective collectors
        :return:
        """
        return [""""""]

    def test_for_invalid_arguments(self):
        """
        This method checks whether the collector creates a valid command for the installed version
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self._test_for_invalid_arguments(session=session,
                                             workspace_str=self._workspaces[0],
                                             expected_command_count=2)

    def test_verify_results(self):
        """
        This method checks whether the collector correctly verifies the command output
        :return:
        """
        pass


class TestHttpNucleiClass(BaseKaliCollectorTestCase):
    """
    vhostgobuster allows the explicit exclusion of specific host names via kiscollect's --filter argument. The
    correct behaviour of this excplicit exclusion is tested by this unittest.
    """

    def __init__(self, test_name: str):
        super().__init__(test_name,
                         collector_name="httpnuclei",
                         collector_class=HttpNucleiCollector)

    def _create_test_data(self, workspace_str: str):
        with self._engine.session_scope() as session:
            # Setup database
            self.create_network(session=session,
                                network="0.0.0.0/0",
                                scope=ScopeType.strict,
                                workspace_str=workspace_str)
            self.create_network(session=session,
                                network="::/0",
                                scope=ScopeType.strict,
                                workspace_str=workspace_str)
            host_name1 = self.create_hostname(session=session,
                                              workspace_str=workspace_str,
                                              host_name="www.test1.local", scope=ScopeType.all)
            host_name2 = self.create_hostname(session=session,
                                              workspace_str=workspace_str,
                                              host_name="www.test2.local", scope=ScopeType.all)
            host_name3 = self.create_hostname(session=session,
                                              workspace_str=workspace_str,
                                              host_name="www.test3.local", scope=ScopeType.exclude)
            service1 = self.create_service(session=session, workspace_str=workspace_str, address="127.0.0.1", port=80)
            service1.host.in_scope = True
            service2 = self.create_service(session=session, workspace_str=workspace_str, address="::1", port=443)
            service2.host.in_scope = True
            service3 = self.create_service(session=session, workspace_str=workspace_str, address="192.168.1.2", port=80)
            service3.host.in_scope = False
            self._domain_utils.add_host_host_name_mapping(session=session,
                                                          host=service1.host,
                                                          host_name=host_name1,
                                                          mapping_type=DnsResourceRecordType.a)
            self._domain_utils.add_host_host_name_mapping(session=session,
                                                          host=service2.host,
                                                          host_name=host_name2,
                                                          mapping_type=DnsResourceRecordType.aaaa)
            self._domain_utils.add_host_host_name_mapping(session=session,
                                                          host=service3.host,
                                                          host_name=host_name3,
                                                          mapping_type=DnsResourceRecordType.a)

    def test_basic_command_creation(self):
        """
        Test correct command creation
        """
        workspace_str = self._workspaces[0]
        self.init_db()
        self._create_test_data(workspace_str)
        # Create command
        with tempfile.TemporaryDirectory() as temp_dir:
            arguments = {"workspace": workspace_str, "output_dir": temp_dir, "vhost": VhostChoice.all}
            test_suite = CollectorProducerTestSuite(engine=self._engine, arguments=arguments)
            test_suite.create_commands([self._arg_parse_module])
            # Check content of created wordlist. It should not contain test1.local and www.test1.local.
            with self._engine.session_scope() as session:
                result = session.query(Command).all()
                self.assertEqual(4, len(result))
                result = session.query(Command) \
                    .join(Service) \
                    .join(Host) \
                    .filter(Service.port == 80).one()
                self.assertTrue("http://127.0.0.1" in result.os_command)
                result = session.query(Command) \
                    .join(Service) \
                    .join(Host) \
                    .filter(Service.port == 443).one()
                self.assertTrue("http://[::1]" in result.os_command)
                result = session.query(Command) \
                    .join(Service) \
                    .join(HostName) \
                    .filter(Service.port == 80).one()
                self.assertTrue("http://www.test1.local" in result.os_command)
                result = session.query(Command) \
                    .join(Service) \
                    .join(HostName) \
                    .filter(Service.port == 443).one()
                self.assertTrue("http://www.test2.local" in result.os_command)

    def test_command_creation_with_proxy(self):
        """
        Test correct command creation
        """
        workspace_str = self._workspaces[0]
        self.init_db()
        self._create_test_data(workspace_str)
        # Create command
        with tempfile.TemporaryDirectory() as temp_dir:
            arguments = {"workspace": workspace_str, "output_dir": temp_dir, "http_proxy": "http://127.0.0.1:8080"}
            test_suite = CollectorProducerTestSuite(engine=self._engine, arguments=arguments)
            test_suite.create_commands([self._arg_parse_module])
            # Check content of created wordlist. It should not contain test1.local and www.test1.local.
            with self._engine.session_scope() as session:
                result = session.query(Command).first()
                index = result.os_command.index("-p")
                self.assertEqual("http://127.0.0.1:8080", result.os_command[index + 1])

    def test_command_creation_with_basic_authentication(self):
        """
        Test correct command creation
        """
        workspace_str = self._workspaces[0]
        self.init_db()
        self._create_test_data(workspace_str)
        # Create command
        with tempfile.TemporaryDirectory() as temp_dir:
            arguments = {"workspace": workspace_str, "output_dir": temp_dir, "user": "test", "password": "test"}
            test_suite = CollectorProducerTestSuite(engine=self._engine, arguments=arguments)
            test_suite.create_commands([self._arg_parse_module])
            # Check content of created wordlist. It should not contain test1.local and www.test1.local.
            with self._engine.session_scope() as session:
                result = session.query(Command).first()
                index = result.os_command.index("-H")
                self.assertEqual("Authorization: Basic dGVzdDp0ZXN0", result.os_command[index + 1])

    def test_command_creation_with_cookies(self):
        """
        Test correct command creation
        """
        workspace_str = self._workspaces[0]
        self.init_db()
        self._create_test_data(workspace_str)
        # Create command
        with tempfile.TemporaryDirectory() as temp_dir:
            arguments = {"workspace": workspace_str,
                         "output_dir": temp_dir,
                         "cookies": ["JSESSIONID=123", "CSRFTOKEN=12"]}
            test_suite = CollectorProducerTestSuite(engine=self._engine, arguments=arguments)
            test_suite.create_commands([self._arg_parse_module])
            # Check content of created wordlist. It should not contain test1.local and www.test1.local.
            with self._engine.session_scope() as session:
                result = session.query(Command).first()
                index = result.os_command.index("-H")
                self.assertEqual("Cookie: JSESSIONID=123; CSRFTOKEN=12", result.os_command[index + 1])

    def test_command_creation_with_basic_authentication_and_cookies(self):
        """
        Test correct command creation
        """
        workspace_str = self._workspaces[0]
        self.init_db()
        self._create_test_data(workspace_str)
        # Create command
        with tempfile.TemporaryDirectory() as temp_dir:
            arguments = {"workspace": workspace_str,
                         "output_dir": temp_dir,
                         "user": "test",
                         "password": "test",
                         "cookies": ["JSESSIONID=123", "CSRFTOKEN=12"]}
            test_suite = CollectorProducerTestSuite(engine=self._engine, arguments=arguments)
            test_suite.create_commands([self._arg_parse_module])
            # Check content of created wordlist. It should not contain test1.local and www.test1.local.
            with self._engine.session_scope() as session:
                result = session.query(Command).first()
                index = result.os_command.index("-H")
                self.assertEqual("Authorization: Basic dGVzdDp0ZXN0", result.os_command[index + 1])
                self.assertEqual("Cookie: JSESSIONID=123; CSRFTOKEN=12", result.os_command[index + 2])
