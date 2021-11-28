#!/usr/bin/python3
"""
this file implements all unittests for collector httpgobuaster
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
from collectors.os.modules.http.vhostgobuster import CollectorClass as VhostGobusterCollector
from database.model import Command
from database.model import CollectorType
from database.model import ScopeType
from database.model import DomainName
from database.model import HostName
from database.model import Service
from database.model import ProtocolType
from database.model import DnsResourceRecordType


class BaseVhostGobusterCollectorTestCase(BaseKaliHttpCollectorTestCase):
    """
    This class implements all unittestss for the given collector
    """
    def __init__(self, test_name: str, **kwargs):
        super().__init__(test_name,
                         collector_name="vhostgobuster",
                         collector_class=VhostGobusterCollector)

    @staticmethod
    def get_command_text_outputs() -> List[str]:
        """
        This method returns example outputs of the respective collectors
        :return:
        """
        return ["""===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          https://mysite.com
[+] Threads:      10
[+] Wordlist:     common-vhosts.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2019/06/21 08:36:00 Starting gobuster
===============================================================
\rFound: www.mysite.com (Status: 403) [Size: 915]
\rFound: piwik.mysite.com (Status: 403) [Size: 915]
\rFound: mail.mysite.com (Status: 403) [Size: 915]
\rFound: www1.mysite.com (Status: 403) [Size: 915]
\rFound: hidden.mysite.com (Status: 403) [Size: 915]
\rFound: mysite.com (Status: 403) [Size: 915]
===============================================================
2019/06/21 08:36:05 Finished
==============================================================="""]

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
        self.init_db()
        with tempfile.TemporaryDirectory() as temp_dir:
            test_suite = CollectorProducerTestSuite(engine=self._engine,
                                                    arguments={"workspace": self._workspaces[0],
                                                               "output_dir": temp_dir})
            with self._engine.session_scope() as session:
                self.create_hostname(session=session,
                                     workspace_str=self._workspaces[0],
                                     host_name="www.mysite.com",
                                     scope=ScopeType.all)
                self.create_hostname(session=session,
                                     workspace_str=self._workspaces[0],
                                     host_name="piwik.mysite.com",
                                     scope=ScopeType.all)
                self.create_hostname(session=session,
                                     workspace_str=self._workspaces[0],
                                     host_name="mail.mysite.com",
                                     scope=ScopeType.all)
                source = self.create_source(session, source_str=self._collector_name)
                command = self.create_command(session=session,
                                              workspace_str=self._workspaces[0],
                                              command=["gobuster", "192.168.1.1"],
                                              collector_name_str=self._collector_name,
                                              collector_name_type=CollectorType.host_service,
                                              service_port=80,
                                              scope=ScopeType.all,
                                              stdout_output=self.get_command_text_outputs()[0],
                                              output_path=temp_dir)
                test_suite.verify_results(session=session,
                                          arg_parse_module=self._arg_parse_module,
                                          command=command,
                                          source=source,
                                          report_item=self._report_item)
        with self._engine.session_scope() as session:
            vhosts = ["www.mysite.com", "piwik.mysite.com", "mysite.com", "mail.mysite.com", "www1.mysite.com",
                      "hidden.mysite.com"]
            vhosts.sort()
            results = session.query(Command).count()
            self.assertEqual(1, results)
            results = session.query(DomainName).all()
            self.assertEqual(1, len(results))
            results = session.query(HostName).all()
            self.assertEqual(6, len(results))
            host_names = [item.full_name for item in results]
            self.assertIn("www.mysite.com", host_names)
            self.assertIn("piwik.mysite.com", host_names)
            self.assertIn("mail.mysite.com", host_names)
            # Check host_name.vhosts
            for host_name in results:
                if host_name.full_name in vhosts:
                    self.assertEqual(1, len(host_name.vhosts))
                    self.assertEqual(80, host_name.vhosts[0].port)
                    self.assertEqual(ProtocolType.tcp, host_name.vhosts[0].protocol)
                    self.assertEqual("192.168.1.1", host_name.vhosts[0].host.address)
                else:
                    raise ValueError("this case ('{}') should not happen.".format(host_name.name))
            # Check service.vhost
            service = session.query(Service).one()
            actual_vhosts = [item.full_name for item in service.vhosts]
            actual_vhosts.sort()
            self.assertListEqual(vhosts, actual_vhosts)


class TestVhostGoBusterFilteringClass(BaseKaliCollectorTestCase):
    """
    vhostgobuster allows the explicit exclusion of specific host names via kiscollect's --filter argument. The
    correct behaviour of this excplicit exclusion is tested by this unittest.
    """

    def __init__(self, test_name: str):
        super().__init__(test_name,
                         collector_name="vhostgobuster",
                         collector_class=VhostGobusterCollector)

    def _create_test_data(self, workspace_str: str):
        with self._engine.session_scope() as session:
            # Setup database
            self.create_network(session=session,
                                network="192.168.1.0/24",
                                scope=ScopeType.all,
                                workspace_str=workspace_str)
            self.create_hostname(session=session,
                                 workspace_str=workspace_str,
                                 host_name="www.test1.local", scope=ScopeType.all)
            self.create_hostname(session=session,
                                 workspace_str=workspace_str,
                                 host_name="www.test2.local", scope=ScopeType.all)
            host_name = self.create_hostname(session=session,
                                             workspace_str=workspace_str,
                                             host_name="www.test3.local", scope=ScopeType.all)
            self.create_service(session=session, workspace_str=workspace_str, address="192.168.1.1", port=80)
            host = self.create_host(session=session, workspace_str=workspace_str, address="192.168.1.2")
            self._domain_utils.add_host_host_name_mapping(session=session,
                                                          host=host,
                                                          host_name=host_name,
                                                          mapping_type=DnsResourceRecordType.a)

    def test_filter_explicit_exclude(self):
        """
        Test explicit exclusions --filter test1.local www.test1.local.
        """
        workspace_str = self._workspaces[0]
        exclude_filter = ["test1.local", "www.test1.local", "www.test3.local"]
        include_filter = ["test2.local", "www.test2.local", "test3.local"]
        self.init_db()
        self._create_test_data(workspace_str)
        # Create command
        with tempfile.TemporaryDirectory() as temp_dir:
            arguments = {"workspace": workspace_str, "output_dir": temp_dir, "filter": exclude_filter}
            test_suite = CollectorProducerTestSuite(engine=self._engine, arguments=arguments)
            test_suite.create_commands([self._arg_parse_module])
            # Check content of created wordlist. It should not contain test1.local and www.test1.local.
            with self._engine.session_scope() as session:
                command = session.query(Command).one()
                with open(os.path.join(temp_dir,
                                       "{0}/vhostgobuster_{0}-tcp-80-wordlist.txt".format(command.host.address)), "r") as file:
                    lines = [line.strip() for line in file.readlines()]
                    self.assertEqual(3, len(lines))
                    self.assertNotIn(exclude_filter[0], lines)
                    self.assertNotIn(exclude_filter[1], lines)
                    self.assertNotIn(exclude_filter[2], lines)
                    self.assertIn(include_filter[0], lines)
                    self.assertIn(include_filter[1], lines)
                    self.assertIn(include_filter[2], lines)

    def test_filter_explicit_include(self):
        """
        Test explicit exclusions --filter +test1.local +www.test1.local.
        """
        workspace_str = self._workspaces[0]
        include_filter = ["test1.local", "www.test1.local"]
        exclude_filter = ["test2.local", "www.test2.local", "www.test3.local", "test3.local"]
        self.init_db()
        self._create_test_data(workspace_str)
        # Create command
        with tempfile.TemporaryDirectory() as temp_dir:
            arguments = {"workspace": workspace_str,
                         "output_dir": temp_dir,
                         "filter": ["+{}".format(item) for item in include_filter]}
            test_suite = CollectorProducerTestSuite(engine=self._engine, arguments=arguments)
            test_suite.create_commands([self._arg_parse_module])
            # Check content of created wordlist. It should not contain test2.local and www.test2.local.
            with self._engine.session_scope() as session:
                command = session.query(Command).one()
                with open(os.path.join(temp_dir,
                                       "{0}/vhostgobuster_{0}-tcp-80-wordlist.txt".format(command.host.address)), "r") as file:
                    lines = [line.strip() for line in file.readlines()]
                    self.assertEqual(2, len(lines))
                    self.assertIn(include_filter[0], lines)
                    self.assertIn(include_filter[1], lines)
                    self.assertNotIn(exclude_filter[0], lines)
                    self.assertNotIn(exclude_filter[1], lines)
                    self.assertNotIn(exclude_filter[2], lines)
                    self.assertNotIn(exclude_filter[3], lines)

    def test_filter_explicit_include_II(self):
        """
        Test explicit exclusions --filter +test1.local +www.test1.local +www.test3.local. Note that www.test3.local
        resolves to an IP address and therefore is usually not included by vhostgobuster.
        """
        workspace_str = self._workspaces[0]
        include_filter = ["test1.local", "www.test1.local", "www.test3.local"]
        exclude_filter = ["test2.local", "www.test2.local", "test3.local"]
        self.init_db()
        self._create_test_data(workspace_str)
        # Create command
        with tempfile.TemporaryDirectory() as temp_dir:
            arguments = {"workspace": workspace_str,
                         "output_dir": temp_dir,
                         "filter": ["+{}".format(item) for item in include_filter]}
            test_suite = CollectorProducerTestSuite(engine=self._engine, arguments=arguments)
            test_suite.create_commands([self._arg_parse_module])
            # Check content of created wordlist. It should not contain test2.local and www.test2.local.
            with self._engine.session_scope() as session:
                command = session.query(Command).one()
                with open(os.path.join(temp_dir,
                                       "{0}/vhostgobuster_{0}-tcp-80-wordlist.txt".format(command.host.address)), "r") as file:
                    lines = [line.strip() for line in file.readlines()]
                    self.assertEqual(3, len(lines))
                    self.assertIn(include_filter[0], lines)
                    self.assertIn(include_filter[1], lines)
                    self.assertIn(include_filter[2], lines)
                    self.assertNotIn(exclude_filter[0], lines)
                    self.assertNotIn(exclude_filter[1], lines)
                    self.assertNotIn(exclude_filter[2], lines)

    def test_no_filter(self):
        """
        Test explicit exclusions --filter +test1.local +www.test1.local.
        """
        workspace_str = self._workspaces[0]
        include_filter = ["test1.local", "www.test1.local", "test2.local", "www.test2.local", "test3.local"]
        self.init_db()
        self._create_test_data(workspace_str)
        # Create command
        with tempfile.TemporaryDirectory() as temp_dir:
            arguments = {"workspace": workspace_str, "output_dir": temp_dir}
            test_suite = CollectorProducerTestSuite(engine=self._engine, arguments=arguments)
            test_suite.create_commands([self._arg_parse_module])
            # Check content of created wordlist. It should not contain www.test1.local.
            with self._engine.session_scope() as session:
                command = session.query(Command).one()
                with open(os.path.join(temp_dir,
                                       "{0}/vhostgobuster_{0}-tcp-80-wordlist.txt".format(command.host.address)), "r") as file:
                    lines = [line.strip() for line in file.readlines()]
                    self.assertEqual(5, len(lines))
                    self.assertIn(include_filter[0], lines)
                    self.assertIn(include_filter[1], lines)
                    self.assertIn(include_filter[2], lines)
                    self.assertIn(include_filter[3], lines)
                    self.assertIn(include_filter[4], lines)
