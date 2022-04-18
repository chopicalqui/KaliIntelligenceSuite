#!/usr/bin/python3
"""
this file implements unittests for the kiscollect
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

import os
import queue
import tempfile
from database.model import VhostChoice
from database.model import CommandStatus
from unittests.tests.core import BaseKisTestCase
from collectors.os.collector import CollectorProducer


class TestCollectorProducerInitialization(BaseKisTestCase):
    """
    This class test's the correct collector producer thread initialization.
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def test_default_arguments_for_collector_producer(self):
        """
        Test the correct default initialization.
        """
        self.init_db()
        workspace = "unittest"
        # Initialize collector producer
        commands_queue = queue.Queue()
        producer = CollectorProducer(self._engine, commands_queue)
        parser = CollectorProducer.get_argument_parser(description="")
        collector_group = CollectorProducer.add_collector_argument_group(parser)
        producer.add_argparser_arguments(collector_group)
        # create database
        with self._engine.session_scope() as session:
            self.create_workspace(session=session, workspace=workspace)
        args = parser.parse_args(["-w", workspace])
        arguments = vars(args)
        producer.init(arguments)
        # Check settings
        self.assertEqual(1, producer._number_of_threads)
        self.assertEqual(workspace, producer._workspace)
        self.assertIsNone(producer._vhost)
        self.assertListEqual([], producer._included_items)
        self.assertListEqual([], producer._excluded_items)
        self.assertListEqual([], producer._restart_statuses)
        self.assertFalse(producer._strict_open)
        self.assertIsNone(producer._delay_min)
        self.assertIsNone(producer._delay_max)
        self.assertFalse(producer._continue_execution)
        self.assertFalse(producer._print_commands)
        self.assertFalse(producer._analyze_results)

    def test_set_arguments_for_collector_producer(self):
        """
        Test the correct initialization using user-specific configurations.
        """
        self.init_db()
        workspace = "unittest"
        # Initialize collector producer
        commands_queue = queue.Queue()
        producer = CollectorProducer(self._engine, commands_queue)
        parser = CollectorProducer.get_argument_parser(description="")
        collector_group = CollectorProducer.add_collector_argument_group(parser)
        producer.add_argparser_arguments(collector_group)
        # create database
        with self._engine.session_scope() as session:
            self.create_workspace(session=session, workspace=workspace)
        args = parser.parse_args(["-w", workspace,
                                  "--testing",
                                  "-S",
                                  "--vhost", VhostChoice.domain.name,
                                  "--tld",
                                  "--debug",
                                  "--strict",
                                  "--analyze",
                                  "--filter", "127.0.0.1",
                                  "--threads", "10",
                                  "-D", "5",
                                  "-M", "10",
                                  "--restart", CommandStatus.failed.name, CommandStatus.terminated.name,
                                  "--continue",
                                  "--proxychains"])
        arguments = vars(args)
        producer.init(arguments)
        # Check settings
        self.assertEqual(10, producer._number_of_threads)
        self.assertEqual(workspace, producer._workspace)
        self.assertEqual(VhostChoice.domain, producer._vhost)
        self.assertListEqual(["127.0.0.1"], producer._excluded_items)
        self.assertListEqual([CommandStatus.failed, CommandStatus.terminated], producer._restart_statuses)
        self.assertTrue(producer._strict_open)
        self.assertEqual(5, producer._delay_min)
        self.assertEqual(10, producer._delay_max)
        self.assertTrue(producer._continue_execution)
        self.assertTrue(producer._print_commands)
        self.assertTrue(producer._analyze_results)


class TestCollectorInitialization(BaseKisTestCase):
    """
    This class test's the correct collector class initialization.
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def test_default_arguments_for_collector_whoishost(self):
        """
        whoishost is a collector that has timeout, delay_min, and delay_max set.
        """
        self.init_db()
        workspace = "unittest"
        # Initialize collector producer
        commands_queue = queue.Queue()
        producer = CollectorProducer(self._engine, commands_queue)
        parser = CollectorProducer.get_argument_parser(description="")
        collector_group = CollectorProducer.add_collector_argument_group(parser)
        producer.add_argparser_arguments(collector_group)
        # create database
        with self._engine.session_scope() as session:
            self.create_workspace(session=session, workspace=workspace)
        args = parser.parse_args(["-w", workspace,
                                  "--whoishost"])
        arguments = vars(args)
        producer.init(arguments)
        # Check configuration
        self.assertEqual(1, len(producer._selected_collectors))
        self.assertEqual("whoishost", producer._selected_collectors[0].name)
        self.assertEqual(510, producer._selected_collectors[0].instance.priority)
        self.assertEqual(30, producer._selected_collectors[0].instance._timeout)
        self.assertEqual("whoishost", producer._selected_collectors[0].instance._name)
        self.assertFalse(producer._selected_collectors[0].instance._active_collector)
        self.assertIsNone(producer._selected_collectors[0].instance._output_dir)
        self.assertEqual(1, producer._selected_collectors[0].instance._number_of_threads)
        self.assertFalse(producer._selected_collectors[0].instance._hashes)
        self.assertIsNone(producer._selected_collectors[0].instance._http_proxy)
        self.assertListEqual([], producer._selected_collectors[0].instance._cookies)
        self.assertEqual(2, producer._selected_collectors[0].instance._min_delay)
        self.assertEqual(5, producer._selected_collectors[0].instance._max_delay)
        self.assertEqual(1, producer._selected_collectors[0].instance._max_threads)
        self.assertIsNone(producer._selected_collectors[0].instance._dns_server)
        self.assertIsNone(producer._selected_collectors[0].instance._user_agent)
        self.assertIsNone(producer._selected_collectors[0].instance._password)
        self.assertIsNone(producer._selected_collectors[0].instance._password_file)
        self.assertIsNone(producer._selected_collectors[0].instance._user)
        self.assertIsNone(producer._selected_collectors[0].instance._domain)
        self.assertIsNone(producer._selected_collectors[0].instance._user_file)
        self.assertIsNone(producer._selected_collectors[0].instance._combo_file)
        self.assertFalse(producer._selected_collectors[0].instance._proxychains)
        self.assertFalse(producer._selected_collectors[0].instance._analyze)
        self.assertListEqual([], producer._selected_collectors[0].instance._whitelist_filter)
        self.assertListEqual([], producer._selected_collectors[0].instance._blacklist_filter)
        self.assertFalse(producer._selected_collectors[0].instance._scan_tld)
        self.assertListEqual([], producer._selected_collectors[0].instance._wordlist_files)
        self.assertFalse(producer._selected_collectors[0].instance._print_commands)
        self.assertEqual("nobody", producer._selected_collectors[0].instance.exec_user.pw_name)

    def test_max_thread_for_collector_whoishost(self):
        """
        whoishost is a collector that has timeout, delay_min, and delay_max set. if a user specifies 10 consuming threads,
        then, this should not have an impact on collector whoihost's max_thread setting.
        """
        self.init_db()
        workspace = "unittest"
        # Initialize collector producer
        commands_queue = queue.Queue()
        producer = CollectorProducer(self._engine, commands_queue)
        parser = CollectorProducer.get_argument_parser(description="")
        collector_group = CollectorProducer.add_collector_argument_group(parser)
        producer.add_argparser_arguments(collector_group)
        # create database
        with self._engine.session_scope() as session:
            self.create_workspace(session=session, workspace=workspace)
        args = parser.parse_args(["-w", workspace,
                                  "--whoishost",
                                  "-t", "10"])
        arguments = vars(args)
        producer.init(arguments)
        # Check configuration
        self.assertEqual(1, len(producer._selected_collectors))
        self.assertEqual("whoishost", producer._selected_collectors[0].name)
        self.assertEqual(510, producer._selected_collectors[0].instance.priority)
        self.assertEqual(30, producer._selected_collectors[0].instance._timeout)
        self.assertEqual("whoishost", producer._selected_collectors[0].instance._name)
        self.assertFalse(producer._selected_collectors[0].instance._active_collector)
        self.assertIsNone(producer._selected_collectors[0].instance._output_dir)
        self.assertEqual(10, producer._selected_collectors[0].instance._number_of_threads)
        self.assertFalse(producer._selected_collectors[0].instance._hashes)
        self.assertIsNone(producer._selected_collectors[0].instance._http_proxy)
        self.assertListEqual([], producer._selected_collectors[0].instance._cookies)
        self.assertEqual(2, producer._selected_collectors[0].instance._min_delay)
        self.assertEqual(5, producer._selected_collectors[0].instance._max_delay)
        self.assertEqual(1, producer._selected_collectors[0].instance._max_threads)
        self.assertIsNone(producer._selected_collectors[0].instance._dns_server)
        self.assertIsNone(producer._selected_collectors[0].instance._user_agent)
        self.assertIsNone(producer._selected_collectors[0].instance._password)
        self.assertIsNone(producer._selected_collectors[0].instance._password_file)
        self.assertIsNone(producer._selected_collectors[0].instance._user)
        self.assertIsNone(producer._selected_collectors[0].instance._domain)
        self.assertIsNone(producer._selected_collectors[0].instance._user_file)
        self.assertIsNone(producer._selected_collectors[0].instance._combo_file)
        self.assertFalse(producer._selected_collectors[0].instance._proxychains)
        self.assertFalse(producer._selected_collectors[0].instance._analyze)
        self.assertListEqual([], producer._selected_collectors[0].instance._whitelist_filter)
        self.assertListEqual([], producer._selected_collectors[0].instance._blacklist_filter)
        self.assertFalse(producer._selected_collectors[0].instance._scan_tld)
        self.assertListEqual([], producer._selected_collectors[0].instance._wordlist_files)
        self.assertFalse(producer._selected_collectors[0].instance._print_commands)
        self.assertEqual("nobody", producer._selected_collectors[0].instance.exec_user.pw_name)

    def test_min_max_delays_for_collector_whoishost_I(self):
        """
        whoishost is a collector that has timeout, delay_min, and delay_max set. if a user specifies min and
        max delays below the collector's default values, then the values should not be updated.
        """
        self.init_db()
        workspace = "unittest"
        # Initialize collector producer
        commands_queue = queue.Queue()
        producer = CollectorProducer(self._engine, commands_queue)
        parser = CollectorProducer.get_argument_parser(description="")
        collector_group = CollectorProducer.add_collector_argument_group(parser)
        producer.add_argparser_arguments(collector_group)
        # create database
        with self._engine.session_scope() as session:
            self.create_workspace(session=session, workspace=workspace)
        args = parser.parse_args(["-w", workspace,
                                  "--whoishost",
                                  "-D", "1",
                                  "-M", "2"])
        arguments = vars(args)
        producer.init(arguments)
        # Check configuration
        self.assertEqual(1, len(producer._selected_collectors))
        self.assertEqual("whoishost", producer._selected_collectors[0].name)
        self.assertEqual(510, producer._selected_collectors[0].instance.priority)
        self.assertEqual(30, producer._selected_collectors[0].instance._timeout)
        self.assertEqual("whoishost", producer._selected_collectors[0].instance._name)
        self.assertFalse(producer._selected_collectors[0].instance._active_collector)
        self.assertIsNone(producer._selected_collectors[0].instance._output_dir)
        self.assertEqual(1, producer._selected_collectors[0].instance._number_of_threads)
        self.assertFalse(producer._selected_collectors[0].instance._hashes)
        self.assertIsNone(producer._selected_collectors[0].instance._http_proxy)
        self.assertListEqual([], producer._selected_collectors[0].instance._cookies)
        self.assertEqual(2, producer._selected_collectors[0].instance._min_delay)
        self.assertEqual(5, producer._selected_collectors[0].instance._max_delay)
        self.assertEqual(1, producer._selected_collectors[0].instance._max_threads)
        self.assertIsNone(producer._selected_collectors[0].instance._dns_server)
        self.assertIsNone(producer._selected_collectors[0].instance._user_agent)
        self.assertIsNone(producer._selected_collectors[0].instance._password)
        self.assertIsNone(producer._selected_collectors[0].instance._password_file)
        self.assertIsNone(producer._selected_collectors[0].instance._user)
        self.assertIsNone(producer._selected_collectors[0].instance._domain)
        self.assertIsNone(producer._selected_collectors[0].instance._user_file)
        self.assertIsNone(producer._selected_collectors[0].instance._combo_file)
        self.assertFalse(producer._selected_collectors[0].instance._proxychains)
        self.assertFalse(producer._selected_collectors[0].instance._analyze)
        self.assertListEqual([], producer._selected_collectors[0].instance._whitelist_filter)
        self.assertListEqual([], producer._selected_collectors[0].instance._blacklist_filter)
        self.assertFalse(producer._selected_collectors[0].instance._scan_tld)
        self.assertListEqual([], producer._selected_collectors[0].instance._wordlist_files)
        self.assertFalse(producer._selected_collectors[0].instance._print_commands)
        self.assertEqual("nobody", producer._selected_collectors[0].instance.exec_user.pw_name)

    def test_min_max_delays_for_collector_whoishost_II(self):
        """
        whoishost is a collector that has timeout, delay_min, and delay_max set. if a user specifies min and
        max delays above the collector's default values, then the values are updated.
        """
        self.init_db()
        workspace = "unittest"
        # Initialize collector producer
        commands_queue = queue.Queue()
        producer = CollectorProducer(self._engine, commands_queue)
        parser = CollectorProducer.get_argument_parser(description="")
        collector_group = CollectorProducer.add_collector_argument_group(parser)
        producer.add_argparser_arguments(collector_group)
        # create database
        with self._engine.session_scope() as session:
            self.create_workspace(session=session, workspace=workspace)
        args = parser.parse_args(["-w", workspace,
                                  "--whoishost",
                                  "-D", "20",
                                  "-M", "30"])
        arguments = vars(args)
        producer.init(arguments)
        # Check configuration
        self.assertEqual(1, len(producer._selected_collectors))
        self.assertEqual("whoishost", producer._selected_collectors[0].name)
        self.assertEqual(510, producer._selected_collectors[0].instance.priority)
        self.assertEqual(30, producer._selected_collectors[0].instance._timeout)
        self.assertEqual("whoishost", producer._selected_collectors[0].instance._name)
        self.assertFalse(producer._selected_collectors[0].instance._active_collector)
        self.assertIsNone(producer._selected_collectors[0].instance._output_dir)
        self.assertEqual(1, producer._selected_collectors[0].instance._number_of_threads)
        self.assertFalse(producer._selected_collectors[0].instance._hashes)
        self.assertIsNone(producer._selected_collectors[0].instance._http_proxy)
        self.assertListEqual([], producer._selected_collectors[0].instance._cookies)
        self.assertEqual(20, producer._selected_collectors[0].instance._min_delay)
        self.assertEqual(30, producer._selected_collectors[0].instance._max_delay)
        self.assertEqual(1, producer._selected_collectors[0].instance._max_threads)
        self.assertIsNone(producer._selected_collectors[0].instance._dns_server)
        self.assertIsNone(producer._selected_collectors[0].instance._user_agent)
        self.assertIsNone(producer._selected_collectors[0].instance._password)
        self.assertIsNone(producer._selected_collectors[0].instance._password_file)
        self.assertIsNone(producer._selected_collectors[0].instance._user)
        self.assertIsNone(producer._selected_collectors[0].instance._domain)
        self.assertIsNone(producer._selected_collectors[0].instance._user_file)
        self.assertIsNone(producer._selected_collectors[0].instance._combo_file)
        self.assertFalse(producer._selected_collectors[0].instance._proxychains)
        self.assertFalse(producer._selected_collectors[0].instance._analyze)
        self.assertListEqual([], producer._selected_collectors[0].instance._whitelist_filter)
        self.assertListEqual([], producer._selected_collectors[0].instance._blacklist_filter)
        self.assertFalse(producer._selected_collectors[0].instance._scan_tld)
        self.assertListEqual([], producer._selected_collectors[0].instance._wordlist_files)
        self.assertFalse(producer._selected_collectors[0].instance._print_commands)
        self.assertEqual("nobody", producer._selected_collectors[0].instance.exec_user.pw_name)

    def test_force_timout_for_collector_whoishost(self):
        """
        whoishost is a collector that has timeout, delay_min, and delay_max set. if a user specifies a default timeout,
        then the collector's default timeout is overwritten.
        """
        self.init_db()
        workspace = "unittest"
        # Initialize collector producer
        commands_queue = queue.Queue()
        producer = CollectorProducer(self._engine, commands_queue)
        parser = CollectorProducer.get_argument_parser(description="")
        collector_group = CollectorProducer.add_collector_argument_group(parser)
        producer.add_argparser_arguments(collector_group)
        # create database
        with self._engine.session_scope() as session:
            self.create_workspace(session=session, workspace=workspace)
        args = parser.parse_args(["-w", workspace,
                                  "--whoishost",
                                  "-T", "60"])
        arguments = vars(args)
        producer.init(arguments)
        # Check configuration
        self.assertEqual(1, len(producer._selected_collectors))
        self.assertEqual("whoishost", producer._selected_collectors[0].name)
        self.assertEqual(510, producer._selected_collectors[0].instance.priority)
        self.assertEqual(60, producer._selected_collectors[0].instance._timeout)
        self.assertEqual("whoishost", producer._selected_collectors[0].instance._name)
        self.assertFalse(producer._selected_collectors[0].instance._active_collector)
        self.assertIsNone(producer._selected_collectors[0].instance._output_dir)
        self.assertEqual(1, producer._selected_collectors[0].instance._number_of_threads)
        self.assertFalse(producer._selected_collectors[0].instance._hashes)
        self.assertIsNone(producer._selected_collectors[0].instance._http_proxy)
        self.assertListEqual([], producer._selected_collectors[0].instance._cookies)
        self.assertEqual(2, producer._selected_collectors[0].instance._min_delay)
        self.assertEqual(5, producer._selected_collectors[0].instance._max_delay)
        self.assertEqual(1, producer._selected_collectors[0].instance._max_threads)
        self.assertIsNone(producer._selected_collectors[0].instance._dns_server)
        self.assertIsNone(producer._selected_collectors[0].instance._user_agent)
        self.assertIsNone(producer._selected_collectors[0].instance._password)
        self.assertIsNone(producer._selected_collectors[0].instance._password_file)
        self.assertIsNone(producer._selected_collectors[0].instance._user)
        self.assertIsNone(producer._selected_collectors[0].instance._domain)
        self.assertIsNone(producer._selected_collectors[0].instance._user_file)
        self.assertIsNone(producer._selected_collectors[0].instance._combo_file)
        self.assertFalse(producer._selected_collectors[0].instance._proxychains)
        self.assertFalse(producer._selected_collectors[0].instance._analyze)
        self.assertListEqual([], producer._selected_collectors[0].instance._whitelist_filter)
        self.assertListEqual([], producer._selected_collectors[0].instance._blacklist_filter)
        self.assertFalse(producer._selected_collectors[0].instance._scan_tld)
        self.assertListEqual([], producer._selected_collectors[0].instance._wordlist_files)
        self.assertFalse(producer._selected_collectors[0].instance._print_commands)
        self.assertEqual("nobody", producer._selected_collectors[0].instance.exec_user.pw_name)

    def test_set_arguments_for_collector_producer(self):
        """
        whoishost is a collector that has timeout, delay_min, and delay_max set. this unittest checks whether all
        kiscollect arguments are applied on the collector.
        """
        self.init_db()
        workspace = "unittest"
        # Initialize collector producer
        commands_queue = queue.Queue()
        producer = CollectorProducer(self._engine, commands_queue)
        parser = CollectorProducer.get_argument_parser(description="")
        collector_group = CollectorProducer.add_collector_argument_group(parser)
        producer.add_argparser_arguments(collector_group)
        # create database
        with self._engine.session_scope() as session:
            self.create_workspace(session=session, workspace=workspace)
        with tempfile.TemporaryDirectory() as temp_dir:
            password_file = os.path.join(temp_dir, "passwords.txt")
            user_file = os.path.join(temp_dir, "users.txt")
            combo_file = os.path.join(temp_dir, "combo.txt")
            wordlist_file = os.path.join(temp_dir, "wordlist.txt")
            args = parser.parse_args(["-w", workspace,
                                      "--whoishost",
                                      "-o", temp_dir,
                                      "-t", "5",
                                      "--hashes",
                                      "--http-proxy", "https://127.0.0.1:8080",
                                      "--cookies", "JSESSIONID=a",
                                      "--dns-server", "8.8.8.8",
                                      "--user-agent", "wget/3.8",
                                      "--password", "Password123",
                                      "-P", password_file,
                                      "-d", "red.local",
                                      "-u", "testuser",
                                      "-U", user_file,
                                      "-C", combo_file,
                                      "--proxychains",
                                      "--analyze",
                                      "--filter", "+127.0.0.2",
                                      "--tld",
                                      "-L", wordlist_file,
                                      "-S"])
            arguments = vars(args)
            producer.init(arguments)
            # Check configuration
            self.assertEqual(1, len(producer._selected_collectors))
            self.assertEqual("whoishost", producer._selected_collectors[0].name)
            self.assertEqual(510, producer._selected_collectors[0].instance.priority)
            self.assertEqual(30, producer._selected_collectors[0].instance._timeout)
            self.assertEqual("whoishost", producer._selected_collectors[0].instance._name)
            self.assertFalse(producer._selected_collectors[0].instance._active_collector)
            self.assertEqual(temp_dir, producer._selected_collectors[0].instance._output_dir)
            self.assertEqual(5, producer._selected_collectors[0].instance._number_of_threads)
            self.assertTrue(producer._selected_collectors[0].instance._hashes)
            self.assertEqual("127.0.0.1:8080", producer._selected_collectors[0].instance._http_proxy.netloc)
            self.assertListEqual(["JSESSIONID=a"], producer._selected_collectors[0].instance._cookies)
            self.assertEqual(2, producer._selected_collectors[0].instance._min_delay)
            self.assertEqual(5, producer._selected_collectors[0].instance._max_delay)
            self.assertEqual(1, producer._selected_collectors[0].instance._max_threads)
            self.assertEqual("8.8.8.8", producer._selected_collectors[0].instance._dns_server)
            self.assertEqual("wget/3.8", producer._selected_collectors[0].instance._user_agent)
            self.assertEqual("Password123", producer._selected_collectors[0].instance._password)
            self.assertEqual(password_file, producer._selected_collectors[0].instance._password_file)
            self.assertEqual("red.local", producer._selected_collectors[0].instance._domain)
            self.assertEqual("testuser", producer._selected_collectors[0].instance._user)
            self.assertEqual(user_file, producer._selected_collectors[0].instance._user_file)
            self.assertEqual(combo_file, producer._selected_collectors[0].instance._combo_file)
            self.assertTrue(producer._selected_collectors[0].instance._proxychains)
            self.assertTrue(producer._selected_collectors[0].instance._analyze)
            self.assertListEqual(["127.0.0.2"], producer._selected_collectors[0].instance._whitelist_filter)
            self.assertTrue(producer._selected_collectors[0].instance._scan_tld)
            self.assertListEqual([wordlist_file], producer._selected_collectors[0].instance._wordlist_files)
            self.assertTrue(producer._selected_collectors[0].instance._print_commands)
            self.assertEqual("nobody", producer._selected_collectors[0].instance.exec_user.pw_name)

    def test_filter_argument(self):
        """
        It should not be possible to include and exclude items in the filter argument at the same time.
        """
        self.init_db()
        workspace = "unittest"
        # Initialize collector producer
        commands_queue = queue.Queue()
        producer = CollectorProducer(self._engine, commands_queue)
        parser = CollectorProducer.get_argument_parser(description="")
        collector_group = CollectorProducer.add_collector_argument_group(parser)
        producer.add_argparser_arguments(collector_group)
        # create database
        with self._engine.session_scope() as session:
            self.create_workspace(session=session, workspace=workspace)
        args = parser.parse_args(["-w", workspace,
                                  "--filter", "192.168.1.1", "+192.168.1.2"])
        arguments = vars(args)
        with self.assertRaises(ValueError):
            producer.init(arguments)
