#!/usr/bin/python3
"""
this file implements all unittests for collector shodannetwork
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

import queue
import tempfile
from database.model import Network
from database.model import Command
from database.model import ScopeType
from unittests.tests.core import BaseKisTestCase
from collectors.os.collector import CollectorProducer


class TestCollectorInitialization(BaseKisTestCase):
    """
    This class test's the correct collector class initialization.
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def test_command_creation_private_network(self):
        """
        KIS should not query private networks as they cannot be scanned by shodan.
        """
        self.init_db()
        # Initialize collector producer
        workspace_name = "unittest"
        commands_queue = queue.Queue()
        producer = CollectorProducer(self._engine, commands_queue)
        parser = CollectorProducer.get_argument_parser(description="")
        collector_group = CollectorProducer.add_collector_argument_group(parser)
        producer.add_argparser_arguments(collector_group)
        # create database
        with self._engine.session_scope() as session:
            workspace = self.create_workspace(session=session, workspace=workspace_name)
            session.add(Network(workspace=workspace, network="192.168.1.1", scope=ScopeType.all))
            session.add(Network(workspace=workspace, network="192.168.2.0/24", scope=ScopeType.all))
            session.add(Network(workspace=workspace, network="192.168.0.0/16", scope=ScopeType.all))
            result = session.query(Network).count()
            self.assertEqual(3, result)
        with tempfile.TemporaryDirectory() as temp_dir:
            args = parser.parse_args(["-w", workspace_name, "--shodannetwork", "-S", "-o", temp_dir])
            producer.init(vars(args))
            producer.start()
            producer.join()
        # Verify results
        with self._engine.session_scope() as session:
            result = session.query(Command).count()
            self.assertEqual(0, result)

    def test_command_creation_other_networks(self):
        """
        KIS should not query private networks as they cannot be scanned by shodan.
        """
        self.init_db()
        # Initialize collector producer
        workspace_name = "unittest"
        commands_queue = queue.Queue()
        producer = CollectorProducer(self._engine, commands_queue)
        parser = CollectorProducer.get_argument_parser(description="")
        collector_group = CollectorProducer.add_collector_argument_group(parser)
        producer.add_argparser_arguments(collector_group)
        # create database
        with self._engine.session_scope() as session:
            workspace = self.create_workspace(session=session, workspace=workspace_name)
            session.add(Network(workspace=workspace, network="0.0.0.0/0", scope=ScopeType.all))
            session.add(Network(workspace=workspace, network="::1", scope=ScopeType.all))
            session.add(Network(workspace=workspace, network="::/0", scope=ScopeType.all))
            result = session.query(Network).count()
            self.assertEqual(3, result)
        with tempfile.TemporaryDirectory() as temp_dir:
            args = parser.parse_args(["-w", workspace_name, "--shodannetwork", "-S", "-o", temp_dir])
            producer.init(vars(args))
            producer.start()
            producer.join()
        # Verify results
        with self._engine.session_scope() as session:
            result = session.query(Command).count()
            self.assertEqual(0, result)
