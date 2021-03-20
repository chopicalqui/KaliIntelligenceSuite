#!/usr/bin/python3
"""
this file implements unittests for testing the scope
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

from unittests.tests.core import BaseKisTestCase
from database.model import Host
from database.model import Network
from database.model import HostName
from database.model import DomainName
from database.model import DnsResourceRecordType
from database.model import ScopeType
from database.model import Workspace
from database.model import HostHostNameMapping
from collectors.core import IpUtils
from collectors.core import DomainUtils
from sqlalchemy.orm.session import Session


class NetworkScopeContradictionTestCases(BaseKisTestCase):
    """
    This class implements general tests.
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)
        self._workspace = "unittest"

    def test_scope_contradiction_at_insert(self):
        """
        This method checks whether scope contradictions are correctly identified.

        This unittest tests PostgreSQL functions: update_network_scopes_after_network_changes.
        """
        # set up database
        self.init_db()
        try:
            with self._engine.session_scope() as session:
                self.create_network(session=session,
                                    workspace_str=self._workspace,
                                    network="192.168.1.0/24",
                                    scope=ScopeType.all)
                self.create_network(session=session,
                                    workspace_str=self._workspace,
                                    network="192.168.1.128/25",
                                    scope=ScopeType.exclude)
        except Exception as ex:
            self.assertTrue("insert failed because there is the following scope contradiction" in str(ex))

    def test_scope_contradiction_at_update(self):
        """
        This method checks whether scope contradictions are correctly identified.

        This unittest tests PostgreSQL functions: update_network_scopes_after_network_changes.
        """
        # set up database
        self.init_db()
        try:
            with self._engine.session_scope() as session:
                self.create_network(session=session,
                                    workspace_str=self._workspace,
                                    network="192.168.1.0/24",
                                    scope=ScopeType.all)
                self.create_network(session=session,
                                    workspace_str=self._workspace,
                                    network="192.168.1.128/25",
                                    scope=ScopeType.all)
            with self._engine.session_scope() as session:
                network = session.query(Network).filter_by(network="192.168.1.128/25").one()
                network.scope = ScopeType.strict
        except Exception as ex:
            self.assertTrue("insert failed because there is the following scope contradiction" in str(ex))

    def test_network_address_update(self):
        """
        This method checks whether the update of a network address, triggers an exception.

        This unittest tests PostgreSQL functions: update_network_scopes_after_network_changes
        """
        # set up database
        self.init_db()
        try:
            with self._engine.session_scope() as session:
                self.create_network(session=session,
                                    workspace_str=self._workspace,
                                    network="192.168.1.0/24",
                                    scope=ScopeType.all)
            with self._engine.session_scope() as session:
                network = session.query(Network).filter_by(network="192.168.1.0/24").one()
                network.network = "127.0.0.0/24"
        except Exception as ex:
            self.assertTrue("changing the networks address (192.168.1.0/24) is not allowed as it might make scoping" in str(ex))


class NetworkAssignmentsAndScopeTypeAllTestCases(BaseKisTestCase):
    """
    This class implements functionalities for testing the correct network assignments with scope type all
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)
        self._workspace = "unittest"

    def test_simple_insert(self):
        """
        Per default a network's scope should be NULL/None.
        """

        # set up database
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = IpUtils.add_workspace(session=session, name=self._workspace)
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="0.0.0.0/0")
        with self._engine.session_scope() as session:
            network = session.query(Network).filter_by(network="0.0.0.0/0").one()
            self.assertFalse(network.in_scope)
            self.assertIsNone(network.scope)

    def test_insert_scope_all_within_none_01(self):
        """
        It should be possible to insert sub-network with scope all within a network with no scope.
        """
        # set up database
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = IpUtils.add_workspace(session=session, name=self._workspace)
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="0.0.0.0/0")
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="192.168.1.0/24",
                                scope=ScopeType.all)
        with self._engine.session_scope() as session:
            network = session.query(Network).filter_by(network="0.0.0.0/0").one()
            self.assertIsNone(network.scope)
            self.assertFalse(network.in_scope)
            network = session.query(Network).filter_by(network="192.168.1.0/24").one()
            self.assertEqual(ScopeType.all, network.scope)
            self.assertTrue(network.in_scope)

    def test_insert_scope_all_within_none_02(self):
        """
        It should be possible to insert sub-network with scope all within a network with no scope.
        """
        # set up database
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = IpUtils.add_workspace(session=session, name=self._workspace)
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="192.168.1.0/24",
                                scope=ScopeType.all)
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="0.0.0.0/0")
        with self._engine.session_scope() as session:
            network = session.query(Network).filter_by(network="0.0.0.0/0").one()
            self.assertFalse(network.in_scope)
            self.assertIsNone(network.scope)
            network = session.query(Network).filter_by(network="192.168.1.0/24").one()
            self.assertTrue(network.in_scope)
            self.assertEqual(ScopeType.all, network.scope)

    def test_insert_scope_none_within_all_01(self):
        """
        If a subnetwork is inserted within a network with scope all, then the new network's scope should be all as well.
        """
        # set up database
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = IpUtils.add_workspace(session=session, name=self._workspace)
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="0.0.0.0/0",
                                scope=ScopeType.all)
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="192.168.1.0/24")
        with self._engine.session_scope() as session:
            network = session.query(Network).filter_by(network="0.0.0.0/0").one()
            self.assertTrue(network.in_scope)
            self.assertEqual(ScopeType.all, network.scope)
            network = session.query(Network).filter_by(network="192.168.1.0/24").one()
            self.assertTrue(network.in_scope)
            self.assertEqual(ScopeType.all, network.scope)

    def test_insert_scope_none_within_all_02(self):
        """
        If a subnetwork is inserted within a network with scope all, then the new network's scope should be all as well.
        """
        # set up database
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = IpUtils.add_workspace(session=session, name=self._workspace)
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="192.168.1.0/24")
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="0.0.0.0/0",
                                scope=ScopeType.all)
        with self._engine.session_scope() as session:
            network = session.query(Network).filter_by(network="0.0.0.0/0").one()
            self.assertEqual(ScopeType.all, network.scope)
            self.assertTrue(network.in_scope)
            network = session.query(Network).filter_by(network="192.168.1.0/24").one()
            self.assertEqual(ScopeType.all, network.scope)
            self.assertTrue(network.in_scope)

    def test_insert_multiple_networks(self):
        """
        All sub-networks should be put in scope if parent network is put in scope.
        """
        # set up database
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = IpUtils.add_workspace(session=session, name=self._workspace)
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="192.168.1.0/24")
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="192.168.1.224/27")
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="192.168.1.128/25",
                                scope=ScopeType.all)
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="0.0.0.0/0")
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="192.168.1.192/26")
        with self._engine.session_scope() as session:
            network = session.query(Network).filter_by(network="0.0.0.0/0").one()
            self.assertIsNone(network.scope)
            self.assertFalse(network.in_scope)
            network = session.query(Network).filter_by(network="192.168.1.0/24").one()
            self.assertIsNone(network.scope)
            self.assertFalse(network.in_scope)
            network = session.query(Network).filter_by(network="192.168.1.128/25").one()
            self.assertEqual(ScopeType.all, network.scope)
            self.assertTrue(network.in_scope)
            network = session.query(Network).filter_by(network="192.168.1.192/26").one()
            self.assertEqual(ScopeType.all, network.scope)
            self.assertTrue(network.in_scope)
            network = session.query(Network).filter_by(network="192.168.1.224/27").one()
            self.assertEqual(ScopeType.all, network.scope)
            self.assertTrue(network.in_scope)

    def test_update_child_scope_all(self):
        """
        Excluding the sub-network from scope without an out-of-scope parent network, should not have an effect on the
        parent network.
        """
        self.test_insert_scope_all_within_none_01()
        with self._engine.session_scope() as session:
            network = session.query(Network).filter_by(network="192.168.1.0/24").one()
            self.assertEqual(ScopeType.all, network.scope)
            self.assertTrue(network.in_scope)
            network.scope = ScopeType.exclude
        with self._engine.session_scope() as session:
            network = session.query(Network).filter_by(network="0.0.0.0/0").one()
            self.assertFalse(network.in_scope)
            self.assertIsNone(network.scope)
            network = session.query(Network).filter_by(network="192.168.1.0/24").one()
            self.assertFalse(network.in_scope)
            self.assertEqual(ScopeType.exclude, network.scope)

    def test_update_parent_scope_all(self):
        """
        Exclude parent scope from scope should also exclude child from scope.
        """
        self.test_insert_scope_none_within_all_01()
        with self._engine.session_scope() as session:
            network = session.query(Network).filter_by(network="0.0.0.0/0").one()
            self.assertTrue(network.in_scope)
            self.assertEqual(ScopeType.all, network.scope)
            network.scope = ScopeType.exclude
        with self._engine.session_scope() as session:
            network = session.query(Network).filter_by(network="0.0.0.0/0").one()
            self.assertFalse(network.in_scope)
            self.assertEqual(ScopeType.exclude, network.scope)
            network = session.query(Network).filter_by(network="192.168.1.0/24").one()
            self.assertFalse(network.in_scope)
            self.assertEqual(ScopeType.exclude, network.scope)

    def test_update_exclude_multiple_networks(self):
        """
        All sub-networks should be put out of scope if parent network is put out of scope.
        """
        self.test_insert_multiple_networks()
        with self._engine.session_scope() as session:
            network = session.query(Network).filter_by(network="0.0.0.0/0").one()
            self.assertFalse(network.in_scope)
            self.assertIsNone(network.scope)
            network = session.query(Network).filter_by(network="192.168.1.0/24").one()
            self.assertFalse(network.in_scope)
            self.assertIsNone(network.scope)
            network.scope = ScopeType.exclude
        with self._engine.session_scope() as session:
            network = session.query(Network).filter_by(network="0.0.0.0/0").one()
            self.assertFalse(network.in_scope)
            self.assertIsNone(network.scope)
            network = session.query(Network).filter_by(network="192.168.1.0/24").one()
            self.assertFalse(network.in_scope)
            self.assertEqual(ScopeType.exclude, network.scope)
            network = session.query(Network).filter_by(network="192.168.1.128/25").one()
            self.assertFalse(network.in_scope)
            self.assertEqual(ScopeType.exclude, network.scope)
            network = session.query(Network).filter_by(network="192.168.1.192/26").one()
            self.assertFalse(network.in_scope)
            self.assertEqual(ScopeType.exclude, network.scope)
            network = session.query(Network).filter_by(network="192.168.1.224/27").one()
            self.assertFalse(network.in_scope)
            self.assertEqual(ScopeType.exclude, network.scope)

    def test_delete_scope_all_within_none(self):
        """
        Deleting a sub-network should not have an impact on the parent network.
        """
        self.test_insert_scope_all_within_none_01()
        with self._engine.session_scope() as session:
            network = session.query(Network).filter_by(network="192.168.1.0/24").first()
            session.delete(network)
        with self._engine.session_scope() as session:
            count = session.query(Network).count()
            self.assertEqual(1, count)
            network = session.query(Network).filter_by(network="0.0.0.0/0").one()
            self.assertFalse(network.in_scope)
            self.assertIsNone(network.scope)

    def test_delete_scope_all_parent(self):
        """
        Deleting a sub-network should not have an impact on the parent network.
        """
        self.test_insert_scope_all_within_none_01()
        with self._engine.session_scope() as session:
            network = session.query(Network).filter_by(network="0.0.0.0/0").first()
            session.delete(network)
        with self._engine.session_scope() as session:
            count = session.query(Network).count()
            self.assertEqual(1, count)
            network = session.query(Network).filter_by(network="192.168.1.0/24").one()
            self.assertTrue(network.in_scope)
            self.assertEqual(ScopeType.all, network.scope)


class NetworkScopeTypeStrictTestCases(BaseKisTestCase):
    """
    This class implements functionalities for testing scope type strict
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)
        self._workspace = "unittest"

    def test_insert_strict_network_with_host_scope_none(self):
        """
        If a host is added to a network with scope strict, then the host's scope can remain as specified.
        """
        # set up database
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = IpUtils.add_workspace(session=session, name=self._workspace)
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="192.168.1.0/24",
                                scope=ScopeType.strict)
            IpUtils.add_host(session=session,
                             workspace=workspace,
                             address="192.168.1.1")
        with self._engine.session_scope() as session:
            result = session.query(Host).filter_by(address="192.168.1.1").one()
            self.assertFalse(result.in_scope)
            self.assertEqual("192.168.1.0/24", result.ipv4_network.network)
            self.assertTrue(result.ipv4_network.in_scope)
            self.assertEqual(ScopeType.strict, result.ipv4_network.scope)

    def test_insert_strict_network_with_host_scope_false(self):
        """
        If a host is added to a network with scope strict, then the host's scope can remain as specified.
        """
        # set up database
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = IpUtils.add_workspace(session=session, name=self._workspace)
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="192.168.1.0/24",
                                scope=ScopeType.strict)
            IpUtils.add_host(session=session,
                             workspace=workspace,
                             address="192.168.1.1",
                             in_scope=False)
        with self._engine.session_scope() as session:
            result = session.query(Host).filter_by(address="192.168.1.1").one()
            self.assertFalse(result.in_scope)
            self.assertEqual("192.168.1.0/24", result.ipv4_network.network)
            self.assertEqual(ScopeType.strict, result.ipv4_network.scope)
            self.assertTrue(result.ipv4_network.in_scope)

    def test_insert_strict_network_with_host_scope_true(self):
        """
        If a host is added to a network with scope strict, then the host's scope can remain as specified.
        """
        # set up database
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = IpUtils.add_workspace(session=session, name=self._workspace)
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="192.168.1.0/24",
                                scope=ScopeType.strict)
            IpUtils.add_host(session=session,
                             workspace=workspace,
                             address="192.168.1.1",
                             in_scope=True)
        with self._engine.session_scope() as session:
            result = session.query(Host).filter_by(address="192.168.1.1").one()
            self.assertTrue(result.in_scope)
            self.assertEqual("192.168.1.0/24", result.ipv4_network.network)
            self.assertEqual(ScopeType.strict, result.ipv4_network.scope)
            self.assertTrue(result.ipv4_network.in_scope)

    def test_insert_strict_parent_network_to_subnetwork_all_01(self):
        """
        It should be possible to specify networks with scope type all within parent networks of scope type strict.
        """
        # set up database
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = IpUtils.add_workspace(session=session, name=self._workspace)
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="0.0.0.0/0",
                                scope=ScopeType.strict)
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="192.168.1.0/24",
                                scope=ScopeType.all)
        with self._engine.session_scope() as session:
            network = session.query(Network).filter_by(network="0.0.0.0/0").one()
            self.assertEqual(ScopeType.strict, network.scope)
            self.assertTrue(network.in_scope)
            network = session.query(Network).filter_by(network="192.168.1.0/24").one()
            self.assertEqual(ScopeType.all, network.scope)
            self.assertTrue(network.in_scope)


class HostScopeTypeNoneTestCases(BaseKisTestCase):
    """
    This class implements functionalities for testing correct host to network assignments and scoping.
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)
        self._workspace = "unittest"

    def test_insert_host_with_no_network_01(self):
        """
        Test correct host to network assignment.
        """
        # set up database
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = IpUtils.add_workspace(session=session, name=self._workspace)
            IpUtils.add_host(session=session,
                             workspace=workspace,
                             address="192.168.1.1")
        with self._engine.session_scope() as session:
            result = session.query(Host).filter_by(address="192.168.1.1").one()
            self.assertFalse(result.in_scope)

    def test_insert_host_with_no_network_02(self):
        """
        Test correct host to network assignment.
        """
        # set up database
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = IpUtils.add_workspace(session=session, name=self._workspace)
            IpUtils.add_host(session=session,
                             workspace=workspace,
                             address="192.168.1.1",
                             in_scope=True)
        with self._engine.session_scope() as session:
            result = session.query(Host).filter_by(address="192.168.1.1").one()
            self.assertFalse(result.in_scope)

    def test_simple_insert_to_network_01(self):
        """
        Test correct host to network assignment.
        """
        # set up database
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = IpUtils.add_workspace(session=session, name=self._workspace)
            IpUtils.add_host(session=session,
                             workspace=workspace,
                             address="192.168.1.1")
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="192.168.1.0/24",
                                scope=ScopeType.all)
        with self._engine.session_scope() as session:
            result = session.query(Host).filter_by(address="192.168.1.1").one()
            self.assertTrue(result.in_scope)
            self.assertEqual(ScopeType.all, result.ipv4_network.scope)
            self.assertEqual("192.168.1.0/24", result.ipv4_network.network)
            self.assertTrue(result.ipv4_network.in_scope)

    def test_simple_insert_to_network_02(self):
        """
        Test correct host to network assignment.
        """
        # set up database
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = IpUtils.add_workspace(session=session, name=self._workspace)
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="192.168.1.0/24",
                                scope=ScopeType.all)
            IpUtils.add_host(session=session,
                             workspace=workspace,
                             address="192.168.1.1")
        with self._engine.session_scope() as session:
            result = session.query(Host).filter_by(address="192.168.1.1").one()
            self.assertTrue(result.in_scope)
            self.assertEqual(ScopeType.all, result.ipv4_network.scope)
            self.assertEqual("192.168.1.0/24", result.ipv4_network.network)
            self.assertTrue(result.ipv4_network.in_scope)

    def test_insert_host_with_wrong_scope_01(self):
        """
        Inserting an in-scope into an out-of-scope network should automatically put the host out-of-scope.
        """
        # set up database
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = IpUtils.add_workspace(session=session, name=self._workspace)
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="192.168.1.0/24")
            IpUtils.add_host(session=session,
                             workspace=workspace,
                             address="192.168.1.1",
                             in_scope=True)
        with self._engine.session_scope() as session:
            result = session.query(Host).filter_by(address="192.168.1.1").one()
            self.assertFalse(result.in_scope)
            self.assertIsNone(result.ipv4_network.scope)
            self.assertEqual("192.168.1.0/24", result.ipv4_network.network)
            self.assertFalse(result.ipv4_network.in_scope)

    def test_insert_host_with_wrong_scope_02(self):
        """
        Inserting an in-scope into an out-of-scope network should automatically put the host out-of-scope.
        """
        # set up database
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = IpUtils.add_workspace(session=session, name=self._workspace)
            IpUtils.add_host(session=session,
                             workspace=workspace,
                             address="192.168.1.1",
                             in_scope=True)
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="192.168.1.0/24")
        with self._engine.session_scope() as session:
            result = session.query(Host).filter_by(address="192.168.1.1").one()
            self.assertFalse(result.in_scope)
            self.assertIsNone(result.ipv4_network.scope)
            self.assertEqual("192.168.1.0/24", result.ipv4_network.network)
            self.assertFalse(result.ipv4_network.in_scope)

    def test_simple_insert_to_host_01(self):
        """
        Test correct host to host assignment.
        """
        # set up database
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = IpUtils.add_workspace(session=session, name=self._workspace)
            IpUtils.add_host(session=session,
                             workspace=workspace,
                             address="192.168.1.1")
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="192.168.1.1",
                                scope=ScopeType.all)
        with self._engine.session_scope() as session:
            result = session.query(Host).filter_by(address="192.168.1.1").one()
            self.assertTrue(result.in_scope)
            self.assertEqual(ScopeType.all, result.ipv4_network.scope)
            self.assertEqual("192.168.1.1", result.ipv4_network.network)
            self.assertTrue(result.ipv4_network.in_scope)

    def test_simple_insert_to_host_02(self):
        """
        Test correct host to host assignment.
        """
        # set up database
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = IpUtils.add_workspace(session=session, name=self._workspace)
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="192.168.1.1",
                                scope=ScopeType.all)
            IpUtils.add_host(session=session,
                             workspace=workspace,
                             address="192.168.1.1")
        with self._engine.session_scope() as session:
            result = session.query(Host).filter_by(address="192.168.1.1").one()
            self.assertTrue(result.in_scope)
            self.assertEqual(ScopeType.all, result.ipv4_network.scope)
            self.assertEqual("192.168.1.1", result.ipv4_network.network)
            self.assertTrue(result.ipv4_network.in_scope)

    def test_insert_to_subnetwork_01(self):
        """
        Test correct assignment to sub-network
        """
        # set up database
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = IpUtils.add_workspace(session=session, name=self._workspace)
            IpUtils.add_host(session=session,
                             workspace=workspace,
                             address="192.168.1.1")
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="0.0.0.0/0",
                                scope=ScopeType.all)
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="192.168.1.0/24",
                                scope=ScopeType.all)
        with self._engine.session_scope() as session:
            result = session.query(Host).filter_by(address="192.168.1.1").one()
            self.assertTrue(result.in_scope)
            self.assertEqual("192.168.1.0/24", result.ipv4_network.network)
            self.assertEqual(ScopeType.all, result.ipv4_network.scope)
            self.assertTrue(result.ipv4_network.in_scope)

    def test_insert_to_subnetwork_02(self):
        """
        Test correct assignment to sub-network
        """
        # set up database
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = IpUtils.add_workspace(session=session, name=self._workspace)
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="192.168.1.0/24",
                                scope=ScopeType.all)
            IpUtils.add_host(session=session,
                             workspace=workspace,
                             address="192.168.1.1")
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="0.0.0.0/0",
                                scope=ScopeType.all)
        with self._engine.session_scope() as session:
            result = session.query(Host).filter_by(address="192.168.1.1").one()
            self.assertTrue(result.in_scope)
            self.assertEqual("192.168.1.0/24", result.ipv4_network.network)
            self.assertEqual(ScopeType.all, result.ipv4_network.scope)
            self.assertTrue(result.ipv4_network.in_scope)

    def test_insert_to_subnetwork_03(self):
        """
        Test correct assignment to sub-network
        """
        # set up database
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = IpUtils.add_workspace(session=session, name=self._workspace)
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="192.168.1.0/24",
                                scope=ScopeType.all)
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="0.0.0.0/0",
                                scope=ScopeType.all)
            IpUtils.add_host(session=session,
                             workspace=workspace,
                             address="192.168.1.1")
        with self._engine.session_scope() as session:
            result = session.query(Host).filter_by(address="192.168.1.1").one()
            self.assertTrue(result.in_scope)
            self.assertEqual("192.168.1.0/24", result.ipv4_network.network)
            self.assertEqual(ScopeType.all, result.ipv4_network.scope)
            self.assertTrue(result.ipv4_network.in_scope)

    def test_assign_to_host(self):
        """
        Test correct assignment to host
        """
        # set up database
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = IpUtils.add_workspace(session=session, name=self._workspace)
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="192.168.1.0/24",
                                scope=ScopeType.all)
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="0.0.0.0/0",
                                scope=ScopeType.all)
            IpUtils.add_host(session=session,
                             workspace=workspace,
                             address="192.168.1.1")
        with self._engine.session_scope() as session:
            result = session.query(Host).filter_by(address="192.168.1.1").one()
            self.assertTrue(result.in_scope)
            self.assertEqual("192.168.1.0/24", result.ipv4_network.network)
            self.assertEqual(ScopeType.all, result.ipv4_network.scope)
            self.assertTrue(result.ipv4_network.in_scope)

    def test_multi_network_assignments(self):
        """
        Test correct assignment to sub-network
        """
        # set up database
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = IpUtils.add_workspace(session=session, name=self._workspace)
            IpUtils.add_host(session=session,
                             workspace=workspace,
                             address="10.10.10.10")
            IpUtils.add_host(session=session,
                             workspace=workspace,
                             address="192.168.1.255")
            IpUtils.add_host(session=session,
                             workspace=workspace,
                             address="192.168.1.1")
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="192.168.1.128/25",
                                scope=ScopeType.all)
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="0.0.0.0/0")
            IpUtils.add_host(session=session,
                             workspace=workspace,
                             address="192.168.1.2")
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="192.168.1.0/24")
            IpUtils.add_host(session=session,
                             workspace=workspace,
                             address="192.168.1.225")
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="192.168.1.224/27")
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="192.168.1.192/26")
            IpUtils.add_host(session=session,
                             workspace=workspace,
                             address="192.168.1.129")
        with self._engine.session_scope() as session:
            result = session.query(Host).filter_by(address="10.10.10.10").one()
            self.assertEqual('0.0.0.0/0', result.ipv4_network.network)
            self.assertFalse(result.ipv4_network.in_scope)
            self.assertFalse(result.in_scope)
            result = session.query(Host).filter_by(address="192.168.1.1").one()
            self.assertEqual('192.168.1.0/24', result.ipv4_network.network)
            self.assertFalse(result.ipv4_network.in_scope)
            self.assertFalse(result.in_scope)
            result = session.query(Host).filter_by(address="192.168.1.2").one()
            self.assertEqual('192.168.1.0/24', result.ipv4_network.network)
            self.assertFalse(result.ipv4_network.in_scope)
            self.assertFalse(result.in_scope)
            result = session.query(Host).filter_by(address="192.168.1.129").one()
            self.assertEqual('192.168.1.128/25', result.ipv4_network.network)
            self.assertTrue(result.ipv4_network.in_scope)
            self.assertTrue(result.in_scope)
            result = session.query(Host).filter_by(address="192.168.1.225").one()
            self.assertEqual('192.168.1.224/27', result.ipv4_network.network)
            self.assertTrue(result.ipv4_network.in_scope)
            self.assertTrue(result.in_scope)
            result = session.query(Host).filter_by(address="192.168.1.225").one()
            self.assertEqual('192.168.1.224/27', result.ipv4_network.network)
            self.assertTrue(result.ipv4_network.in_scope)
            self.assertTrue(result.in_scope)

    def test_multi_network_assignments_01(self):
        """
        Test correct assignment to sub-network
        """
        # set up database
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = IpUtils.add_workspace(session=session, name=self._workspace)
            IpUtils.add_host(session=session,
                             workspace=workspace,
                             address="192.168.1.1")
            IpUtils.add_host(session=session,
                             workspace=workspace,
                             address="192.168.1.2")
            IpUtils.add_host(session=session,
                             workspace=workspace,
                             address="192.168.1.129")
            IpUtils.add_host(session=session,
                             workspace=workspace,
                             address="192.168.1.254")
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="192.168.1.0/24",
                                scope=ScopeType.all)
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="192.168.1.224/27")
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="192.168.1.128/25")
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="192.168.1.192/26")
            IpUtils.add_host(session=session,
                             workspace=workspace,
                             address="192.168.1.253")
            IpUtils.add_network(session=session,
                                workspace=workspace,
                                network="0.0.0.0/0")
        with self._engine.session_scope() as session:
            # Ensure that scope of largest parent network is automatically assigned to sub-networks
            network = session.query(Network).filter_by(network="0.0.0.0/0").one()
            self.assertIsNone(network.scope)
            network = session.query(Network).filter_by(network="192.168.1.0/24").one()
            self.assertEqual(ScopeType.all, network.scope)
            network = session.query(Network).filter_by(network="192.168.1.224/27").one()
            self.assertEqual(ScopeType.all, network.scope)
            network = session.query(Network).filter_by(network="192.168.1.128/25").one()
            self.assertEqual(ScopeType.all, network.scope)
            network = session.query(Network).filter_by(network="192.168.1.192/26").one()
            self.assertEqual(ScopeType.all, network.scope)

    def test_simple_update_network_scope_01(self):
        """
        If a network is excluded from scope, then the containing hosts should be out of scope as well.
        """
        self.test_simple_insert_to_network_01()
        # Perform update
        with self._engine.session_scope() as session:
            result = session.query(Network).filter_by(network="192.168.1.0/24").one()
            self.assertEqual(ScopeType.all, result.scope)
            self.assertTrue(result.in_scope)
            result.scope = ScopeType.exclude
        # Check results
        with self._engine.session_scope() as session:
            result = session.query(Host).filter_by(address="192.168.1.1").one()
            self.assertFalse(result.in_scope)
            self.assertEqual(ScopeType.exclude, result.ipv4_network.scope)
            self.assertEqual("192.168.1.0/24", result.ipv4_network.network)
            self.assertFalse(result.ipv4_network.in_scope)

    def test_update_single_host_scope(self):
        """
        Check if single host to host scope update works
        """
        self.test_simple_insert_to_host_01()
        # Perform update
        with self._engine.session_scope() as session:
            result = session.query(Network).filter_by(network="192.168.1.1").one()
            self.assertEqual(ScopeType.all, result.scope)
            self.assertTrue(result.in_scope)
            result.scope = ScopeType.exclude
        # Check results
        with self._engine.session_scope() as session:
            result = session.query(Host).filter_by(address="192.168.1.1").one()
            self.assertFalse(result.in_scope)
            self.assertFalse(result.ipv4_network.in_scope)
            self.assertEqual(ScopeType.exclude, result.ipv4_network.scope)
            self.assertEqual("192.168.1.1", result.ipv4_network.network)

    def test_update_wrong_host_scope(self):
        """
        An incorrect update of the host scope should lead to automatic correction.
        """
        self.test_simple_insert_to_network_01()
        with self._engine.session_scope() as session:
            result = session.query(Host).filter_by(address="192.168.1.1").one()
            self.assertTrue(result.in_scope)
            self.assertTrue(result.ipv4_network.in_scope)
            self.assertEqual(ScopeType.all, result.ipv4_network.scope)
            self.assertEqual("192.168.1.0/24", result.ipv4_network.network)
            result.in_scope = False
        with self._engine.session_scope() as session:
            result = session.query(Host).filter_by(address="192.168.1.1").one()
            self.assertTrue(result.in_scope)
            self.assertTrue(result.ipv4_network.in_scope)
            self.assertEqual(ScopeType.all, result.ipv4_network.scope)
            self.assertEqual("192.168.1.0/24", result.ipv4_network.network)

    def test_update_parent_network_scope(self):
        """
        The update of the parent network's scope should update all sub-network scopes
        """
        self.test_insert_to_subnetwork_01()
        # Perform update
        with self._engine.session_scope() as session:
            result = session.query(Network).filter_by(network="0.0.0.0/0").one()
            self.assertEqual(ScopeType.all, result.scope)
            self.assertTrue(result.in_scope)
            result.scope = ScopeType.exclude
        # Check results
        with self._engine.session_scope() as session:
            result = session.query(Host).filter_by(address="192.168.1.1").one()
            self.assertFalse(result.in_scope)
            self.assertFalse(result.ipv4_network.in_scope)
            self.assertEqual(ScopeType.exclude, result.ipv4_network.scope)
            self.assertEqual("192.168.1.0/24", result.ipv4_network.network)

    def test_update_multi_network_assignments(self):
        """
        The update of the parent network's scope should update all sub-network scopes
        """
        self.test_multi_network_assignments()
        # Perform update
        with self._engine.session_scope() as session:
            result = session.query(Network).filter_by(network="192.168.1.128/25").one()
            self.assertEqual(ScopeType.all, result.scope)
            self.assertTrue(result.in_scope)
            result.scope = ScopeType.exclude
        # Check results
        with self._engine.session_scope() as session:
            result = session.query(Host).filter_by(address="10.10.10.10").one()
            self.assertEqual('0.0.0.0/0', result.ipv4_network.network)
            self.assertFalse(result.ipv4_network.in_scope)
            self.assertFalse(result.in_scope)
            result = session.query(Host).filter_by(address="192.168.1.1").one()
            self.assertEqual('192.168.1.0/24', result.ipv4_network.network)
            self.assertFalse(result.ipv4_network.in_scope)
            self.assertFalse(result.in_scope)
            result = session.query(Host).filter_by(address="192.168.1.2").one()
            self.assertEqual('192.168.1.0/24', result.ipv4_network.network)
            self.assertFalse(result.ipv4_network.in_scope)
            self.assertFalse(result.in_scope)
            result = session.query(Host).filter_by(address="192.168.1.129").one()
            self.assertEqual('192.168.1.128/25', result.ipv4_network.network)
            self.assertFalse(result.ipv4_network.in_scope)
            self.assertFalse(result.in_scope)
            result = session.query(Host).filter_by(address="192.168.1.225").one()
            self.assertEqual('192.168.1.224/27', result.ipv4_network.network)
            self.assertFalse(result.ipv4_network.in_scope)
            self.assertFalse(result.in_scope)
            result = session.query(Host).filter_by(address="192.168.1.225").one()
            self.assertEqual('192.168.1.224/27', result.ipv4_network.network)
            self.assertFalse(result.ipv4_network.in_scope)
            self.assertFalse(result.in_scope)
        # Perform update
        with self._engine.session_scope() as session:
            result = session.query(Network).filter_by(network="192.168.1.224/27").one()
            self.assertEqual(ScopeType.exclude, result.scope)
            self.assertFalse(result.in_scope)
            result.scope = ScopeType.all
        # Check results
        with self._engine.session_scope() as session:
            result = session.query(Host).filter_by(address="10.10.10.10").one()
            self.assertEqual('0.0.0.0/0', result.ipv4_network.network)
            self.assertFalse(result.ipv4_network.in_scope)
            self.assertFalse(result.in_scope)
            result = session.query(Host).filter_by(address="192.168.1.1").one()
            self.assertEqual('192.168.1.0/24', result.ipv4_network.network)
            self.assertFalse(result.ipv4_network.in_scope)
            self.assertFalse(result.in_scope)
            result = session.query(Host).filter_by(address="192.168.1.2").one()
            self.assertEqual('192.168.1.0/24', result.ipv4_network.network)
            self.assertFalse(result.ipv4_network.in_scope)
            self.assertFalse(result.in_scope)
            result = session.query(Host).filter_by(address="192.168.1.129").one()
            self.assertEqual('192.168.1.128/25', result.ipv4_network.network)
            self.assertFalse(result.ipv4_network.in_scope)
            self.assertFalse(result.in_scope)
            result = session.query(Host).filter_by(address="192.168.1.225").one()
            self.assertEqual('192.168.1.224/27', result.ipv4_network.network)
            self.assertTrue(result.ipv4_network.in_scope)
            self.assertTrue(result.in_scope)
            result = session.query(Host).filter_by(address="192.168.1.225").one()
            self.assertTrue(result.ipv4_network.in_scope)
            self.assertEqual('192.168.1.224/27', result.ipv4_network.network)
            self.assertTrue(result.in_scope)
        # Perform update
        with self._engine.session_scope() as session:
            result = session.query(Network).filter_by(network="0.0.0.0/0").one()
            self.assertIsNone(result.scope)
            result.scope = ScopeType.all
        # Check results
        with self._engine.session_scope() as session:
            result = session.query(Host).filter_by(address="10.10.10.10").one()
            self.assertEqual('0.0.0.0/0', result.ipv4_network.network)
            self.assertTrue(result.ipv4_network.in_scope)
            self.assertTrue(result.in_scope)
            result = session.query(Host).filter_by(address="192.168.1.1").one()
            self.assertEqual('192.168.1.0/24', result.ipv4_network.network)
            self.assertTrue(result.ipv4_network.in_scope)
            self.assertTrue(result.in_scope)
            result = session.query(Host).filter_by(address="192.168.1.2").one()
            self.assertEqual('192.168.1.0/24', result.ipv4_network.network)
            self.assertTrue(result.ipv4_network.in_scope)
            self.assertTrue(result.in_scope)
            result = session.query(Host).filter_by(address="192.168.1.129").one()
            self.assertEqual('192.168.1.128/25', result.ipv4_network.network)
            self.assertTrue(result.ipv4_network.in_scope)
            self.assertTrue(result.in_scope)
            result = session.query(Host).filter_by(address="192.168.1.225").one()
            self.assertEqual('192.168.1.224/27', result.ipv4_network.network)
            self.assertTrue(result.ipv4_network.in_scope)
            self.assertTrue(result.in_scope)
            result = session.query(Host).filter_by(address="192.168.1.225").one()
            self.assertEqual('192.168.1.224/27', result.ipv4_network.network)
            self.assertTrue(result.ipv4_network.in_scope)
            self.assertTrue(result.in_scope)

    def test_delete_network_with_one_host(self):
        """
        Test correct host to network assignment.
        """
        self.test_simple_insert_to_network_01()
        with self._engine.session_scope() as session:
            session.query(Network).filter_by(network="192.168.1.0/24").delete()
        with self._engine.session_scope() as session:
            result = session.query(Host).filter_by(address="192.168.1.1").one()
            self.assertFalse(result.in_scope)
            self.assertIsNone(result.ipv4_network)

    def test_delete_smallest_subnetwork_with_one_host(self):
        """
        Test correct host to network assignment.
        """
        self.test_insert_to_subnetwork_01()
        with self._engine.session_scope() as session:
            session.query(Network).filter_by(network="192.168.1.0/24").delete()
        with self._engine.session_scope() as session:
            result = session.query(Host).filter_by(address="192.168.1.1").one()
            self.assertTrue(result.in_scope)
            self.assertTrue(result.ipv4_network.in_scope)
            self.assertEqual("0.0.0.0/0", result.ipv4_network.network)

    def test_delete_smallest_network_inmulti_network_assignments(self):
        """
        The update of the parent network's scope should update all sub-network scopes
        """
        self.test_multi_network_assignments()
        # Perform update
        with self._engine.session_scope() as session:
            session.query(Network).filter_by(network="192.168.1.224/27").delete()
        # check database
        with self._engine.session_scope() as session:
            result = session.query(Host).filter_by(address="10.10.10.10").one()
            self.assertEqual('0.0.0.0/0', result.ipv4_network.network)
            self.assertFalse(result.ipv4_network.in_scope)
            self.assertFalse(result.in_scope)
            result = session.query(Host).filter_by(address="192.168.1.1").one()
            self.assertEqual('192.168.1.0/24', result.ipv4_network.network)
            self.assertFalse(result.ipv4_network.in_scope)
            self.assertFalse(result.in_scope)
            result = session.query(Host).filter_by(address="192.168.1.2").one()
            self.assertEqual('192.168.1.0/24', result.ipv4_network.network)
            self.assertFalse(result.ipv4_network.in_scope)
            self.assertFalse(result.in_scope)
            result = session.query(Host).filter_by(address="192.168.1.129").one()
            self.assertEqual('192.168.1.128/25', result.ipv4_network.network)
            self.assertTrue(result.ipv4_network.in_scope)
            self.assertTrue(result.in_scope)
            result = session.query(Host).filter_by(address="192.168.1.225").one()
            self.assertEqual('192.168.1.192/26', result.ipv4_network.network)
            self.assertTrue(result.ipv4_network.in_scope)
            self.assertTrue(result.in_scope)
            result = session.query(Host).filter_by(address="192.168.1.225").one()
            self.assertEqual('192.168.1.192/26', result.ipv4_network.network)
            self.assertTrue(result.ipv4_network.in_scope)
            self.assertTrue(result.in_scope)

    def test_delete_largest_network_inmulti_network_assignments(self):
        """
        The update of the parent network's scope should update all sub-network scopes
        """
        self.test_multi_network_assignments()
        # Perform update
        with self._engine.session_scope() as session:
            session.query(Network).filter_by(network="0.0.0.0/0").delete()
        # check database
        with self._engine.session_scope() as session:
            result = session.query(Host).filter_by(address="10.10.10.10").one()
            self.assertIsNone(result.ipv4_network)
            self.assertFalse(result.in_scope)
            result = session.query(Host).filter_by(address="192.168.1.1").one()
            self.assertEqual('192.168.1.0/24', result.ipv4_network.network)
            self.assertFalse(result.ipv4_network.in_scope)
            self.assertFalse(result.in_scope)
            result = session.query(Host).filter_by(address="192.168.1.2").one()
            self.assertEqual('192.168.1.0/24', result.ipv4_network.network)
            self.assertFalse(result.ipv4_network.in_scope)
            self.assertFalse(result.in_scope)
            result = session.query(Host).filter_by(address="192.168.1.129").one()
            self.assertEqual('192.168.1.128/25', result.ipv4_network.network)
            self.assertTrue(result.ipv4_network.in_scope)
            self.assertTrue(result.in_scope)
            result = session.query(Host).filter_by(address="192.168.1.225").one()
            self.assertEqual('192.168.1.224/27', result.ipv4_network.network)
            self.assertTrue(result.ipv4_network.in_scope)
            self.assertTrue(result.in_scope)
            result = session.query(Host).filter_by(address="192.168.1.225").one()
            self.assertEqual('192.168.1.224/27', result.ipv4_network.network)
            self.assertTrue(result.ipv4_network.in_scope)
            self.assertTrue(result.in_scope)

    def test_delete_middle_network_inmulti_network_assignments(self):
        """
        The update of the parent network's scope should update all sub-network scopes
        """
        self.test_multi_network_assignments()
        # Perform update
        with self._engine.session_scope() as session:
            session.query(Network).filter_by(network="192.168.1.0/24").delete()
        # check database
        with self._engine.session_scope() as session:
            result = session.query(Host).filter_by(address="10.10.10.10").one()
            self.assertEqual('0.0.0.0/0', result.ipv4_network.network)
            self.assertFalse(result.ipv4_network.in_scope)
            self.assertFalse(result.in_scope)
            result = session.query(Host).filter_by(address="192.168.1.1").one()
            self.assertEqual('0.0.0.0/0', result.ipv4_network.network)
            self.assertFalse(result.ipv4_network.in_scope)
            self.assertFalse(result.in_scope)
            result = session.query(Host).filter_by(address="192.168.1.2").one()
            self.assertEqual('0.0.0.0/0', result.ipv4_network.network)
            self.assertFalse(result.ipv4_network.in_scope)
            self.assertFalse(result.in_scope)
            result = session.query(Host).filter_by(address="192.168.1.129").one()
            self.assertEqual('192.168.1.128/25', result.ipv4_network.network)
            self.assertTrue(result.ipv4_network.in_scope)
            self.assertTrue(result.in_scope)
            result = session.query(Host).filter_by(address="192.168.1.225").one()
            self.assertEqual('192.168.1.224/27', result.ipv4_network.network)
            self.assertTrue(result.ipv4_network.in_scope)
            self.assertTrue(result.in_scope)
            result = session.query(Host).filter_by(address="192.168.1.225").one()
            self.assertEqual('192.168.1.224/27', result.ipv4_network.network)
            self.assertTrue(result.ipv4_network.in_scope)
            self.assertTrue(result.in_scope)


class DomainNameScopeTypeAllTestCases(BaseKisTestCase):
    """
    This class implements functionalities for testing the domain names with scope type all
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)
        self._domain_utils = DomainUtils()
        self._workspace = "unittest"

    def test_insert_second_level_domain(self):
        """
        Inserting a second-level domain with scope type all should set its host name record scope to true.
        """
        # set up database
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = IpUtils.add_workspace(session=session, name=self._workspace)
            self._domain_utils.add_domain_name(session=session,
                                               workspace=workspace,
                                               item="test.local",
                                               scope=ScopeType.all)
        with self._engine.session_scope() as session:
            result = session.query(DomainName).filter_by(name="test.local").one()
            self.assertTrue(result.in_scope)
            result = session.query(HostName).filter(HostName.name.is_(None)).one()
            self.assertEqual("test.local", result.domain_name.name)
            self.assertTrue(result._in_scope)

    def test_insert_host_name(self):
        """
        Inserting a second-level domain with scope type all should set its host name record scope to true.
        """
        # set up database
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = IpUtils.add_workspace(session=session, name=self._workspace)
            self._domain_utils.add_domain_name(session=session,
                                               workspace=workspace,
                                               item="www.test.local",
                                               scope=ScopeType.all)
            self._domain_utils.add_domain_name(session=session,
                                               workspace=workspace,
                                               item="ftp.test.local",
                                               scope=ScopeType.all)
        with self._engine.session_scope() as session:
            result = session.query(HostName).filter(HostName.name.is_(None)).one()
            self.assertEqual("test.local", result.domain_name.name)
            self.assertTrue(result._in_scope)
            result = session.query(HostName).filter_by(name="www").one()
            self.assertEqual("test.local", result.domain_name.name)
            self.assertTrue(result._in_scope)
            result = session.query(HostName).filter_by(name="ftp").one()
            self.assertEqual("test.local", result.domain_name.name)
            self.assertTrue(result._in_scope)

    def test_update_host_name_scope(self):
        """
        Manual updates of the scope should be automatically corrected.
        """
        # set up database
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = IpUtils.add_workspace(session=session, name=self._workspace)
            self._domain_utils.add_domain_name(session=session,
                                               workspace=workspace,
                                               item="www.test.local",
                                               scope=ScopeType.all)
        with self._engine.session_scope() as session:
            result = session.query(HostName).filter_by(name="www").one()
            self.assertEqual("test.local", result.domain_name.name)
            self.assertTrue(result._in_scope)
            result._in_scope = False
        with self._engine.session_scope() as session:
            result = session.query(HostName).filter_by(name="www").one()
            self.assertEqual("test.local", result.domain_name.name)
            self.assertTrue(result._in_scope)

    def test_update_second_level_domain_scope(self):
        """
        Putting the second-level domain out of scope, should automatically update all host names
        """
        self.test_insert_host_name()
        # Exclude domain from scope
        with self._engine.session_scope() as session:
            result = session.query(DomainName).one()
            result.scope = ScopeType.exclude
        # Check correct update
        with self._engine.session_scope() as session:
            result = session.query(HostName).filter(HostName.name.is_(None)).one()
            self.assertEqual("test.local", result.domain_name.name)
            self.assertFalse(result._in_scope)
            result = session.query(HostName).filter_by(name="www").one()
            self.assertEqual("test.local", result.domain_name.name)
            self.assertFalse(result._in_scope)
            result = session.query(HostName).filter_by(name="ftp").one()
            self.assertEqual("test.local", result.domain_name.name)
            self.assertFalse(result._in_scope)
        # Include domain in scope
        with self._engine.session_scope() as session:
            result = session.query(DomainName).one()
            result.scope = ScopeType.all
        # Check correct update
        with self._engine.session_scope() as session:
            result = session.query(HostName).filter(HostName.name.is_(None)).one()
            self.assertEqual("test.local", result.domain_name.name)
            self.assertTrue(result._in_scope)
            result = session.query(HostName).filter_by(name="www").one()
            self.assertEqual("test.local", result.domain_name.name)
            self.assertTrue(result._in_scope)
            result = session.query(HostName).filter_by(name="ftp").one()
            self.assertEqual("test.local", result.domain_name.name)
            self.assertTrue(result._in_scope)


class DomainNameScopeTypeStrictTestCases(BaseKisTestCase):
    """
    This class implements functionalities for testing the domain names with scope type strict
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)
        self._domain_utils = DomainUtils()
        self._workspace = "unittest"

    def test_insert_second_level_domain(self):
        """
        Inserting a second-level domain with scope type strict should set its host name record scope to true.
        """
        # set up database
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = IpUtils.add_workspace(session=session, name=self._workspace)
            self._domain_utils.add_domain_name(session=session,
                                               workspace=workspace,
                                               item="test.local",
                                               scope=ScopeType.strict)
            self._domain_utils.add_domain_name(session=session,
                                               workspace=workspace,
                                               item="www.test.local")
        with self._engine.session_scope() as session:
            result = session.query(HostName).filter(HostName.name.is_(None)).one()
            self.assertEqual("test.local", result.domain_name.name)
            self.assertTrue(result._in_scope)
            self.assertTrue(result.domain_name.in_scope)
            result = session.query(HostName).filter_by(name="www").one()
            self.assertEqual("test.local", result.domain_name.name)
            self.assertFalse(result._in_scope)
            self.assertTrue(result.domain_name.in_scope)

    def test_insert_host_name(self):
        """
        Inserting a second-level domain with scope type all should set its host name record scope to true.
        """
        # set up database
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = IpUtils.add_workspace(session=session, name=self._workspace)
            self._domain_utils.add_domain_name(session=session,
                                               workspace=workspace,
                                               item="www.test.local",
                                               scope=ScopeType.strict)
            self._domain_utils.add_domain_name(session=session,
                                               workspace=workspace,
                                               item="ftp.test.local",
                                               scope=ScopeType.strict)
            self._domain_utils.add_domain_name(session=session,
                                               workspace=workspace,
                                               item="mail.test.local")
            host_name = self._domain_utils.add_domain_name(session=session,
                                                           workspace=workspace,
                                                           item="citrix.test.local")
            host_name._in_scope = True
        with self._engine.session_scope() as session:
            result = session.query(HostName).filter(HostName.name.is_(None)).one()
            self.assertEqual("test.local", result.domain_name.name)
            self.assertTrue(result._in_scope)
            self.assertTrue(result.domain_name.in_scope)
            result = session.query(HostName).filter_by(name="www").one()
            self.assertEqual("test.local", result.domain_name.name)
            self.assertTrue(result._in_scope)
            self.assertTrue(result.domain_name.in_scope)
            result = session.query(HostName).filter_by(name="ftp").one()
            self.assertEqual("test.local", result.domain_name.name)
            self.assertTrue(result._in_scope)
            self.assertTrue(result.domain_name.in_scope)
            result = session.query(HostName).filter_by(name="mail").one()
            self.assertEqual("test.local", result.domain_name.name)
            self.assertFalse(result._in_scope)
            self.assertTrue(result.domain_name.in_scope)
            result = session.query(HostName).filter_by(name="citrix").one()
            self.assertEqual("test.local", result.domain_name.name)
            self.assertTrue(result._in_scope)
            self.assertTrue(result.domain_name.in_scope)

    def test_update_host_name_scope(self):
        """
        Manual updates of the scope should not be automatically corrected.
        """
        # set up database
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = IpUtils.add_workspace(session=session, name=self._workspace)
            self._domain_utils.add_domain_name(session=session,
                                               workspace=workspace,
                                               item="test1.local")
            self._domain_utils.add_domain_name(session=session,
                                               workspace=workspace,
                                               item="www.test.local",
                                               scope=ScopeType.strict)
            self._domain_utils.add_domain_name(session=session,
                                               workspace=workspace,
                                               item="ftp.test.local")
        with self._engine.session_scope() as session:
            result = session.query(DomainName).filter_by(name="test1.local").one()
            self.assertFalse(result.in_scope)
            result = session.query(HostName).filter_by(name="www").one()
            self.assertEqual("test.local", result.domain_name.name)
            self.assertTrue(result._in_scope)
            result._in_scope = False
            result = session.query(HostName).filter_by(name="ftp").one()
            self.assertEqual("test.local", result.domain_name.name)
            self.assertFalse(result._in_scope)
            result._in_scope = True
        with self._engine.session_scope() as session:
            result = session.query(HostName).filter_by(name="www").one()
            self.assertEqual("test.local", result.domain_name.name)
            self.assertFalse(result._in_scope)
            result = session.query(HostName).filter_by(name="ftp").one()
            self.assertEqual("test.local", result.domain_name.name)
            self.assertTrue(result._in_scope)

    def test_update_second_level_domain_scope(self):
        """
        Putting the second-level domain out of scope, should automatically update all host names
        """
        self.test_insert_host_name()
        # Exclude domain from scope
        with self._engine.session_scope() as session:
            result = session.query(DomainName).one()
            result.scope = ScopeType.exclude
        # Check correct update
        with self._engine.session_scope() as session:
            result = session.query(HostName).filter(HostName.name.is_(None)).one()
            self.assertEqual("test.local", result.domain_name.name)
            self.assertFalse(result._in_scope)
            result = session.query(HostName).filter_by(name="www").one()
            self.assertEqual("test.local", result.domain_name.name)
            self.assertFalse(result._in_scope)
            result = session.query(HostName).filter_by(name="ftp").one()
            self.assertEqual("test.local", result.domain_name.name)
            self.assertFalse(result._in_scope)
        # Include domain in scope
        with self._engine.session_scope() as session:
            result = session.query(DomainName).one()
            result.scope = ScopeType.strict
        # Check correct update
        with self._engine.session_scope() as session:
            result = session.query(HostName).filter(HostName.name.is_(None)).one()
            self.assertEqual("test.local", result.domain_name.name)
            self.assertFalse(result._in_scope)
            result = session.query(HostName).filter_by(name="www").one()
            self.assertEqual("test.local", result.domain_name.name)
            self.assertFalse(result._in_scope)
            result = session.query(HostName).filter_by(name="ftp").one()
            self.assertEqual("test.local", result.domain_name.name)
            self.assertFalse(result._in_scope)


class BaseScopeTypeVhostTestCases(BaseKisTestCase):
    """
    This class implements core functionalities for testing the scope type vhost
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)
        self._domain_utils = DomainUtils()
        self._workspace = "unittest"
        self._domain_utils = DomainUtils()

    def _create_host_host_name_mapping(self,
                                       session: Session,
                                       workspace: Workspace,
                                       host_str: str,
                                       network_str: str,
                                       host_name_str: str,
                                       network_scope: ScopeType = None,
                                       domain_name_scope: ScopeType = None,
                                       host_name_scope: bool = None,
                                       host_scope: bool = None,
                                       mapping_type: DnsResourceRecordType = None) -> HostHostNameMapping:
        IpUtils.add_network(session=session,
                            workspace=workspace,
                            network=network_str,
                            scope=network_scope)
        host = IpUtils.add_host(session=session,
                                workspace=workspace,
                                address=host_str,
                                in_scope=host_scope)
        host_name = self._domain_utils.add_domain_name(session=session,
                                                       workspace=workspace,
                                                       item=host_name_str,
                                                       scope=domain_name_scope)
        if host_name_scope is not None:
            host_name._in_scope = host_name_scope
        mapping = self._domain_utils.add_host_host_name_mapping(session=session,
                                                                host=host,
                                                                host_name=host_name,
                                                                mapping_type=mapping_type)
        return mapping


class DomainNameScopeTypeVhostTestCases(BaseScopeTypeVhostTestCases):
    """
    This class implements core functionalities for testing the scope type vhost
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def test_insert_network_scopetype_all(self):
        """
        This method checks whether the host scope is correctly set during the initial creation with network scope all.

        This unittest tests PostgreSQL functions: update_hosts_after_network_changes and update_hosts_after_host_changes
        """
        # set up database
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = IpUtils.add_workspace(session=session, name=self._workspace)
            # IPv4
            self._create_host_host_name_mapping(session=session,
                                                workspace=workspace,
                                                host_str="127.0.0.1",
                                                network_str="127.0.0.1/32",
                                                host_name_str="ipv4-test1.local",
                                                network_scope=ScopeType.all,
                                                domain_name_scope=ScopeType.vhost,
                                                mapping_type=DnsResourceRecordType.a)
            self._create_host_host_name_mapping(session=session,
                                                workspace=workspace,
                                                host_str="127.0.0.2",
                                                network_str="127.0.0.2/32",
                                                host_name_str="ipv4-test2.local",
                                                network_scope=ScopeType.exclude,
                                                domain_name_scope=ScopeType.vhost,
                                                mapping_type=DnsResourceRecordType.a)
            self._create_host_host_name_mapping(session=session,
                                                workspace=workspace,
                                                host_str="127.0.0.3",
                                                network_str="127.0.0.3/32",
                                                host_name_str="ipv4-test3.local",
                                                network_scope=ScopeType.all,
                                                domain_name_scope=ScopeType.vhost,
                                                mapping_type=DnsResourceRecordType.alias)
            self._create_host_host_name_mapping(session=session,
                                                workspace=workspace,
                                                host_str="127.0.0.4",
                                                network_str="127.0.0.4/32",
                                                host_name_str="ipv4-test4.local",
                                                network_scope=ScopeType.exclude,
                                                domain_name_scope=ScopeType.vhost,
                                                mapping_type=DnsResourceRecordType.alias)
            # IPv6
            self._create_host_host_name_mapping(session=session,
                                                workspace=workspace,
                                                host_str="::1",
                                                network_str="::1/128",
                                                host_name_str="ipv6-test1.local",
                                                network_scope=ScopeType.all,
                                                domain_name_scope=ScopeType.vhost,
                                                mapping_type=DnsResourceRecordType.aaaa)
            self._create_host_host_name_mapping(session=session,
                                                workspace=workspace,
                                                host_str="::2",
                                                network_str="::2/128",
                                                host_name_str="ipv6-test2.local",
                                                network_scope=ScopeType.exclude,
                                                domain_name_scope=ScopeType.vhost,
                                                mapping_type=DnsResourceRecordType.aaaa)
            self._create_host_host_name_mapping(session=session,
                                                workspace=workspace,
                                                host_str="::3",
                                                network_str="::3/128",
                                                host_name_str="ipv6-test3.local",
                                                network_scope=ScopeType.all,
                                                domain_name_scope=ScopeType.vhost,
                                                mapping_type=DnsResourceRecordType.alias)
            self._create_host_host_name_mapping(session=session,
                                                workspace=workspace,
                                                host_str="::4",
                                                network_str="::4/128",
                                                host_name_str="ipv6-test4.local",
                                                network_scope=ScopeType.exclude,
                                                domain_name_scope=ScopeType.vhost,
                                                mapping_type=DnsResourceRecordType.alias)
        # Update the database
        with self._engine.session_scope() as session:
            result = session.query(DomainName).filter_by(name="ipv4-test1.local").one()
            self.assertTrue(result.in_scope)
            result = self.query_hostname(session=session, workspace_str=self._workspace, host_name="ipv4-test1.local")
            self.assertTrue(result._in_scope)
            result = session.query(Host).filter_by(address="127.0.0.1").one()
            self.assertTrue(result.in_scope)

            result = session.query(DomainName).filter_by(name="ipv4-test2.local").one()
            self.assertTrue(result.in_scope)
            result = self.query_hostname(session=session, workspace_str=self._workspace, host_name="ipv4-test2.local")
            self.assertFalse(result._in_scope)
            result = session.query(Host).filter_by(address="127.0.0.2").one()
            self.assertFalse(result.in_scope)

            result = session.query(DomainName).filter_by(name="ipv4-test3.local").one()
            self.assertTrue(result.in_scope)
            result = self.query_hostname(session=session, workspace_str=self._workspace, host_name="ipv4-test3.local")
            self.assertFalse(result._in_scope)
            result = session.query(Host).filter_by(address="127.0.0.3").one()
            self.assertTrue(result.in_scope)

            result = session.query(DomainName).filter_by(name="ipv4-test4.local").one()
            self.assertTrue(result.in_scope)
            result = self.query_hostname(session=session, workspace_str=self._workspace, host_name="ipv4-test4.local")
            self.assertFalse(result._in_scope)
            result = session.query(Host).filter_by(address="127.0.0.4").one()
            self.assertFalse(result.in_scope)

            # IPv6
            result = session.query(DomainName).filter_by(name="ipv6-test1.local").one()
            self.assertTrue(result.in_scope)
            result = self.query_hostname(session=session, workspace_str=self._workspace, host_name="ipv6-test1.local")
            self.assertTrue(result._in_scope)
            result = session.query(Host).filter_by(address="::1").one()
            self.assertTrue(result.in_scope)

            result = session.query(DomainName).filter_by(name="ipv6-test2.local").one()
            self.assertTrue(result.in_scope)
            result = self.query_hostname(session=session, workspace_str=self._workspace, host_name="ipv6-test2.local")
            self.assertFalse(result._in_scope)
            result = session.query(Host).filter_by(address="::2").one()
            self.assertFalse(result.in_scope)

            result = session.query(DomainName).filter_by(name="ipv6-test3.local").one()
            self.assertTrue(result.in_scope)
            result = self.query_hostname(session=session, workspace_str=self._workspace, host_name="ipv6-test4.local")
            self.assertFalse(result._in_scope)
            result = session.query(Host).filter_by(address="::3").one()
            self.assertTrue(result.in_scope)

            result = session.query(DomainName).filter_by(name="ipv6-test4.local").one()
            self.assertTrue(result.in_scope)
            result = self.query_hostname(session=session, workspace_str=self._workspace, host_name="ipv6-test4.local")
            self.assertFalse(result._in_scope)
            result = session.query(Host).filter_by(address="::4").one()
            self.assertFalse(result.in_scope)








class HostScopingTestCases(BaseKisTestCase):
    """
    This class implements functionalities for testing the host scope
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def _create_host_host_name_mapping(self,
                                       session: Session,
                                       workspace_str: str,
                                       ipv4_address: str,
                                       network_str: str,
                                       network_scope: ScopeType,
                                       host_name_str: str,
                                       mapping_type: DnsResourceRecordType = None,
                                       host_name_scope: ScopeType = ScopeType.all) -> HostHostNameMapping:
        source = None
        self.create_network(session=session,
                            workspace_str=workspace_str,
                            network=network_str,
                            scope=network_scope)
        host = self.create_host(session=session,
                                workspace_str=workspace_str,
                                address=ipv4_address,
                                in_scope=None)
        host_name = self.create_hostname(session=session,
                                         workspace_str=workspace_str,
                                         host_name=host_name_str,
                                         scope=host_name_scope)
        mapping = self._domain_utils.add_host_host_name_mapping(session=session,
                                                                host=host,
                                                                host_name=host_name,
                                                                mapping_type=mapping_type,
                                                                source=source)
        return mapping

    def test_network_test_insert_all(self):
        """
        This method checks whether the host scope is correctly set during the initial creation with network scope all.

        This unittest tests PostgreSQL functions: update_hosts_after_network_changes and update_hosts_after_host_changes
        """
        # set up database
        self.init_db()
        workspace = "unittest"
        with self._engine.session_scope() as session:
            # IPv4
            self._create_host_host_name_mapping(session=session,
                                                workspace_str=workspace,
                                                ipv4_address="127.0.0.1",
                                                network_str="127.0.0.1/32",
                                                network_scope=ScopeType.all,
                                                host_name_str="ipv4-test1.local",
                                                mapping_type=DnsResourceRecordType.a,
                                                host_name_scope=ScopeType.all)
            self._create_host_host_name_mapping(session=session,
                                                workspace_str=workspace,
                                                ipv4_address="127.0.0.2",
                                                network_str="127.0.0.2/32",
                                                network_scope=ScopeType.all,
                                                host_name_str="ipv4-test2.local",
                                                mapping_type=DnsResourceRecordType.a,
                                                host_name_scope=ScopeType.exclude)
            self._create_host_host_name_mapping(session=session,
                                                workspace_str=workspace,
                                                ipv4_address="127.0.0.3",
                                                network_str="127.0.0.3/32",
                                                network_scope=ScopeType.all,
                                                host_name_str="ipv4-test3.local",
                                                mapping_type=DnsResourceRecordType.alias,
                                                host_name_scope=ScopeType.all)
            self._create_host_host_name_mapping(session=session,
                                                workspace_str=workspace,
                                                ipv4_address="127.0.0.4",
                                                network_str="127.0.0.4/32",
                                                network_scope=ScopeType.all,
                                                host_name_str="ipv4-test4.local",
                                                mapping_type=DnsResourceRecordType.alias,
                                                host_name_scope=ScopeType.exclude)
            # IPv6
            self._create_host_host_name_mapping(session=session,
                                                workspace_str=workspace,
                                                ipv4_address="::1",
                                                network_str="::1/128",
                                                network_scope=ScopeType.all,
                                                host_name_str="ipv6-test1.local",
                                                mapping_type=DnsResourceRecordType.aaaa,
                                                host_name_scope=ScopeType.all)
            self._create_host_host_name_mapping(session=session,
                                                workspace_str=workspace,
                                                ipv4_address="::2",
                                                network_str="::2/128",
                                                network_scope=ScopeType.all,
                                                host_name_str="ipv6-test2.local",
                                                mapping_type=DnsResourceRecordType.aaaa,
                                                host_name_scope=ScopeType.exclude)
            self._create_host_host_name_mapping(session=session,
                                                workspace_str=workspace,
                                                ipv4_address="::3",
                                                network_str="::3/128",
                                                network_scope=ScopeType.all,
                                                host_name_str="ipv6-test3.local",
                                                mapping_type=DnsResourceRecordType.alias,
                                                host_name_scope=ScopeType.all)
            self._create_host_host_name_mapping(session=session,
                                                workspace_str=workspace,
                                                ipv4_address="::4",
                                                network_str="::4/128",
                                                network_scope=ScopeType.all,
                                                host_name_str="ipv6-test4.local",
                                                mapping_type=DnsResourceRecordType.alias,
                                                host_name_scope=ScopeType.exclude)
        # Update the database
        with self._engine.session_scope() as session:
            host = session.query(Host).filter_by(address="127.0.0.1").one()
            self.assertTrue(host.in_scope)
            host = session.query(Host).filter_by(address="127.0.0.2").one()
            self.assertFalse(host.in_scope)
            host = session.query(Host).filter_by(address="127.0.0.3").one()
            self.assertEqual(True, host.in_scope)
            host = session.query(Host).filter_by(address="127.0.0.4").one()
            self.assertEqual(True, host.in_scope)
            host = session.query(Host).filter_by(address="::1").one()
            self.assertEqual(True, host.in_scope)
            host = session.query(Host).filter_by(address="::2").one()
            self.assertEqual(True, host.in_scope)
            host = session.query(Host).filter_by(address="::3").one()
            self.assertEqual(True, host.in_scope)
            host = session.query(Host).filter_by(address="::4").one()
            self.assertEqual(True, host.in_scope)

    def test_network_test_insert_strict(self):
        """
        This method checks whether the host scope is correctly set during the initial creation with network scope all.

        This unittest tests PostgreSQL functions: update_hosts_after_network_changes and update_hosts_after_host_changes
        """
        # set up database
        self.init_db()
        workspace = "unittest"
        with self._engine.session_scope() as session:
            # IPv4
            mapping = self._create_host_host_name_mapping(session=session,
                                                          workspace_str=workspace,
                                                          ipv4_address="127.0.0.1",
                                                          network_str="127.0.0.1/32",
                                                          network_scope=ScopeType.strict,
                                                          host_name_str="ipv4-test1.local",
                                                          mapping_type=DnsResourceRecordType.a,
                                                          host_name_scope=ScopeType.all)
            mapping.host.in_scope = True
            self._create_host_host_name_mapping(session=session,
                                                workspace_str=workspace,
                                                ipv4_address="127.0.0.2",
                                                network_str="127.0.0.2/32",
                                                network_scope=ScopeType.strict,
                                                host_name_str="ipv4-test2.local",
                                                mapping_type=DnsResourceRecordType.a,
                                                host_name_scope=ScopeType.exclude)
            self._create_host_host_name_mapping(session=session,
                                                workspace_str=workspace,
                                                ipv4_address="127.0.0.3",
                                                network_str="127.0.0.3/32",
                                                network_scope=ScopeType.strict,
                                                host_name_str="ipv4-test3.local",
                                                mapping_type=DnsResourceRecordType.alias,
                                                host_name_scope=ScopeType.all)
            mapping = self._create_host_host_name_mapping(session=session,
                                                          workspace_str=workspace,
                                                          ipv4_address="127.0.0.4",
                                                          network_str="127.0.0.4/32",
                                                          network_scope=ScopeType.strict,
                                                          host_name_str="ipv4-test4.local",
                                                          mapping_type=DnsResourceRecordType.alias,
                                                          host_name_scope=ScopeType.exclude)
            mapping.host.in_scope = True
            # IPv6
            mapping = self._create_host_host_name_mapping(session=session,
                                                          workspace_str=workspace,
                                                          ipv4_address="::1",
                                                          network_str="::1/128",
                                                          network_scope=ScopeType.strict,
                                                          host_name_str="ipv6-test1.local",
                                                          mapping_type=DnsResourceRecordType.aaaa,
                                                          host_name_scope=ScopeType.all)
            mapping.host.in_scope = True
            self._create_host_host_name_mapping(session=session,
                                                workspace_str=workspace,
                                                ipv4_address="::2",
                                                network_str="::2/128",
                                                network_scope=ScopeType.strict,
                                                host_name_str="ipv6-test2.local",
                                                mapping_type=DnsResourceRecordType.aaaa,
                                                host_name_scope=ScopeType.exclude)
            self._create_host_host_name_mapping(session=session,
                                                workspace_str=workspace,
                                                ipv4_address="::3",
                                                network_str="::3/128",
                                                network_scope=ScopeType.strict,
                                                host_name_str="ipv6-test3.local",
                                                mapping_type=DnsResourceRecordType.alias,
                                                host_name_scope=ScopeType.all)
            mapping = self._create_host_host_name_mapping(session=session,
                                                          workspace_str=workspace,
                                                          ipv4_address="::4",
                                                          network_str="::4/128",
                                                          network_scope=ScopeType.strict,
                                                          host_name_str="ipv6-test4.local",
                                                          mapping_type=DnsResourceRecordType.alias,
                                                          host_name_scope=ScopeType.exclude)
            mapping.host.in_scope = True
        # Update the database
        with self._engine.session_scope() as session:
            host = session.query(Host).filter_by(address="127.0.0.1").one()
            self.assertEqual(True, host.in_scope)
            host = session.query(Host).filter_by(address="127.0.0.2").one()
            self.assertEqual(False, host.in_scope)
            host = session.query(Host).filter_by(address="127.0.0.3").one()
            self.assertEqual(False, host.in_scope)
            host = session.query(Host).filter_by(address="127.0.0.4").one()
            self.assertEqual(True, host.in_scope)
            host = session.query(Host).filter_by(address="::1").one()
            self.assertEqual(True, host.in_scope)
            host = session.query(Host).filter_by(address="::2").one()
            self.assertEqual(False, host.in_scope)
            host = session.query(Host).filter_by(address="::3").one()
            self.assertEqual(False, host.in_scope)
            host = session.query(Host).filter_by(address="::4").one()
            self.assertEqual(True, host.in_scope)

    def test_network_test_insert_exclude(self):
        """
        This method checks whether the host scope is correctly set during the initial creation with network scope all.

        This unittest tests PostgreSQL functions: update_hosts_after_network_changes and update_hosts_after_host_changes
        """
        # set up database
        self.init_db()
        workspace = "unittest"
        with self._engine.session_scope() as session:
            # IPv4
            mapping = self._create_host_host_name_mapping(session=session,
                                                          workspace_str=workspace,
                                                          ipv4_address="127.0.0.1",
                                                          network_str="127.0.0.1/32",
                                                          network_scope=ScopeType.exclude,
                                                          host_name_str="ipv4-test1.local",
                                                          mapping_type=DnsResourceRecordType.a,
                                                          host_name_scope=ScopeType.all)
            mapping.host.in_scope = True
            self._create_host_host_name_mapping(session=session,
                                                workspace_str=workspace,
                                                ipv4_address="127.0.0.2",
                                                network_str="127.0.0.2/32",
                                                network_scope=ScopeType.exclude,
                                                host_name_str="ipv4-test2.local",
                                                mapping_type=DnsResourceRecordType.a,
                                                host_name_scope=ScopeType.exclude)
            self._create_host_host_name_mapping(session=session,
                                                workspace_str=workspace,
                                                ipv4_address="127.0.0.3",
                                                network_str="127.0.0.3/32",
                                                network_scope=ScopeType.strict,
                                                host_name_str="ipv4-test3.local",
                                                mapping_type=DnsResourceRecordType.alias,
                                                host_name_scope=ScopeType.all)
            mapping = self._create_host_host_name_mapping(session=session,
                                                          workspace_str=workspace,
                                                          ipv4_address="127.0.0.4",
                                                          network_str="127.0.0.4/32",
                                                          network_scope=ScopeType.exclude,
                                                          host_name_str="ipv4-test4.local",
                                                          mapping_type=DnsResourceRecordType.alias,
                                                          host_name_scope=ScopeType.exclude)
            mapping.host.in_scope = True
            # IPv6
            mapping = self._create_host_host_name_mapping(session=session,
                                                          workspace_str=workspace,
                                                          ipv4_address="::1",
                                                          network_str="::1/128",
                                                          network_scope=ScopeType.exclude,
                                                          host_name_str="ipv6-test1.local",
                                                          mapping_type=DnsResourceRecordType.aaaa,
                                                          host_name_scope=ScopeType.all)
            mapping.host.in_scope = True
            self._create_host_host_name_mapping(session=session,
                                                workspace_str=workspace,
                                                ipv4_address="::2",
                                                network_str="::2/128",
                                                network_scope=ScopeType.exclude,
                                                host_name_str="ipv6-test2.local",
                                                mapping_type=DnsResourceRecordType.aaaa,
                                                host_name_scope=ScopeType.exclude)
            self._create_host_host_name_mapping(session=session,
                                                workspace_str=workspace,
                                                ipv4_address="::3",
                                                network_str="::3/128",
                                                network_scope=ScopeType.exclude,
                                                host_name_str="ipv6-test3.local",
                                                mapping_type=DnsResourceRecordType.alias,
                                                host_name_scope=ScopeType.all)
            mapping = self._create_host_host_name_mapping(session=session,
                                                          workspace_str=workspace,
                                                          ipv4_address="::4",
                                                          network_str="::4/128",
                                                          network_scope=ScopeType.exclude,
                                                          host_name_str="ipv6-test4.local",
                                                          mapping_type=DnsResourceRecordType.alias,
                                                          host_name_scope=ScopeType.exclude)
            mapping.host.in_scope = True
        # Update the database
        with self._engine.session_scope() as session:
            host = session.query(Host).filter_by(address="127.0.0.1").one()
            self.assertEqual(False, host.in_scope)
            host = session.query(Host).filter_by(address="127.0.0.2").one()
            self.assertEqual(False, host.in_scope)
            host = session.query(Host).filter_by(address="127.0.0.3").one()
            self.assertEqual(False, host.in_scope)
            host = session.query(Host).filter_by(address="127.0.0.4").one()
            self.assertEqual(False, host.in_scope)
            host = session.query(Host).filter_by(address="::1").one()
            self.assertEqual(False, host.in_scope)
            host = session.query(Host).filter_by(address="::2").one()
            self.assertEqual(False, host.in_scope)
            host = session.query(Host).filter_by(address="::3").one()
            self.assertEqual(False, host.in_scope)
            host = session.query(Host).filter_by(address="::4").one()
            self.assertEqual(False, host.in_scope)

    def test_network_test_insert_vhost(self):
        """
        This method checks whether the host scope is correctly set during the initial creation with network scope all.

        This unittest tests PostgreSQL functions: update_hosts_after_network_changes and update_hosts_after_host_changes
        """
        # set up database
        self.init_db()
        workspace = "unittest"
        with self._engine.session_scope() as session:
            # IPv4
            self._create_host_host_name_mapping(session=session,
                                                workspace_str=workspace,
                                                ipv4_address="127.0.0.1",
                                                network_str="127.0.0.1/32",
                                                network_scope=ScopeType.vhost,
                                                host_name_str="ipv4-test1.local",
                                                mapping_type=DnsResourceRecordType.a,
                                                host_name_scope=ScopeType.all)
            self._create_host_host_name_mapping(session=session,
                                                workspace_str=workspace,
                                                ipv4_address="127.0.0.2",
                                                network_str="127.0.0.2/32",
                                                network_scope=ScopeType.vhost,
                                                host_name_str="ipv4-test2.local",
                                                mapping_type=DnsResourceRecordType.a,
                                                host_name_scope=ScopeType.exclude)
            self._create_host_host_name_mapping(session=session,
                                                workspace_str=workspace,
                                                ipv4_address="127.0.0.3",
                                                network_str="127.0.0.3/32",
                                                network_scope=ScopeType.vhost,
                                                host_name_str="ipv4-test3.local",
                                                mapping_type=DnsResourceRecordType.alias,
                                                host_name_scope=ScopeType.all)
            self._create_host_host_name_mapping(session=session,
                                                workspace_str=workspace,
                                                ipv4_address="127.0.0.4",
                                                network_str="127.0.0.4/32",
                                                network_scope=ScopeType.vhost,
                                                host_name_str="ipv4-test4.local",
                                                mapping_type=DnsResourceRecordType.alias,
                                                host_name_scope=ScopeType.exclude)
            # IPv6
            self._create_host_host_name_mapping(session=session,
                                                workspace_str=workspace,
                                                ipv4_address="::1",
                                                network_str="::1/128",
                                                network_scope=ScopeType.vhost,
                                                host_name_str="ipv6-test1.local",
                                                mapping_type=DnsResourceRecordType.aaaa,
                                                host_name_scope=ScopeType.all)
            self._create_host_host_name_mapping(session=session,
                                                workspace_str=workspace,
                                                ipv4_address="::2",
                                                network_str="::2/128",
                                                network_scope=ScopeType.vhost,
                                                host_name_str="ipv6-test2.local",
                                                mapping_type=DnsResourceRecordType.aaaa,
                                                host_name_scope=ScopeType.exclude)
            self._create_host_host_name_mapping(session=session,
                                                workspace_str=workspace,
                                                ipv4_address="::3",
                                                network_str="::3/128",
                                                network_scope=ScopeType.vhost,
                                                host_name_str="ipv6-test3.local",
                                                mapping_type=DnsResourceRecordType.alias,
                                                host_name_scope=ScopeType.all)
            self._create_host_host_name_mapping(session=session,
                                                workspace_str=workspace,
                                                ipv4_address="::4",
                                                network_str="::4/128",
                                                network_scope=ScopeType.vhost,
                                                host_name_str="ipv6-test4.local",
                                                mapping_type=DnsResourceRecordType.alias,
                                                host_name_scope=ScopeType.exclude)
        # Update the database
        with self._engine.session_scope() as session:
            host = session.query(Host).filter_by(address="127.0.0.1").one()
            self.assertEqual(True, host.in_scope)
            host = session.query(Host).filter_by(address="127.0.0.2").one()
            self.assertEqual(False, host.in_scope)
            host = session.query(Host).filter_by(address="127.0.0.3").one()
            self.assertEqual(False, host.in_scope)
            host = session.query(Host).filter_by(address="127.0.0.4").one()
            self.assertEqual(False, host.in_scope)
            host = session.query(Host).filter_by(address="::1").one()
            self.assertEqual(True, host.in_scope)
            host = session.query(Host).filter_by(address="::2").one()
            self.assertEqual(False, host.in_scope)
            host = session.query(Host).filter_by(address="::3").one()
            self.assertEqual(False, host.in_scope)
            host = session.query(Host).filter_by(address="::4").one()
            self.assertEqual(False, host.in_scope)


class HostNameScopingTestCases(BaseKisTestCase):
    """
    This class implements functionalities for testing the host name scope
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def test_domain_name_test_insert_all(self):
        """
        This method checks whether the domain name's host name object (the object where the host_name.name
        is null) is correctly set during the initial creation with domain scope all.

        This unittest tests PostgreSQL functions: update_host_names_after_domain_name_scope_changes and
        update_host_name_scope.
        """
        # set up database
        self.init_db()
        workspace = "unittest"
        with self._engine.session_scope() as session:
            self.create_host_host_name_mapping(session=session,
                                               workspace_str=workspace,
                                               ipv4_address="127.0.0.1",
                                               host_name_str="ipv4-test1.local",
                                               mapping_type=DnsResourceRecordType.a,
                                               host_name_scope=ScopeType.all,
                                               host_scope=True)
            self.create_host_host_name_mapping(session=session,
                                               workspace_str=workspace,
                                               ipv4_address="127.0.0.2",
                                               host_name_str="ipv4-test2.local",
                                               mapping_type=DnsResourceRecordType.a,
                                               host_name_scope=ScopeType.all,
                                               host_scope=False)
            self.create_host_host_name_mapping(session=session,
                                               workspace_str=workspace,
                                               ipv4_address="127.0.0.3",
                                               host_name_str="ipv4-test3.local",
                                               mapping_type=DnsResourceRecordType.alias,
                                               host_name_scope=ScopeType.all,
                                               host_scope=True)
            self.create_host_host_name_mapping(session=session,
                                               workspace_str=workspace,
                                               ipv4_address="127.0.0.4",
                                               host_name_str="ipv4-test4.local",
                                               mapping_type=DnsResourceRecordType.alias,
                                               host_name_scope=ScopeType.all,
                                               host_scope=False)
            self.create_host_host_name_mapping(session=session,
                                               workspace_str=workspace,
                                               ipv4_address="::1",
                                               host_name_str="ipv6-test1.local",
                                               mapping_type=DnsResourceRecordType.aaaa,
                                               host_name_scope=ScopeType.all,
                                               host_scope=True)
            self.create_host_host_name_mapping(session=session,
                                               workspace_str=workspace,
                                               ipv4_address="::2",
                                               host_name_str="ipv6-test2.local",
                                               mapping_type=DnsResourceRecordType.aaaa,
                                               host_name_scope=ScopeType.all,
                                               host_scope=False)
            self.create_host_host_name_mapping(session=session,
                                               workspace_str=workspace,
                                               ipv4_address="::3",
                                               host_name_str="ipv6-test3.local",
                                               mapping_type=DnsResourceRecordType.alias,
                                               host_name_scope=ScopeType.all,
                                               host_scope=True)
            self.create_host_host_name_mapping(session=session,
                                               workspace_str=workspace,
                                               ipv4_address="::4",
                                               host_name_str="ipv6-test4.local",
                                               mapping_type=DnsResourceRecordType.alias,
                                               host_name_scope=ScopeType.all,
                                               host_scope=False)
        # Update the database
        with self._engine.session_scope() as session:
            domain = session.query(DomainName).filter_by(name="ipv4-test1.local").one()
            self.assertEqual(True, domain.host_names[0]._in_scope)
            domain = session.query(DomainName).filter_by(name="ipv4-test2.local").one()
            self.assertEqual(True, domain.host_names[0]._in_scope)
            domain = session.query(DomainName).filter_by(name="ipv4-test3.local").one()
            self.assertEqual(True, domain.host_names[0]._in_scope)
            domain = session.query(DomainName).filter_by(name="ipv4-test4.local").one()
            self.assertEqual(True, domain.host_names[0]._in_scope)
            domain = session.query(DomainName).filter_by(name="ipv6-test1.local").one()
            self.assertEqual(True, domain.host_names[0]._in_scope)
            domain = session.query(DomainName).filter_by(name="ipv6-test2.local").one()
            self.assertEqual(True, domain.host_names[0]._in_scope)
            domain = session.query(DomainName).filter_by(name="ipv6-test3.local").one()
            self.assertEqual(True, domain.host_names[0]._in_scope)
            domain = session.query(DomainName).filter_by(name="ipv6-test4.local").one()
            self.assertEqual(True, domain.host_names[0]._in_scope)

    def test_domain_name_test_insert_strict(self):
        """
        This method checks whether the domain name's host name object (the object where the host_name.name
        is null) is correctly set during the initial creation with domain scope explicit.

        This unittest tests PostgreSQL functions: update_host_names_after_domain_name_scope_changes and
        update_host_name_scope.
        """
        # set up database
        self.init_db()
        workspace = "unittest"
        with self._engine.session_scope() as session:
            mapping = self.create_host_host_name_mapping(session=session,
                                                         workspace_str=workspace,
                                                         ipv4_address="127.0.0.1",
                                                         host_name_str="ipv4-test1.local",
                                                         mapping_type=DnsResourceRecordType.a,
                                                         host_name_scope=ScopeType.strict,
                                                         host_scope=True)
            mapping.host_name._in_scope = True
            mapping = self.create_host_host_name_mapping(session=session,
                                                         workspace_str=workspace,
                                                         ipv4_address="127.0.0.2",
                                                         host_name_str="ipv4-test2.local",
                                                         mapping_type=DnsResourceRecordType.a,
                                                         host_name_scope=ScopeType.strict,
                                                         host_scope=False)
            mapping = self.create_host_host_name_mapping(session=session,
                                                         workspace_str=workspace,
                                                         ipv4_address="127.0.0.3",
                                                         host_name_str="ipv4-test3.local",
                                                         mapping_type=DnsResourceRecordType.alias,
                                                         host_name_scope=ScopeType.strict,
                                                         host_scope=True)
            mapping = self.create_host_host_name_mapping(session=session,
                                                         workspace_str=workspace,
                                                         ipv4_address="127.0.0.4",
                                                         host_name_str="ipv4-test4.local",
                                                         mapping_type=DnsResourceRecordType.alias,
                                                         host_name_scope=ScopeType.strict,
                                                         host_scope=False)
            mapping.host_name._in_scope = True
            mapping = self.create_host_host_name_mapping(session=session,
                                                         workspace_str=workspace,
                                                         ipv4_address="::1",
                                                         host_name_str="ipv6-test1.local",
                                                         mapping_type=DnsResourceRecordType.aaaa,
                                                         host_name_scope=ScopeType.strict,
                                                         host_scope=True)
            mapping.host_name._in_scope = True
            mapping = self.create_host_host_name_mapping(session=session,
                                                         workspace_str=workspace,
                                                         ipv4_address="::2",
                                                         host_name_str="ipv6-test2.local",
                                                         mapping_type=DnsResourceRecordType.aaaa,
                                                         host_name_scope=ScopeType.strict,
                                                         host_scope=False)
            mapping = self.create_host_host_name_mapping(session=session,
                                                         workspace_str=workspace,
                                                         ipv4_address="::3",
                                                         host_name_str="ipv6-test3.local",
                                                         mapping_type=DnsResourceRecordType.alias,
                                                         host_name_scope=ScopeType.strict,
                                                         host_scope=True)
            mapping = self.create_host_host_name_mapping(session=session,
                                                         workspace_str=workspace,
                                                         ipv4_address="::4",
                                                         host_name_str="ipv6-test4.local",
                                                         mapping_type=DnsResourceRecordType.alias,
                                                         host_name_scope=ScopeType.strict,
                                                         host_scope=False)
            mapping.host_name._in_scope = True
        # Update the database
        with self._engine.session_scope() as session:
            domain = session.query(DomainName).filter_by(name="ipv4-test1.local").one()
            self.assertEqual(True, domain.host_names[0]._in_scope)
            domain = session.query(DomainName).filter_by(name="ipv4-test2.local").one()
            self.assertEqual(False, domain.host_names[0]._in_scope)
            domain = session.query(DomainName).filter_by(name="ipv4-test3.local").one()
            self.assertEqual(False, domain.host_names[0]._in_scope)
            domain = session.query(DomainName).filter_by(name="ipv4-test4.local").one()
            self.assertEqual(True, domain.host_names[0]._in_scope)
            domain = session.query(DomainName).filter_by(name="ipv6-test1.local").one()
            self.assertEqual(True, domain.host_names[0]._in_scope)
            domain = session.query(DomainName).filter_by(name="ipv6-test2.local").one()
            self.assertEqual(False, domain.host_names[0]._in_scope)
            domain = session.query(DomainName).filter_by(name="ipv6-test3.local").one()
            self.assertEqual(False, domain.host_names[0]._in_scope)
            domain = session.query(DomainName).filter_by(name="ipv6-test4.local").one()
            self.assertEqual(True, domain.host_names[0]._in_scope)

    def test_domain_name_test_insert_exclude(self):
        """
        This method checks whether the domain name's host name object (the object where the host_name.name
        is null) is correctly set during the initial creation with domain scope vhost.

        This unittest tests PostgreSQL functions: update_host_names_after_domain_name_scope_changes and
        update_host_name_scope.
        """
        # set up database
        self.init_db()
        workspace = "unittest"
        with self._engine.session_scope() as session:
            self.create_host_host_name_mapping(session=session,
                                               workspace_str=workspace,
                                               ipv4_address="127.0.0.1",
                                               host_name_str="ipv4-test1.local",
                                               mapping_type=DnsResourceRecordType.a,
                                               host_name_scope=ScopeType.exclude,
                                               host_scope=True)
            self.create_host_host_name_mapping(session=session,
                                               workspace_str=workspace,
                                               ipv4_address="127.0.0.2",
                                               host_name_str="ipv4-test2.local",
                                               mapping_type=DnsResourceRecordType.a,
                                               host_name_scope=ScopeType.exclude,
                                               host_scope=False)
            self.create_host_host_name_mapping(session=session,
                                               workspace_str=workspace,
                                               ipv4_address="127.0.0.3",
                                               host_name_str="ipv4-test3.local",
                                               mapping_type=DnsResourceRecordType.alias,
                                               host_name_scope=ScopeType.exclude,
                                               host_scope=True)
            self.create_host_host_name_mapping(session=session,
                                               workspace_str=workspace,
                                               ipv4_address="127.0.0.4",
                                               host_name_str="ipv4-test4.local",
                                               mapping_type=DnsResourceRecordType.alias,
                                               host_name_scope=ScopeType.exclude,
                                               host_scope=False)
            self.create_host_host_name_mapping(session=session,
                                               workspace_str=workspace,
                                               ipv4_address="::1",
                                               host_name_str="ipv6-test1.local",
                                               mapping_type=DnsResourceRecordType.aaaa,
                                               host_name_scope=ScopeType.exclude,
                                               host_scope=True)
            self.create_host_host_name_mapping(session=session,
                                               workspace_str=workspace,
                                               ipv4_address="::2",
                                               host_name_str="ipv6-test2.local",
                                               mapping_type=DnsResourceRecordType.aaaa,
                                               host_name_scope=ScopeType.exclude,
                                               host_scope=False)
            self.create_host_host_name_mapping(session=session,
                                               workspace_str=workspace,
                                               ipv4_address="::3",
                                               host_name_str="ipv6-test3.local",
                                               mapping_type=DnsResourceRecordType.alias,
                                               host_name_scope=ScopeType.exclude,
                                               host_scope=True)
            self.create_host_host_name_mapping(session=session,
                                               workspace_str=workspace,
                                               ipv4_address="::4",
                                               host_name_str="ipv6-test4.local",
                                               mapping_type=DnsResourceRecordType.alias,
                                               host_name_scope=ScopeType.exclude,
                                               host_scope=False)
        # Update the database
        with self._engine.session_scope() as session:
            domain = session.query(DomainName).filter_by(name="ipv4-test1.local").one()
            self.assertEqual(False, domain.host_names[0]._in_scope)
            domain = session.query(DomainName).filter_by(name="ipv4-test2.local").one()
            self.assertEqual(False, domain.host_names[0]._in_scope)
            domain = session.query(DomainName).filter_by(name="ipv4-test3.local").one()
            self.assertEqual(False, domain.host_names[0]._in_scope)
            domain = session.query(DomainName).filter_by(name="ipv4-test4.local").one()
            self.assertEqual(False, domain.host_names[0]._in_scope)
            domain = session.query(DomainName).filter_by(name="ipv6-test1.local").one()
            self.assertEqual(False, domain.host_names[0]._in_scope)
            domain = session.query(DomainName).filter_by(name="ipv6-test2.local").one()
            self.assertEqual(False, domain.host_names[0]._in_scope)
            domain = session.query(DomainName).filter_by(name="ipv6-test3.local").one()
            self.assertEqual(False, domain.host_names[0]._in_scope)
            domain = session.query(DomainName).filter_by(name="ipv6-test4.local").one()
            self.assertEqual(False, domain.host_names[0]._in_scope)

    def test_domain_name_test_insert_vhost(self):
        """
        This method checks whether the domain name's host name object (the object where the host_name.name
        is null) is correctly set during the initial creation with domain scope vhost.

        This unittest tests PostgreSQL functions: update_host_names_after_domain_name_scope_changes and
        update_host_name_scope.
        """
        # set up database
        self.init_db()
        workspace = "unittest"
        with self._engine.session_scope() as session:
            self.create_host_host_name_mapping(session=session,
                                               workspace_str=workspace,
                                               ipv4_address="127.0.0.1",
                                               host_name_str="ipv4-test1.local",
                                               mapping_type=DnsResourceRecordType.a,
                                               host_name_scope=ScopeType.vhost,
                                               host_scope=True)
            self.create_host_host_name_mapping(session=session,
                                               workspace_str=workspace,
                                               ipv4_address="127.0.0.2",
                                               host_name_str="ipv4-test2.local",
                                               mapping_type=DnsResourceRecordType.a,
                                               host_name_scope=ScopeType.vhost,
                                               host_scope=False)
            self.create_host_host_name_mapping(session=session,
                                               workspace_str=workspace,
                                               ipv4_address="127.0.0.3",
                                               host_name_str="ipv4-test3.local",
                                               mapping_type=DnsResourceRecordType.alias,
                                               host_name_scope=ScopeType.vhost,
                                               host_scope=True)
            self.create_host_host_name_mapping(session=session,
                                               workspace_str=workspace,
                                               ipv4_address="127.0.0.4",
                                               host_name_str="ipv4-test4.local",
                                               mapping_type=DnsResourceRecordType.alias,
                                               host_name_scope=ScopeType.vhost,
                                               host_scope=False)
            self.create_host_host_name_mapping(session=session,
                                               workspace_str=workspace,
                                               ipv4_address="::1",
                                               host_name_str="ipv6-test1.local",
                                               mapping_type=DnsResourceRecordType.aaaa,
                                               host_name_scope=ScopeType.vhost,
                                               host_scope=True)
            self.create_host_host_name_mapping(session=session,
                                               workspace_str=workspace,
                                               ipv4_address="::2",
                                               host_name_str="ipv6-test2.local",
                                               mapping_type=DnsResourceRecordType.aaaa,
                                               host_name_scope=ScopeType.vhost,
                                               host_scope=False)
            self.create_host_host_name_mapping(session=session,
                                               workspace_str=workspace,
                                               ipv4_address="::3",
                                               host_name_str="ipv6-test3.local",
                                               mapping_type=DnsResourceRecordType.alias,
                                               host_name_scope=ScopeType.vhost,
                                               host_scope=True)
            self.create_host_host_name_mapping(session=session,
                                               workspace_str=workspace,
                                               ipv4_address="::4",
                                               host_name_str="ipv6-test4.local",
                                               mapping_type=DnsResourceRecordType.alias,
                                               host_name_scope=ScopeType.vhost,
                                               host_scope=False)
        # Update the database
        with self._engine.session_scope() as session:
            domain = session.query(DomainName).filter_by(name="ipv4-test1.local").one()
            self.assertEqual(True, domain.host_names[0]._in_scope)
            domain = session.query(DomainName).filter_by(name="ipv4-test2.local").one()
            self.assertEqual(False, domain.host_names[0]._in_scope)
            domain = session.query(DomainName).filter_by(name="ipv4-test3.local").one()
            self.assertEqual(False, domain.host_names[0]._in_scope)
            domain = session.query(DomainName).filter_by(name="ipv4-test4.local").one()
            self.assertEqual(False, domain.host_names[0]._in_scope)
            domain = session.query(DomainName).filter_by(name="ipv6-test1.local").one()
            self.assertEqual(True, domain.host_names[0]._in_scope)
            domain = session.query(DomainName).filter_by(name="ipv6-test2.local").one()
            self.assertEqual(False, domain.host_names[0]._in_scope)
            domain = session.query(DomainName).filter_by(name="ipv6-test3.local").one()
            self.assertEqual(False, domain.host_names[0]._in_scope)
            domain = session.query(DomainName).filter_by(name="ipv6-test4.local").one()
            self.assertEqual(False, domain.host_names[0]._in_scope)