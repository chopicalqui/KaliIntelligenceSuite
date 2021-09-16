#!/usr/bin/python3
"""
this file implements unittests for creating commands
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
import re
from unittests.tests.core import BaseKisTestCase
from database.model import Workspace
from database.model import Host
from database.model import Service
from database.model import ProtocolType
from database.model import Network
from database.model import HostName
from database.model import DomainName
from database.model import Command
from database.model import DnsResourceRecordType
from database.model import CommandStatus
from database.model import Email
from database.model import Company
from database.model import ScopeType
from database.model import ServiceState
from database.model import CollectorName
from database.model import CredentialType
from database.model import PathType
from collectors.os.modules.core import BaseCollector
from collectors.os.collector import VhostChoice
from collectors.os.collector import CollectorProducer
from collectors.os.modules.http.httpnikto import CollectorClass as NiktoCollector
from collectors.os.modules.http.httpburpsuitepro import CollectorClass as BurpSuiteProCollector
from unittests.tests.collectors.kali.modules.core import BaseKaliCollectorTestCase
from unittests.tests.collectors.core import CollectorProducerTestSuite
from sqlalchemy.orm.session import Session


class PathCreationTest(BaseKisTestCase):
    """
    This class tests the collector's path creation functionality
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def test_service(self):
        collector_name = "test"
        address = "127.0.0.1"
        port = 80
        protocol = ProtocolType.tcp
        with tempfile.TemporaryDirectory() as temp_dir:
            host = Host(address=address)
            service = Service(host=host, protocol=ProtocolType.tcp, port=port)
            collector = BaseCollector(priority=10,
                                      timeout=0,
                                      name=collector_name,
                                      output_dir=temp_dir,
                                      engine=self._engine)
            working_dir = collector.create_path(service=service)
            xml_file = collector.create_xml_file_path(service=service)
            self.assertEqual(os.path.join(temp_dir, address), working_dir)
            self.assertTrue(os.path.isdir(working_dir))
            self.assertEqual(os.path.join(temp_dir, address, "{}_{}-{}-{}.xml".format(collector_name,
                                                                                      address,
                                                                                      protocol.name,
                                                                                      port)), xml_file)

    def test_host(self):
        collector_name = "test"
        address = "127.0.0.1"
        with tempfile.TemporaryDirectory() as temp_dir:
            host = Host(address=address)
            collector = BaseCollector(priority=10,
                                      timeout=0,
                                      name=collector_name,
                                      output_dir=temp_dir,
                                      engine=self._engine)
            working_dir = collector.create_path(host=host)
            xml_file = collector.create_xml_file_path(host=host)
            self.assertEqual(os.path.join(temp_dir, address), working_dir)
            self.assertTrue(os.path.isdir(working_dir))
            self.assertEqual(os.path.join(temp_dir, address, "{}_{}.xml".format(collector_name, address)), xml_file)

    def test_network(self):
        collector_name = "test"
        address = "127.0.0.0/24"
        with tempfile.TemporaryDirectory() as temp_dir:
            network = Network(network=address)
            collector = BaseCollector(priority=10,
                                      timeout=0,
                                      name=collector_name,
                                      output_dir=temp_dir,
                                      engine=self._engine)
            working_dir = collector.create_path(network=network)
            xml_file = collector.create_xml_file_path(network=network)
            address = address.replace("/", "_")
            self.assertEqual(os.path.join(temp_dir, address), working_dir)
            self.assertTrue(os.path.isdir(working_dir))
            self.assertEqual(os.path.join(temp_dir, address, "{}_{}.xml".format(collector_name, address)), xml_file)

    def test_host_name(self):
        collector_name = "test"
        address = "www.unittests.com"
        with tempfile.TemporaryDirectory() as temp_dir:
            host_name = HostName(name=address)
            collector = BaseCollector(priority=10,
                                      timeout=0,
                                      name=collector_name,
                                      output_dir=temp_dir,
                                      engine=self._engine)
            working_dir = collector.create_path(host_name=host_name)
            xml_file = collector.create_xml_file_path(host_name=host_name)
            self.assertEqual(os.path.join(temp_dir, address), working_dir)
            self.assertTrue(os.path.isdir(working_dir))
            self.assertEqual(os.path.join(temp_dir, address, "{}_{}.xml".format(collector_name, address)), xml_file)

    def test_domain_name(self):
        collector_name = "test"
        address = "unittests.com"
        with tempfile.TemporaryDirectory() as temp_dir:
            domain_name = DomainName(name=address)
            collector = BaseCollector(priority=10,
                                      timeout=0,
                                      name=collector_name,
                                      output_dir=temp_dir,
                                      engine=self._engine)
            working_dir = collector.create_path(domain_name=domain_name)
            xml_file = collector.create_xml_file_path(domain_name=domain_name)
            self.assertEqual(os.path.join(temp_dir, address), working_dir)
            self.assertTrue(os.path.isdir(working_dir))
            self.assertEqual(os.path.join(temp_dir, address, "{}_{}.xml".format(collector_name, address)), xml_file)

    def test_email(self):
        collector_name = "test"
        address = "support@unittest.com"
        with tempfile.TemporaryDirectory() as temp_dir:
            domain_name = DomainName(name="unittest.com")
            host_name = HostName(name=None, domain_name=domain_name)
            email = Email(address="support", host_name=host_name)
            collector = BaseCollector(priority=10,
                                      timeout=0,
                                      name=collector_name,
                                      output_dir=temp_dir,
                                      engine=self._engine)
            working_dir = collector.create_path(email=email)
            xml_file = collector.create_xml_file_path(email=email)
            self.assertEqual(os.path.join(temp_dir, address), working_dir)
            self.assertTrue(os.path.isdir(working_dir))
            self.assertEqual(os.path.join(temp_dir, address, "{}_{}.xml".format(collector_name, address)), xml_file)

    def test_company(self):
        collector_name = "test"
        address = "Test LLC"
        with tempfile.TemporaryDirectory() as temp_dir:
            company = Company(name=address)
            collector = BaseCollector(priority=10,
                                      timeout=0,
                                      name=collector_name,
                                      output_dir=temp_dir,
                                      engine=self._engine)
            working_dir = collector.create_path(company=company)
            xml_file = collector.create_xml_file_path(company=company)
            address = address.replace(" ", "-")
            self.assertEqual(os.path.join(temp_dir, address), working_dir)
            self.assertTrue(os.path.isdir(working_dir))
            self.assertEqual(os.path.join(temp_dir, address, "{}_{}.xml".format(collector_name, address)), xml_file)


class TestBurpSuiteProCommandCreation(BaseKaliCollectorTestCase):
    """
    This class tests the command creation logic
    """

    def __init__(self, test_name: str):
        super().__init__(test_name,
                         collector_name="httpburpsuitepro",
                         collector_class=BurpSuiteProCollector)

    def _unittest_service_command_creation(self,
                                           session: Session,
                                           vhost: VhostChoice = None,
                                           workspace_str: str = "unittest",
                                           host_name_scope: ScopeType = ScopeType.all,
                                           host_scope: ScopeType = ScopeType.all):
        source = self.create_source(session=session, source_str="dnshost")
        # Setup database
        self.create_network(session=session,
                            network="192.168.1.0/24",
                            scope=host_scope,
                            workspace_str=workspace_str)
        self.create_host(session=session, workspace_str=workspace_str, address="192.168.1.1")
        host = self.create_host(session=session, workspace_str=workspace_str, address="192.168.1.2")
        self.create_hostname(session=session,
                             workspace_str=workspace_str,
                             host_name="www.test1.com", scope=host_name_scope)
        host_name = self.create_hostname(session=session,
                                         workspace_str=workspace_str,
                                         host_name="www.test2.com", scope=host_name_scope)
        self.create_service(session=session, workspace_str=workspace_str, address="192.168.1.1", port=80)
        self.create_service(session=session, workspace_str=workspace_str, address="192.168.1.2", port=80)
        self.create_service(session=session, workspace_str=workspace_str, host_name_str="www.test1.com", port=80)
        self.create_service(session=session, workspace_str=workspace_str, host_name_str="www.test3.com", port=80)
        self._domain_utils.add_host_host_name_mapping(session=session,
                                                      host=host,
                                                      host_name=host_name,
                                                      source=source,
                                                      mapping_type=DnsResourceRecordType.a)
        session.commit()
        # Create command
        with tempfile.TemporaryDirectory() as temp_dir:
            arguments = {"workspace": workspace_str, "output_dir": temp_dir}
            if vhost:
                arguments["vhost"] = vhost
            test_suite = CollectorProducerTestSuite(engine=self._engine, arguments=arguments)
            test_suite.create_commands([self._arg_parse_module])
        session.commit()
        # Verify results
        if not vhost:
            results = session.query(Command) \
                .join(Host) \
                .join(Workspace).filter(Workspace.name == workspace_str).count()
            self.assertEqual(2 if host_scope == ScopeType.all else 0, results)
            results = session.query(Command) \
                .join(HostName) \
                .join(DomainName) \
                .join(Workspace).filter(Workspace.name == workspace_str).count()
            self.assertEqual(0, results)
        elif vhost == VhostChoice.all:
            results = session.query(Command) \
                .join(Host) \
                .join(Workspace).filter(Workspace.name == workspace_str).count()
            self.assertEqual(2 if host_scope == ScopeType.all else 0, results)
            results = session.query(Command) \
                .join(HostName) \
                .join(DomainName) \
                .join(Workspace).filter(Workspace.name == workspace_str).count()
            self.assertEqual(1 if host_name_scope == ScopeType.all and host_scope == ScopeType.all else 0, results)
        elif vhost == VhostChoice.domain:
            results = session.query(Command) \
                .join(Host) \
                .join(Workspace).filter(Workspace.name == workspace_str).count()
            self.assertEqual(0, results)
            results = session.query(Command) \
                .join(HostName) \
                .join(DomainName) \
                .join(Workspace).filter(Workspace.name == workspace_str).count()
            self.assertEqual(1 if host_name_scope == ScopeType.all and host_scope == ScopeType.all else 0, results)

    def test_vhost_none_host_in_scope(self):
        self.init_db()
        vhost = None
        with self._engine.session_scope() as session:
            self._unittest_service_command_creation(session,
                                                    vhost=vhost,
                                                    host_scope=ScopeType.all,
                                                    host_name_scope=ScopeType.exclude)

    def test_vhost_none_host_name_in_scope(self):
        self.init_db()
        vhost = None
        with self._engine.session_scope() as session:
            self._unittest_service_command_creation(session,
                                                    vhost=vhost,
                                                    host_scope=ScopeType.exclude,
                                                    host_name_scope=ScopeType.all)

    def test_vhost_none_host_host_name_in_scope(self):
        self.init_db()
        vhost = None
        with self._engine.session_scope() as session:
            self._unittest_service_command_creation(session,
                                                    vhost=vhost,
                                                    host_scope=ScopeType.all,
                                                    host_name_scope=ScopeType.all)

    def test_vhost_none(self):
        self.init_db()
        vhost = None
        with self._engine.session_scope() as session:
            self._unittest_service_command_creation(session,
                                                    vhost=vhost,
                                                    host_scope=ScopeType.exclude,
                                                    host_name_scope=ScopeType.exclude)

    def test_vhost_all_host_in_scope(self):
        self.init_db()
        vhost = VhostChoice.all
        with self._engine.session_scope() as session:
            self._unittest_service_command_creation(session,
                                                    vhost=vhost,
                                                    host_scope=ScopeType.all,
                                                    host_name_scope=ScopeType.exclude)

    def test_vhost_all_host_name_in_scope(self):
        self.init_db()
        vhost = VhostChoice.all
        with self._engine.session_scope() as session:
            self._unittest_service_command_creation(session,
                                                    vhost=vhost,
                                                    host_scope=ScopeType.exclude,
                                                    host_name_scope=ScopeType.all)

    def test_vhost_all_host_host_name_in_scope(self):
        self.init_db()
        vhost = VhostChoice.all
        with self._engine.session_scope() as session:
            self._unittest_service_command_creation(session,
                                                    vhost=vhost,
                                                    host_scope=ScopeType.all,
                                                    host_name_scope=ScopeType.all)

    def test_vhost_all(self):
        self.init_db()
        vhost = VhostChoice.all
        with self._engine.session_scope() as session:
            self._unittest_service_command_creation(session,
                                                    vhost=vhost,
                                                    host_scope=ScopeType.exclude,
                                                    host_name_scope=ScopeType.exclude)

    def test_vhost_domain_host_in_scope(self):
        self.init_db()
        vhost = VhostChoice.domain
        with self._engine.session_scope() as session:
            self._unittest_service_command_creation(session,
                                                    vhost=vhost,
                                                    host_scope=ScopeType.all,
                                                    host_name_scope=ScopeType.exclude)

    def test_vhost_domain_host_name_in_scope(self):
        self.init_db()
        vhost = VhostChoice.domain
        with self._engine.session_scope() as session:
            self._unittest_service_command_creation(session,
                                                    vhost=vhost,
                                                    host_scope=ScopeType.exclude,
                                                    host_name_scope=ScopeType.all)

    def test_vhost_domain_host_host_name_in_scope(self):
        self.init_db()
        vhost = VhostChoice.domain
        with self._engine.session_scope() as session:
            self._unittest_service_command_creation(session,
                                                    vhost=vhost,
                                                    host_scope=ScopeType.all,
                                                    host_name_scope=ScopeType.all)

    def test_vhost_domain(self):
        self.init_db()
        vhost = VhostChoice.domain
        with self._engine.session_scope() as session:
            self._unittest_service_command_creation(session,
                                                    vhost=vhost,
                                                    host_scope=ScopeType.exclude,
                                                    host_name_scope=ScopeType.exclude)


class TestCommandServiceCreation(BaseKaliCollectorTestCase):
    """
    This class tests the command creation logic
    """

    def __init__(self, test_name: str):
        super().__init__(test_name,
                         collector_name="httpnikto",
                         collector_class=NiktoCollector)

    def _unittest_service_command_creation(self,
                                           session: Session,
                                           vhost: VhostChoice = None,
                                           workspace_str: str = "unittest",
                                           host_name_scope: ScopeType = ScopeType.all,
                                           host_scope: ScopeType = ScopeType.all):
        source = self.create_source(session=session, source_str="dnshost")
        # Setup database
        self.create_network(session=session,
                            network="192.168.1.0/24",
                            scope=host_scope,
                            workspace_str=workspace_str)
        self.create_host(session=session, workspace_str=workspace_str, address="192.168.1.1")
        host = self.create_host(session=session, workspace_str=workspace_str, address="192.168.1.2")
        self.create_hostname(session=session,
                             workspace_str=workspace_str,
                             host_name="www.test1.com", scope=host_name_scope)
        host_name = self.create_hostname(session=session,
                                         workspace_str=workspace_str,
                                         host_name="www.test2.com", scope=host_name_scope)
        self.create_service(session=session, workspace_str=workspace_str, address="192.168.1.1", port=80)
        self.create_service(session=session, workspace_str=workspace_str, address="192.168.1.2", port=80)
        self.create_service(session=session, workspace_str=workspace_str, host_name_str="www.test1.com", port=80)
        self.create_service(session=session, workspace_str=workspace_str, host_name_str="www.test3.com", port=80)
        self._domain_utils.add_host_host_name_mapping(session=session,
                                                      host=host,
                                                      host_name=host_name,
                                                      source=source,
                                                      mapping_type=DnsResourceRecordType.a)
        session.commit()
        # Create command
        with tempfile.TemporaryDirectory() as temp_dir:
            arguments = {"workspace": workspace_str, "output_dir": temp_dir}
            if vhost:
                arguments["vhost"] = vhost
            test_suite = CollectorProducerTestSuite(engine=self._engine, arguments=arguments)
            test_suite.create_commands([self._arg_parse_module])
        session.commit()
        # Verify results
        if not vhost:
            results = session.query(Command) \
                .join(Service) \
                .join(Host) \
                .join(Workspace).filter(Workspace.name == workspace_str).count()
            self.assertEqual(2 if host_scope == ScopeType.all else 0, results)
            results = session.query(Command) \
                .join(Service) \
                .join(HostName) \
                .join(DomainName) \
                .join(Workspace).filter(Workspace.name == workspace_str).count()
            self.assertEqual(0, results)
        elif vhost == VhostChoice.all:
            results = session.query(Command) \
                .join(Service) \
                .join(Host) \
                .join(Workspace).filter(Workspace.name == workspace_str).count()
            self.assertEqual(2 if host_scope == ScopeType.all else 0, results)
            results = session.query(Command) \
                .join(Service) \
                .join(HostName) \
                .join(DomainName) \
                .join(Workspace).filter(Workspace.name == workspace_str).count()
            self.assertEqual(1 if host_name_scope == ScopeType.all and host_scope == ScopeType.all else 0, results)
        elif vhost == VhostChoice.domain:
            results = session.query(Command) \
                .join(Service) \
                .join(Host) \
                .join(Workspace).filter(Workspace.name == workspace_str).count()
            self.assertEqual(0, results)
            results = session.query(Command) \
                .join(Service) \
                .join(HostName) \
                .join(DomainName) \
                .join(Workspace).filter(Workspace.name == workspace_str).count()
            self.assertEqual(1 if host_name_scope == ScopeType.all and host_scope == ScopeType.all else 0, results)

    def test_vhost_none_host_in_scope(self):
        self.init_db()
        vhost = None
        with self._engine.session_scope() as session:
            self._unittest_service_command_creation(session,
                                                    vhost=vhost,
                                                    host_scope=ScopeType.all,
                                                    host_name_scope=ScopeType.exclude)

    def test_vhost_none_host_name_in_scope(self):
        self.init_db()
        vhost = None
        with self._engine.session_scope() as session:
            self._unittest_service_command_creation(session,
                                                    vhost=vhost,
                                                    host_scope=ScopeType.exclude,
                                                    host_name_scope=ScopeType.all)

    def test_vhost_none_host_host_name_in_scope(self):
        self.init_db()
        vhost = None
        with self._engine.session_scope() as session:
            self._unittest_service_command_creation(session,
                                                    vhost=vhost,
                                                    host_scope=ScopeType.all,
                                                    host_name_scope=ScopeType.all)

    def test_vhost_none(self):
        self.init_db()
        vhost = None
        with self._engine.session_scope() as session:
            self._unittest_service_command_creation(session,
                                                    vhost=vhost,
                                                    host_scope=ScopeType.exclude,
                                                    host_name_scope=ScopeType.exclude)

    def test_vhost_all_host_in_scope(self):
        self.init_db()
        vhost = VhostChoice.all
        with self._engine.session_scope() as session:
            self._unittest_service_command_creation(session,
                                                    vhost=vhost,
                                                    host_scope=ScopeType.all,
                                                    host_name_scope=ScopeType.exclude)

    def test_vhost_all_host_name_in_scope(self):
        self.init_db()
        vhost = VhostChoice.all
        with self._engine.session_scope() as session:
            self._unittest_service_command_creation(session,
                                                    vhost=vhost,
                                                    host_scope=ScopeType.exclude,
                                                    host_name_scope=ScopeType.all)

    def test_vhost_all_host_host_name_in_scope(self):
        self.init_db()
        vhost = VhostChoice.all
        with self._engine.session_scope() as session:
            self._unittest_service_command_creation(session,
                                                    vhost=vhost,
                                                    host_scope=ScopeType.all,
                                                    host_name_scope=ScopeType.all)

    def test_vhost_all(self):
        self.init_db()
        vhost = VhostChoice.all
        with self._engine.session_scope() as session:
            self._unittest_service_command_creation(session,
                                                    vhost=vhost,
                                                    host_scope=ScopeType.exclude,
                                                    host_name_scope=ScopeType.exclude)

    def test_vhost_domain_host_in_scope(self):
        self.init_db()
        vhost = VhostChoice.domain
        with self._engine.session_scope() as session:
            self._unittest_service_command_creation(session,
                                                    vhost=vhost,
                                                    host_scope=ScopeType.all,
                                                    host_name_scope=ScopeType.exclude)

    def test_vhost_domain_host_name_in_scope(self):
        self.init_db()
        vhost = VhostChoice.domain
        with self._engine.session_scope() as session:
            self._unittest_service_command_creation(session,
                                                    vhost=vhost,
                                                    host_scope=ScopeType.exclude,
                                                    host_name_scope=ScopeType.all)

    def test_vhost_domain_host_host_name_in_scope(self):
        self.init_db()
        vhost = VhostChoice.domain
        with self._engine.session_scope() as session:
            self._unittest_service_command_creation(session,
                                                    vhost=vhost,
                                                    host_scope=ScopeType.all,
                                                    host_name_scope=ScopeType.all)

    def test_vhost_domain(self):
        self.init_db()
        vhost = VhostChoice.domain
        with self._engine.session_scope() as session:
            self._unittest_service_command_creation(session,
                                                    vhost=vhost,
                                                    host_scope=ScopeType.exclude,
                                                    host_name_scope=ScopeType.exclude)


class TestCommandIpv4NetworkDomainCreation(BaseKaliCollectorTestCase):
    """
    This class tests the command creation logic
    """

    def __init__(self, test_name: str):
        super().__init__(test_name,
                         collector_name="nikto",
                         collector_class=NiktoCollector)

    def _unittest_service_command_creation(self,
                                           vhost: VhostChoice = None,
                                           workspace_str: str = "unittest",
                                           host_name_scope: ScopeType = ScopeType.all,
                                           host_scope: ScopeType = ScopeType.all,
                                           mapping_type: DnsResourceRecordType = DnsResourceRecordType.a):
        self.init_db()
        vhost = None
        with self._engine.session_scope() as session:
            source = self.create_source(session=session, source_str="dnshost")
            # Setup database
            self.create_network(session=session,
                                network="192.168.1.0/24",
                                scope=host_scope,
                                workspace_str=workspace_str)
            host = self.create_host(session=session, workspace_str=workspace_str, address="192.168.1.1")
            self.create_host(session=session, workspace_str=workspace_str, address="192.168.2.1")
            self.create_hostname(session=session,
                                 workspace_str=workspace_str,
                                 host_name="www.test1.com", scope=host_name_scope)
            host_name = self.create_hostname(session=session,
                                             workspace_str=workspace_str,
                                             host_name="www.test2.com", scope=host_name_scope)
            self.create_service(session=session, workspace_str=workspace_str, address="192.168.1.1", port=80)
            self.create_service(session=session, workspace_str=workspace_str, address="192.168.2.2", port=80)
            self._domain_utils.add_host_host_name_mapping(session=session,
                                                          host=host,
                                                          host_name=host_name,
                                                          source=source,
                                                          mapping_type=mapping_type)
        # Create command
        with self._engine.session_scope() as session:
            with tempfile.TemporaryDirectory() as temp_dir:
                arguments = {"workspace": workspace_str, "output_dir": temp_dir, "nikto": True}
                if vhost:
                    arguments["vhost"] = vhost
                test_suite = CollectorProducerTestSuite(engine=self._engine, arguments=arguments)
                test_suite.create_commands([self._arg_parse_module])
        # Verify results
        with self._engine.session_scope() as session:
            if not vhost:
                results = session.query(Command) \
                    .join(Host) \
                    .join(Network) \
                    .join(Workspace).filter(Workspace.name == workspace_str).count()
                self.assertEqual(1 if host_scope == ScopeType.all else 0, results)
                results = session.query(Command) \
                    .join(HostName) \
                    .join(DomainName) \
                    .join(Workspace).filter(Workspace.name == workspace_str).count()
                self.assertEqual(0, results)
            elif vhost == VhostChoice.all:
                results = session.query(Command) \
                    .join(Host) \
                    .join(Network) \
                    .join(Workspace).filter(Workspace.name == workspace_str).count()
                self.assertEqual(1 if host_scope == ScopeType.all else 0, results)
                results = session.query(Command) \
                    .join(HostName) \
                    .join(DomainName) \
                    .join(Workspace).filter(Workspace.name == workspace_str).count()
                self.assertEqual(1 if host_name_scope == ScopeType.all and host_scope == ScopeType.all
                                      and bool(mapping_type & DnsResourceRecordType.a) else 0,
                                 results)
            elif vhost == VhostChoice.domain:
                results = session.query(Command) \
                    .join(Host) \
                    .join(Network) \
                    .join(Workspace).filter(Workspace.name == workspace_str).count()
                self.assertEqual(0, results)
                results = session.query(Command) \
                    .join(HostName) \
                    .join(DomainName) \
                    .join(Workspace).filter(Workspace.name == workspace_str).count()
                self.assertEqual(1 if host_name_scope == ScopeType.all and host_scope == ScopeType.all and
                                      bool(mapping_type & DnsResourceRecordType.a) else 0,
                                 results)

    def test_vhost_none_ipv4_network_in_scope(self):
        vhost = None
        self._unittest_service_command_creation(vhost=vhost,
                                                host_scope=ScopeType.all,
                                                host_name_scope=ScopeType.exclude,
                                                mapping_type=DnsResourceRecordType.a)
        self._unittest_service_command_creation(vhost=vhost,
                                                host_scope=ScopeType.all,
                                                host_name_scope=ScopeType.exclude,
                                                mapping_type=DnsResourceRecordType.ptr)
        self._unittest_service_command_creation(vhost=vhost,
                                                host_scope=ScopeType.all,
                                                host_name_scope=ScopeType.exclude,
                                                mapping_type=DnsResourceRecordType.a)
        self._unittest_service_command_creation(vhost=vhost,
                                                host_scope=ScopeType.all,
                                                host_name_scope=ScopeType.exclude,
                                                mapping_type=DnsResourceRecordType.ptr)

    def test_vhost_none_host_name_in_scope(self):
        vhost = None
        self._unittest_service_command_creation(vhost=vhost,
                                                host_scope=ScopeType.exclude,
                                                host_name_scope=ScopeType.all,
                                                mapping_type=DnsResourceRecordType.a)
        self._unittest_service_command_creation(vhost=vhost,
                                                host_scope=ScopeType.exclude,
                                                host_name_scope=ScopeType.all,
                                                mapping_type=DnsResourceRecordType.ptr)

    def test_vhost_none_ipv4_network_host_name_in_scope(self):
        vhost = None
        self._unittest_service_command_creation(vhost=vhost,
                                                host_scope=ScopeType.all,
                                                host_name_scope=ScopeType.all,
                                                mapping_type=DnsResourceRecordType.a)
        self._unittest_service_command_creation(vhost=vhost,
                                                host_scope=ScopeType.all,
                                                host_name_scope=ScopeType.all,
                                                mapping_type=DnsResourceRecordType.ptr)

    def test_vhost_none(self):
        vhost = None
        self._unittest_service_command_creation(vhost=vhost,
                                                host_scope=ScopeType.exclude,
                                                host_name_scope=ScopeType.exclude,
                                                mapping_type=DnsResourceRecordType.a)
        self._unittest_service_command_creation(vhost=vhost,
                                                host_scope=ScopeType.exclude,
                                                host_name_scope=ScopeType.exclude,
                                                mapping_type=DnsResourceRecordType.ptr)

    def test_vhost_all_ipv4_network_in_scope(self):
        vhost = VhostChoice.all
        self._unittest_service_command_creation(vhost=vhost,
                                                host_scope=ScopeType.all,
                                                host_name_scope=ScopeType.exclude,
                                                mapping_type=DnsResourceRecordType.a)
        self._unittest_service_command_creation(vhost=vhost,
                                                host_scope=ScopeType.all,
                                                host_name_scope=ScopeType.exclude,
                                                mapping_type=DnsResourceRecordType.ptr)

    def test_vhost_all_host_name_in_scope(self):
        vhost = VhostChoice.all
        self._unittest_service_command_creation(vhost=vhost,
                                                host_scope=ScopeType.exclude,
                                                host_name_scope=ScopeType.all,
                                                mapping_type=DnsResourceRecordType.a)
        self._unittest_service_command_creation(vhost=vhost,
                                                host_scope=ScopeType.exclude,
                                                host_name_scope=ScopeType.all,
                                                mapping_type=DnsResourceRecordType.ptr)

    def test_vhost_all_ipv4_network_host_name_in_scope(self):
        vhost = VhostChoice.all
        self._unittest_service_command_creation(vhost=vhost,
                                                host_scope=ScopeType.all,
                                                host_name_scope=ScopeType.all,
                                                mapping_type=DnsResourceRecordType.a)
        self._unittest_service_command_creation(vhost=vhost,
                                                host_scope=ScopeType.all,
                                                host_name_scope=ScopeType.all,
                                                mapping_type=DnsResourceRecordType.ptr)

    def test_vhost_all(self):
        vhost = VhostChoice.all
        self._unittest_service_command_creation(vhost=vhost,
                                                host_scope=ScopeType.exclude,
                                                host_name_scope=ScopeType.exclude,
                                                mapping_type=DnsResourceRecordType.a)
        self._unittest_service_command_creation(vhost=vhost,
                                                host_scope=ScopeType.exclude,
                                                host_name_scope=ScopeType.exclude,
                                                mapping_type=DnsResourceRecordType.ptr)

    def test_vhost_domain_ipv4_network_in_scope(self):
        vhost = VhostChoice.domain
        self._unittest_service_command_creation(vhost=vhost,
                                                host_scope=ScopeType.all,
                                                host_name_scope=ScopeType.exclude,
                                                mapping_type=DnsResourceRecordType.a)
        self._unittest_service_command_creation(vhost=vhost,
                                                host_scope=ScopeType.all,
                                                host_name_scope=ScopeType.exclude,
                                                mapping_type=DnsResourceRecordType.ptr)

    def test_vhost_domain_host_name_in_scope(self):
        vhost = VhostChoice.domain
        self._unittest_service_command_creation(vhost=vhost,
                                                host_scope=ScopeType.exclude,
                                                host_name_scope=ScopeType.all,
                                                mapping_type=DnsResourceRecordType.a)
        self._unittest_service_command_creation(vhost=vhost,
                                                host_scope=ScopeType.exclude,
                                                host_name_scope=ScopeType.all,
                                                mapping_type=DnsResourceRecordType.ptr)

    def test_vhost_domain_ipv4_network_host_name_in_scope(self):
        vhost = VhostChoice.domain
        self._unittest_service_command_creation(vhost=vhost,
                                                host_scope=ScopeType.all,
                                                host_name_scope=ScopeType.all,
                                                mapping_type=DnsResourceRecordType.a)
        self._unittest_service_command_creation(vhost=vhost,
                                                host_scope=ScopeType.all,
                                                host_name_scope=ScopeType.all,
                                                mapping_type=DnsResourceRecordType.ptr)

    def test_vhost_domain(self):
        vhost = VhostChoice.domain
        self._unittest_service_command_creation(vhost=vhost,
                                                host_scope=ScopeType.exclude,
                                                host_name_scope=ScopeType.exclude,
                                                mapping_type=DnsResourceRecordType.a)
        self._unittest_service_command_creation(vhost=vhost,
                                                host_scope=ScopeType.exclude,
                                                host_name_scope=ScopeType.exclude,
                                                mapping_type=DnsResourceRecordType.ptr)


class TestHostNameServiceCreationTrigger(BaseKaliCollectorTestCase):
    """
    This class tests the command creation logic
    """

    def __init__(self, test_name: str):
        super().__init__(test_name,
                         collector_name="nikto",
                         collector_class=NiktoCollector)

    def _create_test_data(self,
                          session: Session,
                          workspace_str: str = "unittest") -> Host:
        source = self.create_source(session=session, source_str="dnshost")
        self.create_service(session=session, workspace_str=workspace_str, address="192.168.10.1", port=80)
        self.create_service(session=session, workspace_str=workspace_str, address="192.168.10.2", port=80)
        self.create_network(session=session,
                            network="192.168.1.0/24",
                            scope=ScopeType.all,
                            workspace_str=workspace_str)
        host1 = self.create_host(session=session, workspace_str=workspace_str, address="192.168.1.1")
        host2 = self.create_host(session=session, workspace_str=workspace_str, address="192.168.1.2")
        self.create_service(session=session, workspace_str=workspace_str, address="192.168.1.1", port=80)
        host_name1 = self.create_hostname(session=session,
                                          workspace_str=workspace_str,
                                          host_name="www.test1.com", scope=ScopeType.all)
        host_name2 = self.create_hostname(session=session,
                                          workspace_str=workspace_str,
                                          host_name="www.test.com", scope=ScopeType.all)
        self._domain_utils.add_host_host_name_mapping(session=session,
                                                      host=host1,
                                                      host_name=host_name1,
                                                      source=source,
                                                      mapping_type=DnsResourceRecordType.a)
        self._domain_utils.add_host_host_name_mapping(session=session,
                                                      host=host2,
                                                      host_name=host_name2,
                                                      source=source,
                                                      mapping_type=DnsResourceRecordType.ptr)
        return host1

    def _compare_service(self, expected: Service, actual: Service):
        self.assertEqual(expected.protocol, actual.protocol)
        self.assertEqual(expected.port, actual.port)
        self.assertEqual(expected.nmap_service_name, actual.nmap_service_name)
        self.assertEqual(expected.nessus_service_name, actual.nessus_service_name)
        self.assertEqual(expected.nmap_service_confidence,
                         actual.nmap_service_confidence)
        self.assertEqual(expected.nessus_service_confidence,
                         actual.nessus_service_confidence)
        self.assertEqual(expected.nmap_service_name_original,
                         actual.nmap_service_name_original)
        self.assertEqual(expected.state, actual.state)
        self.assertEqual(expected.nmap_service_state_reason,
                         actual.nmap_service_state_reason)
        self.assertEqual(expected.nmap_product, actual.nmap_product)
        self.assertEqual(expected.nmap_version, actual.nmap_version)
        self.assertEqual(expected.nmap_tunnel, actual.nmap_tunnel)
        self.assertEqual(expected.nmap_os_type, actual.nmap_os_type)

    def test_new_host_host_name_mapping(self):
        self.init_db()
        # test insert
        with self._engine.session_scope() as session:
            self._create_test_data(session=session)
            results_host_name_service = session.query(Service)\
                .join(HostName).one_or_none()
            results_host_service = session.query(Service)\
                .join(Host).filter(Host.address == "192.168.1.1").one_or_none()
            self.assertIsNone(results_host_name_service.host_id)
            self.assertIsNone(results_host_service.host_name_id)
            self._compare_service(results_host_service, results_host_name_service)
        # test update
        with self._engine.session_scope() as session:
            results_host_name_service = session.query(Service) \
                .join(HostName).one_or_none()
            results_host_name_service.nmap_service_name = "http"
        with self._engine.session_scope() as session:
            results_host_name_service = session.query(Service)\
                .join(HostName).one_or_none()
            results_host_service = session.query(Service)\
                .join(Host).filter(Host.address == "192.168.1.1").one_or_none()
            self.assertEqual("http", results_host_name_service.nmap_service_name)
            self.assertEqual("http", results_host_service.nmap_service_name)
            self._compare_service(results_host_service, results_host_name_service)

    def test_new_service_for_host(self):
        self.init_db()
        workspace_str = "unittest"
        # setup database
        with self._engine.session_scope() as session:
            source = self.create_source(session=session, source_str="dnshost")
            self.create_service(session=session, workspace_str=workspace_str, address="192.168.10.1", port=80)
            self.create_service(session=session, workspace_str=workspace_str, address="192.168.10.2", port=80)
            host = self.create_host(session=session, workspace_str=workspace_str, address="192.168.1.1")
            host_name = self.create_hostname(session=session,
                                             workspace_str=workspace_str,
                                             host_name="www.test1.com", scope=ScopeType.all)
            host_name_id = host_name.id
            self._domain_utils.add_host_host_name_mapping(session=session,
                                                          host=host,
                                                          host_name=host_name,
                                                          source=source,
                                                          mapping_type=DnsResourceRecordType.a)
        # test trigger
        with self._engine.session_scope() as session:
            service = self.create_service(session=session,
                                          workspace_str=workspace_str,
                                          address="192.168.1.1", port=443,
                                          protocol_type=ProtocolType.tcp)
            # verify trigger
            results = session.query(Service).join(HostName).filter(Service.port == 443).one()
            self.assertEqual(host_name_id, results.host_name_id)
            self.assertIsNone(results.host_id)
            self._compare_service(service, results)
        # test service update
        with self._engine.session_scope() as session:
            results = session.query(Service).join(Host).filter(Service.port == 443).one()
            results.nmap_service_name = 'http'
        with self._engine.session_scope() as session:
            results_host_name_service = session.query(Service) \
                .join(HostName).one_or_none()
            results_host_service = session.query(Service) \
                .join(Host).filter(Host.address == "192.168.1.1").one_or_none()
            self.assertEqual("http", results_host_name_service.nmap_service_name)
            self.assertEqual("http", results_host_service.nmap_service_name)
            self._compare_service(results_host_service, results_host_name_service)

    def test_new_service_for_host_name(self):
        self.init_db()
        workspace_str = "unittest"
        # setup database
        with self._engine.session_scope() as session:
            source = self.create_source(session=session, source_str="dnshost")
            self.create_service(session=session, workspace_str=workspace_str, address="192.168.10.1", port=80)
            self.create_service(session=session, workspace_str=workspace_str, address="192.168.10.2", port=80)
            host = self.create_host(session=session, workspace_str=workspace_str, address="192.168.1.1")
            host_name = self.create_hostname(session=session,
                                             workspace_str=workspace_str,
                                             host_name="www.test1.com", scope=ScopeType.all)
            host_id = host.id
            self._domain_utils.add_host_host_name_mapping(session=session,
                                                          host=host,
                                                          host_name=host_name,
                                                          source=source,
                                                          mapping_type=DnsResourceRecordType.a)
        # test trigger
        with self._engine.session_scope() as session:
            service = self.create_service(session=session,
                                          workspace_str=workspace_str,
                                          host_name_str="www.test1.com",
                                          port=443)
            # verify trigger
            results = session.query(Service).join(Host).filter(Service.port == 443).one()
            self.assertEqual(host_id, results.host_id)
            self.assertIsNone(results.host_name_id)
            self._compare_service(service, results)
        # test service update
        with self._engine.session_scope() as session:
            results = session.query(Service).join(HostName).filter(Service.port == 443).one()
            results.nmap_service_name = 'http'
        with self._engine.session_scope() as session:
            results_host_name_service = session.query(Service) \
                .join(HostName).one_or_none()
            results_host_service = session.query(Service) \
                .join(Host).filter(Host.address == "192.168.1.1").one_or_none()
            self.assertEqual("http", results_host_name_service.nmap_service_name)
            self.assertEqual("http", results_host_service.nmap_service_name)
            self._compare_service(results_host_service, results_host_name_service)


class TestCommandDeletion(BaseKisTestCase):
    """
    This class tests the command deletion
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def _create_test_data(self, session: Session):
        for workspace_str in self._workspaces:
            self._populate_all_tables(session=session, workspace_str=workspace_str)

    def test_command_reset(self):
        self.init_db(load_cipher_suites=True)
        # setup database
        with self._engine.session_scope() as session:
            self._create_test_data(session=session)
        # delete pending commands
        with self._engine.session_scope():
            self._engine.delete_incomplete_commands(workspace=self._workspaces[0])
        # check database
        with self._engine.session_scope() as session:
            results = {}
            for workspace in self._workspaces:
                results[workspace] = 0
            # count number of commands
            for command in session.query(Command).all():
                results[command.workspace.name] += 1
            for workspace in self._workspaces:
                if workspace == self._workspaces[0]:
                    self.assertEqual(1, results[workspace])
                else:
                    self.assertEqual(5, results[workspace])


class TestSettingCommandComplete(BaseKisTestCase):
    """
    This class tests the database.utils.set_commands_incomplete
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def _create_test_data(self, session: Session):
        for workspace_str in self._workspaces:
            self._populate_all_tables(session=session, workspace_str=workspace_str)

    def _unittest_command_incomplete(self, collector_name: str = None):
        self.init_db(load_cipher_suites=True)
        # setup database
        with self._engine.session_scope() as session:
            self._create_test_data(session=session)
        # update pending commands
        self._engine.set_commands_incomplete(workspace=self._workspaces[0], collector_name=collector_name)
        # check database
        with self._engine.session_scope() as session:
            results = {}
            for workspace in self._workspaces:
                results[workspace] = 0
            # count number of commands
            for command in session.query(Command).all():
                if command.status == CommandStatus.terminated:
                    results[command.workspace.name] += 1
            for workspace in self._workspaces:
                if workspace == self._workspaces[0]:
                    self.assertEqual(1 if collector_name else 4, results[workspace])
                else:
                    self.assertEqual(0, results[workspace])

    def test_command_incomplete_with_collector_name(self):
        self._unittest_command_incomplete("tcpnmap")

    def test_command_incomplete_without_collector_name(self):
        self._unittest_command_incomplete()


class TestCreatingAllCommands(BaseKisTestCase):
    """
    This class tests the creation of all collectors
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)
        self._readme_path = os.path.join(os.path.dirname(__file__), "..", "..", "README.md")
        self._re_entry = re.compile("^\|\s*(?P<priority>[0-9]+)\s*\|\s*(?P<collector_name>[a-zA-Z0-9]+)\s*"
                                    "\|\s*(?P<level>[a-zA-Z0-9, ]+)\s*\|\s*(?P<type>[a-zA-Z0-9*]+)\s*\|"
                                    "\s*(?P<ip_version>[a-zA-Z0-9, -]+)\s*\|\s*(?P<timeout>.+)\s*\|"
                                    "\s*(?P<username>.+)\s*\|.*$")
        self._collector_info = {}
        with open(self._readme_path, "r") as file:
            for line in file.readlines():
                line = line.strip()
                match = self._re_entry.match(line)
                if match:
                    priority = match.group("priority").strip()
                    if priority != "-":
                        collector_name = match.group("collector_name").strip()
                        priority = match.group("priority").strip()
                        priority = int(priority) if priority.isnumeric() else None
                        level = match.group("level").strip().split(", ")
                        ip_version = match.group("ip_version").strip().split(", ")
                        timeout = match.group("timeout").strip()
                        timeout = int(timeout) if timeout.isnumeric() else 0
                        username = match.group("username").strip()
                        if collector_name not in ["vnceyewitness", "httpnikto"]:
                            self._collector_info[collector_name] = {"priority": priority,
                                                                    "levels": level,
                                                                    "ipversions": ip_version,
                                                                    "username": username,
                                                                    "timeout": timeout,
                                                                    "arguments": True}
                            if collector_name in ["tcpmasscannetwork",
                                                  "tcpnmapdomain",
                                                  "tcpnmapnetwork",
                                                  "udpnmapdomain",
                                                  "udpnmapnetwork"]:
                                self._collector_info[collector_name]["arguments"] = ["interesting"]

    def _add_service(self, session: Session, host: Host, host_name: HostName, port: int):
        service = self._domain_utils.add_service(session=session,
                                                 port=port,
                                                 protocol_type=ProtocolType.tcp,
                                                 state=ServiceState.Open,
                                                 nmap_tunnel="ssl" if port == 443 else None,
                                                 host=host)
        if port == 25:
            self._domain_utils.add_service_method(session=session,
                                                  name="VRFY",
                                                  service=service)
            service = self._domain_utils.add_service(session=session,
                                                     port=port,
                                                     protocol_type=ProtocolType.tcp,
                                                     state=ServiceState.Open,
                                                     nmap_tunnel="ssl" if port == 443 else None,
                                                     host_name=host_name)
            self._domain_utils.add_service_method(session=session,
                                                  name="VRFY",
                                                  service=service)
        if port in [80, 443]:
            self._domain_utils.add_service_method(session=session,
                                                  name="PUT",
                                                  service=service)
            service.nmap_product = "Apache"
            service = self._domain_utils.add_service(session=session,
                                                     port=port,
                                                     protocol_type=ProtocolType.tcp,
                                                     state=ServiceState.Open,
                                                     nmap_tunnel="ssl" if port == 443 else None,
                                                     host_name=host_name)
            service.nmap_product = "Nginx"
            self._domain_utils.add_service_method(session=session,
                                                  name="PUT",
                                                  service=service)
        if port == 445:
            self._domain_utils.add_path(session=session,
                                        service=service,
                                        path="C$",
                                        path_type=PathType.smb_share)
            service = self._domain_utils.add_service(session=session,
                                                     port=port,
                                                     protocol_type=ProtocolType.tcp,
                                                     state=ServiceState.Open,
                                                     nmap_tunnel="ssl" if port == 443 else None,
                                                     host_name=host_name)
            self._domain_utils.add_path(session=session,
                                        service=service,
                                        path="C$",
                                        path_type=PathType.smb_share)
        service = self._domain_utils.add_service(session=session,
                                                 port=port,
                                                 protocol_type=ProtocolType.udp,
                                                 state=ServiceState.Open,
                                                 host=host)
        if port == 161:
            self._domain_utils.add_credential(session=session,
                                              credential_type=CredentialType.cleartext,
                                              password="public",
                                              service=service)
            service = self._domain_utils.add_service(session=session,
                                                     port=port,
                                                     protocol_type=ProtocolType.udp,
                                                     state=ServiceState.Open,
                                                     host=host)
            self._domain_utils.add_credential(session=session,
                                              credential_type=CredentialType.cleartext,
                                              password="public",
                                              service=service)

    def _create_database(self,
                         workspace: str,
                         ipv4_network_str: str,
                         ipv6_network_str: str,
                         ipv4_address_str: str,
                         ipv6_address_str: str,
                         ipv4_host_name_str: str,
                         ipv6_host_name_str: str,
                         company_str: str):
        """
        This method sets up the database for testing
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            ipv4_network = self.create_network(session=session,
                                               workspace_str=workspace,
                                               network=ipv4_network_str,
                                               scope=ScopeType.all)
            self.create_network(session=session,
                                workspace_str=workspace,
                                network=ipv6_network_str,
                                scope=ScopeType.all)
            ipv4_host = self.create_host(session=session,
                                         workspace_str=workspace,
                                         address=ipv4_address_str,
                                         in_scope=True)
            ipv6_host = self.create_host(session=session,
                                         workspace_str=workspace,
                                         address=ipv6_address_str,
                                         in_scope=True)
            ipv4_host_name = self.create_hostname(session=session,
                                                  workspace_str=workspace,
                                                  host_name=ipv4_host_name_str,
                                                  scope=ScopeType.all)
            ipv6_host_name = self.create_hostname(session=session,
                                                  workspace_str=workspace,
                                                  host_name=ipv6_host_name_str,
                                                  scope=ScopeType.all)
            self._domain_utils.add_host_host_name_mapping(session=session,
                                                          host=ipv4_host,
                                                          host_name=ipv4_host_name,
                                                          mapping_type=DnsResourceRecordType.a)
            self._domain_utils.add_host_host_name_mapping(session=session,
                                                          host=ipv6_host,
                                                          host_name=ipv6_host_name,
                                                          mapping_type=DnsResourceRecordType.aaaa)
            self._domain_utils.add_company(session=session,
                                           workspace=ipv4_network.workspace,
                                           name=company_str,
                                           network=ipv4_network,
                                           verify=False)
            for port in [21, 22, 23, 25, 53, 79, 80, 69, 110, 111, 123, 137, 143, 161, 389, 443, 445, 500, 623, 1099,
                         1300, 1433, 1521, 2049, 3306, 3389, 3478, 5060, 5432, 5900, 6000]:
                self._add_service(session=session,
                                  host=ipv4_host,
                                  host_name=ipv4_host_name,
                                  port=port)
                self._add_service(session=session,
                                  host=ipv6_host,
                                  host_name=ipv6_host_name,
                                  port=port)

    def _test_address_in_command(self, command: Command, address: str) -> bool:
        result = False
        for argument in command.os_command:
            if address in argument:
                result = True
                break
        return result

    def _assert_list_equal(self, expected_list: list, actual_list: list):
        expected_list = [item.lower() for item in expected_list]
        expected_list.sort()
        actual_list = [item.lower() for item in actual_list]
        actual_list.sort()
        self.assertListEqual(expected_list, actual_list)

    def test_command_creation(self):
        """
        This method reads all collectors listed in README.md and creates the commands in the database in order to
        ensure that creation is successful. afterwards it performs certains checks to ensure that the specification in
        the README.md (support of IPv4 and IPv6) meets the implementation
        """
        workspace = self._workspaces[0]
        producer = CollectorProducer(engine=self._engine)
        # Set up database
        self._create_database(workspace=workspace,
                              ipv4_network_str="1.1.1.0/24",
                              ipv6_network_str="64:ff9b::/64",
                              ipv4_address_str="1.1.1.1",
                              ipv6_address_str="64:ff9b::1:1:1:1",
                              ipv4_host_name_str="ipv4.test.com",
                              ipv6_host_name_str="ipv6.test.com",
                              company_str="Test LLC")
        # Create commands
        with tempfile.TemporaryDirectory() as temp_dir:
            arguments = {"workspace": workspace,
                         "output_dir": temp_dir,
                         "vhost": "all",
                         "wordlist_files": ["/usr/share/wordlists/dirb/common.txt"],
                         "print_commands": True}
            specific_collector = None
            if specific_collector:
                arguments[specific_collector] = True
            else:
                for collector, config in self._collector_info.items():
                    arguments[collector] = config["arguments"]
            producer.init(arguments)
            producer._create(debug=True)

            # Check compliance to README
            for collector in producer.selected_collectors:
                collector_name = collector.name
                priority = collector.instance.priority
                timeout = collector.instance.timeout
                exec_user = collector.instance.exec_user.pw_name
                print("Check instance: {} ({})".format(collector_name, priority))
                self.assertIn(collector_name, self._collector_info.keys())
                self.assertEqual(self._collector_info[collector_name]["priority"], priority)
                self.assertEqual(self._collector_info[collector_name]["timeout"], timeout)
                self.assertEqual(self._collector_info[collector_name]["username"], exec_user)
        # Check database (use the following code for trouble shooting; the code above takes very long to create all 580
        # commands.
        # with tempfile.TemporaryDirectory() as temp_dir:
        #     arguments = {"workspace": workspace,
        #                  "output_dir": temp_dir,
        #                  "vhost": "all",
        #                  "wordlist_files": ["/usr/share/wordlists/dirb/common.txt"],
        #                  "print_commands": True}
        #     specific_collector = None
        #     if specific_collector:
        #         arguments[specific_collector] = True
        #     else:
        #         for collector, config in self._collector_info.items():
        #             arguments[collector] = config["arguments"]
        with self._engine.session_scope() as session:
            for collector, values in self._collector_info.items():
                print("Check database: {}".format(collector))
                actual_versions = {}
                if specific_collector and specific_collector != collector:
                    continue
                # this are collectors that should not have created a command as no API config is available for them
                if collector in ["builtwith", "hostio", "censysdomain", "shodanhost" "securitytrails", "virustotal",
                                 "hunter", "shodanhost", "censyshost", "httpburpsuitepro"]:
                    results = session.query(Command) \
                        .join(CollectorName) \
                        .join((Service, Command.service)) \
                        .join(Host) \
                        .filter(CollectorName.name == collector).all()
                    if len(results) != 0:
                        raise ValueError("error in collector '{}': command returned. although "
                                         "no API config available".format(collector))
                    continue
                if "service" in values["levels"]:
                    # check service/host commands
                    results = session.query(Command) \
                        .join(CollectorName) \
                        .join((Service, Command.service)) \
                        .join(Host) \
                        .filter(CollectorName.name == collector).all()
                    if len(results) == 0:
                        raise ValueError("error in collector '{}' (service): no command returned".format(collector))
                    for command in results:
                        if command.service.host.version == 4:
                            actual_versions["IPv4"] = None
                            if not self._test_address_in_command(command, command.service.address):
                                raise ValueError("error in collector '{}': address '{}' not found in "
                                                 "command '{}'".format(command.collector_name.name,
                                                                       command.service.address,
                                                                       command.os_command_string))
                        elif command.service.host.version == 6:
                            actual_versions["IPv6"] = None
                            if not self._test_address_in_command(command, command.service.address):
                                raise ValueError("error in collector '{}': address '{}' not found in "
                                                 "command '{}'".format(command.collector_name.name,
                                                                       command.service.address,
                                                                       command.os_command_string))
                    self._assert_list_equal(values["ipversions"], list(actual_versions.keys()))
                if "vhost" in values["levels"]:
                    # check service/vhost commands
                    results = session.query(Command) \
                        .join(CollectorName) \
                        .join((Service, Command.service)) \
                        .join(HostName) \
                        .filter(CollectorName.name == collector).all()
                    if len(results) == 0:
                        raise ValueError("error in collector '{}' (vhost): no command returned".format(collector))
                    for command in results:
                        if command.service.host_name.resolves_to_in_scope_ipv4_address():
                            actual_versions["IPv4"] = None
                            if not self._test_address_in_command(command, command.service.address):
                                raise ValueError("error in collector '{}': address '{}' not found in "
                                                 "command '{}'".format(command.collector_name.name,
                                                                       command.service.address,
                                                                       command.os_command_string))
                        elif command.service.host_name.resolves_to_in_scope_ipv6_address():
                            actual_versions["IPv6"] = None
                            if not self._test_address_in_command(command, command.service.address):
                                raise ValueError("error in collector '{}': address '{}' not found in "
                                                 "command '{}'".format(command.collector_name.name,
                                                                       command.service.address,
                                                                       command.os_command_string))
                    self._assert_list_equal(values["ipversions"], list(actual_versions.keys()))
                if "network" in values["levels"]:
                    # check service/vhost commands
                    results = session.query(Command) \
                        .join(CollectorName) \
                        .join((Network, Command.ipv4_network)) \
                        .filter(CollectorName.name == collector).all()
                    if len(results) == 0:
                        raise ValueError("error in collector '{}': no command returned".format(collector))
                    for command in results:
                        if command.collector_name.name not in ["httpburpsuitepro"]:
                            if command.ipv4_network.ip_network.version == 4:
                                actual_versions["IPv4"] = None
                                if not self._test_address_in_command(command, command.ipv4_network.network):
                                    raise ValueError("error in collector '{}': address '{}' not found in "
                                                     "command '{}'".format(command.collector_name.name,
                                                                           command.ipv4_network.network,
                                                                           command.os_command_string))
                            elif command.ipv4_network.ip_network.version == 6:
                                actual_versions["IPv6"] = None
                                if not self._test_address_in_command(command, command.ipv4_network.network):
                                    raise ValueError("error in collector '{}': address '{}' not found in "
                                                     "command '{}'".format(command.collector_name.name,
                                                                           command.ipv4_network.network,
                                                                           command.os_command_string))
                    self._assert_list_equal(values["ipversions"], list(actual_versions.keys()))
                if "host" in values["levels"]:
                    # check service/vhost commands
                    results = session.query(Command) \
                        .join(CollectorName) \
                        .join((Host, Command.host)) \
                        .filter(CollectorName.name == collector).all()
                    if len(results) == 0:
                        raise ValueError("error in collector '{}': no command returned".format(collector))
                    for command in results:
                        if command.host.version == 4:
                            actual_versions["IPv4"] = None
                            if not self._test_address_in_command(command, command.host.address):
                                raise ValueError("error in collector '{}': address '{}' not found in "
                                                 "command '{}'".format(command.collector_name.name,
                                                                       command.host.address,
                                                                       command.os_command_string))
                        elif command.host.version == 6:
                            actual_versions["IPv6"] = None
                            if not self._test_address_in_command(command, command.host.address):
                                raise ValueError("error in collector '{}': address '{}' not found in "
                                                 "command '{}'".format(command.collector_name.name,
                                                                       command.service.address,
                                                                       command.os_command_string))
                    self._assert_list_equal(values["ipversions"], list(actual_versions.keys()))

    def test_command_execution(self):
        """
        This method shall be used to debug the behaviour of a collector's command creation.
        """
        workspace = self._workspaces[0]
        producer = CollectorProducer(engine=self._engine)
        # Set up database
        self._create_database(workspace=workspace,
                              ipv4_network_str="1.1.1.0/24",
                              ipv6_network_str="64:ff9b::/64",
                              ipv4_address_str="1.1.1.1",
                              ipv6_address_str="64:ff9b::1:1:1:1",
                              ipv4_host_name_str="ipv4.test.com",
                              ipv6_host_name_str="ipv6.test.com",
                              company_str="Test LLC")
        with tempfile.TemporaryDirectory() as temp_dir:
            arguments = {"workspace": workspace,
                         "output_dir": temp_dir,
                         "vhost": "all",
                         "wordlist_files": ["/usr/share/wordlists/dirb/common.txt"],
                         "print_commands": True}
            # Create commands: manually run command and verify outputs
            # arguments["httpkiterunner"] = True
            # producer.init(arguments)
            # producer._create(debug=True)
