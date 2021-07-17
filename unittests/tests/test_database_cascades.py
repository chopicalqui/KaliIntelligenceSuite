#!/usr/bin/python3
"""
this file implements unittests for cascades in the data model
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
from database.model import Workspace
from database.model import Host
from database.model import Service
from database.model import ServiceMethod
from database.model import HttpQuery
from database.model import Credentials
from database.model import Email
from database.model import Network
from database.model import Source
from database.model import HostName
from database.model import DomainName
from database.model import Path
from database.model import PathType
from database.model import AdditionalInfo
from database.model import Command
from database.model import CollectorName
from database.model import CollectorType
from database.model import HostHostNameMapping
from database.model import HostNameHostNameMapping
from database.model import ScopeType


class TestDeleteWorkspace(BaseKisTestCase):
    
    def __init__(self, test_name: str):
        super().__init__(test_name)

    def test_delete_workspace_with_host(self):
        self.init_db()
        # create database
        with self._engine.session_scope() as session:
            self.create_host(session)
        # delete workspace
        with self._engine.session_scope() as session:
            workspace = session.query(Workspace)
            self.assertEqual(1, session.query(Host).count())
            self.assertEqual(1, workspace.count())
            session.query(Workspace).delete()
        # check database
        with self._engine.session_scope() as session:
            self.assertEqual(0, session.query(Host).count())
            self.assertEqual(0, session.query(Workspace).count())

    def test_delete_workspace_with_ipv4_network(self):
        self.init_db()
        # create database
        with self._engine.session_scope() as session:
            self.create_network(session)
        # delete workspace
        with self._engine.session_scope() as session:
            self.assertEqual(1, session.query(Network).count())
            self.assertEqual(1, session.query(Workspace).count())
            session.query(Workspace).delete()
        # check database
        with self._engine.session_scope() as session:
            self.assertEqual(0, session.query(Network).count())
            self.assertEqual(0, session.query(Workspace).count())

    def test_delete_workspace_with_domain_name(self):
        self.init_db()
        # create database
        with self._engine.session_scope() as session:
            self.create_hostname(session)
        # delete workspace
        with self._engine.session_scope() as session:
            self.assertEqual(1, session.query(DomainName).count())
            self.assertEqual(2, session.query(HostName).count())
            self.assertEqual(1, session.query(Workspace).count())
            session.query(Workspace).delete()
        # check database
        with self._engine.session_scope() as session:
            self.assertEqual(0, session.query(DomainName).count())
            self.assertEqual(0, session.query(HostName).count())
            self.assertEqual(0, session.query(Workspace).count())

    def test_delete_workspace_with_all(self):
        self.init_db(load_cipher_suites=True)
        # create database
        with self._engine.session_scope() as session:
            for workspace_str in self._workspaces:
                self._populate_all_tables(session=session, workspace_str=workspace_str)
        # check database and delete first workspace
        with self._engine.session_scope() as session:
            for workspace_str in self._workspaces:
                self._check_database(session, workspace_str)
            workspace = session.query(Workspace).filter_by(name=self._workspaces[0])
            # delete first workspace
            workspace.delete()
        # check database
        with self._engine.session_scope() as session:
            self._check_database(session, self._workspaces[1])
            workspace = session.query(Workspace).filter_by(name=self._workspaces[1])
            # delete first workspace
            workspace.delete()
        # check database
        with self._engine.session_scope() as session:
            self._check_database_empty(session=session)


class TestDeleteIpv4Network(BaseKisTestCase):
    def __init__(self, test_name: str):
        super().__init__(test_name)

    def test_delete_ipv4_network_with_host(self):
        self.init_db()
        # create database
        with self._engine.session_scope() as session:
            self.create_network(session=session,
                                workspace_str=self._workspaces[0],
                                network="192.168.0.0/24",
                                scope=ScopeType.all)
            self.create_host(session=session,
                             workspace_str=self._workspaces[0],
                             address="192.168.0.1")
        # delete workspace
        with self._engine.session_scope() as session:
            network = session.query(Network).one()
            self.assertEqual(1, session.query(Host).count())
            self.assertEqual(True, session.query(Host).one().in_scope)
            self.assertEqual(1, session.query(Workspace).count())
            session.delete(network)
        # check database
        with self._engine.session_scope() as session:
            self.assertEqual(0, session.query(Network).count())
            self.assertEqual(False, session.query(Host).one().in_scope)
            self.assertEqual(1, session.query(Workspace).count())

    def test_delete_ipv4_network_with_additional_info(self):
        self.init_db()
        # create database
        with self._engine.session_scope() as session:
            item = self.create_network(session=session)
            self._domain_utils.add_additional_info(session=session,
                                                   name="key",
                                                   values=["value1", "value2"],
                                                   source=self.create_source(session=session, source_str="test"),
                                                   ipv4_network=item)
        # delete workspace
        with self._engine.session_scope() as session:
            item = session.query(Network).one()
            self.assertEqual(1, len(item.additional_info))
            self.assertEqual(1, session.query(Source).count())
            session.delete(item)
        # check database
        with self._engine.session_scope() as session:
            self.assertEqual(0, session.query(AdditionalInfo).count())
            self.assertEqual(1, session.query(Source).count())
            self.assertEqual(0, session.query(Network).count())

    def test_delete_ipv4_network_with_command(self):
        self.init_db()
        # create database
        with self._engine.session_scope() as session:
            self.create_command(session=session,
                                workspace_str=self._workspaces[0],
                                command=["sleep", "10"],
                                collector_name_str="str",
                                ipv4_network_str="192.168.0.0/24")
        # delete workspace
        with self._engine.session_scope() as session:
            item = session.query(Network).one()
            self.assertEqual(1, len(item.commands))
            session.delete(item)
        # check database
        with self._engine.session_scope() as session:
            self.assertEqual(0, session.query(Command).count())
            self.assertEqual(0, session.query(Network).count())


class TestDeleteHost(BaseKisTestCase):
    def __init__(self, test_name: str):
        super().__init__(test_name)

    def test_delete_host_with_ipv4_network(self):
        self.init_db()
        # create database
        with self._engine.session_scope() as session:
            self.create_network(session=session,
                                workspace_str=self._workspaces[0],
                                network="192.168.0.0/24")
            self.create_host(session=session,
                             workspace_str=self._workspaces[0],
                             address="192.168.0.1")
        # delete workspace
        with self._engine.session_scope() as session:
            self.assertEqual(1, session.query(Network).count())
            self.assertEqual(1, session.query(Host).count())
            results = session.query(Host).one()
            self.assertEqual("192.168.0.0/24", results.ipv4_network.network)
            self.assertEqual(1, session.query(Workspace).count())
            session.delete(results)
        # check database
        with self._engine.session_scope() as session:
            self.assertEqual(1, session.query(Network).count())
            self.assertEqual(0, session.query(Host).count())
            self.assertEqual(1, session.query(Workspace).count())

    def test_delete_host_with_service(self):
        self.init_db()
        # create database
        with self._engine.session_scope() as session:
            self.create_service(session=session, address="192.168.0.1")
        # delete workspace
        with self._engine.session_scope() as session:
            service = session.query(Service).one()
            self.assertEqual("192.168.0.1", service.host.address)
            session.delete(service.host)
        # check database
        with self._engine.session_scope() as session:
            self.assertEqual(0, session.query(Service).count())
            self.assertEqual(0, session.query(Host).count())
            self.assertEqual(1, session.query(Workspace).count())

    def test_delete_host_with_host_name(self):
        self.init_db()
        # create database
        with self._engine.session_scope() as session:
            self.create_host_host_name_mapping(session, host_name_str="www.unittest.com")
        # delete workspace
        with self._engine.session_scope() as session:
            host = session.query(Host).one()
            self.assertEqual(1, len(host.host_names))
            self.assertEqual("www.unittest.com", host.host_names[0].full_name)
            # you must use this delete operation; host.delete() does not work
            session.query(Host).delete()
        # check database
        with self._engine.session_scope() as session:
            self.assertListEqual(["unittest.com", "www.unittest.com"],
                                 [item.full_name for item in session.query(HostName).all()])
            self.assertEqual(0, session.query(HostHostNameMapping).count())
            self.assertEqual(1, session.query(DomainName).count())
            self.assertEqual(0, session.query(Host).count())
            self.assertEqual(1, session.query(Workspace).count())

    def test_delete_host_with_additional_info(self):
        self.init_db()
        # create database
        with self._engine.session_scope() as session:
            item = self.create_host(session=session,
                                    workspace_str=self._workspaces[0],
                                    address="192.168.0.1")
            self._domain_utils.add_additional_info(session=session,
                                                   name="key",
                                                   values=["value1", "value2"],
                                                   source=self.create_source(session=session, source_str="test"),
                                                   host=item)
        # delete workspace
        with self._engine.session_scope() as session:
            host = session.query(Host).one()
            self.assertEqual(1, len(host.additional_info))
            self.assertEqual(1, session.query(Source).count())
            session.query(Host).delete()
        # check database
        with self._engine.session_scope() as session:
            self.assertEqual(0, session.query(AdditionalInfo).count())
            self.assertEqual(1, session.query(Source).count())
            self.assertEqual(0, session.query(Host).count())

    def test_delete_host_with_command(self):
        self.init_db()
        # create database
        with self._engine.session_scope() as session:
            item = self.create_host(session=session)
            collector_name = self._engine.get_or_create(session,
                                                        CollectorName,
                                                        name="nikto",
                                                        type=CollectorType.host,
                                                        priority=1)
            self._domain_utils.add_command(session=session,
                                           os_command=["sleep", "10"],
                                           collector_name=collector_name,
                                           host=item)
        # delete workspace
        with self._engine.session_scope() as session:
            item = session.query(Host).one()
            self.assertEqual(1, len(item.commands))
            session.delete(item)
        # check database
        with self._engine.session_scope() as session:
            self.assertEqual(0, session.query(Command).count())
            self.assertEqual(0, session.query(Host).count())


class TestDeleteHostName(BaseKisTestCase):
    def __init__(self, test_name: str):
        super().__init__(test_name)

    def test_delete_host_name(self):
        self.init_db()
        # create database
        with self._engine.session_scope() as session:
            self.create_hostname(session, host_name="www.test.com")

        # delete workspace
        with self._engine.session_scope() as session:
            host_name = session.query(HostName).filter_by(name="www").one()
            self.assertEqual("www.test.com", host_name.full_name)
            session.delete(host_name)
        # check database
        with self._engine.session_scope() as session:
            self.assertEqual(1, session.query(DomainName).count())
            self.assertIsNone(session.query(HostName).one().name)

    def test_delete_host_name_with_service(self):
        self.init_db()
        # create database
        with self._engine.session_scope() as session:
            self.create_service(session=session, host_name_str="www.test.com")
        # delete workspace
        with self._engine.session_scope() as session:
            service = session.query(Service).one()
            self.assertEqual("www.test.com", service.host_name.full_name)
            session.delete(service.host_name)
        # check database
        with self._engine.session_scope() as session:
            self.assertEqual(0, session.query(Service).count())
            self.assertIsNone(session.query(HostName).one().name)
            self.assertEqual(1, session.query(DomainName).count())

    def test_delete_host_name_with_host(self):
        self.init_db()
        # create database
        with self._engine.session_scope() as session:
            self.create_host_host_name_mapping(session, ipv4_address="192.168.1.1", host_name_str="www.unittest.com")
        # delete workspace
        with self._engine.session_scope() as session:
            host_name = session.query(HostName).filter_by(name="www").one()
            self.assertEqual(1, len(host_name.hosts))
            self.assertEqual("192.168.1.1", host_name.hosts[0].address)
            # you must use this delete operation; host_name.delete() does not work
            session.query(HostName).delete()
        # check database
        with self._engine.session_scope() as session:
            self.assertEqual(1, session.query(DomainName).count())
            self.assertEqual(1, session.query(Workspace).count())
            self.assertEqual("192.168.1.1", session.query(Host).one().address)
            self.assertEqual(0, session.query(HostHostNameMapping).count())

    def test_delete_domain_name_with_email(self):
        self.init_db()
        # create database
        with self._engine.session_scope() as session:
            self.create_email(session, email_address="test@test.com")
        # delete workspace
        with self._engine.session_scope() as session:
            item = session.query(DomainName).one()
            self.assertEqual("test@test.com", item.host_names[0].emails[0].email_address)
            session.delete(item)
        # check database
        with self._engine.session_scope() as session:
            self.assertEqual(0, session.query(DomainName).count())
            self.assertEqual(0, session.query(HostName).count())
            self.assertEqual(0, session.query(Email).count())
            self.assertEqual(1, session.query(Workspace).count())

    def test_delete_host_name_with_additional_info(self):
        self.init_db()
        # create database
        with self._engine.session_scope() as session:
            host_name = self.create_hostname(session=session,
                                             workspace_str=self._workspaces[0])
            self._domain_utils.add_additional_info(session=session,
                                                   name="key",
                                                   values=["value1", "value2"],
                                                   source=self.create_source(session=session, source_str="test"),
                                                   host_name=host_name)
        # delete workspace
        with self._engine.session_scope() as session:
            item = session.query(HostName).filter_by(name="www").one()
            self.assertEqual(1, len(item.additional_info))
            self.assertEqual(1, session.query(Source).count())
            self.assertEqual(2, session.query(HostName).count())
            session.delete(item)
        # check database
        with self._engine.session_scope() as session:
            self.assertEqual(0, session.query(AdditionalInfo).count())
            self.assertEqual(1, session.query(Source).count())
            self.assertEqual(1, session.query(HostName).count())

    def test_delete_host_name_with_command(self):
        self.init_db()
        # create database
        with self._engine.session_scope() as session:
            item = self.create_hostname(session=session)
            collector_name = self._engine.get_or_create(session,
                                                        CollectorName,
                                                        name="nikto",
                                                        type=CollectorType.host_name_service,
                                                        priority=1)
            self._domain_utils.add_command(session=session,
                                           os_command=["sleep", "10"],
                                           collector_name=collector_name,
                                           host_name=item)
        # delete workspace
        with self._engine.session_scope() as session:
            item = session.query(HostName).filter_by(name="www").one()
            self.assertEqual(1, len(item.commands))
            session.delete(item)
        # check database
        with self._engine.session_scope() as session:
            self.assertEqual(0, session.query(Command).count())
            self.assertEqual(1, session.query(HostName).count())


class TestDeleteService(BaseKisTestCase):
    def __init__(self, test_name: str):
        super().__init__(test_name)

    def test_delete_service_with_host(self):
        self.init_db()
        # create database
        with self._engine.session_scope() as session:
            self.create_service(session=session,
                                workspace_str="unittest",
                                address="192.168.0.1")
        # delete workspace
        with self._engine.session_scope() as session:
            service = session.query(Service).one()
            self.assertEqual("192.168.0.1", service.host.address)
            session.delete(service)
        # check database
        with self._engine.session_scope() as session:
            self.assertEqual(0, session.query(Service).count())
            self.assertEqual(1, session.query(Host).count())

    def test_delete_service_with_host_name(self):
        self.init_db()
        # create database
        with self._engine.session_scope() as session:
            self.create_service(session=session,
                                workspace_str="unittest",
                                host_name_str="www.test.com")
        # delete workspace
        with self._engine.session_scope() as session:
            service = session.query(Service).one()
            self.assertEqual("www.test.com", service.host_name.full_name)
            session.delete(service)
        # check database
        with self._engine.session_scope() as session:
            self.assertEqual(0, session.query(Service).count())
            self.assertEqual(2, session.query(HostName).count())

    def test_delete_service_with_method(self):
        self.init_db()
        # create database
        with self._engine.session_scope() as session:
            service = self.create_service(session=session,
                                          workspace_str="unittest",
                                          host_name_str="www.test.com")
            self._domain_utils.add_service_method(session=session, name="PUT", service=service)
        # delete workspace
        with self._engine.session_scope() as session:
            service = session.query(Service).one()
            self.assertEqual("www.test.com", service.host_name.full_name)
            self.assertEqual(1, len(service.service_methods))
            self.assertEqual("PUT", service.service_methods[0].name)
            session.delete(service)
        # check database
        with self._engine.session_scope() as session:
            self.assertEqual(0, session.query(Service).count())
            self.assertEqual(0, session.query(ServiceMethod).count())

    def test_delete_services_with_method(self):
        self.init_db()
        # create database
        with self._engine.session_scope() as session:
            service1 = self.create_service(session=session,
                                           workspace_str="unittest",
                                           host_name_str="www.test1.com")
            service2 = self.create_service(session=session,
                                           workspace_str="unittest",
                                           host_name_str="www.test2.com")
            self._domain_utils.add_service_method(session=session, name="PUT", service=service1)
            self._domain_utils.add_service_method(session=session, name="PUT", service=service2)
        # delete workspace
        with self._engine.session_scope() as session:
            service = session.query(Service).all()[0]
            self.assertEqual(2, session.query(Service).count())
            self.assertEqual(1, len(service.service_methods))
            self.assertEqual("PUT", service.service_methods[0].name)
            session.delete(service)
        # check database
        with self._engine.session_scope() as session:
            self.assertEqual(1, session.query(Service).count())
            self.assertEqual(1, session.query(ServiceMethod).count())

    def test_delete_services_with_path(self):
        self.init_db()
        # create database
        with self._engine.session_scope() as session:
            service = self.create_service(session=session,
                                          workspace_str=self._workspaces[0],
                                          host_name_str="www.test1.com")
            self.create_path(session=session,
                             workspace_str=self._workspaces[0],
                             path="/tmp",
                             path_type=PathType.Http,
                             service=service)
        # delete workspace
        with self._engine.session_scope() as session:
            service = session.query(Service).one()
            self.assertEqual(1, len(service.paths))
            session.delete(service)
        # check database
        with self._engine.session_scope() as session:
            self.assertEqual(0, session.query(Service).count())
            self.assertEqual(0, session.query(Path).count())

    def test_delete_services_with_credentials(self):
        self.init_db()
        # create database
        with self._engine.session_scope() as session:
            service = self.create_service(session=session,
                                          workspace_str=self._workspaces[0],
                                          host_name_str="www.test1.com")
            self.create_credential(session=session,
                                   workspace_str=self._workspaces[0],
                                   service=service)
        # delete workspace
        with self._engine.session_scope() as session:
            service = session.query(Service).one()
            self.assertEqual(1, len(service.credentials))
            session.delete(service)
        # check database
        with self._engine.session_scope() as session:
            self.assertEqual(0, session.query(Service).count())
            self.assertEqual(0, session.query(Credentials).count())

    def test_delete_service_with_additional_info(self):
        self.init_db()
        # create database
        with self._engine.session_scope() as session:
            item = self.create_service(session=session,
                                       workspace_str="unittest",
                                       address="192.168.0.1")
            self._domain_utils.add_additional_info(session=session,
                                                   name="key",
                                                   values=["value1", "value2"],
                                                   source=self.create_source(session=session, source_str="test"),
                                                   service=item)
        # delete workspace
        with self._engine.session_scope() as session:
            item = session.query(Service).one()
            self.assertEqual(1, len(item.additional_info))
            self.assertEqual(1, session.query(Source).count())
            session.delete(item)
        # check database
        with self._engine.session_scope() as session:
            self.assertEqual(0, session.query(AdditionalInfo).count())
            self.assertEqual(1, session.query(Source).count())
            self.assertEqual(0, session.query(Service).count())

    def test_delete_service_with_command(self):
        self.init_db()
        # create database
        with self._engine.session_scope() as session:
            item = self.create_service(session=session)
            collector_name = self._engine.get_or_create(session,
                                                        CollectorName,
                                                        name="nikto",
                                                        type=CollectorType.service,
                                                        priority=1)
            self._domain_utils.add_command(session=session,
                                           os_command=["sleep", "10"],
                                           collector_name=collector_name,
                                           service=item)
        # delete workspace
        with self._engine.session_scope() as session:
            item = session.query(Service).one()
            self.assertEqual(1, len(item.commands))
            session.delete(item)
        # check database
        with self._engine.session_scope() as session:
            self.assertEqual(0, session.query(Command).count())
            self.assertEqual(0, session.query(Service).count())


class TestDeleteServiceMethod(BaseKisTestCase):
    def __init__(self, test_name: str):
        super().__init__(test_name)

    def test_delete_method_with_service(self):
        self.init_db()
        # create database
        with self._engine.session_scope() as session:
            service = self.create_service(session=session,
                                          workspace_str="unittest",
                                          host_name_str="www.test.com")
            self._domain_utils.add_service_method(session=session, name="PUT", service=service)
        # delete workspace
        with self._engine.session_scope() as session:
            item = session.query(ServiceMethod).one()
            self.assertIsNotNone(item.service)
            self.assertEqual("PUT", item.name)
            session.delete(item)
        # check database
        with self._engine.session_scope() as session:
            self.assertEqual(1, session.query(Service).count())
            self.assertEqual(0, session.query(ServiceMethod).count())


class TestDeleteSource(BaseKisTestCase):
    def __init__(self, test_name: str):
        super().__init__(test_name)

    def test_delete_source_with_hosts(self):
        self.init_db()
        # create database
        with self._engine.session_scope() as session:
            source = self.create_source(session, "unittest")
            host1 = self.create_host(session=session,
                                     workspace_str=self._workspaces[0],
                                     address="192.168.0.1")
            host2 = self.create_host(session=session,
                                     workspace_str=self._workspaces[0],
                                     address="192.168.0.2")
            source.hosts.append(host1)
            source.hosts.append(host2)
        # delete workspace
        with self._engine.session_scope() as session:
            source = session.query(Source).one()
            self.assertEqual(2, len(source.hosts))
            session.delete(source)
        # check database
        with self._engine.session_scope() as session:
            items = session.query(Host).all()
            self.assertEqual(2, len(items))
            for item in items:
                self.assertEqual(0, len(item.sources))

    def test_delete_source_with_ipv4_network(self):
        self.init_db()
        # create database
        with self._engine.session_scope() as session:
            source = self.create_source(session, "unittest")
            network1 = self.create_network(session, network="192.168.0.0/24")
            network2 = self.create_network(session, network="192.168.1.0/24")
            source.ipv4_networks.append(network1)
            source.ipv4_networks.append(network2)
        # delete workspace
        with self._engine.session_scope() as session:
            source = session.query(Source).one()
            self.assertEqual(2, len(source.ipv4_networks))
            session.delete(source)
        # check database
        with self._engine.session_scope() as session:
            items = session.query(Network).all()
            self.assertEqual(2, len(items))
            for item in items:
                self.assertEqual(0, len(item.sources))

    def test_delete_source_with_host_names(self):
        self.init_db()
        # create database
        with self._engine.session_scope() as session:
            source = self.create_source(session, "unittest")
            item1 = self.create_hostname(session, host_name="www.test1.com")
            item2 = self.create_hostname(session, host_name="www.test2.com")
            source.host_names.append(item1)
            source.host_names.append(item2)
        # delete workspace
        with self._engine.session_scope() as session:
            source = session.query(Source).one()
            self.assertEqual(2, len(source.host_names))
            session.delete(source)
        # check database
        with self._engine.session_scope() as session:
            items = session.query(HostName).all()
            self.assertEqual(4, len(items))
            for item in items:
                self.assertEqual(0, len(item.sources))

    def test_delete_source_with_service(self):
        self.init_db()
        # create database
        with self._engine.session_scope() as session:
            source = self.create_source(session, "unittest")
            item1 = self.create_service(session, port=80)
            item2 = self.create_service(session, port=443)
            source.services.append(item1)
            source.services.append(item2)
        # delete workspace
        with self._engine.session_scope() as session:
            source = session.query(Source).one()
            self.assertEqual(2, len(source.services))
            session.delete(source)
        # check database
        with self._engine.session_scope() as session:
            items = session.query(Service).all()
            self.assertEqual(2, len(items))
            for item in items:
                self.assertEqual(0, len(item.sources))


class TestDeleteEmail(BaseKisTestCase):
    def __init__(self, test_name: str):
        super().__init__(test_name)

    def test_delete_email_with_additional_info(self):
        self.init_db()
        # create database
        with self._engine.session_scope() as session:
            item = self.create_email(session=session)
            self._domain_utils.add_additional_info(session=session,
                                                   name="key",
                                                   values=["value1", "value2"],
                                                   source=self.create_source(session=session, source_str="test"),
                                                   email=item)
        # delete workspace
        with self._engine.session_scope() as session:
            item = session.query(Email).one()
            self.assertEqual(1, len(item.additional_info))
            self.assertEqual(1, session.query(Source).count())
            session.delete(item)
        # check database
        with self._engine.session_scope() as session:
            self.assertEqual(0, session.query(AdditionalInfo).count())
            self.assertEqual(1, session.query(Source).count())
            self.assertEqual(0, session.query(Email).count())

    def test_delete_email_with_credentials(self):
        self.init_db()
        # create database
        with self._engine.session_scope() as session:
            item = self.create_email(session=session)
            self.create_credential(session=session,
                                   workspace_str=self._workspaces[0],
                                   email=item)
        # delete workspace
        with self._engine.session_scope() as session:
            item = session.query(Email).one()
            self.assertEqual(1, len(item.credentials))
            session.delete(item)
        # check database
        with self._engine.session_scope() as session:
            self.assertEqual(0, session.query(Email).count())
            self.assertEqual(0, session.query(Credentials).count())

    def test_delete_email_with_command(self):
        self.init_db()
        # create database
        with self._engine.session_scope() as session:
            item = self.create_email(session=session)
            collector_name = self._engine.get_or_create(session,
                                                        CollectorName,
                                                        name="nikto",
                                                        type=CollectorType.email,
                                                        priority=1)
            self._domain_utils.add_command(session=session,
                                           os_command=["sleep", "10"],
                                           collector_name=collector_name,
                                           email=item)
        # delete workspace
        with self._engine.session_scope() as session:
            item = session.query(Email).one()
            self.assertEqual(1, len(item.commands))
            session.delete(item)
        # check database
        with self._engine.session_scope() as session:
            self.assertEqual(0, session.query(Command).count())
            self.assertEqual(0, session.query(Email).count())


class TestDeletePath(BaseKisTestCase):
    def __init__(self, test_name: str):
        super().__init__(test_name)

    def test_delete_path_with_http_query(self):
        self.init_db()
        # create database
        with self._engine.session_scope() as session:
            service = self.create_service(session=session, workspace_str=self._workspaces[0])
            path = self.create_path(session=session, workspace_str=self._workspaces[0], service=service)
            self._engine.get_or_create(session, HttpQuery, query="a=b&c=d", path=path)
        # delete workspace
        with self._engine.session_scope() as session:
            item = session.query(Path).one()
            self.assertIsNotNone(item.service)
            self.assertEqual(1, len(item.queries))
            session.delete(item)
        # check database
        with self._engine.session_scope() as session:
            self.assertEqual(1, session.query(Service).count())
            self.assertEqual(0, session.query(HttpQuery).count())
            self.assertEqual(0, session.query(Path).count())


class TestDeleteHttpQuery(BaseKisTestCase):
    def __init__(self, test_name: str):
        super().__init__(test_name)

    def test_delete_http_query_with_path(self):
        self.init_db()
        # create database
        with self._engine.session_scope() as session:
            service = self.create_service(session=session, workspace_str=self._workspaces[0])
            path = self.create_path(session=session, workspace_str=self._workspaces[0], service=service)
            self._engine.get_or_create(session, HttpQuery, query="a=b&c=d", path=path)
        # delete workspace
        with self._engine.session_scope() as session:
            item = session.query(HttpQuery).one()
            self.assertIsNotNone(item.path)
            self.assertIsNotNone(item.path.service)
            session.delete(item)
        # check database
        with self._engine.session_scope() as session:
            self.assertEqual(1, session.query(Service).count())
            self.assertEqual(0, session.query(HttpQuery).count())
            self.assertEqual(1, session.query(Path).count())


class TestDeleteHostNameHostNameMapping(BaseKisTestCase):
    def __init__(self, test_name: str):
        super().__init__(test_name)

    def test_delete_source_host_name(self):
        self.init_db()
        # create database
        with self._engine.session_scope() as session:
            self.create_host_name_host_name_mapping(session=session,
                                                    source_host_name_str="www.unittest.com",
                                                    resolved_host_name_str="resolved.unittest.com",
                                                    source_str="test")
        # check and delete data
        with self._engine.session_scope() as session:
            mapping = session.query(HostNameHostNameMapping).one()
            self.assertTrue("www.unittest.com", mapping.source_host_name)
            self.assertTrue("resolved.unittest.com", mapping.resolved_host_name)
            self.assertTrue("test", mapping.sources[0].name)
            session.delete(mapping.source_host_name)
        # check data
        with self._engine.session_scope() as session:
            self.assertEqual(0, session.query(HostNameHostNameMapping).count())
            self.assertEqual(0, session.query(HostName).filter_by(name="www").count())
            self.assertEqual(1, session.query(HostName).filter_by(name="resolved").count())

    def test_delete_resolved_host_name(self):
        self.init_db()
        # create database
        with self._engine.session_scope() as session:
            self.create_host_name_host_name_mapping(session=session,
                                                    source_host_name_str="www.unittest.com",
                                                    resolved_host_name_str="resolved.unittest.com",
                                                    source_str="test")
        # check and delete data
        with self._engine.session_scope() as session:
            mapping = session.query(HostNameHostNameMapping).one()
            self.assertTrue("www.unittest.com", mapping.source_host_name)
            self.assertTrue("resolved.unittest.com", mapping.resolved_host_name)
            self.assertTrue("test", mapping.sources[0].name)
            session.delete(mapping.resolved_host_name)
        # check data
        with self._engine.session_scope() as session:
            self.assertEqual(0, session.query(HostNameHostNameMapping).count())
            self.assertEqual(1, session.query(HostName).filter_by(name="www").count())
            self.assertEqual(0, session.query(HostName).filter_by(name="resolved").count())

    def test_delete_mapping(self):
        self.init_db()
        # create database
        with self._engine.session_scope() as session:
            self.create_host_name_host_name_mapping(session=session,
                                                    source_host_name_str="www.unittest.com",
                                                    resolved_host_name_str="resolved.unittest.com",
                                                    source_str="test")
        # check and delete data
        with self._engine.session_scope() as session:
            mapping = session.query(HostNameHostNameMapping).one()
            self.assertTrue("www.unittest.com", mapping.source_host_name)
            self.assertTrue("resolved.unittest.com", mapping.resolved_host_name)
            self.assertTrue("test", mapping.sources[0].name)
            session.delete(mapping)
        # check data
        with self._engine.session_scope() as session:
            self.assertEqual(0, session.query(HostNameHostNameMapping).count())
            self.assertEqual(1, session.query(HostName).filter_by(name="www").count())
            self.assertEqual(1, session.query(HostName).filter_by(name="resolved").count())
