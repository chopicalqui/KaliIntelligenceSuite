#!/usr/bin/python3
"""
this file implements unittests for the data model
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

from unittests.tests.core import BaseDataModelTestCase
from unittests.tests.core import BaseKisTestCase
from database.model import Workspace
from database.model import Host
from database.model import Service
from database.model import ServiceMethod
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
from database.model import CipherSuiteProtocolVersion
from database.model import CipherSuiteSecurity
from database.model import ScopeType
from database.model import CollectorName
from database.model import CollectorType
from database.model import FileType
from database.model import File
from database.model import HostHostNameMapping
from database.model import HostNameHostNameMapping
from database.model import CipherSuite
from database.model import KeyExchangeAlgorithm
from database.model import SymmetricAlgorithm
from database.model import HashAlgorithm
from database.model import TlsInfo
from database.model import TlsVersion
from database.model import TlsPreference
from database.model import TlsInfoCipherSuiteMapping
from database.model import CertInfo
from database.model import AsymmetricAlgorithm
from database.model import CertType
from datetime import datetime


class TestWorkspace(BaseDataModelTestCase):
    """
    Test data model for workspace
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, Workspace)

    def test_unique_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            self._test_unique_constraint(session, name="unittest")

    def test_not_null_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            self._test_not_null_constraint(session)

    def test_check_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            pass

    def test_success(self):
        self.init_db()
        with self._engine.session_scope() as session:
            self._test_success(session, name="unittest")


class TestCollectorName(BaseDataModelTestCase):
    """
    Test data model for collector name
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, CollectorName)

    def test_unique_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            self._test_unique_constraint(session, name="unittest", type=CollectorType.domain)

    def test_not_null_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            self._test_not_null_constraint(session)
            self._test_not_null_constraint(session, name="unittest")
            self._test_not_null_constraint(session, type=CollectorType.domain)

    def test_check_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            pass

    def test_success(self):
        self.init_db()
        with self._engine.session_scope() as session:
            self._test_success(session, name="unittest", type=CollectorType.domain)


class TestServiceMethod(BaseDataModelTestCase):
    """
    Test data model for service method
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, ServiceMethod)

    def test_unique_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            service = self.create_service(session)
            self._test_unique_constraint(session, name="unittest", service=service)

    def test_not_null_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            self._test_not_null_constraint(session, name="unittest", service=None)

    def test_check_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            service = self.create_service(session)
            self._test_check_constraint(session, ex_message='null value in column "name" violates not-null constraint')
            self._test_check_constraint(session,
                                        name="test",
                                        ex_message='null value in column "service_id" violates not-null constraint')
            self._test_check_constraint(session,
                                        service=service,
                                        ex_message='null value in column "name" violates not-null constraint')

    def test_success(self):
        self.init_db()
        with self._engine.session_scope() as session:
            service = self.create_service(session)
            self._test_success(session, name="unittest", service=service)


class TestHost(BaseDataModelTestCase):
    """
    Test data model for host
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, model=Host)

    def test_unique_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = self.create_workspace(session)
            self._test_unique_constraint(session, address="192.168.1.1", workspace=workspace)

    def test_not_null_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = self.create_workspace(session)
            self._test_not_null_constraint(session, address="192.168.1.1")
            self._test_not_null_constraint(session, workspace=workspace)

    def test_success(self):
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = self.create_workspace(session)
            self._test_success(session, workspace=workspace, address="192.168.1.1")


class TestIpv4Network(BaseDataModelTestCase):
    """
    Test data model for IPv4 network
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, model=Network)

    def test_unique_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = self.create_workspace(session)
            self._test_unique_constraint(session, network="192.168.1.0/24", workspace=workspace)

    def test_not_null_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = self.create_workspace(session)
            self._test_not_null_constraint(session, network="192.168.1.0/24")
            self._test_not_null_constraint(session, workspace=workspace)

    def test_check_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            pass

    def test_success(self):
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = self.create_workspace(session)
            self._test_success(session, workspace=workspace, network="192.168.1.0/24")


class TestHostName(BaseDataModelTestCase):
    """
    Test data model for host name
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, model=HostName)

    def test_unique_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            domain_name = self.create_domain_name(session)
            self._test_unique_constraint(session, name="www", domain_name=domain_name)

    def test_not_null_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            self._test_not_null_constraint(session, name="www")

    def test_check_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            pass

    def test_success(self):
        self.init_db()
        with self._engine.session_scope() as session:
            domain_name = self.create_domain_name(session)
            self._test_success(session, name="www", domain_name=domain_name)
            self._test_success(session, domain_name=domain_name)


class TestDomainName(BaseDataModelTestCase):
    """
    Test data model for domain name
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, model=DomainName)

    def test_unique_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = self.create_workspace(session)
            self._test_unique_constraint(session, name="test.com", workspace=workspace)

    def test_not_null_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = self.create_workspace(session)
            self._test_not_null_constraint(session, workspace=workspace)
            self._test_not_null_constraint(session, name="test.com")

    def test_check_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            pass

    def test_success(self):
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = self.create_workspace(session)
            self._test_success(session, name="test.com", workspace=workspace)


class TestEmail(BaseDataModelTestCase):
    """
    Test data model for email
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, model=Email)

    def test_unique_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            host_name = self.create_hostname(session)
            self._test_unique_constraint(session, address="test", host_name=host_name)

    def test_not_null_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            host_name = self.create_hostname(session)
            self._test_not_null_constraint(session, host_name=host_name)
            self._test_not_null_constraint(session, address="test")

    def test_check_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            pass

    def test_success(self):
        self.init_db()
        with self._engine.session_scope() as session:
            host_name = self.create_hostname(session)
            self._test_success(session, address="test", host_name=host_name)


class TestSource(BaseDataModelTestCase):
    """
    Test data model for source
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, model=Source)

    def test_unique_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            self._test_unique_constraint(session, name="unittest")

    def test_not_null_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            self._test_not_null_constraint(session)

    def test_check_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            pass

    def test_success(self):
        self.init_db()
        with self._engine.session_scope() as session:
            self._test_unique_constraint(session, name="unittest")


class TestService(BaseDataModelTestCase):
    """
    Test data model for service
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, model=Service)

    def test_unique_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            host_name = self.create_hostname(session, workspace_str=self._workspaces[0])
            host = self.create_host(session, workspace_str=self._workspaces[0])
            self._test_unique_constraint(session,
                                         port=80,
                                         protocol=ProtocolType.tcp,
                                         host=host,
                                         state=ServiceState.Open)
            self._test_unique_constraint(session,
                                         port=80,
                                         protocol=ProtocolType.tcp,
                                         host_name=host_name,
                                         state=ServiceState.Open)

    def test_not_null_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            host = self.create_host(session)
            self._test_not_null_constraint(session)
            self._test_not_null_constraint(session,
                                           port=80,
                                           protocol=ProtocolType.tcp,
                                           host=host)
            self._test_not_null_constraint(session,
                                           port=80,
                                           host=host,
                                           state=ServiceState.Open)
            self._test_not_null_constraint(session,
                                           port=80,
                                           protocol=ProtocolType.tcp,
                                           host=host)

    def test_check_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            host_name = self.create_hostname(session, workspace_str=self._workspaces[0])
            host = self.create_host(session, workspace_str=self._workspaces[0])
            self._test_check_constraint(session,
                                        port=80,
                                        protocol=ProtocolType.tcp,
                                        state=ServiceState.Open)
            self._test_check_constraint(session,
                                        port=80,
                                        protocol=ProtocolType.tcp,
                                        state=ServiceState.Open,
                                        host=host,
                                        host_name=host_name)

    def test_success(self):
        self.init_db()
        with self._engine.session_scope() as session:
            host_name = self.create_hostname(session, workspace_str=self._workspaces[0])
            host = self.create_host(session, workspace_str=self._workspaces[0])
            self._test_success(session,
                               port=80,
                               protocol=ProtocolType.tcp,
                               host=host,
                               state=ServiceState.Open)
            self._test_success(session,
                               port=80,
                               protocol=ProtocolType.tcp,
                               host_name=host_name,
                               state=ServiceState.Open)


class TestAdditionalInfo(BaseDataModelTestCase):
    """
    Test data model for additional info
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, model=AdditionalInfo)

    def test_unique_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            host_name = self.create_hostname(session, workspace_str=self._workspaces[0])
            service = self.create_service(session, workspace_str=self._workspaces[0])
            self._test_unique_constraint(session,
                                         name="key",
                                         host_name=host_name)
            self._test_unique_constraint(session,
                                         name="key",
                                         service=service)

    def test_not_null_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            host_name = self.create_hostname(session, workspace_str=self._workspaces[0])
            service = self.create_service(session, workspace_str=self._workspaces[0])
            self._test_not_null_constraint(session)
            self._test_not_null_constraint(session,
                                           host_name=host_name)
            self._test_not_null_constraint(session,
                                           service=service)

    def test_check_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            host_name = self.create_hostname(session, workspace_str=self._workspaces[0])
            service = self.create_service(session, workspace_str=self._workspaces[0])
            self._test_check_constraint(session, name="unittest")
            self._test_check_constraint(session,
                                        name="unittest",
                                        host_name=host_name,
                                        service=service)
            self._test_check_constraint(session,
                                        name="unittest",
                                        host_name=host_name,
                                        service=service)

    def test_success(self):
        self.init_db()
        with self._engine.session_scope() as session:
            host_name = self.create_hostname(session, workspace_str=self._workspaces[0])
            service = self.create_service(session, workspace_str=self._workspaces[0])
            self._test_success(session,
                               name="key",
                               host_name=host_name)
            self._test_success(session,
                               name="key",
                               service=service)


class TestCommand(BaseDataModelTestCase):
    """
    Test data model for command
    """

    # todo: update for new collector
    def __init__(self, test_name: str):
        super().__init__(test_name, model=Command)

    def test_unique_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            host_name = self.create_hostname(session, workspace_str=self._workspaces[0])
            service_host = self.create_service(session, workspace_str=self._workspaces[0])
            service_host_name = self.create_service(session,
                                                    workspace_str=self._workspaces[0],
                                                    host_name_str="www.test.com")
            host = self.create_host(session, workspace_str=self._workspaces[0])
            ipv4_network = self.create_network(session, workspace_str=self._workspaces[0])
            collector_name = self.create_collector_name(session)
            self._test_unique_constraint(session,
                                         os_command=["sleep", "10"],
                                         collector_name=collector_name,
                                         service=service_host)
            self._test_unique_constraint(session,
                                         os_command=["sleep", "10"],
                                         collector_name=collector_name,
                                         service=service_host_name)
            self._test_unique_constraint(session,
                                         os_command=["sleep", "10"],
                                         collector_name=collector_name,
                                         host=host)
            self._test_unique_constraint(session,
                                         os_command=["sleep", "10"],
                                         collector_name=collector_name,
                                         host_name=host_name)
            self._test_unique_constraint(session,
                                         os_command=["sleep", "10"],
                                         collector_name=collector_name,
                                         ipv4_network=ipv4_network)

    def test_not_null_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            collector_name = self.create_collector_name(session)
            self._test_not_null_constraint(session, os_command=["sleep", "10"], collector_name=None)
            self._test_not_null_constraint(session, os_command=None, collector_name=None)
            self._test_not_null_constraint(session, os_command=None, collector_name=collector_name)

    def test_check_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            host_name = self.create_hostname(session, workspace_str=self._workspaces[0], host_name="www.unittest.com")
            service_host = self.create_service(session, address="10.10.10.10", workspace_str=self._workspaces[0])
            service_host_name = self.create_service(session,
                                                    workspace_str=self._workspaces[0],
                                                    host_name_str="www.test.com")
            host = self.create_host(session, address="10.10.10.11", workspace_str=self._workspaces[0])
            ipv4_network = self.create_network(session, workspace_str=self._workspaces[0])
            collector_name = self.create_collector_name(session)
            self._test_check_constraint(session,
                                        os_command=["sleep", "10"],
                                        collector_name=collector_name)
            # this won't cause a violation due to the checks implemented in the constructor
            self._test_check_constraint(session,
                                        os_command=["sleep", "10"],
                                        collector_name=collector_name,
                                        service=service_host,
                                        ipv4_network=ipv4_network,
                                        ex_message=None)
            self._test_check_constraint(session,
                                        os_command=["sleep", "10"],
                                        collector_name=collector_name,
                                        service=service_host_name,
                                        ipv4_network=ipv4_network,
                                        ex_message=None)
            self._test_check_constraint(session,
                                        os_command=["sleep", "10"],
                                        collector_name=collector_name,
                                        host=host,
                                        ipv4_network=ipv4_network,
                                        ex_message=None)
            self._test_check_constraint(session,
                                        os_command=["sleep", "10"],
                                        collector_name=collector_name,
                                        host_name=host_name,
                                        ipv4_network=ipv4_network,
                                        ex_message=None)

    def test_success(self):
        self.init_db()
        with self._engine.session_scope() as session:
            host_name = self.create_hostname(session, workspace_str=self._workspaces[0])
            service_host = self.create_service(session, workspace_str=self._workspaces[0])
            service_host_name = self.create_service(session,
                                                    workspace_str=self._workspaces[0],
                                                    host_name_str="www.test.com")
            host = self.create_host(session, workspace_str=self._workspaces[0])
            ipv4_network = self.create_network(session, workspace_str=self._workspaces[0])
            collector_name = self.create_collector_name(session)
            result = self._test_success(session,
                                        os_command=["sleep", "10"],
                                        collector_name=collector_name,
                                        service=service_host)
            self.assertIsNotNone(service_host.host_id)
            self.assertIsNotNone(service_host.host)
            self.assertEqual(service_host.host_id, result.host_id)
            self.assertEqual(service_host.id, result.id)
            result = self._test_success(session,
                                        os_command=["sleep", "10"],
                                        collector_name=collector_name,
                                        service=service_host_name)
            self.assertIsNotNone(service_host_name.host_name_id)
            self.assertIsNotNone(service_host_name.host_name)
            self.assertEqual(service_host_name.host_name_id, result.host_name.id)
            self.assertEqual(service_host_name.id, result.id)
            self._test_success(session,
                               os_command=["sleep", "11"],
                               collector_name=collector_name,
                               host=host)
            self._test_success(session,
                               os_command=["sleep", "11"],
                               collector_name=collector_name,
                               host_name=host_name)
            self._test_success(session,
                               os_command=["sleep", "10"],
                               collector_name=collector_name,
                               ipv4_network=ipv4_network)


class TestCredentials(BaseDataModelTestCase):
    """
    Test data model for credentials
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, model=Credentials)

    def test_unique_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            email = self.create_email(session, workspace_str=self._workspaces[0])
            service = self.create_service(session, workspace_str=self._workspaces[0])
            self._test_unique_constraint(session,
                                         username="username",
                                         password="password",
                                         domain="domain",
                                         type=CredentialType.Cleartext,
                                         service=service)
            self._test_unique_constraint(session,
                                         username="username",
                                         password="password",
                                         type=CredentialType.Cleartext,
                                         service=service)
            self._test_unique_constraint(session,
                                         username="username",
                                         password="password",
                                         domain="domain",
                                         type=CredentialType.Cleartext,
                                         email=email)
            self._test_unique_constraint(session,
                                         username="username",
                                         password="password",
                                         type=CredentialType.Cleartext,
                                         email=email)

    def test_not_null_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            pass

    def test_check_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            email = self.create_email(session, workspace_str=self._workspaces[0])
            service = self.create_service(session, workspace_str=self._workspaces[0])
            self._test_check_constraint(session)
            self._test_check_constraint(session,
                                        username="username",
                                        password="password",
                                        domain="domain",
                                        type=CredentialType.Cleartext)
            self._test_check_constraint(session,
                                        username="username",
                                        password="password",
                                        domain="domain",
                                        type=CredentialType.Cleartext,
                                        email=email,
                                        service=service)

    def test_success(self):
        self.init_db()
        with self._engine.session_scope() as session:
            email = self.create_email(session, workspace_str=self._workspaces[0])
            service = self.create_service(session, workspace_str=self._workspaces[0])
            self._test_success(session,
                               username="username",
                               service=service)
            self._test_success(session,
                               password="password",
                               type=CredentialType.Cleartext,
                               service=service)
            self._test_success(session,
                               username="username",
                               password="password",
                               type=CredentialType.Cleartext,
                               service=service)
            self._test_success(session,
                               username="username",
                               email=email)
            self._test_success(session,
                               password="password",
                               type=CredentialType.Cleartext,
                               email=email)
            self._test_success(session,
                               username="username",
                               password="password",
                               type=CredentialType.Cleartext,
                               email=email)


class TestPath(BaseDataModelTestCase):
    """
    Test data model for path
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, Path)

    def test_unique_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            service = self.create_service(session)
            self._test_unique_constraint(session, name="/tmp", type=PathType.Http, service=service)

    def test_not_null_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            service = self.create_service(session)
            self._test_not_null_constraint(session)
            self._test_not_null_constraint(session, name="/tmp")
            self._test_not_null_constraint(session, name="/tmp", type=PathType.Http)
            self._test_not_null_constraint(session, name="/tmp", service=service)
            self._test_not_null_constraint(session, type=PathType.Http, service=service)

    def test_check_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            pass

    def test_success(self):
        self.init_db()
        with self._engine.session_scope() as session:
            service = self.create_service(session)
            self._test_success(session, name="/tmp", type=PathType.Http, service=service)


class TestFile(BaseDataModelTestCase):
    """
    Test data model for file
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, File)

    def test_unique_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = self.create_workspace(session)
            self._test_unique_constraint(session,
                                         content=b"test",
                                         sha256_value="sha256_value",
                                         type=FileType.screenshot,
                                         workspace=workspace)

    def test_not_null_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = self.create_workspace(session)
            self._test_not_null_constraint(session)
            self._test_not_null_constraint(session,
                                           sha256_value="sha256_value",
                                           type=FileType.screenshot,
                                           workspace=workspace)
            self._test_not_null_constraint(session,
                                           content=b"test",
                                           type=FileType.screenshot,
                                           workspace=workspace)
            self._test_not_null_constraint(session,
                                           content=b"test",
                                           sha256_value="sha256_value",
                                           workspace=workspace)
            self._test_not_null_constraint(session,
                                           content=b"test",
                                           sha256_value="sha256_value",
                                           type=FileType.screenshot)

    def test_check_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            pass

    def test_success(self):
        self.init_db()
        with self._engine.session_scope() as session:
            with self._engine.session_scope() as session:
                workspace = self.create_workspace(session)
                self._test_success(session,
                                   content=b"test",
                                   sha256_value="sha256_value",
                                   type=FileType.screenshot,
                                   workspace=workspace)


class TestCompany(BaseDataModelTestCase):
    """
    Test data model for company
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, Company)

    def test_unique_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = self.create_workspace(session=session, workspace=self._workspaces[0])
            self._test_unique_constraint(session, name="test ag", workspace=workspace)

    def test_not_null_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = self.create_workspace(session=session, workspace=self._workspaces[0])
            self._test_not_null_constraint(session)
            self._test_not_null_constraint(session, name="test ag")
            self._test_not_null_constraint(session, workspace=workspace)

    def test_success(self):
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = self.create_workspace(session=session, workspace=self._workspaces[0])
            self._test_success(session, name="test ag", workspace=workspace)

    def test_set_domain_in_scope(self):
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_hostname(session=session,
                                 workspace_str="unittest",
                                 host_name="www.test.com",
                                 scope=ScopeType.all)
            self.create_email(session=session,
                              workspace_str="unittest",
                              email_address="test@test.com",
                              scope=ScopeType.exclude)
        with self._engine.session_scope() as session:
            domain = session.query(DomainName).all()
            self.assertEqual(1, len(domain))
            self.assertTrue(domain[0].in_scope)


class TestHostHostNameMapping(BaseDataModelTestCase):
    """
    Test data model for HostHostNameMapping
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, HostHostNameMapping)

    def test_unique_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            host_name = self.create_hostname(session=session, workspace_str=self._workspaces[0])
            host = self.create_host(session=session, workspace_str=self._workspaces[0])
            self._test_unique_constraint(session, host=host, host_name=host_name)
            self._test_unique_constraint(session, host=host, host_name=host_name)

    def test_not_null_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            host_name = self.create_hostname(session=session, workspace_str=self._workspaces[0])
            host = self.create_host(session=session, workspace_str=self._workspaces[0])
            self._test_not_null_constraint(session)
            self._test_not_null_constraint(session, host=host)
            self._test_not_null_constraint(session, host_name=host_name)

    def test_check_constraint(self):
        pass

    def test_success(self):
        self.init_db()
        with self._engine.session_scope() as session:
            host_name = self.create_hostname(session=session, workspace_str=self._workspaces[0])
            host = self.create_host(session=session, workspace_str=self._workspaces[0])
            self._test_success(session, host=host, host_name=host_name)


class TestHostNameHostNameMapping(BaseDataModelTestCase):
    """
    Test data model for HostNameHostNameMapping
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, HostNameHostNameMapping)

    def test_unique_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            source_host_name = self.create_hostname(session=session,
                                                    workspace_str=self._workspaces[0],
                                                    host_name="www.unittest1.com")
            resolved_host_name = self.create_hostname(session=session,
                                                      workspace_str=self._workspaces[0],
                                                      host_name="www.unittest2.com")
            self._test_unique_constraint(session,
                                         source_host_name=source_host_name,
                                         resolved_host_name=resolved_host_name)
            self._test_unique_constraint(session,
                                         source_host_name=source_host_name,
                                         resolved_host_name=resolved_host_name)

    def test_not_null_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            source_host_name = self.create_hostname(session=session,
                                                    workspace_str=self._workspaces[0],
                                                    host_name="www.unittest1.com")
            self._test_not_null_constraint(session)
            self._test_not_null_constraint(session,
                                           source_host_name=source_host_name)
            self._test_not_null_constraint(session,
                                           resolved_host_name=source_host_name)

    def test_check_constraint(self):
        pass

    def test_success(self):
        self.init_db()
        with self._engine.session_scope() as session:
            source_host_name = self.create_hostname(session=session,
                                                    workspace_str=self._workspaces[0],
                                                    host_name="www.unittest1.com")
            resolved_host_name = self.create_hostname(session=session,
                                                      workspace_str=self._workspaces[0],
                                                      host_name="www.unittest2.com")
            self._test_success(session, source_host_name=source_host_name, resolved_host_name=resolved_host_name)


class TestCipherSuite(BaseDataModelTestCase):
    """
    Test data model for CipherSuite
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, CipherSuite)

    def test_unique_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            self._test_unique_constraint(session,
                                         iana_name='TLS_ECDH_anon_WITH_RC4_128_SHA',
                                         openssl_name='AECDH-RC4-SHA',
                                         gnutls_name='test',
                                         byte_1=1,
                                         byte_2=2,
                                         protocol_version=CipherSuiteProtocolVersion.tls,
                                         security=CipherSuiteSecurity.insecure,
                                         enc_algorithm=SymmetricAlgorithm.aes128,
                                         hash_algorithm=HashAlgorithm.md5)

    def test_not_null_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            self._test_not_null_constraint(session,
                                           openssl_name='AECDH-RC4-SHA',
                                           gnutls_name='test',
                                           byte_1=1,
                                           byte_2=2,
                                           protocol_version=CipherSuiteProtocolVersion.tls,
                                           security=CipherSuiteSecurity.insecure,
                                           enc_algorithm=SymmetricAlgorithm.aes128,
                                           hash_algorithm=HashAlgorithm.md5)
            self._test_not_null_constraint(session,
                                           iana_name='TLS_ECDH_anon_WITH_RC4_128_SHA',
                                           openssl_name='AECDH-RC4-SHA',
                                           gnutls_name='test',
                                           byte_2=2,
                                           protocol_version=CipherSuiteProtocolVersion.tls,
                                           security=CipherSuiteSecurity.insecure,
                                           enc_algorithm=SymmetricAlgorithm.aes128,
                                           hash_algorithm=HashAlgorithm.md5)
            self._test_not_null_constraint(session,
                                           iana_name='TLS_ECDH_anon_WITH_RC4_128_SHA',
                                           openssl_name='AECDH-RC4-SHA',
                                           gnutls_name='test',
                                           byte_1=1,
                                           protocol_version=CipherSuiteProtocolVersion.tls,
                                           security=CipherSuiteSecurity.insecure,
                                           enc_algorithm=SymmetricAlgorithm.aes128,
                                           hash_algorithm=HashAlgorithm.md5)
            self._test_not_null_constraint(session,
                                           iana_name='TLS_ECDH_anon_WITH_RC4_128_SHA',
                                           openssl_name='AECDH-RC4-SHA',
                                           gnutls_name='test',
                                           byte_1=1,
                                           byte_2=2,
                                           security=CipherSuiteSecurity.insecure,
                                           enc_algorithm=SymmetricAlgorithm.aes128,
                                           hash_algorithm=HashAlgorithm.md5)
            self._test_not_null_constraint(session,
                                           iana_name='TLS_ECDH_anon_WITH_RC4_128_SHA',
                                           openssl_name='AECDH-RC4-SHA',
                                           gnutls_name='test',
                                           byte_1=1,
                                           byte_2=2,
                                           protocol_version=CipherSuiteProtocolVersion.tls,
                                           enc_algorithm=SymmetricAlgorithm.aes128,
                                           hash_algorithm=HashAlgorithm.md5)
            self._test_not_null_constraint(session,
                                           iana_name='TLS_ECDH_anon_WITH_RC4_128_SHA',
                                           openssl_name='AECDH-RC4-SHA',
                                           gnutls_name='test',
                                           byte_1=1,
                                           byte_2=2,
                                           protocol_version=CipherSuiteProtocolVersion.tls,
                                           security=CipherSuiteSecurity.insecure,
                                           hash_algorithm=HashAlgorithm.md5)
            self._test_not_null_constraint(session,
                                           iana_name='TLS_ECDH_anon_WITH_RC4_128_SHA',
                                           openssl_name='AECDH-RC4-SHA',
                                           gnutls_name='test',
                                           byte_1=1,
                                           byte_2=2,
                                           protocol_version=CipherSuiteProtocolVersion.tls,
                                           security=CipherSuiteSecurity.insecure,
                                           enc_algorithm=SymmetricAlgorithm.aes128)

    def test_check_constraint(self):
        pass

    def test_success(self):
        self.init_db()
        with self._engine.session_scope() as session:
            self._test_success(session,
                               iana_name='TLS_ECDH_anon_WITH_RC4_128_SHA',
                               openssl_name='AECDH-RC4-SHA',
                               gnutls_name='test',
                               byte_1=1,
                               byte_2=2,
                               protocol_version=CipherSuiteProtocolVersion.tls,
                               security=CipherSuiteSecurity.insecure,
                               enc_algorithm=SymmetricAlgorithm.aes128,
                               hash_algorithm=HashAlgorithm.md5)


class TestTlsInfo(BaseDataModelTestCase):
    """
    Test data model for CipherSuite
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, TlsInfo)

    def test_unique_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            service = self.create_service(session=session)
            self._test_unique_constraint(session,
                                         version=TlsVersion.tls13,
                                         service=service,
                                         compressors=[],
                                         preference=TlsPreference.client)

    def test_not_null_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            service = self.create_service(session=session)
            self._test_not_null_constraint(session,
                                           service=service)
            self._test_not_null_constraint(session,
                                           version=TlsVersion.tls13)

    def test_check_constraint(self):
        pass

    def test_success(self):
        self.init_db()
        with self._engine.session_scope() as session:
            service = self.create_service(session=session)
            self._test_success(session,
                               version=TlsVersion.tls13,
                               service=service,
                               compressors=[],
                               preference=TlsPreference.client)


class TestCertInfo(BaseDataModelTestCase):
    """
    Test data model for CipherSuite
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, CertInfo)

    def test_unique_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            service = self.create_service(session=session)
            company = self.create_company(session=session)
            host_name = self.create_hostname(session=session)
            self._test_unique_constraint(session,
                                         service=service,
                                         serial_number=1,
                                         common_name="www.test.com",
                                         issuer_name="www.test.com",
                                         signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                         signature_bits=2048,
                                         hash_algorithm=HashAlgorithm.sha1,
                                         cert_type=CertType.root,
                                         valid_from=datetime.now(),
                                         valid_until=datetime.now(),
                                         extension_info={})
            self._test_unique_constraint(session,
                                         company=company,
                                         serial_number=1,
                                         common_name="www.test.com",
                                         issuer_name="www.test.com",
                                         signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                         signature_bits=2048,
                                         hash_algorithm=HashAlgorithm.sha1,
                                         cert_type=CertType.root,
                                         valid_from=datetime.now(),
                                         valid_until=datetime.now(),
                                         extension_info={})
            self._test_unique_constraint(session,
                                         host_name=host_name,
                                         serial_number=1,
                                         common_name="www.test.com",
                                         issuer_name="www.test.com",
                                         signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                         signature_bits=2048,
                                         hash_algorithm=HashAlgorithm.sha1,
                                         cert_type=CertType.root,
                                         valid_from=datetime.now(),
                                         valid_until=datetime.now(),
                                         extension_info={})

    def test_not_null_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            service = self.create_service(session=session)
            company = self.create_company(session=session)
            host_name = self.create_hostname(session=session)
            self._test_not_null_constraint(session,
                                           service=service,
                                           common_name="www.test.com",
                                           issuer_name="www.test.com",
                                           signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                           signature_bits=2048,
                                           hash_algorithm=HashAlgorithm.sha1,
                                           cert_type=CertType.root,
                                           valid_from=datetime.now(),
                                           valid_until=datetime.now(),
                                           extension_info={})
            self._test_not_null_constraint(session,
                                           company=company,
                                           common_name="www.test.com",
                                           issuer_name="www.test.com",
                                           signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                           signature_bits=2048,
                                           hash_algorithm=HashAlgorithm.sha1,
                                           cert_type=CertType.root,
                                           valid_from=datetime.now(),
                                           valid_until=datetime.now(),
                                           extension_info={})
            self._test_not_null_constraint(session,
                                           host_name=host_name,
                                           common_name="www.test.com",
                                           issuer_name="www.test.com",
                                           signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                           signature_bits=2048,
                                           hash_algorithm=HashAlgorithm.sha1,
                                           cert_type=CertType.root,
                                           valid_from=datetime.now(),
                                           valid_until=datetime.now(),
                                           extension_info={})
            self._test_not_null_constraint(session,
                                           service=service,
                                           serial_number=1,
                                           issuer_name="www.test.com",
                                           signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                           signature_bits=2048,
                                           hash_algorithm=HashAlgorithm.sha1,
                                           cert_type=CertType.root,
                                           valid_from=datetime.now(),
                                           valid_until=datetime.now(),
                                           extension_info={})
            self._test_not_null_constraint(session,
                                           service=service,
                                           serial_number=1,
                                           common_name="www.test.com",
                                           signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                           signature_bits=2048,
                                           hash_algorithm=HashAlgorithm.sha1,
                                           cert_type=CertType.root,
                                           valid_from=datetime.now(),
                                           valid_until=datetime.now(),
                                           extension_info={})
            self._test_not_null_constraint(session,
                                           service=service,
                                           serial_number=1,
                                           common_name="www.test.com",
                                           issuer_name="www.test.com",
                                           signature_bits=2048,
                                           hash_algorithm=HashAlgorithm.sha1,
                                           cert_type=CertType.root,
                                           valid_from=datetime.now(),
                                           valid_until=datetime.now(),
                                           extension_info={})
            self._test_not_null_constraint(session,
                                           service=service,
                                           serial_number=1,
                                           common_name="www.test.com",
                                           signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                           hash_algorithm=HashAlgorithm.sha1,
                                           cert_type=CertType.root,
                                           valid_from=datetime.now(),
                                           valid_until=datetime.now(),
                                           extension_info={})
            self._test_not_null_constraint(session,
                                           service=service,
                                           serial_number=1,
                                           common_name="www.test.com",
                                           issuer_name="www.test.com",
                                           signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                           signature_bits=2048,
                                           cert_type=CertType.root,
                                           valid_from=datetime.now(),
                                           valid_until=datetime.now(),
                                           extension_info={})
            self._test_not_null_constraint(session,
                                           service=service,
                                           serial_number=1,
                                           common_name="www.test.com",
                                           issuer_name="www.test.com",
                                           signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                           signature_bits=2048,
                                           hash_algorithm=HashAlgorithm.sha1,
                                           valid_from=datetime.now(),
                                           valid_until=datetime.now(),
                                           extension_info={})
            self._test_not_null_constraint(session,
                                           service=service,
                                           serial_number=1,
                                           common_name="www.test.com",
                                           issuer_name="www.test.com",
                                           signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                           signature_bits=2048,
                                           hash_algorithm=HashAlgorithm.sha1,
                                           cert_type=CertType.root,
                                           valid_until=datetime.now(),
                                           extension_info={})
            self._test_not_null_constraint(session,
                                           service=service,
                                           serial_number=1,
                                           common_name="www.test.com",
                                           issuer_name="www.test.com",
                                           signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                           signature_bits=2048,
                                           hash_algorithm=HashAlgorithm.sha1,
                                           cert_type=CertType.root,
                                           valid_from=datetime.now(),
                                           extension_info={})

    def test_check_constraint(self):

        self.init_db()
        with self._engine.session_scope() as session:
            service = self.create_service(session=session)
            company = self.create_company(session=session)
            host_name = self.create_hostname(session=session)
            self._test_check_constraint(session,
                                        serial_number=1,
                                        common_name="www.test.com",
                                        issuer_name="www.test.com",
                                        signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                        signature_bits=2048,
                                        hash_algorithm=HashAlgorithm.sha1,
                                        cert_type=CertType.root,
                                        valid_from=datetime.now(),
                                        valid_until=datetime.now(),
                                        extension_info={})
            self._test_check_constraint(session,
                                        service=service,
                                        company=company,
                                        serial_number=1,
                                        common_name="www.test.com",
                                        issuer_name="www.test.com",
                                        signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                        signature_bits=2048,
                                        hash_algorithm=HashAlgorithm.sha1,
                                        cert_type=CertType.root,
                                        valid_from=datetime.now(),
                                        valid_until=datetime.now(),
                                        extension_info={})
            self._test_check_constraint(session,
                                        service=service,
                                        host_name=host_name,
                                        serial_number=1,
                                        common_name="www.test.com",
                                        issuer_name="www.test.com",
                                        signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                        signature_bits=2048,
                                        hash_algorithm=HashAlgorithm.sha1,
                                        cert_type=CertType.root,
                                        valid_from=datetime.now(),
                                        valid_until=datetime.now(),
                                        extension_info={})
            self._test_check_constraint(session,
                                        host_name=host_name,
                                        company=company,
                                        serial_number=1,
                                        common_name="www.test.com",
                                        issuer_name="www.test.com",
                                        signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                        signature_bits=2048,
                                        hash_algorithm=HashAlgorithm.sha1,
                                        cert_type=CertType.root,
                                        valid_from=datetime.now(),
                                        valid_until=datetime.now(),
                                        extension_info={})
            self._test_check_constraint(session,
                                        service=service,
                                        host_name=host_name,
                                        company=company,
                                        serial_number=1,
                                        common_name="www.test.com",
                                        issuer_name="www.test.com",
                                        signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                        signature_bits=2048,
                                        hash_algorithm=HashAlgorithm.sha1,
                                        cert_type=CertType.root,
                                        valid_from=datetime.now(),
                                        valid_until=datetime.now(),
                                        extension_info={})

    def test_success(self):
        self.init_db()
        with self._engine.session_scope() as session:
            service = self.create_service(session=session)
            company = self.create_company(session=session)
            host_name = self.create_hostname(session=session)
            self._test_success(session,
                               service=service,
                               serial_number=1,
                               common_name="www.test.com",
                               issuer_name="www.test.com",
                               signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                               signature_bits=2048,
                               hash_algorithm=HashAlgorithm.sha1,
                               cert_type=CertType.root,
                               valid_from=datetime.now(),
                               valid_until=datetime.now(),
                               extension_info={})
            self._test_success(session,
                               company=company,
                               serial_number=1,
                               common_name="www.test.com",
                               issuer_name="www.test.com",
                               signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                               signature_bits=2048,
                               hash_algorithm=HashAlgorithm.sha1,
                               cert_type=CertType.root,
                               valid_from=datetime.now(),
                               valid_until=datetime.now(),
                               extension_info={})
            self._test_success(session,
                               host_name=host_name,
                               serial_number=1,
                               common_name="www.test.com",
                               issuer_name="www.test.com",
                               signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                               signature_bits=2048,
                               hash_algorithm=HashAlgorithm.sha1,
                               cert_type=CertType.root,
                               valid_from=datetime.now(),
                               valid_until=datetime.now(),
                               extension_info={})


class TestTlsInfoCipherSuiteMapping(BaseDataModelTestCase):
    """
    Test data model for TlsInfoCipherSuiteMapping
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, TlsInfoCipherSuiteMapping)

    def test_unique_constraint(self):
        self.init_db(load_cipher_suites=True)
        with self._engine.session_scope() as session:
            tls_info = self.create_tls_info(session=session)
            cipher_suite = self.query_cipher_suite(session=session)
            self._test_unique_constraint(session=session,
                                         tls_info=tls_info,
                                         cipher_suite=cipher_suite,
                                         order=1,
                                         prefered=False,
                                         kex_algorithm_details=KeyExchangeAlgorithm.ecdh_x25519)

    def test_not_null_constraint(self):
        self.init_db(load_cipher_suites=True)
        with self._engine.session_scope() as session:
            tls_info = self.create_tls_info(session=session)
            cipher_suite = self.query_cipher_suite(session=session)
            self._test_not_null_constraint(session=session,
                                           cipher_suite=cipher_suite,
                                           order=1,
                                           prefered=False,
                                           kex_algorithm_details=KeyExchangeAlgorithm.ecdh_x25519)
            self._test_not_null_constraint(session=session,
                                           tls_info=tls_info,
                                           order=1,
                                           prefered=False,
                                           kex_algorithm_details=KeyExchangeAlgorithm.ecdh_x25519)
            self._test_not_null_constraint(session=session,
                                           tls_info=tls_info,
                                           cipher_suite=cipher_suite,
                                           prefered=False,
                                           kex_algorithm_details=KeyExchangeAlgorithm.ecdh_x25519)
            self._test_not_null_constraint(session=session,
                                           tls_info=tls_info,
                                           cipher_suite=cipher_suite,
                                           order=1,
                                           kex_algorithm_details=KeyExchangeAlgorithm.ecdh_x25519)
            self._test_not_null_constraint(session=session,
                                           tls_info=tls_info,
                                           cipher_suite=cipher_suite,
                                           order=1,
                                           kex_algorithm_details=KeyExchangeAlgorithm.ecdh_x25519)
            self._test_not_null_constraint(session=session,
                                           tls_info=tls_info,
                                           cipher_suite=cipher_suite,
                                           order=1,
                                           prefered=False)
            self._test_not_null_constraint(session=session,
                                           tls_info=tls_info,
                                           cipher_suite=cipher_suite,
                                           order=1,
                                           kex_algorithm_details=KeyExchangeAlgorithm.ecdh_x25519)

    def test_check_constraint(self):
        pass

    def test_success(self):
        self.init_db(load_cipher_suites=True)
        with self._engine.session_scope() as session:
            tls_info = self.create_tls_info(session=session)
            cipher_suite = self.query_cipher_suite(session=session)
            self._test_success(session=session,
                               tls_info=tls_info,
                               cipher_suite=cipher_suite,
                               order=1,
                               prefered=False,
                               kex_algorithm_details=KeyExchangeAlgorithm.ecdh_x25519)


class HostScopingTestCases(BaseKisTestCase):
    """
    This class implements functionalities for testing the host scope
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def _check_data(self, workspace_str: str, ipv4_address: str, ipv4_network: str, in_scope: bool):
        with self._engine.session_scope() as session:
            result = session.query(Host).join(Workspace) \
                .filter(Host.address == ipv4_address, Workspace.name == workspace_str).one()
            self.assertEqual(ipv4_network, result.ipv4_network.network)
            self.assertEqual(in_scope, result.in_scope)

    def test_network_scope(self):
        self.init_db()
        # set up database
        i = 0
        with self._engine.session_scope() as session:
            for workspace_str in self._workspaces:
                scope = ScopeType.all if (i % 2) == 0 else ScopeType.exclude
                i = i + 1
                workspace = self._domain_utils.add_workspace(session, workspace_str)
                self._ip_utils.add_host(session=session,
                                        workspace=workspace,
                                        address="10.10.0.1",
                                        in_scope=scope == ScopeType.exclude)
                self._ip_utils.add_network(session=session,
                                           workspace=workspace,
                                           network="10.10.0.0/16",
                                           scope=scope)
        # check database setup
        with self._engine.session_scope() as session:
            session.query(Host).join(Network).filter(Host._in_scope,
                                                     Network.scope == ScopeType.all).one()
            session.query(Host).join(Network).filter(Host._in_scope == False,
                                                     Network.scope == ScopeType.exclude).one()
        # lets add a larger network, which is out of scope (this can happen with whois)
        # in this case all sub-networks which are in-scope remain in scope
        with self._engine.session_scope() as session:
            workspace = self._domain_utils.add_workspace(session, self._workspaces[0])
            self._ip_utils.add_network(session=session,
                                       workspace=workspace,
                                       network="10.0.0.0/8",
                                       scope=ScopeType.exclude)
        # check database setup
        with self._engine.session_scope() as session:
            session.query(Host).join(Network).filter(Host._in_scope,
                                                     Network.network == "10.10.0.0/16",
                                                     Network.scope == ScopeType.all).one()
        # lets add a smaller network, which is out of scope but the larger network is in scope
        # in this case, the smaller out of scope network is automatically set in scope by DB trigger and the host must
        # be re-assigned to the smallest network in the database
        with self._engine.session_scope() as session:
            workspace = self._domain_utils.add_workspace(session, self._workspaces[0])
            self._ip_utils.add_network(session=session,
                                       workspace=workspace,
                                       network="10.10.0.0/24",
                                       scope=ScopeType.exclude)
        # check database setup
        with self._engine.session_scope() as session:
            session.query(Host).join(Network).filter(Host._in_scope,
                                                     Network.network == "10.10.0.0/24",
                                                     Network.scope == ScopeType.all).one()

    def test_host_scope_strict(self):
        """
        check trigger: if network's scope is set to strict, then host scope is set to false
        """
        ipv4_address = "192.168.1.1"
        ipv4_network = "192.168.1.0/24"
        # set up database
        self.init_db()
        for workspace in self._workspaces:
            with self._engine.session_scope() as session:
                self.create_host(session=session,
                                 workspace_str=workspace,
                                 address=ipv4_address,
                                 in_scope=True)
            with self._engine.session_scope() as session:
                self.create_network(session=session,
                                    workspace_str=workspace,
                                    network=ipv4_network,
                                    scope=ScopeType.strict)
        # check database
        for workspace in self._workspaces:
            self._check_data(workspace_str=workspace,
                             ipv4_address=ipv4_address,
                             ipv4_network=ipv4_network,
                             in_scope=False)
        # update host
        with self._engine.session_scope() as session:
            result = session.query(Host).join(Workspace) \
                .filter(Host.address == ipv4_address, Workspace.name == self._workspaces[0]).one()
            result.in_scope = True
        # check database
        for workspace in self._workspaces:
            self._check_data(workspace_str=workspace,
                             ipv4_address=ipv4_address,
                             ipv4_network=ipv4_network,
                             in_scope=workspace == self._workspaces[0])
        # update network to scope all
        with self._engine.session_scope() as session:
            for workspace in self._workspaces:
                result = session.query(Network) \
                    .join(Workspace) \
                    .filter(Network.network == ipv4_network, Workspace.name == workspace).one()
                result.scope = ScopeType.all
        # check database
        for workspace in self._workspaces:
            self._check_data(workspace_str=workspace,
                             ipv4_address=ipv4_address,
                             ipv4_network=ipv4_network,
                             in_scope=True)
        # update network to scope exclude
        with self._engine.session_scope() as session:
            for workspace in self._workspaces:
                result = session.query(Network) \
                    .join(Workspace) \
                    .filter(Network.network == ipv4_network, Workspace.name == workspace).one()
                result.scope = ScopeType.exclude
        # check database
        for workspace in self._workspaces:
            self._check_data(workspace_str=workspace,
                             ipv4_address=ipv4_address,
                             ipv4_network=ipv4_network,
                             in_scope=False)

    def test_host_scope_all(self):
        """
        check trigger: if network's scope is set to all, then host scope is set to true
        """
        # set up database
        self.init_db()
        ipv4_address = "192.168.1.1"
        ipv4_network = "192.168.1.0/24"
        for workspace in self._workspaces:
            with self._engine.session_scope() as session:
                self.create_host(session=session,
                                 workspace_str=workspace,
                                 address=ipv4_address,
                                 in_scope=False)
            with self._engine.session_scope() as session:
                self.create_network(session=session,
                                    workspace_str=workspace,
                                    network=ipv4_network,
                                    scope=ScopeType.all)
            with self._engine.session_scope() as session:
                self.create_host(session=session,
                                 workspace_str=workspace,
                                 address="192.168.1.2",
                                 in_scope=False)
        # check database
        for workspace in self._workspaces:
            self._check_data(workspace_str=workspace,
                             ipv4_address=ipv4_address,
                             ipv4_network=ipv4_network,
                             in_scope=True)
            self._check_data(workspace_str=workspace,
                             ipv4_address="192.168.1.2",
                             ipv4_network=ipv4_network,
                             in_scope=True)
        # update host
        with self._engine.session_scope() as session:
            result = session.query(Host).join(Workspace) \
                .filter(Host.address == ipv4_address, Workspace.name == self._workspaces[0]).one()
            result.in_scope = False
        # check database
        for workspace in self._workspaces:
            self._check_data(workspace_str=workspace,
                             ipv4_address=ipv4_address,
                             ipv4_network=ipv4_network,
                             in_scope=True)
        # update network to scope strict
        with self._engine.session_scope() as session:
            for workspace in self._workspaces:
                result = session.query(Network) \
                    .join(Workspace) \
                    .filter(Network.network == ipv4_network, Workspace.name == workspace).one()
                result.scope = ScopeType.strict
        # check database
        for workspace in self._workspaces:
            self._check_data(workspace_str=workspace,
                             ipv4_address=ipv4_address,
                             ipv4_network=ipv4_network,
                             in_scope=False)

    def test_network_assignment(self):
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = self._domain_utils.add_workspace(session, self._workspaces[0])
            self._ip_utils.add_host(session=session,
                                    workspace=workspace,
                                    address="10.10.0.1")
            network_id = self._ip_utils.add_network(session=session,
                                                    workspace=workspace,
                                                    network="10.10.0.1",
                                                    scope=ScopeType.all).id
        with self._engine.session_scope() as session:
            host = session.query(Host).filter_by(address="10.10.0.1").one()
            self.assertIsNotNone(host.ipv4_network_id)
            host_network_id = host.ipv4_network_id
            self.assertEquals(network_id, host_network_id)
        with self._engine.session_scope() as session:
            workspace = self._domain_utils.add_workspace(session, self._workspaces[0])
            self._ip_utils.add_network(session=session,
                                       workspace=workspace,
                                       network="10.10.0.0/29",
                                       scope=ScopeType.all)
        with self._engine.session_scope() as session:
            host = session.query(Host).filter_by(address="10.10.0.1").one()
            self.assertIsNotNone(host.ipv4_network_id)
            host_network_id = host.ipv4_network_id
            self.assertEquals(network_id, host_network_id)

    def test_network_assignment2(self):
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = self._domain_utils.add_workspace(session, self._workspaces[0])
            self._ip_utils.add_host(session=session,
                                    workspace=workspace,
                                    address="10.10.0.1")
            network_id = self._ip_utils.add_network(session=session,
                                                    workspace=workspace,
                                                    network="10.10.0.1",
                                                    scope=ScopeType.all).id
            self._ip_utils.add_network(session=session,
                                       workspace=workspace,
                                       network="10.10.0.0/29",
                                       scope=ScopeType.all)
        with self._engine.session_scope() as session:
            host = session.query(Host).filter_by(address="10.10.0.1").one()
            self.assertIsNotNone(host.ipv4_network_id)
            host_network_id = host.ipv4_network_id
            self.assertEquals(network_id, host_network_id)

    def test_network_assignment3(self):
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = self._domain_utils.add_workspace(session, self._workspaces[0])
            self._ip_utils.add_host(session=session,
                                    workspace=workspace,
                                    address="10.10.0.1")
            network_id = self._ip_utils.add_network(session=session,
                                                    workspace=workspace,
                                                    network="10.10.0.0/29",
                                                    scope=ScopeType.all).id
        with self._engine.session_scope() as session:
            host = session.query(Host).filter_by(address="10.10.0.1").one()
            self.assertIsNotNone(host.ipv4_network_id)
            host_network_id = host.ipv4_network_id
            self.assertEquals(network_id, host_network_id)
        with self._engine.session_scope() as session:
            workspace = self._domain_utils.add_workspace(session, self._workspaces[0])
            network_id = self._ip_utils.add_network(session=session,
                                                    workspace=workspace,
                                                    network="10.10.0.1",
                                                    scope=ScopeType.all).id
        with self._engine.session_scope() as session:
            host = session.query(Host).filter_by(address="10.10.0.1").one()
            self.assertIsNotNone(host.ipv4_network_id)
            host_network_id = host.ipv4_network_id
            self.assertEquals(network_id, host_network_id)
