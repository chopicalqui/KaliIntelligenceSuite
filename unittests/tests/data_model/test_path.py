#!/usr/bin/python3
"""
this file implements unittests for the data model
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

from view.core import ReportItem
from database.model import Path
from database.model import Host
from database.model import Source
from database.model import Service
from database.model import PathType
from database.model import Workspace
from database.model import ProtocolType
from unittests.tests.core import BaseKisTestCase
from unittests.tests.core import BaseDataModelTestCase
from sqlalchemy.orm.session import Session


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
            self._test_unique_constraint(session, name="/tmp", type=PathType.http, service=service)

    def test_not_null_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            service = self.create_service(session)
            self._test_not_null_constraint(session)
            self._test_not_null_constraint(session, name="/tmp")
            self._test_not_null_constraint(session, name="/tmp", type=PathType.http)
            self._test_not_null_constraint(session, name="/tmp", service=service)
            self._test_not_null_constraint(session, type=PathType.http, service=service)

    def test_check_constraint(self):
        pass

    def test_success(self):
        self.init_db()
        with self._engine.session_scope() as session:
            service = self.create_service(session)
            self._test_success(session, name="/tmp", type=PathType.http, service=service)


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


class TestPathCreationTrigger(BaseKisTestCase):
    """
    This test case tests trigger add_services_to_host_name, which among other things automatically adds a path entry
    for web application services.
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def test_create_based_on_tcp_port(self):
        """
        The trigger add_services_to_host_name automatically adds path "/" for services listening at TCP ports 80 and 443.
        """
        self.init_db()
        # Setup database
        with self._engine.session_scope() as session:
            self.create_service(session=session,
                                workspace_str="unittest",
                                address="192.168.1.1",
                                port=80,
                                protocol_type=ProtocolType.tcp)
            self.create_service(session=session,
                                workspace_str="unittest",
                                address="192.168.1.1",
                                port=443,
                                protocol_type=ProtocolType.tcp)
            self.create_service(session=session,
                                workspace_str="unittest",
                                address="192.168.1.1",
                                port=445,
                                protocol_type=ProtocolType.tcp)
        # Check database
        with self._engine.session_scope() as session:
            result = session.query(Path) \
                .join(Service) \
                .join(Host) \
                .filter(Host.address == "192.168.1.1").filter(Service.port == 80).one()
            self.assertEqual("/", result.name)
            result = session.query(Path) \
                .join(Service) \
                .join(Host) \
                .filter(Host.address == "192.168.1.1").filter(Service.port == 443).one()
            self.assertEqual("/", result.name)
            result = session.query(Path) \
                .join(Service) \
                .join(Host) \
                .filter(Host.address == "192.168.1.1").filter(Service.port == 445).one_or_none()
            self.assertIsNone(result)

    def test_create_based_on_udp_port(self):
        """
        The trigger add_services_to_host_name automatically adds path "/" for services listening at TCP ports 80 and 443.

        Therefore, the trigger should not create paths for UDP ports 80 and 443.
        """
        self.init_db()
        # Setup database
        with self._engine.session_scope() as session:
            self.create_service(session=session,
                                workspace_str="unittest",
                                address="192.168.1.1",
                                port=80,
                                protocol_type=ProtocolType.udp)
            self.create_service(session=session,
                                workspace_str="unittest",
                                address="192.168.1.1",
                                port=443,
                                protocol_type=ProtocolType.udp)
            self.create_service(session=session,
                                workspace_str="unittest",
                                address="192.168.1.1",
                                port=445,
                                protocol_type=ProtocolType.udp)
        # Check database
        with self._engine.session_scope() as session:
            result = session.query(Path).all()
            self.assertEqual(0, len(result))

    def test_create_based_on_tcp_nmap_service_name(self):
        """
        The trigger add_services_to_host_name automatically adds path "/" for TCP services based on the nmap_service_name.
        """
        self.init_db()
        # Setup database
        with self._engine.session_scope() as session:
            self.create_service(session=session,
                                workspace_str="unittest",
                                address="192.168.1.1",
                                port=8888,
                                protocol_type=ProtocolType.tcp,
                                nmap_service_name="ssl|http")
            self.create_service(session=session,
                                workspace_str="unittest",
                                address="192.168.1.1",
                                port=8889,
                                protocol_type=ProtocolType.tcp,
                                nmap_service_name="https-proxy")
            self.create_service(session=session,
                                workspace_str="unittest",
                                address="192.168.1.1",
                                port=445,
                                protocol_type=ProtocolType.tcp,
                                nmap_service_name="smb")
        # Check database
        with self._engine.session_scope() as session:
            result = session.query(Path) \
                .join(Service) \
                .join(Host) \
                .filter(Host.address == "192.168.1.1").filter(Service.port == 8888).one()
            self.assertEqual("/", result.name)
            result = session.query(Path) \
                .join(Service) \
                .join(Host) \
                .filter(Host.address == "192.168.1.1").filter(Service.port == 8889).one()
            self.assertEqual("/", result.name)
            result = session.query(Path) \
                .join(Service) \
                .join(Host) \
                .filter(Host.address == "192.168.1.1").filter(Service.port == 445).one_or_none()
            self.assertIsNone(result)

    def test_create_based_on_udp_nmap_service_name(self):
        """
        The trigger add_services_to_host_name automatically adds path "/" for TCP services based on the nmap_service_name.
        """
        self.init_db()
        # Setup database
        with self._engine.session_scope() as session:
            self.create_service(session=session,
                                workspace_str="unittest",
                                address="192.168.1.1",
                                port=8888,
                                protocol_type=ProtocolType.udp,
                                nmap_service_name="ssl|http")
            self.create_service(session=session,
                                workspace_str="unittest",
                                address="192.168.1.1",
                                port=8889,
                                protocol_type=ProtocolType.udp,
                                nmap_service_name="https-proxy")
            self.create_service(session=session,
                                workspace_str="unittest",
                                address="192.168.1.1",
                                port=445,
                                protocol_type=ProtocolType.udp,
                                nmap_service_name="smb")
        # Check database
        with self._engine.session_scope() as session:
            result = session.query(Path).all()
            self.assertEqual(0, len(result))

    def test_create_based_on_tcp_nessus_service_name(self):
        """
        The trigger add_services_to_host_name automatically adds path "/" for TCP services based on the nmap_service_name.
        """
        self.init_db()
        # Setup database
        with self._engine.session_scope() as session:
            self.create_service(session=session,
                                workspace_str="unittest",
                                address="192.168.1.1",
                                port=8888,
                                protocol_type=ProtocolType.tcp,
                                nessus_service_name="homepage")
            self.create_service(session=session,
                                workspace_str="unittest",
                                address="192.168.1.1",
                                port=8889,
                                protocol_type=ProtocolType.tcp,
                                nessus_service_name="greenbone-administrator")
            self.create_service(session=session,
                                workspace_str="unittest",
                                address="192.168.1.1",
                                port=445,
                                protocol_type=ProtocolType.tcp,
                                nessus_service_name="smb")
        # Check database
        with self._engine.session_scope() as session:
            result = session.query(Path) \
                .join(Service) \
                .join(Host) \
                .filter(Host.address == "192.168.1.1").filter(Service.port == 8888).one()
            self.assertEqual("/", result.name)
            result = session.query(Path) \
                .join(Service) \
                .join(Host) \
                .filter(Host.address == "192.168.1.1").filter(Service.port == 8889).one()
            self.assertEqual("/", result.name)
            result = session.query(Path) \
                .join(Service) \
                .join(Host) \
                .filter(Host.address == "192.168.1.1").filter(Service.port == 445).one_or_none()
            self.assertIsNone(result)

    def test_create_based_on_udp_nessus_service_name(self):
        """
        The trigger add_services_to_host_name automatically adds path "/" for TCP services based on the nmap_service_name.
        """
        self.init_db()
        # Setup database
        with self._engine.session_scope() as session:
            self.create_service(session=session,
                                workspace_str="unittest",
                                address="192.168.1.1",
                                port=8888,
                                protocol_type=ProtocolType.udp,
                                nessus_service_name="homepage")
            self.create_service(session=session,
                                workspace_str="unittest",
                                address="192.168.1.1",
                                port=8889,
                                protocol_type=ProtocolType.udp,
                                nessus_service_name="greenbone-administrator")
            self.create_service(session=session,
                                workspace_str="unittest",
                                address="192.168.1.1",
                                port=445,
                                protocol_type=ProtocolType.udp,
                                nessus_service_name="smb")
        # Check database
        with self._engine.session_scope() as session:
            result = session.query(Path).all()
            self.assertEqual(0, len(result))

    def test_manually_add_root_path(self):
        """
        This trigger tests the case when the trigger and the collector both add the HTTP root path.
        """
        self.init_db()
        # Setup database
        with self._engine.session_scope() as session:
            service = self.create_service(session=session,
                                          workspace_str="unittest",
                                          address="192.168.1.1",
                                          port=80,
                                          protocol_type=ProtocolType.tcp,
                                          nessus_service_name="http")
            self._domain_utils.add_path(session=session, service=service, path="/", path_type=PathType.http)
        # Check database
        with self._engine.session_scope() as session:
            result = session.query(Path).all()
            self.assertEqual(1, len(result))
