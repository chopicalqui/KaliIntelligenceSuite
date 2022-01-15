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

from database.model import Service
from database.model import ServiceMethod
from database.model import ServiceState
from database.model import ProtocolType
from unittests.tests.core import BaseDataModelTestCase


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
            self._test_check_constraint(session, ex_message="""null value in column "name" of relation "service_method" violates not-null constraint""")
            self._test_check_constraint(session,
                                        name="test",
                                        ex_message="""null value in column "service_id" of relation "service_method" violates not-null constraint""")
            self._test_check_constraint(session,
                                        service=service,
                                        ex_message='null value in column "name" of relation "service_method" violates not-null constraint')

    def test_success(self):
        self.init_db()
        with self._engine.session_scope() as session:
            service = self.create_service(session)
            self._test_success(session, name="unittest", service=service)

    def test_service_primary_key_update(self):
        self.init_db()
        # Setup database
        with self._engine.session_scope() as session:
            host = self.create_host(session=session)
            session.add(Service(host=host, port=80, protocol=ProtocolType.tcp, state=ServiceState.Open))
            session.add(Service(host=host, port=443, protocol=ProtocolType.tcp, state=ServiceState.Open))
            session.add(Service(host=host, port=8080, protocol=ProtocolType.tcp, state=ServiceState.Open))
        # Update port
        with self.assertRaises(Exception):
            with self._engine.session_scope() as session:
                service = session.query(Service).filter_by(port=80, protocol=ProtocolType.tcp).one()
                service.port = 161
        # Update protocol
        with self.assertRaises(Exception):
            with self._engine.session_scope() as session:
                service = session.query(Service).filter_by(port=80, protocol=ProtocolType.tcp).one()
                service.protocol = ProtocolType.udp
        # Update both
        with self.assertRaises(Exception):
            with self._engine.session_scope() as session:
                service = session.query(Service).filter_by(port=80, protocol=ProtocolType.tcp).one()
                service.port = 161
                service.protocol = ProtocolType.udp
        # Perform legit update
        with self._engine.session_scope() as session:
            service = session.query(Service).filter_by(port=80, protocol=ProtocolType.tcp).one()
            service.state = ServiceState.Closed
            service.nmap_service_name = "https"
            service.nmap_service_confidence = 1
            service.nmap_service_name_original = "https?"
            service.nmap_service_state_reason = "reason"
            service.nmap_product = "nmap_product"
            service.nmap_version = "nmap_version"
            service.nmap_extra_info = "nmap_extra_info"
            service.nmap_os_type = "nmap_os_type"
            service.nmap_tunnel = "nmap_tunnel"
            service.nessus_service_name = "nessus_service_name"
            service.nessus_service_confidence = 1
