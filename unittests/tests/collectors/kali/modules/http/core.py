#!/usr/bin/python3
"""
this file implements core functionalities to test os http collectors
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

from unittests.tests.collectors.kali.modules.core import BaseKaliCollectorTestCase
from unittests.tests.core import BaseKisTestCase
from sqlalchemy.orm.session import Session
from database.model import ProtocolType
from database.model import ServiceState
from database.model import Service
from database.model import ScopeType


class BaseKaliHttpCollectorTestCase(BaseKaliCollectorTestCase):
    """
    This class represents the base class for all os http collector tests
    """

    def __init__(self, test_name: str, **kwargs):
        super().__init__(test_name, **kwargs)

    @staticmethod
    def create_test_data(test_case: BaseKisTestCase,
                         session: Session,
                         workspace_str: str) -> None:
        """
        This method creates test data in the database in order to be able to create commands
        :param test_case: The test case that provides all methods for creating test data
        :param session: The database session based on which the data is created in the database
        :param workspace_str: The workspace within which the data is created
        :return:
        """
        local_ip = test_case.get_local_ip()
        test_case.create_network(session=session,
                                 workspace_str=workspace_str,
                                 network=local_ip,
                                 scope=ScopeType.all)
        test_case.create_service(session=session,
                                 workspace_str=workspace_str,
                                 address=local_ip,
                                 port=443,
                                 protocol_type=ProtocolType.tcp,
                                 state=ServiceState.Open)
        test_case.create_service(session=session,
                                 workspace_str=workspace_str,
                                 address=local_ip,
                                 port=533,
                                 protocol_type=ProtocolType.tcp,
                                 state=ServiceState.Open,
                                 nmap_service_name="https",
                                 nmap_tunnel="ssl",
                                 nmap_service_confidence=10)
        results = session.query(Service).count()
        test_case.assertEqual(2, results)
        session.commit()
