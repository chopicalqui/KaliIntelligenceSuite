#!/usr/bin/python3
"""
this file implements unittests to test for command injections
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
from database.model import Command
from database.model import HostName
from database.model import ScopeType
from unittests.tests.collectors.kali.modules.core import BaseKaliCollectorTestCase
from collectors.os.modules.dns.dnshost import CollectorClass as DnsHostCollector
from unittests.tests.collectors.core import CollectorProducerTestSuite
from sqlalchemy.orm.session import Session


class TestCommandInjectionVulnerabilities(BaseKaliCollectorTestCase):
    """
    This class tests the command creation logic
    """

    def __init__(self, test_name: str):
        super().__init__(test_name,
                         collector_name="dnshost",
                         collector_class=DnsHostCollector)

    def _execute_command(self,
                         session: Session,
                         domain_name: str = None,
                         workspace_str: str = "unittest") -> None:
        domain_name = self.create_domain_name(session=session,
                                              workspace_str=workspace_str,
                                              host_name=domain_name,
                                              scope=ScopeType.all)
        host_name = HostName(domain_name=domain_name)
        session.add(host_name)
        session.commit()
        with tempfile.TemporaryDirectory() as temp_dir:
            test_suite = CollectorProducerTestSuite(engine=self._engine,
                                                    arguments={"workspace": workspace_str,
                                                               "output_dir": temp_dir})
            test_suite.create_commands([self._arg_parse_module])
            test_suite.create_execute_commands([self._arg_parse_module])

    def _unittest(self, domain_name: str, file_name: str):
        self.init_db()
        with self._engine.session_scope() as session:
            self._execute_command(session=session,
                                  domain_name=domain_name,
                                  workspace_str=self._workspaces[0])
        # Make sure command was created
        with self._engine.session_scope() as session:
            results = session.query(Command).count()
            self.assertEqual(1, results)
        if os.path.exists(file_name):
            raise Exception("command injection via back ticks possible")

    def test_backticks(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_name = os.path.join(temp_dir, "test")
            domain_name = "`touch {}`".format(file_name)
            self._unittest(domain_name=domain_name, file_name=file_name)

    def test_and(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_name = os.path.join(temp_dir, "test")
            domain_name = "localhost && touch {}".format(file_name)
            self._unittest(domain_name=domain_name, file_name=file_name)

    def test_or(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_name = os.path.join(temp_dir, "test")
            domain_name = "localhost || touch {}".format(file_name)
            self._unittest(domain_name=domain_name, file_name=file_name)
