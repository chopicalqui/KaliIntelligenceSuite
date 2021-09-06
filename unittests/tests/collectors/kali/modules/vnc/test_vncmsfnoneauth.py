#!/usr/bin/python3
"""
this file implements all unittests for collector whoisdomain
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

import os
import tempfile
from typing import List
from typing import Dict
from unittests.tests.collectors.core import CollectorProducerTestSuite
from unittests.tests.collectors.kali.modules.core import BaseKaliCollectorTestCase
from collectors.os.modules.vnc.vncmsfnoneauth import CollectorClass as VncMsfNoneAuth
from database.model import Credentials
from database.model import CredentialType
from database.model import ScopeType
from database.model import CollectorType


class VncMsfLoginCollectorTestCase(BaseKaliCollectorTestCase):
    """
    This class implements all unittestss for the given collector
    """
    def __init__(self, test_name: str, **kwargs):
        super().__init__(test_name,
                         collector_name="vncmsfnoneauth",
                         collector_class=VncMsfNoneAuth)

    @staticmethod
    def get_command_text_outputs() -> List[str]:
        """
        This method returns example outputs of the respective collectors
        :return:
        """
        return ["""[*] 127.0.0.1:5900        - Scanned 1 of 1 hosts (100% complete)
[*] 127.0.0.1:5900        - VNC server security types supported:
[*] 127.0.0.1:5900        - VNC server security types includes None, free access!
[*] Auxiliary module execution completed"""]

    @staticmethod
    def get_command_json_outputs() -> List[Dict[str, str]]:
        """
        This method returns example outputs of the respective collectors
        :return:
        """
        return []

    def test_verify_results(self):
        """
        This method checks whether the collector correctly verifies the command output
        :return:
        """
        self.init_db()
        with tempfile.TemporaryDirectory() as temp_dir:
            test_suite = CollectorProducerTestSuite(engine=self._engine,
                                                    arguments={"workspace": self._workspaces[0],
                                                               "output_dir": temp_dir})
            with self._engine.session_scope() as session:
                source = self.create_source(session, source_str=self._collector_name)
                command = self.create_command(session=session,
                                              workspace_str=self._workspaces[0],
                                              command=["msfconsole", '-q', '-x', 'use auxiliary/scanner/vnc/vncmsfnoneauth;set RHOSTS=127.0.0.1;run;exit'],
                                              collector_name_str="vncmsfnoneauth",
                                              collector_name_type=CollectorType.host_service,
                                              service_port=5900,
                                              scope=ScopeType.all)
                command.stdout_output = self.get_command_text_outputs()[0].split(os.linesep)
                test_suite.verify_results(session=session,
                                          arg_parse_module=self._arg_parse_module,
                                          command=command,
                                          source=source,
                                          report_item=self._report_item)
            with self._engine.session_scope() as session:
                credential = session.query(Credentials).one()
                self.assertIsNone(credential.username)
                self.assertIsNone(credential.password)
                self.assertIsNone(credential.type)
