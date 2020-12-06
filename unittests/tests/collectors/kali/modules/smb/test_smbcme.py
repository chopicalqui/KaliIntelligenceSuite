#!/usr/bin/python3
"""
this file implements all unittests for collector smbcme
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
from unittests.tests.collectors.kali.modules.dns.core import BaseKaliDnsCollectorTestCase
from collectors.os.modules.smb.smbcme import CollectorClass as SmbCmeCollector
from unittests.tests.collectors.core import CollectorProducerTestSuite
from database.model import CollectorType
from database.model import ScopeType
from database.model import Workspace
from database.model import Service
from database.model import Host


class BaseDnsTakeOverCollectorTestCase(BaseKaliDnsCollectorTestCase):
    """
    This class implements all unittestss for the given collector
    """
    def __init__(self, test_name: str, **kwargs):
        super().__init__(test_name,
                         collector_name="smbcme",
                         collector_class=SmbCmeCollector,
                         **kwargs)

    @staticmethod
    def get_command_text_outputs() -> List[str]:
        """
        This method returns example outputs of the respective collectors
        :return:
        """
        return """$ crackmapexec smb --port 445 10.0.0.1
SMB         10.0.0.1        445    DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:red.local) (signing:True) (SMBv1:False)""".split(os.linesep)

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
                                              command=["crackmapexec", "smb", "10.0.0.1"],
                                              collector_name_str=self._collector_name,
                                              collector_name_type=CollectorType.service,
                                              service_port=445,
                                              scope=ScopeType.all,
                                              output_path=temp_dir)
                command.stdout_output = self.get_command_text_outputs()
                test_suite.verify_results(session=session,
                                          arg_parse_module=self._arg_parse_module,
                                          command=command,
                                          source=source,
                                          report_item=self._report_item)
        with self._engine.session_scope() as session:
            result = session.query(Service) \
                .join(Host) \
                .join(Workspace) \
                .filter(Service.port == 445, Workspace.name == self._workspaces[0]).one()
            self.assertTrue(result.smb_message_signing)
            self.assertEqual("windows", result.host.os_family)
            self.assertEqual("Windows 10.0 Build 17763", result.host.os_details)
