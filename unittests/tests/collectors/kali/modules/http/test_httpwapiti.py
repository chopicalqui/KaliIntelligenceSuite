#!/usr/bin/python3
"""
this file implements all unittests for collector httpwapiti
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
from unittests.tests.collectors.kali.modules.http.core import BaseKaliHttpCollectorTestCase
from collectors.os.modules.http.httpwapiti import CollectorClass as WapitiCollector
from unittests.tests.collectors.core import CollectorProducerTestSuite
from database.model import CollectorType
from database.model import Path
from database.model import ScopeType


class BaseHttpWapitiCollectorTestCase(BaseKaliHttpCollectorTestCase):
    """
    This class implements all unittestss for the given collector
    """
    def __init__(self, test_name: str, **kwargs):
        super().__init__(test_name,
                         collector_name="httpwapiti",
                         collector_class=WapitiCollector)

    @staticmethod
    def get_command_text_outputs() -> List[str]:
        """
        This method returns example outputs of the respective collectors
        :return:
        """
        return """
 ██╗    ██╗ █████╗ ██████╗ ██╗████████╗██╗██████╗
 ██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║╚════██╗
 ██║ █╗ ██║███████║██████╔╝██║   ██║   ██║ █████╔╝
 ██║███╗██║██╔══██║██╔═══╝ ██║   ██║   ██║ ╚═══██╗
 ╚███╔███╔╝██║  ██║██║     ██║   ██║   ██║██████╔╝
  ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝     ╚═╝   ╚═╝   ╚═╝╚═════╝
Wapiti-3.0.1 (wapiti.sourceforge.net)
[*] Saving scan state, please wait...

 Note
========
This scan has been saved in the file /root/.wapiti/scans/127.0.0.1_domain_86d3f83c.db
[*] Wapiti found 3 URLs and forms during the scan
[*] Loading modules:
	 mod_crlf, mod_exec, mod_file, mod_sql, mod_xss, mod_backup, mod_htaccess, mod_blindsql, mod_permanentxss, mod_nikto, mod_delay, mod_buster, mod_shellshock, mod_methods, mod_ssrf

[*] Launching module exec
---
Command execution in http://127.0.0.1/select via injection in the parameter db
Evil request:
    POST /select HTTP/1.1
    Host: 127.0.0.1
    Referer: http://127.0.0.1/
    Content-Type: application/x-www-form-urlencoded

    db=%3Benv&db=fortunes2&db=recipes&db=startrek&db=zippy
---

[*] Launching module file
---
Received a HTTP 500 error in http://127.0.0.1/select
Evil request:
    POST /select HTTP/1.1
    Host: 127.0.0.1
    Referer: http://127.0.0.1/
    Content-Type: application/x-www-form-urlencoded

    db=%2Fetc%2Fpasswd%00&db=fortunes2&db=recipes&db=startrek&db=zippy
---

[*] Launching module sql
---
Received a HTTP 500 error in http://127.0.0.1/select
Evil request:
    POST /select HTTP/1.1
    Host: 127.0.0.1
    Referer: http://127.0.0.1/
    Content-Type: application/x-www-form-urlencoded

    db=%C2%BF%27%22%28&db=fortunes2&db=recipes&db=startrek&db=zippy
---

[*] Launching module xss

[*] Launching module ssrf

[*] Launching module blindsql
---
Received a HTTP 500 error in http://127.0.0.1/select
Evil request:
    POST /select HTTP/1.1
    Host: 127.0.0.1
    Referer: http://127.0.0.1/
    Content-Type: application/x-www-form-urlencoded

    db=%27%20and%20%28SELECT%20%2A%20FROM%20%5BODBC%3BDRIVER%3DSQL%20SERVER%3BServer%3D1.1.1.1%3BDATABASE%3Dw%5D.a.p%29%00&db=fortunes2&db=recipes&db=startrek&db=zippy
---

[*] Launching module permanentxss

Report
------
A report has been generated in the file /tmp/kis/127.0.0.1/httpwapiti_127.0.0.1-tcp-80.txt""".split(os.linesep)

    def test_for_invalid_arguments(self):
        """
        This method checks whether the collector creates a valid command for the installed version
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self._test_for_invalid_arguments(session=session,
                                             workspace_str=self._workspaces[0],
                                             expected_command_count=2)

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
                                              command=["wapiti", "127.0.0.1"],
                                              collector_name_str=self._collector_name,
                                              collector_name_type=CollectorType.host_service,
                                              service_port=80,
                                              scope=ScopeType.all,
                                              output_path=temp_dir)
                command.host.address = "127.0.0.1"
                command.stdout_output = self.get_command_text_outputs()
                test_suite.verify_results(session=session,
                                          arg_parse_module=self._arg_parse_module,
                                          command=command,
                                          source=source,
                                          report_item=self._report_item)
        with self._engine.session_scope() as session:
            results = session.query(Path).count()
            self.assertEqual(2, results)
            results = [item.name for item in session.query(Path).all()]
            self.assertListEqual(["/", "/select"], results)
