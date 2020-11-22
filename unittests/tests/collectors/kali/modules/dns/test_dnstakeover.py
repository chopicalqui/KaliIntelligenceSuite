#!/usr/bin/python3
"""
this file implements all unittests for collector httparachni
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
from collectors.os.modules.dns.dnstakeover import CollectorClass as DnsTakeOverCollector
from unittests.tests.collectors.core import CollectorProducerTestSuite
from database.model import CollectorType
from database.model import HostName
from database.model import HostNameHostNameMapping
from database.model import ScopeType


class BaseDnsTakeOverCollectorTestCase(BaseKaliDnsCollectorTestCase):
    """
    This class implements all unittestss for the given collector
    """
    def __init__(self, test_name: str, **kwargs):
        super().__init__(test_name,
                         collector_name="dnstakeover",
                         collector_class=DnsTakeOverCollector)

    @staticmethod
    def get_command_text_outputs() -> List[str]:
        """
        This method returns example outputs of the respective collectors
        :return:
        """
        return """; <<>> DiG 9.11.5-P4-5-Debian <<>> -t NS unittest.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 56969
;; flags: qr rd ra; QUERY: 1, ANSWER: 4, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; MBZ: 0x0005, udp: 4096
;; QUESTION SECTION:
;unittest.com.			IN	NS
unittest.com.		5	IN	NS	ns-1245.awsdns-27.org.
unittest.com.		5	IN	NS	ns-1697.awsdns-20.uk.

;; ANSWER SECTION:
unittest.com.		5	IN	CNAME	12345.group35.sites.hubspot.net.

;; Query time: 3 msec
;; SERVER: 172.16.56.2#53(172.16.56.2)
;; WHEN: Sun Sep 01 15:56:41 GMT 2019
;; MSG SIZE  rcvd: 179""".split(os.linesep)

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
                                              command=["dig", "unittest.com"],
                                              collector_name_str=self._collector_name,
                                              collector_name_type=CollectorType.domain,
                                              host_name_str="unittest.com",
                                              scope=ScopeType.all,
                                              output_path=temp_dir)
                command.stdout_output = self.get_command_text_outputs()
                test_suite.verify_results(session=session,
                                          arg_parse_module=self._arg_parse_module,
                                          command=command,
                                          source=source,
                                          report_item=self._report_item)
        with self._engine.session_scope() as session:
            results = session.query(HostName).all()
            results = [item.full_name for item in results]
            results.sort()
            expected_results = ["awsdns-27.org",
                                "awsdns-20.uk",
                                "hubspot.net",
                                "ns-1245.awsdns-27.org",
                                "ns-1697.awsdns-20.uk",
                                "unittest.com",
                                "12345.group35.sites.hubspot.net",
                                "group35.sites.hubspot.net",
                                "sites.hubspot.net"]
            expected_results.sort()
            self.assertListEqual(expected_results, results)
            results = ["{} -> {} -> {}".format(item.source_host_name.full_name,
                                               item.type.name,
                                               item.resolved_host_name.full_name)
                       for item in session.query(HostNameHostNameMapping).all()]
            results.sort()
            expected_results = ["unittest.com -> ns -> ns-1245.awsdns-27.org",
                                "unittest.com -> ns -> ns-1697.awsdns-20.uk",
                                "unittest.com -> cname -> 12345.group35.sites.hubspot.net"]
            expected_results.sort()
            self.assertListEqual(expected_results, results)
