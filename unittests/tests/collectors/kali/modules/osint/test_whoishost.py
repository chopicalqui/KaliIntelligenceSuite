#!/usr/bin/python3
"""
this file implements all unittests for collector whoishost
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
from typing import List
from typing import Dict
from unittests.tests.collectors.core import CollectorProducerTestSuite
from unittests.tests.collectors.kali.modules.core import BaseKaliCollectorTestCase
from collectors.os.modules.osint.whoishost import CollectorClass as WhoishostCollector
from database.model import Network
from database.model import CollectorType
from database.model import Host
from database.model import ScopeType
from database.model import Company


class BaseBuiltWithCollectorTestCase(BaseKaliCollectorTestCase):
    """
    This class implements all unittestss for the given collector
    """
    def __init__(self, test_name: str, **kwargs):
        super().__init__(test_name,
                         collector_name="whoishost",
                         collector_class=WhoishostCollector)

    @staticmethod
    def get_command_text_outputs() -> List[str]:
        """
        This method returns example outputs of the respective collectors
        :return:
        """
        return ["""#
# ARIN WHOIS data and services are subject to the Terms of Use
# available at: https://www.arin.net/resources/registry/whois/tou/
#
# If you see inaccuracies in the results, please report at
# https://www.arin.net/resources/registry/whois/inaccuracy_reporting/
#
# Copyright 1997-2020, American Registry for Internet Numbers, Ltd.
#



# start

NetRange:       54.240.0.0 - 54.255.255.255
CIDR:           54.240.0.0/12
NetName:        AMAZON-2011L
NetHandle:      NET-54-240-0-0-1
Parent:         NET54 (NET-54-0-0-0-0)
NetType:        Direct Allocation
OriginAS:       AS16509
Organization:   Amazon Technologies Inc. (AT-88-Z)
RegDate:        2011-12-09
Updated:        2012-04-02
Ref:            https://rdap.arin.net/registry/ip/54.240.0.0""",
                """#
# ARIN WHOIS data and services are subject to the Terms of Use
# available at: https://www.arin.net/resources/registry/whois/tou/
#
# If you see inaccuracies in the results, please report at
# https://www.arin.net/resources/registry/whois/inaccuracy_reporting/
#
# Copyright 1997-2020, American Registry for Internet Numbers, Ltd.
#


NetRange:       216.58.192.0 - 216.58.223.255
CIDR:           216.58.192.0/19
NetName:        GOOGLE
NetHandle:      NET-216-58-192-0-1
Parent:         NET216 (NET-216-0-0-0-0)
NetType:        Direct Allocation
OriginAS:       AS15169
Organization:   Google LLC (GOGL)
RegDate:        2012-01-27
Updated:        2012-01-27
Ref:            https://rdap.arin.net/registry/ip/216.58.192.0



OrgName:        Google LLC
OrgId:          GOGL
Address:        1600 Amphitheatre Parkway""", """% This is the RIPE Database query service.
% The objects are in RPSL format.
%
% The RIPE Database is subject to Terms and Conditions.
% See http://www.ripe.net/db/support/db-terms-conditions.pdf

% Note: this output has been filtered.
%       To receive output for a database update, use the "-B" flag.

% Information related to '2a00:1450:4000::/37'

% Abuse contact for '2a00:1450:4000::/37' is 'ripe-contact@google.com'

inet6num:       2a00:1450:4000::/37
netname:        IE-GOOGLE-2a00-1450-4000-1
descr:          EU metro frontend
country:        ie
admin-c:        GOOG1-RIPE
tech-c:         GOOG1-RIPE
status:         AGGREGATED-BY-LIR
assignment-size:48
mnt-by:         MNT-GOOG-PROD
created:        2016-03-09T19:03:51Z
last-modified:  2016-03-09T19:03:51Z
source:         RIPE

role:           Google Ireland Limited"""]

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
                self.create_network(session=session,
                                    workspace_str=self._workspaces[0],
                                    network="0.0.0.0/0",
                                    scope=ScopeType.all)
                self.create_network(session=session,
                                    workspace_str=self._workspaces[0],
                                    network="::/0",
                                    scope=ScopeType.all)
                session.commit()
                command = self.create_command(session=session,
                                              workspace_str=self._workspaces[0],
                                              command=["whois", "54.240.0.0"],
                                              ipv4_address="54.240.0.0",
                                              collector_name_str=self._collector_name,
                                              collector_name_type=CollectorType.domain,
                                              scope=ScopeType.all,
                                              output_path=temp_dir)
                for stdout_output in self.get_command_text_outputs():
                    command.stdout_output = stdout_output.split(os.linesep)
                    test_suite.verify_results(session=session,
                                              arg_parse_module=self._arg_parse_module,
                                              command=command,
                                              source=source,
                                              report_item=self._report_item)
        with self._engine.session_scope() as session:
            result = [item.network for item in session.query(Network).filter(Network.scope == ScopeType.all)]
            result.sort()
            self.assertListEqual(["0.0.0.0/0",
                                  "216.58.192.0/19",
                                  "2a00:1450:4000::/37",
                                  "54.240.0.0/12",
                                  "::/0"], result)
            result = session.query(Host).one()
            self.assertTrue(result.in_scope)
            self.assertEqual("54.240.0.0/12", result.ipv4_network.network)
            result = session.query(Company).all()
            self.assertEqual(3, len(result))
        with self._engine.session_scope() as session:
            for item in session.query(Network).all():
                session.delete(item)