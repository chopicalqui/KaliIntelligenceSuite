#!/usr/bin/python3
"""
this file implements all unittests for collector tcpnmapdomain
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

from typing import List
from unittests.tests.collectors.kali.modules.scan.core import BaseNmapCollectorTestCase
from collectors.os.modules.scan.tcpnmapdomain import CollectorClass as NmapCollector


class BaseUdpNmapCollectorTestCase(BaseNmapCollectorTestCase):
    """
    This class implements all unittests for the given collector
    """
    def __init__(self, test_name: str, **kwargs):
        super().__init__(test_name,
                         collector_name="tcpnmapdomain",
                         collector_class=NmapCollector)

    @staticmethod
    def get_command_text_outputs() -> List[str]:
        """
        This method returns example outputs of the respective collectors
        :return:
        """
        return []

    @staticmethod
    def get_command_xml_outputs() -> List[str]:
        """
        This method returns example outputs of the respective collectors
        :return:
        """
        return []

    def test_command_creation_vhost_none(self):
        """
        This method tests the correct creation of Nmap scans based on host_names and IPv4 addresses
        :return:
        """
        self._unittest_command_creation_vhost(vhost=None,
                                              expected_ipv4_network_command_results=[],
                                              expected_host_name_commands=["unittest1.com"])
