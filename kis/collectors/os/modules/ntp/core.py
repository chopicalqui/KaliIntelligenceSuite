# -*- coding: utf-8 -*-
"""
implements all base functionality for NTP collectors
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

from collectors.os.modules.core import BaseCollector
from collectors.os.modules.core import ServiceDescriptorBase


class NtpServiceDescriptor(ServiceDescriptorBase):
    """
    This class describes how an NTP service looks like
    """

    def __init__(self):
        super().__init__(default_tcp_ports=[123],
                         default_udp_ports=[123],
                         nmap_udp_service_names=["^ntp$"],
                         nmap_tcp_service_names=["^ntp$"])


class BaseNtpCollector(BaseCollector):
    """
    This is the base class for all NFS collectors
    """

    def __init__(self, priority, timeout, **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=NtpServiceDescriptor(),
                         **kwargs)

