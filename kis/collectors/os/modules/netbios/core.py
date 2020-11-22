# -*- coding: utf-8 -*-
"""
implements all base functionality for NetBIOS collectors
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


class NbtSsServiceDescriptor(ServiceDescriptorBase):
    """
    This class describes how an NetBIOS service looks like
    """

    def __init__(self):
        super().__init__(default_tcp_ports=[137],
                         default_udp_ports=[137],
                         nmap_tcp_service_names=["^netbios\-ns$"],
                         nmap_udp_service_names=["^netbios\-ns$"],
                         nessus_tcp_service_names=["^smb$"],
                         nessus_udp_service_names=["^smb$"])


class NbtNsServiceDescriptor(ServiceDescriptorBase):
    """
    This class describes how an NetBIOS service looks like
    """

    def __init__(self):
        super().__init__(default_tcp_ports=[137],
                         default_udp_ports=[137],
                         nmap_tcp_service_names=["^netbios\-ns$"],
                         nmap_udp_service_names=["^netbios\-ns$"])


class BaseNbtNsCollector(BaseCollector):
    """
    This is the base class for all NetBIOS collectors
    """

    def __init__(self, priority, timeout, **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=NbtNsServiceDescriptor(),
                         **kwargs)


class NbtSsnServiceDescriptor(ServiceDescriptorBase):
    """
    This class describes how an NetBIOS service looks like
    """

    def __init__(self):
        super().__init__(default_tcp_ports=[138],
                         default_udp_ports=[138],
                         nmap_tcp_service_names=["^netbios\-ssn$"],
                         nmap_udp_service_names=["^netbios\-ssn$"])


class BaseNbtSsnNbtNsCollector(BaseCollector):
    """
    This is the base class for all NetBIOS collectors
    """

    def __init__(self, priority, timeout, **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=NbtSsnServiceDescriptor(),
                         **kwargs)