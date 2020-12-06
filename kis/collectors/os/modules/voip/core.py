# -*- coding: utf-8 -*-
"""
implements all base functionality for VoIP collectors
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
from collectors.os.modules.core import BaseCollector
from collectors.os.modules.core import BaseNmap
from collectors.os.modules.core import BaseMsfConsole
from collectors.os.modules.core import ServiceDescriptorBase
from collectors.os.modules.core import BaseExtraServiceInfoExtraction


class SipServiceDescriptor(ServiceDescriptorBase):
    """
    This class describes how an SIP service looks like
    """

    def __init__(self):
        super().__init__(default_tcp_ports=[5060,5061],
                         default_udp_ports=[5060,5061],
                         nmap_udp_service_names=["^sip$", "^sip\-tls$"],
                         nmap_tcp_service_names=["^sip", "^sip\-tls$"])


class StunServiceDescriptor(ServiceDescriptorBase):
    """
    This class describes how an STUN service looks like
    """

    def __init__(self):
        super().__init__(default_tcp_ports=[3478,5349],
                         default_udp_ports=[3478,5349],
                         nmap_udp_service_names=["^stun$", "^stuns$"],
                         nmap_tcp_service_names=["^stun$", "^stuns$"])


class H323ServiceDescriptor(ServiceDescriptorBase):
    """
    This class describes how an H323 service looks like
    """

    def __init__(self):
        super().__init__(default_tcp_ports=[1300, 1720],
                         default_udp_ports=[1300, 1720],
                         nmap_udp_service_names=["^h323hostcallsc$", "^h323q931$"],
                         nmap_tcp_service_names=["^h323hostcallsc$", "^h323q931$"])


class BaseSipCollector(BaseCollector):
    """
    This is the base class for all SIP collectors
    """

    def __init__(self, priority, timeout, **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=SipServiceDescriptor(),
                         **kwargs)


class BaseStunCollector(BaseCollector):
    """
    This is the base class for all SIP collectors
    """

    def __init__(self, priority, timeout, **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=StunServiceDescriptor(),
                         **kwargs)


class H323StunCollector(BaseCollector):
    """
    This is the base class for all SIP collectors
    """

    def __init__(self, priority, timeout, **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=H323ServiceDescriptor(),
                         **kwargs)


class BaseSipNmap(BaseNmap):
    """
    This class implements basic functionality for SIP collectors that use Nmap.
    """
    def __init__(self, priority,
                 timeout,
                 nmap_xml_extractor_classes: List[BaseExtraServiceInfoExtraction],
                 **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=SipServiceDescriptor(),
                         nmap_xml_extractor_classes=nmap_xml_extractor_classes,
                         **kwargs)


class BaseStunNmap(BaseNmap):
    """
    This class implements basic functionality for STUN collectors that use Nmap.
    """
    def __init__(self, priority,
                 timeout,
                 nmap_xml_extractor_classes: List[BaseExtraServiceInfoExtraction],
                 **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=StunServiceDescriptor(),
                         nmap_xml_extractor_classes=nmap_xml_extractor_classes,
                         **kwargs)


class BaseH323Nmap(BaseNmap):
    """
    This class implements basic functionality for H323 collectors that use Nmap.
    """
    def __init__(self, priority,
                 timeout,
                 nmap_xml_extractor_classes: List[BaseExtraServiceInfoExtraction],
                 **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=H323ServiceDescriptor(),
                         nmap_xml_extractor_classes=nmap_xml_extractor_classes,
                         **kwargs)


class BaseSipMsfConsole(BaseMsfConsole):
    """
    This class implements basic functionality for SIP collectors that use msfconsole.
    """
    def __init__(self, priority,
                 timeout,
                 **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=SipServiceDescriptor(),
                         **kwargs)


class BaseStunMsfConsole(BaseMsfConsole):
    """
    This class implements basic functionality for STUN collectors that use msfconsole.
    """
    def __init__(self, priority,
                 timeout,
                 **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=SipServiceDescriptor(),
                         **kwargs)


class BaseH323MsfConsole(BaseMsfConsole):
    """
    This class implements basic functionality for H323 collectors that use msfconsole.
    """
    def __init__(self, priority,
                 timeout,
                 **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=H323ServiceDescriptor(),
                         **kwargs)
