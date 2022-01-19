# -*- coding: utf-8 -*-
"""
implements all base functionality for VNC collectors
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
from collectors.os.modules.core import BaseHydra
from collectors.os.modules.core import BaseNmap
from collectors.os.modules.core import BaseMsfConsole
from collectors.os.modules.core import ServiceDescriptorBase
from collectors.os.modules.core import BaseExtraServiceInfoExtraction


class VncServiceDescriptor(ServiceDescriptorBase):
    """
    This class describes how an VNC service looks like
    """

    def __init__(self):
        super().__init__(default_tcp_ports=[5900, 5901, 5902, 5903],
                         default_udp_ports=[5900, 5901, 5902, 5903],
                         nmap_tcp_service_names=["^vnc$"],
                         nmap_udp_service_names=["^vnc$"])


class BaseVncCollector(BaseCollector):
    """
    This is the base class for all VNC collectors
    """

    def __init__(self, priority, timeout, **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=VncServiceDescriptor(),
                         **kwargs)


class BaseVncHydra(BaseHydra):
    """
    This class implements basic functionality for VNC collectors that use Hydra.
    """
    def __init__(self, priority, timeout, **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=VncServiceDescriptor(),
                         **kwargs)


class BaseVncNmap(BaseNmap):
    """
    This class implements basic functionality for VNC collectors that use Nmap.
    """
    def __init__(self, priority, timeout, nmap_xml_extractor_classes: List[BaseExtraServiceInfoExtraction], **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         nmap_xml_extractor_classes=nmap_xml_extractor_classes,
                         service_descriptors=VncServiceDescriptor(),
                         **kwargs)


class BaseVncMsfConsole(BaseMsfConsole):
    """
    This class implements basic functionality for VNC collectors that use msfconsole.
    """
    def __init__(self, priority,
                 timeout,
                 **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=VncServiceDescriptor(),
                         **kwargs)
