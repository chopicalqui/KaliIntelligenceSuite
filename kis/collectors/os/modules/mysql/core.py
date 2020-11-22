# -*- coding: utf-8 -*-
"""
implements all base functionality for MySQL collectors
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
from collectors.os.modules.core import ServiceDescriptorBase
from collectors.os.modules.core import BaseNmap
from collectors.filesystem.nmap import BaseExtraServiceInfoExtraction


class MySqlServiceDescriptor(ServiceDescriptorBase):
    """
    This class describes how an MySQL service looks like
    """

    def __init__(self):
        super().__init__(default_tcp_ports=[3306],
                         default_udp_ports=[3306],
                         nmap_tcp_service_names=["^mysql$"],
                         nmap_udp_service_names=["^mysql$"])


class BaseMySqlCollector(BaseCollector):
    """
    This is the base class for all MySQL collectors
    """

    def __init__(self, priority, timeout, **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=MySqlServiceDescriptor(),
                         **kwargs)


class BaseMySqlHydra(BaseHydra):
    """
    This class implements basic functionality for MySQL collectors that use Hydra.
    """
    def __init__(self, priority, timeout, **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=MySqlServiceDescriptor(),
                         **kwargs)


class BaseMySqlNmap(BaseNmap):
    """
    This class implements basic functionality for rpcbind collectors that use Nmap.
    """
    def __init__(self, priority,
                 timeout,
                 nmap_xml_extractor_classes: List[BaseExtraServiceInfoExtraction],
                 **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=MySqlServiceDescriptor(),
                         nmap_xml_extractor_classes=nmap_xml_extractor_classes,
                         **kwargs)