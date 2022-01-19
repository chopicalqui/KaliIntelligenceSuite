# -*- coding: utf-8 -*-
"""
implements all base functionality for RDP collectors
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
from typing import List
from database.model import Service
from collectors.os.modules.core import BaseCollector
from collectors.os.modules.core import BaseHydra
from collectors.os.modules.core import BaseNmap
from collectors.os.modules.core import ServiceDescriptorBase
from collectors.os.modules.core import BaseExtraServiceInfoExtraction
from collectors.core import XmlUtils
from sqlalchemy.orm.session import Session


class RdpServiceDescriptor(ServiceDescriptorBase):
    """
    This class describes how an RDP service looks like
    """

    def __init__(self):
        super().__init__(default_tcp_ports=[3389],
                         default_udp_ports=[3389],
                         nmap_tcp_service_names=["^ms\-wbt\-server$"],
                         nmap_udp_service_names=["^ms\-wbt\-server$"],
                         nessus_tcp_service_names=["^msrdp$"])


class BaseRdpCollector(BaseCollector):
    """
    This is the base class for all RDP collectors
    """

    def __init__(self, priority, timeout, **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=RdpServiceDescriptor(),
                         **kwargs)


class BaseRdpHydra(BaseHydra):
    """
    This class implements basic functionality for RDP collectors that use Hydra.
    """
    def __init__(self, priority, timeout, **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=RdpServiceDescriptor(),
                         **kwargs)


class BaseRdpNmap(BaseNmap):
    """
    This class implements basic functionality for RDP collectors that use Nmap.
    """
    def __init__(self, priority,
                 timeout,
                 nmap_xml_extractor_classes: List[BaseExtraServiceInfoExtraction],
                 **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=RdpServiceDescriptor(),
                         nmap_xml_extractor_classes=nmap_xml_extractor_classes,
                         **kwargs)


class RdpExtraInfoExtraction(BaseExtraServiceInfoExtraction):
    """
    This class extracts extra information disclosed by RDP service.
    """
    RDP_NTLM_INFO = "rdp-ntlm-info"
    RDP_ENUM_ENCRYPTION = "rdp-enum-encryption"

    def __init__(self, session: Session, service: Service, **args):
        super().__init__(session, service, **args)

    def _extract_ntlm_info(self, port_tag) -> None:
        """This method extracts NTLM information"""
        super()._extract_ntlm_info(port_tag, tag_id=RdpExtraInfoExtraction.RDP_NTLM_INFO)

    def _extract_rdp_encryption(self, port_tag) -> None:
        """This method extracts RDP encryption information"""
        script = port_tag.findall("*/[@id='{}']".format(RdpExtraInfoExtraction.RDP_ENUM_ENCRYPTION))
        if len(script) > 0:
            output = XmlUtils.get_xml_attribute("output", script[0].attrib)
            if output:
                security_layer_section = False
                encryption_level_section = False
                protocol_version_section = False
                rdp_security_layers = []
                rdp_encryption_level = []
                rdp_protocol_version = []
                for line in output.split(os.linesep):
                    line = line.strip()
                    if line == "Security layer":
                        security_layer_section = True
                    elif line == "RDP Encryption level: Client Compatible":
                        security_layer_section = False
                        encryption_level_section = True
                    elif line == "RDP Protocol Version:":
                        security_layer_section = False
                        encryption_level_section = False
                        line = line.replace("RDP Protocol Version:", "").strip()
                        rdp_protocol_version.append(line)
                    elif security_layer_section:
                        rdp_security_layers.append(line)
                    elif encryption_level_section:
                        rdp_encryption_level.append(line)
                if rdp_security_layers:
                    self._domain_utils.add_additional_info(session=self._session,
                                                           name="RDP security layers",
                                                           values=rdp_security_layers,
                                                           source=self._source,
                                                           service=self._service,
                                                           report_item=self._report_item)
                if rdp_encryption_level:
                    self._domain_utils.add_additional_info(session=self._session,
                                                           name="RDP encryption layers",
                                                           values=rdp_encryption_level,
                                                           source=self._source,
                                                           service=self._service,
                                                           report_item=self._report_item)
                if rdp_protocol_version:
                    self._domain_utils.add_additional_info(session=self._session,
                                                           name="RDP protocol version",
                                                           values=rdp_protocol_version,
                                                           source=self._source,
                                                           service=self._service,
                                                           report_item=self._report_item)

    def extract(self, **kwargs):
        """This method extracts the required information."""
        self._extract_ntlm_info(kwargs["port_tag"])
        self._extract_rdp_encryption(kwargs["port_tag"])