# -*- coding: utf-8 -*-
"""
implements all base functionality for TFTP collectors
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
from database.model import PathType
from collectors.os.modules.core import BaseCollector
from collectors.os.modules.core import BaseHydra
from collectors.os.modules.core import BaseNmap
from collectors.os.modules.core import BaseDotDotPwn
from collectors.os.modules.core import ServiceDescriptorBase
from collectors.os.modules.core import BaseExtraServiceInfoExtraction
from collectors.core import XmlUtils
from sqlalchemy.orm.session import Session


class TftpServiceDescriptor(ServiceDescriptorBase):
    """
    This class describes how an TFTP service looks like
    """

    def __init__(self):
        super().__init__(default_udp_ports=[69],
                         nmap_udp_service_names=["^tftp$"],
                         nessus_udp_service_names=["^tftp$"])


class BaseTftpCollector(BaseCollector):
    """
    This is the base class for all TFTP collectors
    """

    def __init__(self, priority, timeout, **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=TftpServiceDescriptor(),
                         **kwargs)


class BaseTftpHydra(BaseHydra):
    """
    This class implements basic functionality for TFTP collectors that use Hydra.
    """
    def __init__(self, priority, timeout, **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=TftpServiceDescriptor(),
                         **kwargs)


class BaseTftpNmap(BaseNmap):
    """
    This class implements basic functionality for TFTP collectors that use Hydra.
    """
    def __init__(self, priority,
                 timeout,
                 nmap_xml_extractor_classes: List[BaseExtraServiceInfoExtraction],
                 **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=TftpServiceDescriptor(),
                         nmap_xml_extractor_classes=nmap_xml_extractor_classes,
                         **kwargs)


class BaseTftpDotDotPwn(BaseDotDotPwn):
    """
    This class implements basic functionality for TFTP collectors that use Dotdotpwn.
    """

    def __init__(self, priority, timeout, **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=TftpServiceDescriptor(),
                         module="tftp",
                         **kwargs)


class TftpExtraInfoExtraction(BaseExtraServiceInfoExtraction):
    """
    This class extracts extra information disclosed by TFTP service.
    """
    TFTP_ENUM = "tftp-enum"

    def __init__(self, session: Session, service: Service, **args):
        super().__init__(session, service, **args)

    def _extract_tftp_paths(self, port_tag) -> None:
        """This method extracts the supported SMTP commands disclosed by the SMTP service"""
        script = port_tag.findall("*/[@id='{}']".format(TftpExtraInfoExtraction.TFTP_ENUM))
        if len(script) > 0:
            output = XmlUtils.get_xml_attribute("output", script[0].attrib)
            if output:
                for path_str in output.split(os.linesep):
                    path_str = path_str.strip()
                    self._domain_utils.add_path(session=self._session,
                                                service=self._service,
                                                path=path_str,
                                                path_type=PathType.FileSystem,
                                                source=self._source,
                                                report_item=self._report_item)

    def extract(self, **kwargs):
        """This method extracts the required information."""
        self._extract_tftp_paths(kwargs["port_tag"])