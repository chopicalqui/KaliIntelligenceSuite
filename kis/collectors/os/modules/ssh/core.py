# -*- coding: utf-8 -*-
"""
implements all base functionality for SSH collectors
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

import re
from typing import List
from database.model import Service
from collectors.os.modules.core import BaseCollector
from collectors.os.modules.core import BaseHydra
from collectors.os.modules.core import BaseNmap
from collectors.os.modules.core import ServiceDescriptorBase
from collectors.os.modules.core import BaseChangeme
from collectors.os.modules.core import BaseExtraServiceInfoExtraction
from sqlalchemy.orm.session import Session


class SshServiceDescriptor(ServiceDescriptorBase):
    """
    This class describes how an SSH service looks like
    """

    def __init__(self):
        super().__init__(default_tcp_ports=[22],
                         nmap_tcp_service_names=["^ssh$"],
                         nessus_tcp_service_names=["^ssh$"])


class BaseSshCollector(BaseCollector):
    """
    This is the base class for all SSH collectors
    """

    def __init__(self, priority, timeout, **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=SshServiceDescriptor(),
                         **kwargs)


class BaseSshHydra(BaseHydra):
    """
    This class implements basic functionality for SSH collectors that use Hydra.
    """
    def __init__(self, priority, timeout, **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=SshServiceDescriptor(),
                         **kwargs)


class BaseSshChangeme(BaseChangeme):
    """
    This class implements basic functionality for SSH collectors that use Hydra.
    """
    def __init__(self, priority, timeout, **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=SshServiceDescriptor(),
                         **kwargs)


class BaseSshNmap(BaseNmap):
    """
    This class implements basic functionality for SSH collectors that use Hydra.
    """
    def __init__(self, priority,
                 timeout,
                 nmap_xml_extractor_classes: List[BaseExtraServiceInfoExtraction],
                 **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=SshServiceDescriptor(),
                         nmap_xml_extractor_classes=nmap_xml_extractor_classes,
                         **kwargs)


class SshExtraInfoExtraction(BaseExtraServiceInfoExtraction):
    """
    This class extracts extra information from SSH services.
    """
    SSH2_ENUM_ALGOS = "ssh2-enum-algos"

    def __init__(self, session: Session, service: Service, **kwargs):
        super().__init__(session, service, **kwargs)
        self._re_weak_algorithms = [re.compile("^.+\-cbc$"), re.compile("^arcfour((128)|(256))?$")]

    def _extract_ssh2_enum_algos(self, port_tag):
        """Extracts SMB share information disclosed by SMB"""
        weak_algorithms = []
        for script_tag in port_tag.findall("script/[@id='{}']".format(SshExtraInfoExtraction.SSH2_ENUM_ALGOS)):
            for algorithm_table in script_tag.findall("table[@key='encryption_algorithms']"):
                for elem in algorithm_table.findall("elem"):
                    for item in self._re_weak_algorithms:
                        match = item.match(elem.text)
                        if match:
                            weak_algorithms.append(elem.text)
        if weak_algorithms:
            self._domain_utils.add_additional_info(session=self._session,
                                                   name="Weak SSH encryption",
                                                   values=weak_algorithms,
                                                   source=self._source,
                                                   service=self._service,
                                                   report_item=self._report_item)

    def extract(self, **kwargs):
        """This method extracts disclosed information from SMB services."""
        self._extract_ssh2_enum_algos(kwargs["port_tag"])