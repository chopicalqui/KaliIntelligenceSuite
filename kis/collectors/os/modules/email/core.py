# -*- coding: utf-8 -*-
"""
implements all base functionality for SMTP collectors
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


class SmtpServiceDescriptor(ServiceDescriptorBase):
    """
    This class describes how an SMTP service looks like
    """

    def __init__(self):
        super().__init__(default_tcp_ports=[25],
                         nmap_tcp_service_names=["^smtp$"],
                         nessus_tcp_service_names=["^smtp$"])


class BaseSmtpCollector(BaseCollector):
    """
    This is the base class for all SMTP collectors
    """

    def __init__(self, priority, timeout, **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=SmtpServiceDescriptor(),
                         **kwargs)


class BaseSmtpHydra(BaseHydra):
    """
    This class implements basic functionality for SMTP collectors that use Hydra.
    """
    def __init__(self, priority, timeout, **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=SmtpServiceDescriptor(),
                         **kwargs)


class BaseSmtpNmap(BaseNmap):
    """
    This class implements basic functionality for SMTP collectors that use Nmap.
    """
    def __init__(self, priority,
                 timeout,
                 nmap_xml_extractor_classes: List[BaseExtraServiceInfoExtraction],
                 **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=SmtpServiceDescriptor(),
                         nmap_xml_extractor_classes=nmap_xml_extractor_classes,
                         **kwargs)


class Pop3ServiceDescriptor(ServiceDescriptorBase):
    """
    This class describes how an POP3 service looks like
    """

    def __init__(self):
        super().__init__(default_tcp_ports=[110, 995],
                         nmap_tcp_service_names=["^pop3", "^pop3s"])


class BasePop3Collector(BaseCollector):
    """
    This is the base class for all POP3 collectors
    """

    def __init__(self, priority, timeout, **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=Pop3ServiceDescriptor(),
                         **kwargs)


class BasePop3Hydra(BaseHydra):
    """
    This class implements basic functionality for POP3 collectors that use Hydra.
    """
    def __init__(self, priority, timeout, **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=Pop3ServiceDescriptor(),
                         **kwargs)


class BasePop3Nmap(BaseNmap):
    """
    This class implements basic functionality for POP3 collectors that use Nmap.
    """
    def __init__(self, priority,
                 timeout,
                 nmap_xml_extractor_classes: List[BaseExtraServiceInfoExtraction],
                 **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=Pop3ServiceDescriptor(),
                         nmap_xml_extractor_classes=nmap_xml_extractor_classes,
                         **kwargs)


class ImapServiceDescriptor(ServiceDescriptorBase):
    """
    This class describes how an IMAP service looks like
    """

    def __init__(self):
        super().__init__(default_tcp_ports=[143, 993],
                         nmap_tcp_service_names=["^imap", "^imaps"])


class BaseImapCollector(BaseCollector):
    """
    This is the base class for all IMAP collectors
    """

    def __init__(self, priority, timeout, **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=ImapServiceDescriptor(),
                         **kwargs)


class BaseImapHydra(BaseHydra):
    """
    This class implements basic functionality for IMAP collectors that use Hydra.
    """
    def __init__(self, priority, timeout, **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=ImapServiceDescriptor(),
                         **kwargs)


class BaseImapNmap(BaseNmap):
    """
    This class implements basic functionality for IMAP collectors that use Nmap.
    """
    def __init__(self, priority,
                 timeout,
                 nmap_xml_extractor_classes: List[BaseExtraServiceInfoExtraction],
                 **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=ImapServiceDescriptor(),
                         nmap_xml_extractor_classes=nmap_xml_extractor_classes,
                         **kwargs)