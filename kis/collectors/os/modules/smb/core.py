# -*- coding: utf-8 -*-
"""
implements all base functionality for SMB collectors
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
from database.model import CredentialType
from collectors.os.modules.core import BaseCollector
from collectors.os.modules.core import BaseHydra
from collectors.os.modules.core import BaseMedusa
from collectors.os.modules.core import BaseNmap
from collectors.os.modules.core import ServiceDescriptorBase
from collectors.filesystem.nmap import BaseExtraServiceInfoExtraction


class SmbServiceDescriptor(ServiceDescriptorBase):
    """
    This class describes how an SMB service looks like
    """

    def __init__(self):
        super().__init__(default_tcp_ports=[445],
                         nmap_tcp_service_names=["^microsoft\-ds$"],
                         nessus_tcp_service_names=["^cifs$"])


class BaseSmbCollector(BaseCollector):
    """
    This is the base class for all SMB collectors
    """

    def __init__(self, priority, timeout, **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=SmbServiceDescriptor(),
                         **kwargs)


class BaseSmbHydra(BaseHydra):
    """
    This class implements basic functionality for SMB collectors that use Hydra.
    """
    def __init__(self, priority, timeout, **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=SmbServiceDescriptor(),
                         **kwargs)


class BaseSmbMedusa(BaseMedusa):
    """
    This class implements basic functionality for SMB collectors that use Medusa.
    """
    def __init__(self, priority, timeout, **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=SmbServiceDescriptor(),
                         **kwargs)


class BaseSmbNmap(BaseNmap):
    """
    This class implements basic functionality for SMB collectors that use Hydra.
    """
    def __init__(self, priority,
                 timeout,
                 nmap_xml_extractor_classes: List[BaseExtraServiceInfoExtraction],
                 **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=SmbServiceDescriptor(),
                         nmap_xml_extractor_classes=nmap_xml_extractor_classes,
                         **kwargs)

    @staticmethod
    def create_credential_argument(username: str,
                                   password: str,
                                   credential_type: CredentialType = None,
                                   domain: str = None) -> List[str]:
        """
        This method should be used by all collectors to create the argument list for commands
        :param username: The user name
        :param password: The password
        :param domain: The domain or workgroup
        :param credential_type: Hash or Cleartext
        :return:
        """
        result = []
        if username:
            result += ["smbusername={}".format(username)]
        if password:
            password_argument = "smbhash" if credential_type == CredentialType.Hash else "smbpassword"
            result += ["{}={}".format(password_argument, password)]
        if domain:
            result += ["smbdomain={}".format(domain)]
        return result
