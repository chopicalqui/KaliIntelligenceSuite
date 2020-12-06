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

import re
from typing import List
from database.model import CredentialType
from database.model import Service
from database.model import PathType
from collectors.os.modules.core import BaseCollector
from collectors.os.modules.core import BaseHydra
from collectors.os.modules.core import BaseMedusa
from collectors.os.modules.core import BaseNmap
from collectors.os.modules.core import ServiceDescriptorBase
from collectors.os.modules.core import BaseExtraServiceInfoExtraction
from collectors.core import XmlUtils
from sqlalchemy.orm.session import Session


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


class SmbExtraInfoExtraction(BaseExtraServiceInfoExtraction):
    """
    This class extracts extra information (e.g. user names, SMB shares) from SMB services.
    """
    SMB_ENUM_USERS = "smb-enum-users"
    SMB_ENUM_SHARES = "smb-enum-shares"
    SMB_SECURITY_MODE = "smb-security-mode"
    SMB2_SECURITY_MODE = "smb2-security-mode"
    SMB_OS_DISCOVERY = "smb-os-discovery"

    def __init__(self, session: Session, service: Service, **kwargs):
        super().__init__(session, service, **kwargs)
        self._re_user = re.compile("^(?P<domain>.*)\\\\(?P<user>.*) \(RID: (?P<rid>[0-9]+)\)$")
        self._re_path = re.compile("^\\\\\\\\.*?\\\\(?P<name>.+)$")

    def _extract_shares(self, host_tag):
        """Extracts SMB share information disclosed by SMB"""
        script = host_tag.findall("*/script/[@id='{}']".format(SmbExtraInfoExtraction.SMB_ENUM_SHARES))
        script_count = len(script)
        if script_count == 1:
            for table in script[0].findall("./table"):
                name = XmlUtils.get_xml_attribute("key", table.attrib)
                path_match = self._re_path.match(name)
                if path_match:
                    name = path_match.group("name")
                if name:
                    self._domain_utils.add_path(session=self._session,
                                                service=self._service,
                                                path=name,
                                                source=self._source,
                                                path_type=PathType.Smb_Share,
                                                report_item=self._report_item)
        elif script_count > 1:
            raise NotImplementedError("expected only one '/script/[@id='smb-enum-shares']' entry in "
                                      "'parseSmbEnumShares'.")

    def _extract_smb_message_signing(self, host_tag):
        """Extracts SMB share information disclosed by SMB"""
        script = host_tag.findall("*/script/[@id='{}']".format(SmbExtraInfoExtraction.SMB_SECURITY_MODE))
        for item in script:
            message_signing_tag = item.find("./elem[@key='message_signing']")
            if not message_signing_tag:
                self._domain_utils.add_additional_info(session=self._session,
                                                       name="SMB message signing",
                                                       values=[message_signing_tag.text],
                                                       source=self._source,
                                                       service=self._service,
                                                       report_item=self._report_item)

    def _extract_smb2_message_signing(self, host_tag):
        """Extracts SMB share information disclosed by SMB"""
        script = host_tag.findall("*/script/[@id='{}']".format(SmbExtraInfoExtraction.SMB2_SECURITY_MODE))
        for item in script:
            for table_tag in item.findall("table"):
                smb_version = XmlUtils.get_xml_attribute("key", table_tag.attrib)
                message = XmlUtils.get_element_text(table_tag, "elem")
                if smb_version and message:
                    self._domain_utils.add_additional_info(session=self._session,
                                                           name="SMB2 message signing",
                                                           values=["{} ({})".format(message, smb_version)],
                                                           source=self._source,
                                                           service=self._service,
                                                           report_item=self._report_item)

    def _extract_smb_os_discovery(self, host_tag):
        """Extracts SMB share information disclosed by SMB"""
        script = host_tag.findall("*/script/[@id='{}']".format(SmbExtraInfoExtraction.SMB_OS_DISCOVERY))
        for item in script:
            info = XmlUtils.get_element_text(item, "./elem[@key='os']")
            if info is not None:
                self._service.host.os_details = info
                if "windows" in info.lower():
                    self._service.host.os_family = "windows"
            info = XmlUtils.get_element_text(item, "./elem[@key='NetBIOS computer name']")
            if info is not None:
                self._service.host.workgroup = info
            if info is not None:
                self._service.host.os_details = info
                if "windows" in info.lower():
                    self._service.host.os_family = "windows"
            info = XmlUtils.get_element_text(item, "./elem[@key='FQDN']")
            if info is not None:
                self._domain_utils.add_domain_name(session=self._session,
                                                   workspace=self._workspace,
                                                   item=info,
                                                   host=self._service.host,
                                                   source=self._source,
                                                   verify=True,
                                                   report_item=self._report_item)
            info = XmlUtils.get_element_text(item, "./elem[@key='Domain name']")
            if info is not None:
                self._domain_utils.add_domain_name(session=self._session,
                                                   workspace=self._workspace,
                                                   item=info,
                                                   host=self._service.host,
                                                   source=self._source,
                                                   verify=True,
                                                   report_item=self._report_item)
            info = XmlUtils.get_element_text(item, "./elem[@key='Forest name']")
            if info is not None:
                self._domain_utils.add_domain_name(session=self._session,
                                                   workspace=self._workspace,
                                                   item=info,
                                                   host=self._service.host,
                                                   source=self._source,
                                                   verify=True,
                                                   report_item=self._report_item)

    def extract(self, **kwargs):
        """This method extracts disclosed information from SMB services."""
        self._extract_shares(kwargs["host_tag"])
        self._extract_smb_message_signing(kwargs["host_tag"])
        self._extract_smb2_message_signing(kwargs["host_tag"])
        self._extract_smb_os_discovery(kwargs["host_tag"])