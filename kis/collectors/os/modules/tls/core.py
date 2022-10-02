# -*- coding: utf-8 -*-
"""
implements all base functionality for TLS collectors
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

from database.model import Service
from database.model import CertType
from database.model import TlsInfo
from database.model import TlsInfoCipherSuiteMapping
from collectors.os.modules.core import BaseCollector
from collectors.os.modules.core import BaseHydra
from collectors.os.modules.core import BaseNmap
from collectors.os.modules.core import ServiceDescriptorBase
from collectors.os.modules.core import BaseExtraServiceInfoExtraction
from collectors.core import XmlUtils
from sqlalchemy.orm.session import Session


class TlsServiceDescriptor(ServiceDescriptorBase):
    """
    This class describes how an TLS service looks like
    """

    def __init__(self):
        super().__init__()


class BaseTlsCollector(BaseCollector):
    """
    This is the base class for all TLS collectors
    """

    def __init__(self, priority, timeout, **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=TlsServiceDescriptor(),
                         **kwargs)


class BaseTlsHydra(BaseHydra):
    """
    This class implements basic functionality for TLS collectors that use Hydra.
    """
    def __init__(self, priority, timeout, **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=TlsServiceDescriptor(),
                         **kwargs)


class BaseTlsNmap(BaseNmap):
    """
    This class implements basic functionality for TLS collectors that use Hydra.
    """
    def __init__(self, priority,
                 timeout,
                 **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=TlsServiceDescriptor(),
                         **kwargs)


class CertInfoExtraction(BaseExtraServiceInfoExtraction):
    """
    This class extracts extra information disclosed by RpcInfo service.
    """
    CERT_INFO = "ssl-cert"

    def __init__(self, session: Session, service: Service, **args):
        super().__init__(session, service, **args)

    def _extract_dns_info(self, port_tag) -> None:
        """This method determines additional services disclosed by rpcinfo"""
        script = port_tag.find("*/[@id='{}']".format(CertInfoExtraction.CERT_INFO))
        if script:
            pem_tag = script.find("./elem[@key='pem']")
            if not pem_tag and self._command:
                content = pem_tag.text
                self._domain_utils.add_cert_info(session=self._session,
                                                 pem=content,
                                                 cert_type=CertType.identity,
                                                 source=self._source,
                                                 command=self._command,
                                                 service=self._service,
                                                 report_item=self._report_item)

    def extract(self, **kwargs):
        """This method extracts the required information."""
        self._extract_dns_info(kwargs["port_tag"])


class TlsInfoExtraction(BaseExtraServiceInfoExtraction):
    """
    This class extracts extra information disclosed by RpcInfo service.
    """
    TLS_INFO = "ssl-enum-ciphers"

    def __init__(self, session, service: Service, **args):
        super().__init__(session, service, **args)

    def _get_elem_text(self, parent_tag, query: str) -> str:
        result = parent_tag.find(query)
        if result is not None:
            result = result.text
        return result

    def _extract_tls_info(self, port_tag) -> None:
        """This method determines additional services disclosed by rpcinfo"""
        script = port_tag.find("*/[@id='{}']".format(TlsInfoExtraction.TLS_INFO))
        if script:
            for tls_version_tag in script.findall("table"):
                order = 0
                tls_version_str = XmlUtils.get_xml_attribute("key", tls_version_tag.attrib)
                if tls_version_str:
                    tls_version = TlsInfo.get_tls_version(tls_version_str)
                    if tls_version:
                        preference_str = self._get_elem_text(tls_version_tag, query="elem[@key='cipher preference']")
                        if preference_str:
                            preference = TlsInfo.get_tls_preference(preference_str)
                            if preference:
                                tls_info = self._domain_utils.add_tls_info(session=self._session,
                                                                           service=self._service,
                                                                           version=tls_version,
                                                                           preference=preference,
                                                                           report_item=self._report_item)
                                compressor_tag = tls_version_tag.find("table[@key='compressors']")
                                if compressor_tag is not None:
                                    tls_info.compressors = [item.text for item in compressor_tag.findall("elem")
                                                            if item.text != 'NULL']
                                for cipher_tag in tls_version_tag.findall("table[@key='ciphers']"):
                                    for table_tag in cipher_tag.findall("table"):
                                        order += 1
                                        kex_info = self._get_elem_text(table_tag, query="elem[@key='kex_info']")
                                        kex_info = TlsInfoCipherSuiteMapping.get_kex_algorithm(kex_info, self._source)
                                        if kex_info:
                                            tls_cipher = self._get_elem_text(table_tag, query="elem[@key='name']")
                                            self._domain_utils.add_tls_info_cipher_suite_mapping(session=self._session,
                                                                                                 tls_info=tls_info,
                                                                                                 order=order,
                                                                                                 kex_algorithm_details=kex_info,
                                                                                                 iana_name=tls_cipher,
                                                                                                 source=self._source,
                                                                                                 prefered=order == 1,
                                                                                                 report_item=self._report_item)
                            else:
                                raise NotImplementedError("unknown TLS preference: {}".format(preference_str))
                    else:
                        raise NotImplementedError("unknown TLS version: {}".format(tls_version_str))

    def extract(self, **kwargs):
        """This method extracts the required information."""
        self._extract_tls_info(kwargs["port_tag"])