# -*- coding: utf-8 -*-
"""This module implements core functionality for nmap parsers."""

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

import logging
from sqlalchemy.orm.session import Session
from database.model import Workspace
from database.model import Service
from database.model import Source
from collectors.os.modules.smb.core import SmbServiceDescriptor
from collectors.os.modules.smb.core import SmbExtraInfoExtraction
from collectors.os.modules.mssql.core import MsSqlServiceDescriptor
from collectors.os.modules.mssql.core import MsSqlExtraInfoExtraction
from collectors.os.modules.http.core import HttpServiceDescriptor
from collectors.os.modules.http.core import HttpExtraInfoExtraction
from collectors.os.modules.email.core import SmtpServiceDescriptor
from collectors.os.modules.email.core import SmtpExtraInfoExtraction
from collectors.os.modules.ssh.core import SshServiceDescriptor
from collectors.os.modules.ssh.core import SshExtraInfoExtraction
from collectors.os.modules.rdp.core import RdpServiceDescriptor
from collectors.os.modules.rdp.core import RdpExtraInfoExtraction
from collectors.os.modules.tftp.core import TftpServiceDescriptor
from collectors.os.modules.tftp.core import TftpExtraInfoExtraction
from collectors.os.modules.rpc.core import RpcBindServiceDescriptor
from collectors.os.modules.rpc.core import RpcInfoExtraInfoExtraction
from collectors.os.modules.tls.core import TlsServiceDescriptor
from collectors.os.modules.tls.core import CertInfoExtraction
from collectors.os.modules.tls.core import TlsInfoExtraction
from collectors.os.modules.tcptraceroute import TracerouteExtraction

logger = logging.getLogger("nmap.core")


class ExtractionMapper:
    """
    This class checks whether the given service matches the service descriptor and if it does, then it performs the
    extraction.
    """

    def __init__(self,
                 nmap_extractor_class,
                 service_descriptor_classes = [],
                 tls_info: bool = False):
        self._service_descriptors = [item() for item in service_descriptor_classes]
        self._nmap_extractor_class = nmap_extractor_class
        self._tls_info = tls_info

    def run_extraction(self,
                       session: Session,
                       workspace: Workspace,
                       domain_utils,
                       ip_utils,
                       service: Service,
                       source: Source,
                       report_item,
                       **kwargs):
        extractor = self._nmap_extractor_class(session=session,
                                               workspace=workspace,
                                               domain_utils=domain_utils,
                                               ip_utils=ip_utils,
                                               service=service,
                                               source=source,
                                               report_item=report_item)
        if self._service_descriptors:
            for item in self._service_descriptors:
                if (not self._tls_info and item.match_nmap_service_name(service)) or \
                        (self._tls_info and item.match_tls(service)):
                    extractor.extract(**kwargs)
                    break
        else:
            extractor.extract(**kwargs)


class NmapExtractor:
    """
    This method is used by the Nmap file parser to parse all NSE script outputs
    """

    def __init__(self):
        self._mappers = [
            ExtractionMapper(service_descriptor_classes=[SmbServiceDescriptor],
                             nmap_extractor_class=SmbExtraInfoExtraction),
            ExtractionMapper(service_descriptor_classes=[MsSqlServiceDescriptor],
                             nmap_extractor_class=MsSqlExtraInfoExtraction),
            ExtractionMapper(service_descriptor_classes=[HttpServiceDescriptor],
                             nmap_extractor_class=HttpExtraInfoExtraction),
            ExtractionMapper(service_descriptor_classes=[SmtpServiceDescriptor],
                             nmap_extractor_class=SmtpExtraInfoExtraction),
            ExtractionMapper(service_descriptor_classes=[SshServiceDescriptor],
                             nmap_extractor_class=SshExtraInfoExtraction),
            ExtractionMapper(service_descriptor_classes=[RdpServiceDescriptor],
                             nmap_extractor_class=RdpExtraInfoExtraction),
            ExtractionMapper(service_descriptor_classes=[TftpServiceDescriptor],
                             nmap_extractor_class=TftpExtraInfoExtraction),
            ExtractionMapper(service_descriptor_classes=[RpcBindServiceDescriptor],
                             nmap_extractor_class=RpcInfoExtraInfoExtraction),
            ExtractionMapper(service_descriptor_classes=[TlsServiceDescriptor],
                             nmap_extractor_class=CertInfoExtraction,
                             tls_info=True),
            ExtractionMapper(service_descriptor_classes=[TlsServiceDescriptor],
                             nmap_extractor_class=TlsInfoExtraction,
                             tls_info=True),
            ExtractionMapper(nmap_extractor_class=TracerouteExtraction)]

    def execute(self, **kwargs):
        for mapper in self._mappers:
            mapper.run_extraction(**kwargs)

