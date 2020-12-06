# -*- coding: utf-8 -*-
"""
implements all base functionality for RPC collectors
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
import os
from typing import List
from database.model import Service
from database.model import ServiceState
from database.model import Source
from database.utils import Engine
from collectors.os.modules.core import BaseCollector
from collectors.os.modules.core import BaseHydra
from collectors.os.modules.core import ServiceDescriptorBase
from collectors.os.modules.core import BaseNmap
from collectors.os.modules.core import BaseExtraServiceInfoExtraction
from collectors.core import XmlUtils
from sqlalchemy.orm.session import Session


class RpcBindServiceDescriptor(ServiceDescriptorBase):
    """
    This class describes how an rpcbind service looks like
    """

    def __init__(self):
        super().__init__(default_tcp_ports=[111],
                         default_udp_ports=[111],
                         nmap_tcp_service_names=["^rpcbind$"],
                         nmap_udp_service_names=["^rpcbind$"],
                         nessus_tcp_service_names=["^rpc-portmapper$"],
                         nessus_udp_service_names=["^rpc-portmapper$"])


class BaseRpcBindCollector(BaseCollector):
    """
    This is the base class for all rpcbind collectors
    """

    def __init__(self, priority, timeout, **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=RpcBindServiceDescriptor(),
                         **kwargs)


class BaseRpcBindSqlHydra(BaseHydra):
    """
    This class implements basic functionality for rpcbind collectors that use Hydra.
    """
    def __init__(self, priority, timeout, **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=RpcBindServiceDescriptor(),
                         **kwargs)


class BaseRpcBindNmap(BaseNmap):
    """
    This class implements basic functionality for rpcbind collectors that use Nmap.
    """
    def __init__(self, priority,
                 timeout,
                 nmap_xml_extractor_classes: List[BaseExtraServiceInfoExtraction],
                 **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=RpcBindServiceDescriptor(),
                         nmap_xml_extractor_classes=nmap_xml_extractor_classes,
                         **kwargs)


class RpcInfoExtraInfoExtraction(BaseExtraServiceInfoExtraction):
    """
    This class extracts extra information disclosed by RpcInfo service.
    """
    RPC_INFO = "rpcinfo"

    def __init__(self, session: Session, service: Service, **args):
        super().__init__(session, service, **args)
        self._re_process = re.compile("^\s*\d+\s+[\d\,]+\s+(?P<port>\d+)/(?P<protocol>[a-zA-Z]*)\s+(?P<service>.*)$")
        self._source_rpc_info = Engine.get_or_create(self._session, Source, name=Source.RPCINFO)

    def _extract_rpc_info(self, port_tag) -> None:
        """This method determines additional services disclosed by rpcinfo"""
        script = port_tag.findall("*/[@id='{}']".format(RpcInfoExtraInfoExtraction.RPC_INFO))
        if len(script) > 0:
            tmp = XmlUtils.get_xml_attribute("output", script[0].attrib).split(os.linesep)
            for item in tmp:
                match = self._re_process.match(item)
                if match:
                    port = match.group("port")
                    protocol = match.group("protocol")
                    protocol = Service.get_protocol_type(protocol)
                    service_name = match.group("service")
                    service = self._domain_utils.add_service(session=self._session,
                                                             port=port,
                                                             protocol_type=protocol,
                                                             host=self._service.host,
                                                             state=ServiceState.Internal,
                                                             source=self._source_rpc_info,
                                                             report_item=self._report_item)
                    if service:
                        service.nmap_service_name = service_name if not service.nmap_service_name \
                            else service.nmap_service_name
                        service.state = ServiceState.Internal if service.state != ServiceState.Open else service.state

    def extract(self, **kwargs):
        """This method extracts the required information."""
        self._extract_rpc_info(kwargs["port_tag"])