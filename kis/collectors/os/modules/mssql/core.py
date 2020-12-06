# -*- coding: utf-8 -*-
"""
implements all base functionality for Microsoft SQL Server (MSSQL) collectors
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
from database.model import Service
from database.model import ServiceState
from database.model import ProtocolType
from collectors.os.modules.core import BaseCollector
from collectors.os.modules.core import BaseHydra
from collectors.os.modules.core import ServiceDescriptorBase
from collectors.os.modules.core import BaseNmap
from collectors.os.modules.core import BaseExtraServiceInfoExtraction
from collectors.core import XmlUtils
from sqlalchemy.orm.session import Session


class MsSqlServiceDescriptor(ServiceDescriptorBase):
    """
    This class describes how an MSSQL service looks like
    """

    def __init__(self):
        super().__init__(default_tcp_ports=[1433, 1434, 9152],
                         default_udp_ports=[1433, 1434, 9152],
                         nmap_tcp_service_names=["^ms\-sql\-.*$"],
                         nmap_udp_service_names=["^ms\-sql\-.*$"],
                         nessus_tcp_service_names=["^mssql$", "^ms\-sql\-.*$"],
                         nessus_udp_service_names=["^mssql$", "^ms\-sql\-.*$"])


class BaseMsSqlCollector(BaseCollector):
    """
    This is the base class for all MSSQL collectors
    """

    def __init__(self, priority, timeout, **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=MsSqlServiceDescriptor(),
                         **kwargs)


class BaseMsSqlHydra(BaseHydra):
    """
    This class implements basic functionality for MSSQL collectors that use Hydra.
    """
    def __init__(self, priority, timeout, **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=MsSqlServiceDescriptor(),
                         **kwargs)


class BaseMsSqlNmap(BaseNmap):
    """
    This class implements basic functionality for rpcbind collectors that use Nmap.
    """
    def __init__(self, priority,
                 timeout,
                 nmap_xml_extractor_classes: List[BaseExtraServiceInfoExtraction],
                 **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=MsSqlServiceDescriptor(),
                         nmap_xml_extractor_classes=nmap_xml_extractor_classes,
                         **kwargs)


class MsSqlExtraInfoExtraction(BaseExtraServiceInfoExtraction):
    """
    This class extracts extra information (e.g. user names, SMB shares) from MS-SQL services.
    """
    MSSQL_TCP_PORTS = "ms-sql-info"
    MSSQL_NTLM_INFO = "ms-sql-ntlm-info"
    MSSQL_SERVICE_NAME = ["ms-sql-m", "ms-sql-s"]

    def __init__(self, session: Session, service: Service, **args):
        super().__init__(session, service, **args)

    def _extract_sql_info(self, host_tag):
        """This method extracts the required information."""
        script = host_tag.findall("*/script/[@id='{}']".format(MsSqlExtraInfoExtraction.MSSQL_TCP_PORTS))
        script_count = len(script)
        if script_count == 1:
            for table in script[0].findall("./table"):
                tcp_port = XmlUtils.get_xml_text(table.findall(".//*[@key='TCP port']"))
                if tcp_port:
                    service = self._domain_utils.add_service(session=self._session,
                                                             port=tcp_port,
                                                             protocol_type=ProtocolType.tcp,
                                                             state=ServiceState.Open,
                                                             host=self._service.host,
                                                             source=self._source,
                                                             report_item=self._report_item)
                    if service:
                        service.nmap_service_name = MsSqlExtraInfoExtraction.MSSQL_SERVICE_NAME[0]
        elif script_count > 1:
            raise NotImplementedError("expected only one '/script/[@id='{}']' entry.".format(
                MsSqlExtraInfoExtraction.MSSQL_TCP_PORTS))

    def _extract_ntlm_info(self, port_tag) -> None:
        """This method extracts NTLM information"""
        super()._extract_ntlm_info(port_tag, tag_id=MsSqlExtraInfoExtraction.MSSQL_NTLM_INFO)

    def extract(self, **kwargs):
        """This method extracts disclosed information from SMB services."""
        self._extract_sql_info(kwargs["host_tag"])
        self._extract_ntlm_info(kwargs["port_tag"])