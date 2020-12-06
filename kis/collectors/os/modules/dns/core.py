# -*- coding: utf-8 -*-
"""
implements all base functionality for DNS collectors
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
import logging
from collectors.os.modules.core import BaseCollector
from collectors.os.modules.core import BaseHydra
from collectors.os.modules.core import BaseNmap
from collectors.os.modules.core import ServiceDescriptorBase
from collectors.os.modules.core import CommandFailureRule
from collectors.os.modules.core import OutputType
from collectors.os.modules.core import BaseExtraServiceInfoExtraction
from collectors.os.core import PopenCommand
from database.model import Command
from database.model import Source
from database.model import DnsResourceRecordType
from view.core import ReportItem
from typing import List
from sqlalchemy.orm.session import Session

logger = logging.getLogger('dns.core')


class DnsServiceDescriptor(ServiceDescriptorBase):
    """This class describes how an DNS service looks like"""

    def __init__(self):
        super().__init__(default_tcp_ports=[53],
                         default_udp_ports=[53],
                         nmap_tcp_service_names=["^domain$"],
                         nmap_udp_service_names=["^domain$"],
                         nessus_tcp_service_names=["^dns$"],
                         nessus_udp_service_names=["^dns$"])


class BaseDnsCollector(BaseCollector):
    """
    This is the base class for all DNS collectors
    """

    def __init__(self, priority, timeout, **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=DnsServiceDescriptor(),
                         **kwargs)


class BaseDnsHydra(BaseHydra):
    """
    This class implements basic functionality for DNS collectors that use Hydra.
    """
    def __init__(self, priority, timeout, **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=DnsServiceDescriptor(),
                         **kwargs)


class BaseDnsNmap(BaseNmap):
    """
    This class implements basic functionality for DNS collectors that use Nmap.
    """
    def __init__(self, priority,
                 timeout,
                 nmap_xml_extractor_classes: List[BaseExtraServiceInfoExtraction],
                 **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=DnsServiceDescriptor(),
                         nmap_xml_extractor_classes=nmap_xml_extractor_classes,
                         **kwargs)


class BaseDnsHost(BaseDnsCollector):
    """This class implements a collector module that is automatically incorporated into the application."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._re_ipv4 = re.compile("^(?P<domain>.+?)\.? has address (?P<address>.+)$")
        self._re_ipv6 = re.compile("^(?P<domain>.+?)\.? has IPv6 address (?P<address>.+)$", re.IGNORECASE)
        self._re_host_mx = re.compile("^.+ mail is handled by( [0-9]+)? (?P<domain>.+?)\.?$")
        self._re_cname = re.compile("(?P<domain1>.+?)\.? is an alias for (?P<domain2>.+?)\.?$")

    @staticmethod
    def get_failed_regex() -> List[CommandFailureRule]:
        """
        This method returns regular expressions that allows KIS to identify failed command executions
        """
        return [CommandFailureRule(regex=re.compile("^.*connection timed out; no servers could be reached.*$"),
                                   output_type=OutputType.stdout)]

    def verify_results(self, session: Session,
                       command: Command,
                       source: Source,
                       report_item: ReportItem,
                       process: PopenCommand = None, **kwargs) -> None:
        """This method analyses the results of the command execution.

        After the execution, this method checks the OS command's results to determine the command's execution status as
        well as existing vulnerabilities (e.g. weak login credentials, NULL sessions, hidden Web folders). The
        stores the output in table command. In addition, the collector might add derived information to other tables as
        well.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param command: The command instance that contains the results of the command execution
        :param source: The source object of the current collector
        :param report_item: Item that can be used for reporting potential findings in the UI
        :param process: The PopenCommand object that executed the given result. This object holds stderr, stdout, return
        code etc.
        """
        command.hide = True
        for line in command.stdout_output:
            ipv4_match = self._re_ipv4.match(line)
            ipv6_match = self._re_ipv6.match(line)
            cname_match = self._re_cname.match(line)
            mx_host_match = self._re_host_mx.match(line)
            if ipv4_match:
                source_host_str = ipv4_match.group("domain").strip()
                address = ipv4_match.group("address")
                # Add IPv4 address to database
                host = self.add_host(session=session,
                                     command=command,
                                     source=source,
                                     address=address,
                                     report_item=report_item)
                if source_host_str and source_host_str != command.host_name.full_name:
                    source_host = self.add_host_name(session=session,
                                                     command=command,
                                                     host_name=source_host_str,
                                                     source=source,
                                                     report_item=report_item)
                    if source_host and host:
                        self._domain_utils.add_host_host_name_mapping(session=session,
                                                                      host=host,
                                                                      host_name=source_host,
                                                                      source=source,
                                                                      mapping_type=DnsResourceRecordType.a,
                                                                      report_item=report_item)
                        session.flush()
                    else:
                        logger.debug("could not link host name '{}' with host '{}'".format(source_host_str, address))
                if address and not host:
                    logger.debug("ignoring host due to invalid IPv4 address in line: {}".format(line))
                elif host:
                    self._domain_utils.add_host_host_name_mapping(session=session,
                                                                  host=host,
                                                                  host_name=command.host_name,
                                                                  source=source,
                                                                  mapping_type=DnsResourceRecordType.a,
                                                                  report_item=report_item)
                    session.flush()
            elif ipv6_match:
                source_host_str = ipv6_match.group("domain").strip()
                address = ipv6_match.group("address")
                # Add IPv4 address to database
                host = self.add_host(session=session,
                                     command=command,
                                     source=source,
                                     address=address,
                                     report_item=report_item)
                if source_host_str and source_host_str != command.host_name.full_name:
                    source_host = self.add_host_name(session=session,
                                                     command=command,
                                                     host_name=source_host_str,
                                                     source=source,
                                                     report_item=report_item)
                    if source_host and host:
                        self._domain_utils.add_host_host_name_mapping(session=session,
                                                                      host=host,
                                                                      host_name=source_host,
                                                                      source=source,
                                                                      mapping_type=DnsResourceRecordType.aaaa,
                                                                      report_item=report_item)
                        session.flush()
                    else:
                        logger.debug("could not link host name '{}' with host '{}'".format(source_host_str, address))
                if address and not host:
                    logger.debug("ignoring host due to invalid IPv6 address in line: {}".format(line))
                elif host:
                    self._domain_utils.add_host_host_name_mapping(session=session,
                                                                  host=host,
                                                                  host_name=command.host_name,
                                                                  source=source,
                                                                  mapping_type=DnsResourceRecordType.aaaa,
                                                                  report_item=report_item)
                    session.flush()
            elif mx_host_match:
                mx_host_name = mx_host_match.group("domain")
                # Add host name to database
                host_name = self.add_host_name(session=session,
                                               command=command,
                                               source=source,
                                               host_name=mx_host_name,
                                               report_item=report_item)
                if not host_name:
                    logger.debug("ignoring host name due to invalid domain in line: {}".format(line))
            elif cname_match:
                source_domain = cname_match.group("domain1").strip()
                target_domain = cname_match.group("domain2").strip()
                source_host_name = self.add_host_name(session=session,
                                                      command=command,
                                                      host_name=source_domain,
                                                      source=source,
                                                      report_item=report_item)
                target_host_name = self.add_host_name(session=session,
                                                      command=command,
                                                      host_name=target_domain,
                                                      source=source,
                                                      report_item=report_item)
                if not source_host_name:
                    logger.debug("ignoring host name due to invalid domain in line: {}".format(source_domain))
                elif not target_host_name:
                    logger.debug("ignoring host name due to invalid domain in line: {}".format(source_domain))
                else:
                    self.add_host_name_host_name_mapping(session=session,
                                                         command=command,
                                                         source_host_name=source_host_name,
                                                         resolved_host_name=target_host_name,
                                                         source=source,
                                                         mapping_type=DnsResourceRecordType.cname,
                                                         report_item=report_item)
