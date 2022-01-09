# -*- coding: utf-8 -*-
"""This module allows querying information about IPv4/IPv6 addresses."""

__author__ = "Lukas Reiter"
__license__ = "GPL v3.0"
__copyright__ = """Copyright 2022 Lukas Reiter

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

import argparse
from typing import List
from openpyxl import Workbook
from database.model import Host
from database.model import VhostChoice
from database.model import ServiceState
from database.model import CollectorType
from database.model import ReportScopeType
from database.model import ReportVisibility
from database.model import TextReportDetails
from database.model import DnsResourceRecordType
from collectors.os.modules.http.core import HttpServiceDescriptor
from database.report.core import BaseReport
from database.report.core import ReportLanguage


class ReportClass(BaseReport):
    """
    this module allows querying information about services
    """

    def __init__(self, args, **kwargs) -> None:
        super().__init__(args=args,
                         name="service info",
                         title="Overview Identified Services",
                         description="This table provides a consolidated view about all IP addresses (see column "
                                     "'IP Address (IP)'), their virtual hosts (see column 'Host Name (HN)') as well as "
                                     "their identified TCP/UDP services (see columns 'UDP/TCP' and 'Port'). "
                                     ""
                                     "If you are just interested in service information on the IP address level, then "
                                     "filter for value 'Host' in column 'Type'. If you are interested in service "
                                     "information on the virtual host level, filter for value 'VHost' in column "
                                     "'Type'. "
                                     ""
                                     "Note that host names, which do not resolve to an IP address, are not listed in "
                                     "this sheet; use sheet 'host name info' to analyse them.",
                         **kwargs)
        self._type = None
        # The module final of kisreport does not contain arguments --type and --filter
        if args.module != "final":
            self._type = VhostChoice[args.report_level] if args.report_level else None
            if self._type == VhostChoice.all and args.filter:
                raise NotImplementedError("argument --filter is not supported in combination with type option all.")
            if self._type == VhostChoice.all:
                self.title += " (Hosts and Vhosts)"
            elif self._type == VhostChoice.domain:
                self.title += " (Vhosts)"
            else:
                self.title += " (Hosts)"

    @staticmethod
    def get_add_argparse_arguments(parser: argparse.ArgumentParser):
        """
        This method adds the report's specific command line arguments.
        """
        parser.add_argument("-w", "--workspaces",
                            metavar="WORKSPACE",
                            help="query the given workspaces",
                            nargs="+",
                            type=str)
        parser_group = parser.add_mutually_exclusive_group()
        parser_group.add_argument('--text', action='store_true',
                                  help='returns gathered information including all collector outputs as text')
        parser_group.add_argument('--csv', action='store_true', default=True,
                                  help='returns gathered information in csv format')
        parser_group.add_argument('--igrep', type=str, nargs='+', metavar="REGEX",
                                  help="print command outputs that match the given string or Python3 regular "
                                       "expressions REGEX. matching is case insensitive. use named group 'output' "
                                       "to just capture the content of this named group")
        parser_group.add_argument('--grep', type=str, nargs='+', metavar="REGEX",
                                  help="print command outputs that match the given string or Python3 regular "
                                       "expressions REGEX. matching is case sensitive. use named group 'output' "
                                       "to just capture the content of this named group")
        parser.add_argument('--not', dest="grep_not", action='store_true',
                            help='negate the filter logic and only show those IP addresses/vhosts that do not '
                                 'match the --igrep or --grep argument.')
        parser.add_argument("-r", "--report-level", choices=[item.name for item in VhostChoice],
                            help="per default, this module reports only service information associated with hosts. if "
                                 "you also need service information associated with virtual hosts, then use type "
                                 "option 'domain' or 'all' to obtain both."
                                 ""
                                 "Note that option 'all' makes only sense in combination with argument --csv.")
        parser.add_argument('--filter', metavar='IP|NETWORK|DOMAIN|HOSTNAME', type=str, nargs='*',
                            help='list of IP addresses, IP networks, second-level domains (e.g., megacorpone.com), or '
                                 'host names (e.g., www.megacorpone.com) whose information shall be returned.'
                                 'per default, mentioned items are excluded. add + in front of each item '
                                 '(e.g., +192.168.0.1) to return only these items')
        parser.add_argument('--scope', choices=[item.name for item in ReportScopeType],
                            help='return only networks or hosts that are in scope (within) or out of scope '
                                 '(outside). per default, all information is returned')
        parser.add_argument('--visibility', choices=[item.name for item in ReportVisibility],
                            help='return only relevant (relevant) or potentially irrelevant (irrelevant) information '
                                 'in text output (argument --text). examples of potentially irrelevant information '
                                 'are hosts with no open ports or operating system commands that did not return '
                                 'any results. per default, all information is returned')
        parser.add_argument('-X', '--exclude', metavar='COLLECTOR', type=str, nargs='+', default=[],
                            help='list of collector names (e.g., httpnikto) whose outputs should not be returned in '
                                 'text mode (see argument --text). use argument value "all" to exclude all '
                                 'collectors. per default, no collectors are excluded')
        parser.add_argument('-I', '--include', metavar='COLLECTOR', type=str, nargs='+', default=[],
                            help='list of collector names whose outputs should be returned in text mode (see '
                                 'argument --text). per default, all collector information is returned')

    def _filter(self, item: object) -> bool:
        """
        Method determines whether the given item shall be included into the report
        """
        if isinstance(item, Host):
            result = item.is_processable(included_items=self._included_items,
                                         excluded_items=self._excluded_items,
                                         scope=self._scope,
                                         include_host_names=True)
        else:
            result = item.is_processable(included_items=self._included_items,
                                         excluded_items=self._excluded_items,
                                         collector_type=CollectorType.vhost_service,
                                         scope=self._scope,
                                         include_ip_address=True)
        return result

    def _egrep_text(self, item: object) -> List[str]:
        """
        This method returns all lines matching the given list of regular expressions
        :param item: The item whose text output shall be parsed
        :return:
        """
        result = self._egrep(item.get_text(ident=0,
                                           exclude_collectors=self._excluded_collectors,
                                           include_collectors=self._included_collectors,
                                           scope=self._scope,
                                           details=TextReportDetails(TextReportDetails.service_info)))
        return result

    def _get_text_host(self) -> List[str]:
        rvalue = []
        for workspace in self._workspaces:
            for host in workspace.hosts:
                if self._filter(host):
                    rvalue.extend(host.get_text(ident=0,
                                                scope=self._scope,
                                                exclude_collectors=self._excluded_collectors,
                                                include_collectors=self._included_collectors,
                                                report_visibility=self._visibility,
                                                details=TextReportDetails(
                                                    TextReportDetails.meta_data | TextReportDetails.service_info),
                                                color=self._color))
        return rvalue

    def _get_text_vhost(self) -> List[str]:
        rvalue = []
        for workspace in self._workspaces:
            for domain in workspace.domain_names:
                for item in domain.host_names:
                    if self._filter(item):
                        rvalue.extend(item.get_text(ident=0,
                                                    scope=self._scope,
                                                    exclude_collectors=self._excluded_collectors,
                                                    include_collectors=self._included_collectors,
                                                    report_visibility=self._visibility,
                                                    details=TextReportDetails(
                                                        TextReportDetails.meta_data | TextReportDetails.service_info),
                                                    color=self._color))
        return rvalue

    def get_text(self):
        if self._type == VhostChoice.all:
            result = self._get_text_host()
            result += self._get_text_vhost()
        elif self._type == VhostChoice.domain:
            result = self._get_text_vhost()
        else:
            result = self._get_text_host()
        return result

    def _grep_text_host(self) -> List[List[str]]:
        rows = [["DB ID",
                 "Workspace",
                 "Network",
                 "Companies",
                 "In Scope",
                 "Address",
                 "Result"]]
        for workspace in self._workspaces:
            for host in workspace.hosts:
                if self._filter(host):
                    ipv4_network = None
                    companies = None
                    if host.ipv4_network:
                        ipv4_network = host.ipv4_network.network
                        companies = host.ipv4_network.companies_str
                    results = self._egrep_text(host)
                    if self._not_grep and not results:
                        rows.append([host.id,
                                     workspace.name,
                                     ipv4_network,
                                     companies,
                                     host.in_scope,
                                     host.ip,
                                     None])
                    elif not self._not_grep:
                        for result in results:
                            rows.append([host.id,
                                         workspace.name,
                                         ipv4_network,
                                         companies,
                                         host.in_scope,
                                         host.ip,
                                         result])
        return rows

    def _grep_text_vhost(self) -> List[List[str]]:
        rows = [["DB ID (Domain)",
                 "DB ID (Hostname)",
                 "Host Name",
                 "Host Name Scope",
                 "Companies",
                 "Result"]]
        for workspace in self._workspaces:
            for domain in workspace.domain_names:
                for host_name in domain.host_names:
                    if self._filter(host_name):
                        results = self._egrep_text(host_name)
                        if self._not_grep and not results:
                            rows.append([host_name.id,
                                         workspace.name,
                                         host_name.full_name,
                                         host_name._in_scope,
                                         domain.companies_str,
                                         None])
                        elif not self._not_grep:
                            for result in results:
                                rows.append([domain.id,
                                             workspace.name,
                                             domain.name,
                                             domain.scope_str,
                                             domain.companies_str,
                                             result])
        return rows

    def grep_text(self) -> List[List[str]]:
        if self._type == VhostChoice.all:
            result = self._grep_text_host()
            result += self._grep_text_vhost()
        elif self._type == VhostChoice.domain:
            result = self._grep_text_vhost()
        else:
            result = self._grep_text_host()
        return result

    def _get_csv_host(self) -> List[List[str]]:
        result = [["Workspace",
                   "Network (NW)",
                   "Scope (NW)",
                   "Companies (NW)",
                   "IP Address (IP)",
                   "In Scope (IP)",
                   "Private IP",
                   "Hostnames",
                   "Service Summary",
                   "TCP/UDP",
                   "Port",
                   "Service (SRV)",
                   "State",
                   "TLS",
                   "Nmap Reason",
                   "Nmap Name",
                   "Nmap Confidence",
                   "Nmap Name Original",
                   "Nmap Product",
                   "Version",
                   "Product Summary",
                   "Sources (IP)",
                   "Sources (SRV)",
                   "No. Commands (SRV)",
                   "No. Vulnerabilities (SRV)",
                   "DB ID (IP)",
                   "DB ID (SRV)"]]
        for workspace in self._workspaces:
            for host in workspace.hosts:
                if self._filter(host):
                    host_names = host.get_host_host_name_mappings_str(types=[DnsResourceRecordType.a,
                                                                             DnsResourceRecordType.aaaa])
                    network_companies = host.ipv4_network.companies_str
                    private_ip = host.ip_address.is_private
                    host_sources = host.sources_str
                    if host.services:
                        for service in host.services:
                            result.append([workspace.name,  # Workspace
                                           host.ipv4_network.network,  # Network (NW)
                                           host.ipv4_network.scope,  # Scope (NW)
                                           network_companies,  # Companies (NW)
                                           host.address,  # IP Address (IP)
                                           host.in_scope,  # In Scope (IP)
                                           private_ip,  # Private IP
                                           host_names,  # Hostnames
                                           service.summary,  # Service Summary
                                           service.protocol_str,  # TCP/UDP
                                           service.port,  # Port
                                           service.protocol_port_str,  # Service (SRV)
                                           service.state_str,  # State
                                           service.nmap_tunnel,  # TLS
                                           service.nmap_service_state_reason,  # Nmap Reason
                                           service.service_name_with_confidence,  # Nmap Name
                                           service.service_confidence,  # Nmap Confidence
                                           service.nmap_service_name_original_with_confidence,  # Nmap Name Original
                                           service.nmap_product,  # Nmap Product
                                           service.nmap_version,  # Version
                                           service.nmap_product_version,  # Product Summary
                                           host_sources,  # Sources (IP)
                                           service.sources_str,  # Sources (SRV)
                                           len(service.get_completed_commands()),  # No. Commands (SRV)
                                           len(service.vulnerabilities),  # No. Vulnerabilities (SRV)
                                           host.id,  # DB ID (HN)
                                           service.id])  # DB ID (SRV)
                    else:
                        result.append([workspace.name,  # Workspace
                                       host.network.network,  # Network (NW)
                                       host.network.scope,  # Scope (NW)
                                       network_companies,  # Companies (NW)
                                       host.address,  # IP Address (IP)
                                       host.in_scope,  # In Scope (IP)
                                       private_ip,  # Private IP
                                       host_names,  # Hostnames
                                       None,  # Service Summary
                                       None,  # TCP/UDP
                                       None,  # Port
                                       None,  # Service (SRV)
                                       None,  # State
                                       None,  # TLS
                                       None,  # Nmap Reason
                                       None,  # Nmap Name
                                       None,  # Nmap Confidence
                                       None,  # Nmap Name Original
                                       None,  # Nmap Product
                                       None,  # Version
                                       None,  # Product Summary
                                       host_sources,  # Sources (IP)
                                       None,  # Sources (SRV)
                                       None,  # No. Commands (SRV)
                                       None,  # No. Vulnerabilities (SRV)
                                       host.id,  # DB ID (HN)
                                       None])  # DB ID (SRV)
        return result

    def _get_csv_vhost(self) -> List[List[str]]:
        result = [["Workspace",
                   "Second-Level Domain (SLD)",
                   "Scope (SLD)",
                   "Companies (SLD)",
                   "Host Name (HN)",
                   "In Scope (HN)",
                   "In Scope (Vhost)",
                   "Name Only (HN)",
                   "Environment (HN)",
                   "Summary (HN)",
                   "Resolved A/AAAA Records",
                   "Service Summary",
                   "TCP/UDP",
                   "Port",
                   "Service (SRV)",
                   "State",
                   "TLS",
                   "Nmap Reason",
                   "Nmap Name",
                   "Nmap Confidence",
                   "Nmap Name Original",
                   "Nmap Product",
                   "Version",
                   "Product Summary",
                   "Sources (HN)",
                   "Sources (SRV)",
                   "No. Commands (SRV)",
                   "No. Vulnerabilities (SRV)",
                   "DB ID (SLD)",
                   "DB ID (HN)",
                   "DB ID (SRV)"]]
        for workspace in self._workspaces:
            for domain in workspace.domain_names:
                domain_companies = domain.companies_str
                for host_name in domain.host_names:
                    if self._filter(host_name):
                        ipv4_addresses = host_name.get_host_host_name_mappings_str(types=[DnsResourceRecordType.a,
                                                                                          DnsResourceRecordType.aaaa])
                        host_name_sources = host_name.sources_str
                        in_scope = host_name.in_scope(CollectorType.vhost_service)
                        environment = self._domain_config.get_environment(host_name)
                        if host_name.services:
                            for service in host_name.services:
                                result.append([workspace.name,  # Workspace
                                               domain.name,  # Second-Level Domain (SLD)
                                               domain.scope_str,  # Scope (SLD)
                                               domain_companies,  # Companies (SLD)
                                               host_name.full_name,  # Host Name (HN)
                                               host_name._in_scope,  # In Scope (HN)
                                               in_scope,  # In Scope (Vhost)
                                               host_name.name,  # Name Only (HN)
                                               environment,  # Environment (HN)
                                               host_name.summary,  # Summary (HN)
                                               ipv4_addresses,  # Resolved A/AAAA Records
                                               service.summary,  # Service Summary
                                               service.protocol_str,  # TCP/UDP
                                               service.port,  # Port
                                               service.protocol_port_str,  # Service (SRV)
                                               service.state_str,  # State
                                               service.nmap_tunnel,  # TLS
                                               service.nmap_service_state_reason,  # Nmap Reason
                                               service.service_name_with_confidence,  # Nmap Name
                                               service.service_confidence,  # Nmap Confidence
                                               service.nmap_service_name_original_with_confidence,  # Nmap Name Original
                                               service.nmap_product,  # Nmap Product
                                               service.nmap_version,  # Version
                                               service.nmap_product_version,  # Product Summary
                                               host_name_sources,  # Sources (HN)
                                               service.sources_str,  # Sources (SRV)
                                               len(service.get_completed_commands()),  # No. Commands (SRV)
                                               len(service.vulnerabilities),  # No. Vulnerabilities (SRV)
                                               domain.id,  # DB ID (SLD)
                                               host_name.id,  # DB ID (HN)
                                               service.id])  # DB ID (SRV)
                        else:
                            result.append([workspace.name,  # Workspace
                                           domain.name,  # Second-Level Domain (SLD)
                                           domain.scope_str,  # Scope (SLD)
                                           domain.companies_str,  # Companies (SLD)
                                           host_name.full_name,  # Host Name (HN)
                                           host_name._in_scope,  # In Scope (HN)
                                           in_scope,  # In Scope (Vhost)
                                           host_name.name,  # Name Only (HN)
                                           environment,  # Environment (HN)
                                           host_name.summary,  # Summary (HN)
                                           ipv4_addresses,  # Resolved A/AAAA Records
                                           None,  # Service Summary
                                           None,  # TCP/UDP
                                           None,  # Port
                                           None,  # Service
                                           None,  # State
                                           None,  # TLS
                                           None,  # Nmap Reason
                                           None,  # Nmap Name
                                           None,  # Nmap Confidence
                                           None,  # Nmap Name Original
                                           None,  # Nmap Product
                                           None,  # Version
                                           None,  # Product Summary
                                           host_name_sources,  # Sources (HN)
                                           None,  # Sources (SRV)
                                           None,  # No. Commands (SRV)
                                           None,  # No. Vulnerabilities (SRV)
                                           domain.id,  # DB ID (SLD)
                                           host_name.id,  # DB ID (HN)
                                           None])  # DB ID (SRV)
            return result

    def _get_csv_all(self) ->  List[List[str]]:
        descriptor = HttpServiceDescriptor()
        result = [["Workspace",
                   "Type",
                   "Network (NW)",
                   "Scope (NW)",
                   "Company (NW)",
                   "IP Address (IP)",
                   "Version (IP)",
                   "Private IP",
                   "In Scope (IP)",
                   "OS Family",
                   "OS Details",
                   "Host Names/IP Addresses",
                   "Second-Level Domain (SLD)",
                   "Scope (SLD)",
                   "Host Name (HN)",
                   "In Scope (HN)",
                   "In Scope (IP or HN)",
                   "Name Only (HN)",
                   "Company (HN)",
                   "Environment (HN)",
                   "UDP/TCP",
                   "Port",
                   "Service (SRV)",
                   "Nmap Name (SRV)",
                   "Confidence (SRV)",
                   "State (SRV)",
                   "Reason State",
                   "Banner Information",
                   "TLS",
                   "Is HTTP",
                   "URL",
                   "SMB Message Signing",
                   "RD NLA",
                   "DB ID (NW)",
                   "DB ID (IP)",
                   "DB ID (HN)",
                   "DB ID (SRV)",
                   "Source (NW)",
                   "Source (IP)",
                   "Source (HN)",
                   "Source (SRV)",
                   "No. Commands",
                   "No. Vulnerabilities"]]
        for workspace in self._workspaces:
            for host in workspace.hosts:
                if self._filter(host):
                    host_names = [mapping.host_name
                                  for mapping in host.get_host_host_name_mappings([DnsResourceRecordType.a,
                                                                                   DnsResourceRecordType.aaaa])]
                    host_names_str = ", ".join([item.full_name for item in host_names])
                    network_str = host.ipv4_network.network if host.ipv4_network else None
                    network_id = host.ipv4_network.id if host.ipv4_network else None
                    network_companies = host.ipv4_network.companies_str if host.ipv4_network else None
                    network_sources = host.ipv4_network.sources_str if host.ipv4_network else None
                    network_scope = host.ipv4_network.scope_str if host.ipv4_network else None
                    host_is_private = host.ip_address.is_private
                    host_sources = host.sources_str
                    services_exist = False
                    for service in host.services:
                        if service.state in [ServiceState.Open, ServiceState.Closed]:
                            services_exist = True
                            is_http = descriptor.match_nmap_service_name(service)
                            url_str = [path.get_urlparse().geturl() for path in service.paths if path.name == "/"] \
                                if is_http else []
                            result.append([workspace.name,
                                           "Host",
                                           network_str,
                                           network_scope,
                                           network_companies,
                                           host.address,
                                           host.version_str,
                                           host_is_private,
                                           host.in_scope,
                                           host.os_family,
                                           host.os_details,
                                           host_names_str,
                                           None,
                                           None,
                                           host.address,
                                           host.in_scope,
                                           host.in_scope,
                                           None,
                                           None,
                                           None,
                                           service.protocol_str,
                                           service.port,
                                           service.protocol_port_str,
                                           service.service_name_with_confidence,
                                           service.service_confidence,
                                           service.state_str,
                                           service.nmap_service_state_reason,
                                           service.nmap_product_version,
                                           service.tls,
                                           is_http,
                                           url_str[0] if url_str else None,
                                           service.smb_message_signing,
                                           service.rdp_nla,
                                           network_id,
                                           host.id,
                                           None,
                                           service.id,
                                           network_sources,
                                           host_sources,
                                           None,
                                           service.sources_str,
                                           len(service.get_completed_commands()),
                                           len(service.vulnerabilities)])
                    for host_name in host_names:
                        environment = self._domain_config.get_environment(host_name)
                        hosts = [mapping.host
                                 for mapping in host_name.get_host_host_name_mappings([DnsResourceRecordType.a,
                                                                                       DnsResourceRecordType.aaaa])]
                        hosts_str = ", ".join([item.address for item in hosts])
                        host_name_sources = host_name.sources_str
                        network_str = host.ipv4_network.network if host.ipv4_network else None
                        for service in host_name.services:
                            if service.state in [ServiceState.Open, ServiceState.Closed]:
                                services_exist = True
                                is_http = descriptor.match_nmap_service_name(service)
                                url_str = [path.get_urlparse().geturl() for path in service.paths if path.name == "/"] \
                                    if is_http else []
                                result.append([workspace.name,
                                               "VHost",
                                               network_str,
                                               network_scope,
                                               network_companies,
                                               host.address,
                                               host.version_str,
                                               host_is_private,
                                               host.in_scope,
                                               host.os_family,
                                               host.os_details,
                                               hosts_str,
                                               host_name.domain_name.name,
                                               host_name.domain_name.scope_str,
                                               host_name.full_name,
                                               host_name._in_scope,
                                               host.in_scope or host_name._in_scope,
                                               host_name.name,
                                               host_name.companies_str,
                                               environment,
                                               service.protocol_str,
                                               service.port,
                                               service.protocol_port_str,
                                               service.service_name_with_confidence,
                                               service.service_confidence,
                                               service.state_str,
                                               service.nmap_service_state_reason,
                                               service.nmap_product_version,
                                               service.tls,
                                               is_http,
                                               url_str[0] if url_str else None,
                                               service.smb_message_signing,
                                               service.rdp_nla,
                                               network_id,
                                               host.id,
                                               host_name.id,
                                               service.id,
                                               network_sources,
                                               host_sources,
                                               host_name_sources,
                                               service.sources_str,
                                               len(service.get_completed_commands()),
                                               len(service.vulnerabilities)])
                    if not services_exist:
                        result.append([workspace.name,
                                       "Host",
                                       network_str,
                                       network_scope,
                                       network_companies,
                                       host.address,
                                       host.version_str,
                                       host_is_private,
                                       host.in_scope,
                                       host.os_family,
                                       host.os_details,
                                       host_names_str,
                                       None,
                                       None,
                                       host.address,
                                       host.in_scope,
                                       host.in_scope,
                                       None,
                                       None,
                                       None,
                                       None,
                                       None,
                                       None,
                                       None,
                                       None,
                                       "not scanned",
                                       None,
                                       None,
                                       None,
                                       None,
                                       None,
                                       None,
                                       None,
                                       network_id,
                                       host.id,
                                       None,
                                       None,
                                       network_sources,
                                       host_sources,
                                       None,
                                       None,
                                       0,
                                       0])
                        for host_name in host_names:
                            environment = self._domain_config.get_environment(host_name)
                            host_name_sources = host_name.sources_str
                            hosts = [mapping.host
                                     for mapping in host_name.get_host_host_name_mappings([DnsResourceRecordType.a,
                                                                                           DnsResourceRecordType.aaaa])]
                            hosts_str = ", ".join([item.address for item in hosts])
                            result.append([workspace.name,
                                           "VHost",
                                           network_str,
                                           network_scope,
                                           network_companies,
                                           host.address,
                                           host.version_str,
                                           host_is_private,
                                           host.in_scope,
                                           host.os_family,
                                           host.os_details,
                                           hosts_str,
                                           host_name.domain_name.name,
                                           host_name.domain_name.scope_str,
                                           host_name.full_name,
                                           host_name._in_scope,
                                           host.in_scope or host_name._in_scope,
                                           host_name.name,
                                           host_name.companies_str,
                                           environment,
                                           None,
                                           None,
                                           None,
                                           None,
                                           None,
                                           "not scanned",
                                           None,
                                           None,
                                           None,
                                           None,
                                           None,
                                           None,
                                           None,
                                           network_id,
                                           host.id,
                                           host_name.id,
                                           None,
                                           network_sources,
                                           host_sources,
                                           host_name_sources,
                                           None,
                                           0,
                                           0])
        return result

    def get_csv(self) -> List[List[str]]:
        if self._type == VhostChoice.all:
            result = self._get_csv_all()
        elif self._type == VhostChoice.domain:
            result = self._get_csv_vhost()
        else:
            result = self._get_csv_host()
        return result

    def final_report(self, workbook: Workbook):
        """
        This method creates all tables that are relevant to the final report.
        """
        descriptor = HttpServiceDescriptor()
        result = [["Type",
                   "IP Address (IP)",
                   "Host Name (HN)",
                   "Service",
                   "Service\nName",
                   "State",
                   "Is\nHTTP",
                   "TLS",
                   "Banner Information"]]
        if self._args.language == ReportLanguage.de:
            result = [["Typ",
                       "IP-Addresse (IP)",
                       "Hostname (HN)",
                       "Service",
                       "Service\nName",
                       "Status",
                       "Ist\nHTTP",
                       "TLS",
                       "Banner-Information"]]
        for workspace in self._workspaces:
            for host in workspace.hosts:
                if host.in_scope:
                    host_names = [mapping.host_name
                                  for mapping in host.get_host_host_name_mappings([DnsResourceRecordType.a,
                                                                                   DnsResourceRecordType.aaaa])]
                    for service in host.services:
                        if service.state in [ServiceState.Open, ServiceState.Closed]:
                            is_http = descriptor.match_nmap_service_name(service)
                            result.append(["Host",
                                           host.address,
                                           host.address,
                                           service.protocol_port_str,
                                           service.service_name_with_confidence,
                                           service.state_str,
                                           self.TRUE if is_http else None,
                                           self.TRUE if service.tls else None,
                                           service.nmap_product_version])
                    for host_name in host_names:
                        for service in host_name.services:
                            if service.state in [ServiceState.Open, ServiceState.Closed] and \
                                    descriptor.match_nmap_service_name(service):
                                is_http = descriptor.match_nmap_service_name(service)
                                result.append(["VHost",
                                               host.address,
                                               host_name.full_name,
                                               service.protocol_port_str,
                                               service.service_name_with_confidence,
                                               service.state_str,
                                               self.TRUE if is_http else None,
                                               self.TRUE if service.tls else None,
                                               service.nmap_product_version])
        if len(result) > 1:
            self.fill_excel_sheet(worksheet=workbook.create_sheet(),
                                  csv_list=result,
                                  name="Service Results",
                                  title="",
                                  description="")
