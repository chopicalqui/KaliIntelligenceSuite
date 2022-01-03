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
from openpyxl import Workbook
from typing import List
from database.model import Host
from database.model import HostName
from database.model import ReportScopeType
from database.model import ReportVisibility
from database.model import DnsResourceRecordType
from database.model import ServiceState
from collectors.os.modules.http.core import HttpServiceDescriptor
from database.report.core import BaseReport
from database.report.core import ReportLanguage


class ReportClass(BaseReport):
    """
    this module allows querying information about IPv4/IPv6 addresses
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(name="host info",
                         title="IP address details",
                         description="This table provides a consolidated view about all IP addresses (see column "
                                     "'IP Address (IP)'), their virtual hosts (see column 'Host Name (HN)') as well as "
                                     "their identified TCP/UDP services (see columns 'UDP/TCP' and 'Port'). "
                                     ""
                                     "If you are just interested in service information on the IP address level, then "
                                     "filter for value 'Host' in column 'Type'. If you are interested in service "
                                     "information on the virtual host level, filter for value 'VHost' in column "
                                     "'Type'. "
                                     ""
                                     "Note that host ames, which do not resolve to an IP address, are not listed in "
                                     "this sheet; use sheet 'host name info' to analyse them.",
                         **kwargs)

    @staticmethod
    def get_add_argparse_arguments(parser_host: argparse.ArgumentParser):
        """
        This method adds the report's specific command line arguments.
        """
        parser_host.add_argument("-w", "--workspaces",
                                 metavar="WORKSPACE",
                                 help="query the given workspaces",
                                 nargs="+",
                                 type=str)
        parser_host_group = parser_host.add_mutually_exclusive_group()
        parser_host_group.add_argument('--text', action='store_true',
                                       help='returns gathered information including all collector outputs as text')
        parser_host_group.add_argument('--csv', action='store_true', default=True,
                                       help='returns gathered information in csv format')
        parser_host_group.add_argument('--igrep', type=str, nargs='+', metavar="REGEX",
                                       help="print command outputs that match the given string or Python3 regular "
                                            "expressions REGEX. matching is case insensitive. use named group 'output' "
                                            "to just capture the content of this named group")
        parser_host_group.add_argument('--grep', type=str, nargs='+', metavar="REGEX",
                                       help="print command outputs that match the given string or Python3 regular "
                                            "expressions REGEX. matching is case sensitive. use named group 'output' "
                                            "to just capture the content of this named group")
        parser_host.add_argument('--not', dest="grep_not", action='store_true',
                                 help='negate the filter logic and only show those IP addresses that do not match the '
                                      '--igrep or --grep argument.')
        parser_host.add_argument('--filter', metavar='IP|NETWORK|DOMAIN|HOSTNAME', type=str, nargs='*',
                                 help='list of IP addresses, IP networks, second-level domains (e.g., megacorpone.com), or '
                                      'host names (e.g., www.megacorpone.com) whose information shall be returned.'
                                      'per default, mentioned items are excluded. add + in front of each item '
                                      '(e.g., +192.168.0.1) to return only these items')
        parser_host.add_argument('--scope', choices=[item.name for item in ReportScopeType],
                                 help='return only networks or hosts that are in scope (within) or out of scope '
                                      '(outside). per default, all information is returned')
        parser_host.add_argument('--visibility', choices=[item.name for item in ReportVisibility],
                                 help='return only relevant (relevant) or potentially irrelevant (irrelevant) information '
                                      'in text output (argument --text). examples of potentially irrelevant information '
                                      'are hosts with no open ports or operating system commands that did not return '
                                      'any results. per default, all information is returned')
        parser_host.add_argument('-X', '--exclude', metavar='COLLECTOR', type=str, nargs='+', default=[],
                                 help='list of collector names (e.g., httpnikto) whose outputs should not be returned in '
                                      'text mode (see argument --text). use argument value "all" to exclude all '
                                      'collectors. per default, no collectors are excluded')
        parser_host.add_argument('-I', '--include', metavar='COLLECTOR', type=str, nargs='+', default=[],
                                 help='list of collector names whose outputs should be returned in text mode (see '
                                      'argument --text). per default, all collector information is returned')

    def _filter(self, host: Host) -> bool:
        """
        Method determines whether the given item shall be included into the report
        """
        rvalue = host.is_processable(included_items=self._included_items,
                                     excluded_items=self._excluded_items,
                                     scope=self._scope,
                                     include_host_names=True)
        return rvalue

    def _egrep_text(self, host: HostName) -> List[str]:
        """
        This method returns all lines matching the given list of regular expressions
        :param domain: The domain name whose text output shall be parsed
        :return:
        """
        result = self._egrep(host.get_text(ident=0,
                                           exclude_collectors=self._excluded_collectors,
                                           include_collectors=self._included_collectors,
                                           scope=self._scope,
                                           show_metadata=False))
        return result

    def get_text(self) -> List[str]:
        """
        This method returns all information as a list of text.
        :return:
        """
        rvalue = []
        for workspace in self._workspaces:
            for host in workspace.hosts:
                if self._filter(host):
                    rvalue.extend(host.get_text(ident=0,
                                                scope=self._scope,
                                                exclude_collectors=self._excluded_collectors,
                                                include_collectors=self._included_collectors,
                                                report_visibility=self._visibility,
                                                color=self._color))
        return rvalue

    def grep_text(self) -> List[List[str]]:
        """
        This method returns all information as a list of text.
        :return:
        """
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

    def get_csv(self) -> List[List[str]]:
        """
        Method determines whether the given item shall be included into the report
        """
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
