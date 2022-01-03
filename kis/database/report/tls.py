# -*- coding: utf-8 -*-
"""This module allows querying information about identified tls configurations."""

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
from database.model import TlsInfo
from database.model import ScopeType
from database.model import ServiceState
from database.model import CipherSuiteSecurity
from database.model import DnsResourceRecordType
from collectors.os.modules.http.core import HttpServiceDescriptor
from database.report.core import BaseReport
from database.report.core import ReportLanguage


class ReportClass(BaseReport):
    """
    this module allows querying information about identified tls configurations
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(name="tls info",
                         title="Overview TLS Ciphers",
                         description="The table provides an overview of all identified TLS cipher suites.",
                         **kwargs)

    @staticmethod
    def get_add_argparse_arguments(parser_tls: argparse.ArgumentParser):
        """
        This method adds the report's specific command line arguments.
        """
        # setup tls parser
        parser_tls.add_argument("-w", "--workspaces",
                                metavar="WORKSPACE",
                                help="query the given workspaces",
                                nargs="+",
                                type=str)
        parser_tls.add_argument('--csv',
                                default=True,
                                action='store_true',
                                help='returns gathered information in csv format')
        parser_tls.add_argument('--filter', metavar='IP|NETWORK|DOMAIN|HOSTNAME', type=str, nargs='*',
                                help='list of IP addresses, IP networks, second-level domains (e.g., megacorpone.com), or '
                                     'host names (e.g., www.megacorpone.com) whose information shall be returned.'
                                     'per default, mentioned items are excluded. add + in front of each item '
                                     '(e.g., +192.168.0.1) to return only these items')
        parser_tls.add_argument('--scope', choices=[item.name for item in ScopeType],
                                help='return only information about in scope (within) or out of scope (outside) items. '
                                     'per default, all information is returned')

    def _filter(self, tls_info: TlsInfo) -> bool:
        """
        Method determines whether the given item shall be included into the report
        """
        return tls_info.is_processable(included_items=self._included_items,
                                       excluded_items=self._excluded_items,
                                       scope=self.scope)

    def _kex_summary(self, kex_algorithm_str: str, kex_algorithm_bits: int) -> str:
        result = None
        if kex_algorithm_str:
            result = kex_algorithm_str
        if kex_algorithm_bits:
            result = result if result else ""
            result += " {}".format(kex_algorithm_bits)
        return result

    def get_csv(self) -> List[List[str]]:
        """
        This method returns TLS information
        :return: List of strings containing TLS properties
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
                   "Second-Level Domain (SLD)",
                   "Scope (SLD)",
                   "Host Name (HN)",
                   "In Scope (HN)",
                   "Name (HN)",
                   "Company (HN)",
                   "Environment",
                   "UDP/TCP",
                   "Port",
                   "Service (SRV)",
                   "Nmap Name (SRV)",
                   "Confidence (SRV)",
                   "State (SRV)",
                   "Reason State",
                   "Banner Information",
                   "Is HTTP",
                   "URL",
                   "TLS Version",
                   "Preference",
                   "Heartbleed",
                   "Compressors",
                   "Order",
                   "Cipher Suite (IANA)",
                   "Prefered",
                   "KEX Algorithm",
                   "Security",
                   "DB ID (NW)",
                   "DB ID (IP)",
                   "DB ID (HN)",
                   "DB ID (SRV)",
                   "DB ID (TLS)",
                   "Source (NW)",
                   "Source (IP)",
                   "Source (HN)",
                   "Source (SRV)",
                   "Source (TLS)"]]
        for workspace in self._workspaces:
            for host in workspace.hosts:
                host_names = [mapping.host_name
                              for mapping in host.get_host_host_name_mappings([DnsResourceRecordType.a,
                                                                               DnsResourceRecordType.aaaa])]
                network_str = host.ipv4_network.network if host.ipv4_network else None
                network_id = host.ipv4_network.id if host.ipv4_network else None
                network_companies = host.ipv4_network.companies_str if host.ipv4_network else None
                network_sources = host.ipv4_network.sources_str if host.ipv4_network else None
                network_scope = host.ipv4_network.scope_str if host.ipv4_network else None
                host_is_private = host.ip_address.is_private
                host_sources = host.sources_str
                for service in host.services:
                    if service.state in [ServiceState.Open, ServiceState.Closed]:
                        is_http = descriptor.match_nmap_service_name(service)
                        url_str = [path.get_urlparse().geturl() for path in service.paths if path.name == "/"] \
                            if is_http else []
                        patch_missing_kex = {}
                        for tls_info in service.tls_info:
                            if self._filter(tls_info):
                                for mapping in tls_info.cipher_suite_mappings:
                                    cipher_suite = mapping.cipher_suite
                                    key = "{}{}{}{}".format(host.address,
                                                            service.protocol_port_str,
                                                            tls_info.version_str,
                                                            cipher_suite.iana_name)
                                    kex_algorithm = mapping.kex_algorithm_details_str
                                    if kex_algorithm:
                                        patch_missing_kex[key] = kex_algorithm
                                    elif key in patch_missing_kex:
                                        kex_algorithm = patch_missing_kex[key]
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
                                                   None,
                                                   None,
                                                   host.address,
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
                                                   is_http,
                                                   url_str[0] if url_str else None,
                                                   tls_info.version_str,
                                                   tls_info.preference_str,
                                                   tls_info.heartbleed,
                                                   tls_info.compressors_str,
                                                   mapping.order,
                                                   cipher_suite.iana_name,
                                                   mapping.prefered,
                                                   kex_algorithm,
                                                   cipher_suite.security_str,
                                                   network_id,
                                                   host.id,
                                                   None,
                                                   service.id,
                                                   mapping.id,
                                                   network_sources,
                                                   host_sources,
                                                   None,
                                                   service.sources_str,
                                                   mapping.sources_str])
                for host_name in host_names:
                    environment = self._domain_config.get_environment(host_name)
                    host_name_sources = host_name.sources_str
                    network_str = host.ipv4_network.network if host.ipv4_network else None
                    for service in host_name.services:
                        if service.state in [ServiceState.Open, ServiceState.Closed] and \
                                descriptor.match_nmap_service_name(service):
                            url_str = [path.get_urlparse().geturl() for path in service.paths if path.name == "/"]
                            patch_missing_kex = {}
                            for tls_info in service.tls_info:
                                if self._filter(tls_info):
                                    for mapping in tls_info.cipher_suite_mappings:
                                        cipher_suite = mapping.cipher_suite
                                        key = "{}{}{}{}".format(host_name.full_name,
                                                                service.protocol_port_str,
                                                                tls_info.version_str,
                                                                cipher_suite.iana_name)
                                        kex_algorithm = mapping.kex_algorithm_details_str
                                        if kex_algorithm:
                                            patch_missing_kex[key] = kex_algorithm
                                        elif key in patch_missing_kex:
                                            kex_algorithm = patch_missing_kex[key]
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
                                                       host_name.domain_name.name,
                                                       host_name.domain_name.scope_str,
                                                       host_name.full_name,
                                                       host_name._in_scope,
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
                                                       True,
                                                       url_str[0] if url_str else None,
                                                       tls_info.version_str,
                                                       tls_info.preference_str,
                                                       tls_info.heartbleed,
                                                       tls_info.compressors_str,
                                                       mapping.order,
                                                       cipher_suite.iana_name,
                                                       mapping.prefered,
                                                       kex_algorithm,
                                                       cipher_suite.security_str,
                                                       network_id,
                                                       host.id,
                                                       host_name.id,
                                                       service.id,
                                                       mapping.id,
                                                       network_sources,
                                                       host_sources,
                                                       host_name_sources,
                                                       service.sources_str,
                                                       mapping.sources_str])
        return result

    def _final_report_tls_versions(self, workbook: Workbook):
        # Obtain results
        tls_results = {}
        versions = {}
        for workspace in self._workspaces:
            for host in workspace.hosts:
                if host.in_scope:
                    for service in host.services:
                        if service.tls_info:
                            summary = "{} {}".format(service.address, service.protocol_port_str)
                            if summary not in tls_results:
                                tls_results[summary] = {"service": service, "tls_versions": {}}
                            tls_entry = tls_results[summary]["tls_versions"]
                            for tls_info in service.tls_info:
                                tls_entry[tls_info.version_str] = True
                                versions[tls_info.version_str] = None
        if versions:
            # Convert results into two-dimensional array
            result = [["IP Address", "Service"]]
            if self._args.language == ReportLanguage.de:
                result = [["IP-Adresse", "Dienst"]]
            unique_tls_versions = list(versions.keys())
            unique_tls_versions.sort()
            result[0].extend(unique_tls_versions)
            for key, value in tls_results.items():
                service = value["service"]
                version = value["tls_versions"]
                row = [service.address, service.protocol_port_str]
                for item in unique_tls_versions:
                    if item in version:
                        row.append(self.TRUE)
                    else:
                        row.append(None)
                result.append(row)
            if len(result) > 1:
                self.fill_excel_sheet(worksheet=workbook.create_sheet(),
                                      csv_list=result,
                                      name="TLS - Versions",
                                      title="",
                                      description="")

    def _final_report_tls_ciphers(self, workbook: Workbook):
        result = [["IP Address", "Service", "Cipher Suite", "Security"]]
        if self._args.language == ReportLanguage.de:
            result = [["IP-Adresse", "Dienst", "Cipher Suite", "Sicherheit"]]
        for workspace in self._workspaces:
            for host in workspace.hosts:
                if host.in_scope:
                    for service in host.services:
                        for tls_info in service.tls_info:
                            for mapping in tls_info.cipher_suite_mappings:
                                if mapping.cipher_suite.security in [CipherSuiteSecurity.insecure,
                                                                     CipherSuiteSecurity.weak]:
                                    result.append([host.address,
                                                   service.protocol_port_str,
                                                   mapping.cipher_suite.iana_name,
                                                   mapping.cipher_suite.security_str])
        if len(result) > 1:
            self.fill_excel_sheet(worksheet=workbook.create_sheet(),
                                  csv_list=result,
                                  name="TLS - Weak Ciphers",
                                  title="",
                                  description="Classification of cipher suite security is coming from: "
                                              "https://ciphersuite.info")

    def final_report(self, workbook: Workbook):
        """
        This method creates all tables that are relevant to the final report.
        """
        self._final_report_tls_versions(workbook)
        self._final_report_tls_ciphers(workbook)
