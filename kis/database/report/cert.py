# -*- coding: utf-8 -*-
"""This module allows querying information about identified certificates."""

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
from database.model import CertType
from database.model import CertInfo
from database.model import ScopeType
from database.model import ServiceState
from database.model import DnsResourceRecordType
from collectors.os.modules.http.core import HttpServiceDescriptor
from database.report.core import BaseReport
from OpenSSL.crypto import X509StoreContextError


class ReportClass(BaseReport):
    """
    this module allows querying information about identified certificates
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(name="cert info",
                         title="Overview Certificates",
                         description="The table provides an overview of all identified certificates.",
                         **kwargs)

    def _filter(self, cert_info: CertInfo) -> bool:
        """
        Method determines whether the given item shall be included into the report
        """
        return cert_info.is_processable(included_items=self._included_items,
                                        excluded_items=self._excluded_items,
                                        scope=self.scope)

    @staticmethod
    def get_add_argparse_arguments(parser_cert: argparse.ArgumentParser):
        """
        This method adds the report's specific command line arguments.
        """
        # setup cert parser
        parser_cert.add_argument("-w", "--workspaces",
                                 metavar="WORKSPACE",
                                 help="query the given workspaces",
                                 nargs="+",
                                 type=str)
        parser_cert.add_argument('--csv',
                                 default=True,
                                 action='store_true',
                                 help='returns gathered information in csv format')
        parser_cert.add_argument('--filter', metavar='IP|NETWORK|DOMAIN|HOSTNAME', type=str, nargs='*',
                                 help='list of IP addresses, IP networks, second-level domains (e.g., megacorpone.com), or '
                                      'host names (e.g., www.megacorpone.com) whose information shall be returned.'
                                      'per default, mentioned items are excluded. add + in front of each item '
                                      '(e.g., +192.168.0.1) to return only these items')
        parser_cert.add_argument('--scope', choices=[item.name for item in ScopeType],
                                 help='return only information about in scope (within) or out of scope (outside) items. '
                                      'per default, all information is returned')

    def get_csv(self) -> List[List[str]]:
        """
        This method returns all information as CSV.
        :return:
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
                   "HN Coverage",
                   "Cert. Type",
                   "X509 Version",
                   "Subject",
                   "Issuer",
                   "Invalid CA (Self-Signed)",
                   "Signature Algorithm",
                   "Public Key Algorithm",
                   "Public Key Size",
                   "Exponent",
                   "Valid From",
                   "Valid Until",
                   "Valid Years",
                   "Verification",
                   "Has Expired",
                   "Recommended Duration",
                   "Subject Alternative Names",
                   "Key Usage",
                   "Extended Key Usage",
                   "Critical Extensions",
                   "OCSP Server",
                   "CRL",
                   "Serial Number",
                   "DB ID (NW)",
                   "DB ID (IP)",
                   "DB ID (HN)",
                   "DB ID (SRV)",
                   "DB ID (CERT)",
                   "Source (NW)",
                   "Source (IP)",
                   "Source (HN)",
                   "Source (SRV)",
                   "Source (CERT)"]]
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
                        for cert_info in service.cert_info:
                            if self._filter(cert_info):
                                try:
                                    chain = cert_info.chain
                                    cert_info.verify(x509_store=self._domain_config.x509_store,
                                                     chain=chain)
                                    verification = "ok"
                                except X509StoreContextError as ex:
                                    verification = str(ex)
                                matching_host = "n/a"
                                extensions = cert_info.extensions_dict
                                result.append([workspace.name,  # Workspace
                                               "Host",  # Type
                                               network_str,  # Network (NW)
                                               network_scope,  # Scope (NW)
                                               network_companies,  # Company (NW)
                                               host.address,  # IP Address (IP)
                                               host.version_str,  # Version (IP)
                                               host_is_private,  # Private IP
                                               host.in_scope,  # In Scope (IP)
                                               host.os_family,  # OS Family
                                               host.os_details,  # OS Details
                                               None,  # Second-Level Domain (SLD)
                                               None,  # Scope (SLD)
                                               host.address,  # Host Name (HN)
                                               host.in_scope,  # In Scope (HN)
                                               None,  # Name (HN)
                                               None,  # Company (HN)
                                               None,  # Environment
                                               service.protocol_str,  # UDP/TCP
                                               service.port,  # Port
                                               service.protocol_port_str,  # Service (SRV)
                                               service.service_name_with_confidence,  # Nmap Name (SRV)
                                               service.service_confidence,  # Confidence (SRV)
                                               service.state_str,  # State (SRV)
                                               service.nmap_service_state_reason,  # Reason State
                                               service.nmap_product_version,  # Banner Information
                                               is_http,  # Is HTTP
                                               url_str[0] if url_str else None,  # URL
                                               matching_host,  # HN Coverage
                                               cert_info.cert_type_str,  # Cert. Type
                                               cert_info.version,  # X509 Version
                                               cert_info.subject,  # Subject
                                               cert_info.issuer,  # Issuer
                                               cert_info.is_self_signed(),  # Invalid CA (Self-Signed)
                                               cert_info.signature_algorithm,  # Signature Algorithm
                                               cert_info.public_key_name,  # Public Key Algorithm
                                               cert_info.public_key_size,  # Public Key Size
                                               cert_info.exponent,  # Exponent
                                               cert_info.valid_from_str,  # Valid From
                                               cert_info.valid_until_str,  # Valid Until
                                               cert_info.validity_period_days / 365,  # Valid Years
                                               verification,  # Verification
                                               cert_info.has_exired(),  # Has Expired
                                               cert_info.has_recommended_duration(),  # Recommended Duration
                                               cert_info.subject_alt_names_str,  # Subject Alternative Names
                                               str(extensions["keyUsage"]),  # Key Usage
                                               str(extensions["extendedKeyUsage"]),  # Extended Key Usage
                                               cert_info.critical_extensions_str,  # Critical Extensions
                                               cert_info.ocsp_servers_str,  # OCSP Server
                                               cert_info.crl_distribution_points_str,  # CRL
                                               cert_info.serial_number,  # Serial Number
                                               network_id,  # DB ID (NW)
                                               host.id,  # DB ID (IP)
                                               None,  # DB ID (HN)
                                               service.id,  # DB ID (SRV)
                                               cert_info.id,  # DB ID (CERT)
                                               network_sources,  # Source (NW)
                                               host_sources,  # Source (IP)
                                               None,  # Source (HN)
                                               service.sources_str,  # Source (SRV)
                                               cert_info.sources_str])
                for host_name in host_names:
                    environment = self._domain_config.get_environment(host_name)
                    host_name_sources = host_name.sources_str
                    network_str = host.ipv4_network.network if host.ipv4_network else None
                    for service in host_name.services:
                        if service.state in [ServiceState.Open, ServiceState.Closed] and \
                                descriptor.match_nmap_service_name(service):
                            is_http = descriptor.match_nmap_service_name(service)
                            url_str = [path.get_urlparse().geturl() for path in service.paths if path.name == "/"] \
                                if is_http else []
                            for cert_info in service.cert_info:
                                if self._filter(cert_info):
                                    try:
                                        chain = cert_info.chain
                                        cert_info.verify(x509_store=self._domain_config.x509_store,
                                                         chain=chain)
                                        verification = "ok"
                                    except X509StoreContextError as ex:
                                        verification = str(ex)
                                    extensions = cert_info.extensions_dict
                                    matching_host = cert_info.matches_host_name(host_name) \
                                        if cert_info.cert_type == CertType.identity else None
                                    result.append([workspace.name,  # Workspace
                                                   "Host",  # Type
                                                   network_str,  # Network (NW)
                                                   network_scope,  # Scope (NW)
                                                   network_companies,  # Company (NW)
                                                   host.address,  # IP Address (IP)
                                                   host.version_str,  # Version (IP)
                                                   host_is_private,  # Private IP
                                                   host.in_scope,  # In Scope (IP)
                                                   host.os_family,  # OS Family
                                                   host.os_details,  # OS Details
                                                   host_name.domain_name.name,  # Second-Level Domain (SLD)
                                                   host_name.domain_name.scope_str,  # Scope (SLD)
                                                   host_name.full_name,  # Host Name (HN)
                                                   host_name._in_scope,  # In Scope (HN)
                                                   host_name.name,  # Name (HN)
                                                   host_name.companies_str,  # Company (HN)
                                                   environment,  # Environment
                                                   service.protocol_str,  # UDP/TCP
                                                   service.port,  # Port
                                                   service.protocol_port_str,  # Service (SRV)
                                                   service.service_name_with_confidence,  # Nmap Name (SRV)
                                                   service.service_confidence,  # Confidence (SRV)
                                                   service.state_str,  # State (SRV)
                                                   service.nmap_service_state_reason,  # Reason State
                                                   service.nmap_product_version,  # Banner Information
                                                   True,  # Is HTTP
                                                   url_str[0] if url_str else None,  # URL
                                                   matching_host,  # HN Coverage
                                                   cert_info.cert_type_str,  # Cert. Type
                                                   cert_info.version,  # X509 Version
                                                   cert_info.subject,  # Subject
                                                   cert_info.issuer,  # Issuer
                                                   cert_info.is_self_signed(),  # Invalid CA (Self-Signed)
                                                   cert_info.signature_algorithm,  # Signature Algorithm
                                                   cert_info.public_key_name,  # Public Key Algorithm
                                                   cert_info.public_key_size,  # Public Key Size
                                                   cert_info.exponent,  # Exponent
                                                   cert_info.valid_from_str,  # Valid From
                                                   cert_info.valid_until_str,  # Valid Until
                                                   cert_info.validity_period_days / 365,  # Valid Years
                                                   verification,  # Verification
                                                   cert_info.has_exired(),  # Has Expired
                                                   cert_info.has_recommended_duration(),  # Recommended Duration
                                                   cert_info.subject_alt_names_str,  # Subject Alternative Names
                                                   str(extensions["keyUsage"]),  # Key Usage
                                                   str(extensions["extendedKeyUsage"]),  # Extended Key Usage
                                                   cert_info.critical_extensions_str,  # Critical Extensions
                                                   cert_info.ocsp_servers_str,  # OCSP Server
                                                   cert_info.crl_distribution_points_str,  # CRL
                                                   cert_info.serial_number,  # Serial Number
                                                   network_id,  # DB ID (NW)
                                                   host.id,  # DB ID (IP)
                                                   host_name.id,  # DB ID (HN)
                                                   service.id,  # DB ID (SRV)
                                                   cert_info.id,  # DB ID (CERT)
                                                   network_sources,  # Source (NW)
                                                   host_sources,  # Source (IP)
                                                   host_name_sources,  # Source (HN)
                                                   service.sources_str,  # Source (SRV)
                                                   cert_info.sources_str])
        return result
