# -*- coding: utf-8 -*-
""""This file contains all classes for object relational mappings."""

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

import os
import hashlib
import enum
import urllib
import logging
import subprocess
import ipaddress
import re
import pwd
import sqlalchemy as sa
from sqlalchemy import Column
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import DateTime
from sqlalchemy import ForeignKey
from sqlalchemy import Text
from sqlalchemy import Boolean
from sqlalchemy import Table
from sqlalchemy import Enum
from sqlalchemy.ext.mutable import Mutable
from sqlalchemy.orm import relationship
from sqlalchemy.orm import backref
from sqlalchemy import UniqueConstraint
from sqlalchemy import CheckConstraint
from sqlalchemy.dialects.postgresql import MACADDR
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.dialects.postgresql import BYTEA
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
from datetime import timedelta
from typing import List
from typing import Dict
from urllib.parse import urlparse

DeclarativeBase = declarative_base()

logger = logging.getLogger('model')


class FontColor:
    RED = '\033[91m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    GRAY = '\033[90m'
    ORANGE = '\033[33m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'


class WorkspaceNotFound(Exception):
    def __init__(self, workspace: str):
        super().__init__("workspace '{}' does not exist in database".format(workspace))


class NetworkNotFound(Exception):
    def __init__(self, network: str):
        super().__init__("network '{}' does not exist in database".format(network))


class HostNameNotFound(Exception):
    def __init__(self, domain: str):
        super().__init__("host name '{}' does not exist in database".format(domain))


class DomainNameNotFound(Exception):
    def __init__(self, domain: str):
        super().__init__("second-level domain name '{}' does not exist in database".format(domain))


class HostNotFound(Exception):
    def __init__(self, ip_address: str):
        super().__init__("host '{}' does not exist in database".format(ip_address))


class CastingArray(ARRAY):
    def bind_expression(self, bindvalue):
        return sa.cast(bindvalue, self)


class MutableList(Mutable, list):
    def append(self, value):
        list.append(self, value)
        self.changed()

    @classmethod
    def coerce(cls, key, value):
        if not isinstance(value, MutableList):
            if isinstance(value, list):
                return MutableList(value)
            return Mutable.coerce(key, value)
        else:
            return value


class MutableDict(Mutable, dict):
    @classmethod
    def coerce(cls, key, value):
        "Convert plain dictionaries to MutableDict."
        if not isinstance(value, MutableDict):
            if isinstance(value, dict):
                return MutableDict(value)

            # this call will raise ValueError
            return Mutable.coerce(key, value)
        else:
            return value

    def __setitem__(self, key, value):
        "Detect dictionary set events and emit change events."
        dict.__setitem__(self, key, value)
        self.changed()

    def __delitem__(self, key):
        "Detect dictionary del events and emit change events."
        dict.__delitem__(self, key)
        self.changed()


class VhostChoice(enum.Enum):
    all = enum.auto()
    domain = enum.auto()


class Utils:
    """
    This class implements common functionality for all model classes
    """
    @staticmethod
    def get_json(dictionary: dict, key, value, full=False) -> None:
        """This method determines whether the given value shall be added to the given dictionary"""
        if value or full:
            dictionary[key] = value


    @staticmethod
    def get_text(content: list, ident: int, full: bool, text: str, *args, color: str = None) -> None:
        """This method determines whether the given value shall be added to the given dictionary"""
        if args and args[0] or full:
            value = []
            for item in args:
                value.append(item if item is not None else "")
            if color:
                content.append("{}{}{}{}".format(color, " " * ident, text.format(*value), FontColor.END))
            else:
                content.append("{}{}".format(" " * ident, text.format(*value)))


class Url:
    """
    This class implements URL parsing capabilities
    """

    def __init__(self, url: str) -> None:
        self._url = None
        self._port = None
        self._host_name = None
        self._path = None
        self._params = None
        self._query = None
        self._tls = None
        self._scheme = None
        self.url = url

    @property
    def url(self) -> str:
        rvalue = None
        if self._url:
            rvalue = self._url.geturl()
        return rvalue

    @url.setter
    def url(self, value: str) -> None:
        if value:
            self._url = urlparse(value)
            self._path = self._url.path
            self._params = self._url.params
            self._query = self._url.query
            self._scheme = self._url.scheme
            if self._url:
                temp = self._url.netloc.split(":")
                if self._url.netloc:
                    if len(temp) > 2:
                        raise NotImplementedError("case not implemented")
                    elif len(temp) == 2:
                        self._port = temp[1]
                        self._host_name = temp[0]
                    elif len(temp) == 1:
                        self._host_name = temp[0]
                        self._tls = False
                        if self._url.scheme == "http":
                            self._port = 80
                        elif self._url.scheme == "https":
                            self._port = 443
                            self._tls = True
                        elif self._url.scheme == "ftp":
                            self._port = 21
                        else:
                            raise NotImplementedError("case not implemented")
        else:
            self._url = None
            self._port = None
            self._host_name = None
            self._path = None
            self._params = None
            self._query = None
            self._tls = None
            self._scheme = None

    @property
    def port(self) -> int:
        return self._port

    @property
    def tls(self) -> bool:
        return self._tls

    @property
    def host_name(self) -> str:
        return self._host_name

    @property
    def path(self) -> str:
        return self._path

    @property
    def scheme(self) -> str:
        return self._scheme

    @property
    def query(self) -> str:
        return self._query


class CommandStatus(enum.Enum):
    pending = 0
    collecting = 20
    terminated = 110
    failed = 210
    completed = 1000


class CredentialType(enum.Enum):
    Cleartext = 10
    Hash = 20
    Oracle_TNS_SID = 30


class FileType(enum.Enum):
    screenshot = 0
    certificate = 10
    json = 20
    xml = 30
    text = 40
    binary = 50
    other = 60


class ServiceState(enum.Enum):
    Open = enum.auto()
    Internal = enum.auto()
    Open_Filtered = enum.auto()
    Closed_Filtered = enum.auto()
    Filtered = enum.auto()
    Closed = enum.auto()


class DnsResourceRecordType(enum.Flag):
    a = 1
    aaaa = 2
    cname = 4
    ptr = 8
    ns = 16
    mx = 32
    alias = 64
    vhost = 128
    soa = 256
    txt = 512


class CollectorType(enum.Enum):
    service = 10
    host = 20
    # todo: update for new collector
    domain = 30
    ipv4_network = 40
    host_name_service = 50
    email = 60
    company = 70


class ProtocolType(enum.Enum):
    udp = 10
    tcp = 20


class PathType(enum.Enum):
    Http = 10
    Smb_Share = 20
    Nfs_Share = 30
    FileSystem = 40


class ExtensionType(enum.Enum):
    extended_key_usage = enum.auto()
    key_usage = enum.auto()


class TlsPreference(enum.Enum):
    server = enum.auto()
    client = enum.auto()
    indeterminate = enum.auto()
# sudo -u postgres psql kis -c "alter type public.tlspreference add value 'indeterminate';"

class CipherSuiteSecurity(enum.Enum):
    insecure = enum.auto()
    weak = enum.auto()
    secure = enum.auto()
    recommended = enum.auto()


class CipherSuiteProtocolVersion(enum.Enum):
    tls_export = enum.auto()
    tls = enum.auto()
    ssl = enum.auto()
# sudo -u postgres psql kis -c "alter type public.ciphersuiteprotocolversion add value 'ssl';"


class HashAlgorithm(enum.Enum):
    sha1 = enum.auto()
    md5 = enum.auto()
    sha256 = enum.auto()
    sha384 = enum.auto()
    sha512 = enum.auto()
    null = enum.auto()
    ccm = enum.auto()
    ccm8 = enum.auto()


class AsymmetricAlgorithm(enum.Enum):
    rsa = enum.auto()
    dsa = enum.auto()
    ecdsa = enum.auto()
    dss = enum.auto()
    rsa512 = enum.auto()
    rsa1024 = enum.auto()
    rsa2048 = enum.auto()
    rsa3072 = enum.auto()
    rsa4096 = enum.auto()
    anon512 = enum.auto()
# sudo -u postgres psql kis -c "alter type public.asymmetricalgorithm add value 'anon512';"


class AuthenticationAlgorithm(enum.Enum):
    anon = enum.auto()
    dss = enum.auto()
    psk = enum.auto()
    rsa = enum.auto()
    ecdsa = enum.auto()
    krb5 = enum.auto()
    null = enum.auto()
    sha_dss = enum.auto()
    sha = enum.auto()
    sha_rsa = enum.auto()
    eccpwd = enum.auto()
    dhe = enum.auto()


class KeyExchangeAlgorithm(enum.Enum):
    dh = enum.auto()
    dhe = enum.auto()
    ecdh = enum.auto()
    ecdhe = enum.auto()
    krb5 = enum.auto()
    null = enum.auto()
    psk = enum.auto()
    rsa = enum.auto()
    srp = enum.auto()
    eccpwd = enum.auto()
    dh512 = enum.auto()
    dh1024 = enum.auto()
    dh2048 = enum.auto()
    dh2240 = enum.auto()
    dh3072 = enum.auto()
    dh4096 = enum.auto()
    rsa512 = enum.auto()
    rsa1024 = enum.auto()
    rsa2048 = enum.auto()
    rsa3072 = enum.auto()
    rsa4096 = enum.auto()
    p_256 = enum.auto()
    p_384 = enum.auto()
    p_521 = enum.auto()
    ecdh_x25519 = enum.auto()
    secp256r1 = enum.auto()
    secp384r1 = enum.auto()
    secp521r1 = enum.auto()
    anonymous = enum.auto()
# sudo -u postgres psql kis -c "alter type public.keyexchangealgorithm add value 'anonymous';"


class SymmetricAlgorithm(enum.Enum):
    tripledes_ede_cbc = enum.auto()
    aes128 = enum.auto()
    aes128_cbc = enum.auto()
    aes128_ccm = enum.auto()
    aes128_ccm_8 = enum.auto()
    aes128_gcm = enum.auto()
    aes256 = enum.auto()
    aes256_cbc = enum.auto()
    aes256_ccm = enum.auto()
    aes256_gcm = enum.auto()
    aria128_cbc = enum.auto()
    aria128_gcm = enum.auto()
    aria256_cbc = enum.auto()
    aria256_gcm = enum.auto()
    camellia128_cbc = enum.auto()
    camellia128_gcm = enum.auto()
    camellia256_cbc = enum.auto()
    camellia256_gcm = enum.auto()
    chacha20_poly1305 = enum.auto()
    des_cbc = enum.auto()
    des_cbc_40 = enum.auto()
    des40_cbc = enum.auto()
    idea_cbc = enum.auto()
    null = enum.auto()
    rc2_cbc_40 = enum.auto()
    rc2_cbc_128 = enum.auto()
    rc4_128 = enum.auto()
    rc4_56 = enum.auto()
    rc4_40 = enum.auto()
    seed_cbc = enum.auto()
# alter type public.symmetricalgorithm add value 'rc2_cbc_128';


class TlsVersion(enum.Enum):
    ssl2 = enum.auto()
    ssl3 = enum.auto()
    tls10 = enum.auto()
    tls11 = enum.auto()
    tls12 = enum.auto()
    tls13 = enum.auto()


class CertType(enum.Enum):
    identity = enum.auto()
    intermediate = enum.auto()
    root = enum.auto()


class ReportScopeType(enum.Enum):
    within = enum.auto()
    outside = enum.auto()


class ScopeType(enum.Enum):
    # include item and all sub-items (e.g., sub-domains)
    all = enum.auto()
    # only include the current item and no sub-items
    strict = enum.auto()
    # exclude item and all sub-items
    exclude = enum.auto()
    # puts domain/network in scope if counterpart is in scope too
    vhost = enum.auto()


class IpSupport(enum.Enum):
    ipv4 = enum.auto()
    ipv6 = enum.auto()
    all = enum.auto()


class ReportVisibility(enum.Flag):
    irrelevant = enum.auto()
    relevant = enum.auto()


class CollectionTechniqueType(enum.Enum):
    whois = enum.auto()
    reverse_whois = enum.auto()
    reverse_certificate = enum.auto()
    certificate = enum.auto()
    port_scan = enum.auto()
    vulnerability_scan = enum.auto()
    dns_bruteforce = enum.auto()
    dns_lookup = enum.auto()
    reverse_dns_lookup = enum.auto()
    email_scraping = enum.auto()
    leak_search = enum.auto()
    password_bruteforce = enum.auto()
    path_discovery = enum.auto()


class Workspace(DeclarativeBase):
    """This class holds all information about a project."""

    __tablename__ = "workspace"
    id = Column(Integer, primary_key=True)
    name = Column(String(25), nullable=False, unique=True)
    hosts = relationship("Host",
                         backref=backref("workspace"),
                         cascade="delete, delete-orphan",
                         order_by="asc(Host.address)")
    domain_names = relationship("DomainName",
                                backref=backref("workspace"),
                                cascade="delete, delete-orphan",
                                order_by="asc(DomainName.name)")
    ipv4_networks = relationship("Network",
                                 backref=backref("workspace"),
                                 cascade="delete, delete-orphan",
                                 order_by="asc(Network.network)")
    files = relationship("File",
                         cascade="all, delete-orphan",
                         backref=backref("workspace"))
    companies = relationship("Company",
                             backref=backref("workspace"),
                             cascade="delete, delete-orphan",
                             order_by="asc(Company.name)")
    creation_date = Column(DateTime, nullable=False, default=datetime.utcnow())
    last_modified = Column(DateTime, nullable=True, onupdate=datetime.utcnow())

    def __eq__(self, other):
        rvalue = False
        if other:
            rvalue = self.name == other.name
        return rvalue

    def __repr__(self):
        return "<{} name={} />".format(self.__class__.__name__, self.name)


source_host_mapping = Table("source_host_mapping", DeclarativeBase.metadata,
                            Column("id", Integer, primary_key=True),
                            Column("host_id", Integer, ForeignKey('host.id', ondelete='cascade'), nullable=False),
                            Column("source_id", Integer, ForeignKey('source.id', ondelete='cascade'), nullable=False),
                            Column("creation_date", DateTime, nullable=False, default=datetime.utcnow()),
                            Column("last_modified", DateTime, nullable=True, onupdate=datetime.utcnow()),
                            UniqueConstraint("host_id",
                                             "source_id",
                                             name="_source_host_mapping_unique"))

source_service_mapping = Table("source_service_mapping", DeclarativeBase.metadata,
                               Column("id", Integer, primary_key=True),
                               Column("service_id", Integer, ForeignKey('service.id',
                                                                        ondelete='cascade'), nullable=False),
                               Column("source_id", Integer, ForeignKey('source.id',
                                                                       ondelete='cascade'), nullable=False),
                               Column("creation_date", DateTime, nullable=False, default=datetime.utcnow()),
                               Column("last_modified", DateTime, nullable=True, onupdate=datetime.utcnow()),
                               UniqueConstraint("service_id",
                                                "source_id",
                                                name="_source_service_mapping_unique"))

source_credentials_mapping = Table("source_credential_mapping", DeclarativeBase.metadata,
                                   Column("id", Integer, primary_key=True),
                                   Column("credential_id", Integer, ForeignKey('credential.id',
                                                                                ondelete='cascade'), nullable=False),
                                   Column("source_id", Integer, ForeignKey('source.id',
                                                                           ondelete='cascade'), nullable=False),
                                   Column("creation_date", DateTime, nullable=False, default=datetime.utcnow()),
                                   Column("last_modified", DateTime, nullable=True, onupdate=datetime.utcnow()),
                                   UniqueConstraint("credential_id",
                                                    "source_id",
                                                    name="_source_credential_mapping_unique"))

source_path_mapping = Table("source_path_mapping", DeclarativeBase.metadata,
                            Column("id", Integer, primary_key=True),
                            Column("path_id", Integer, ForeignKey('path.id',
                                                                  ondelete='cascade'), nullable=False),
                            Column("source_id", Integer, ForeignKey('source.id',
                                                                    ondelete='cascade'), nullable=False),
                            Column("creation_date", DateTime, nullable=False, default=datetime.utcnow()),
                            Column("last_modified", DateTime, nullable=True, onupdate=datetime.utcnow()))

source_service_method_mapping = Table("source_service_method_mapping", DeclarativeBase.metadata,
                                      Column("id", Integer, primary_key=True),
                                      Column("service_name_id",
                                             Integer, ForeignKey('service_method.id',
                                                                 ondelete='cascade'), nullable=False),
                                      Column("source_id", Integer, ForeignKey('source.id',
                                                                              ondelete='cascade'), nullable=False),
                                      Column("creation_date", DateTime, nullable=False, default=datetime.utcnow()),
                                      Column("last_modified", DateTime, nullable=True, onupdate=datetime.utcnow()))

source_host_name_mapping = Table("source_host_name_mapping", DeclarativeBase.metadata,
                                 Column("id", Integer, primary_key=True),
                                 Column("host_name_id", Integer, ForeignKey('host_name.id',
                                                                            ondelete='cascade'), nullable=False),
                                 Column("source_id", Integer, ForeignKey('source.id',
                                                                         ondelete='cascade'), nullable=False),
                                 Column("creation_date", DateTime, nullable=False, default=datetime.utcnow()),
                                 Column("last_modified", DateTime, nullable=True, onupdate=datetime.utcnow()),
                                 UniqueConstraint("host_name_id",
                                                  "source_id",
                                                  name="_source_host_name_mapping_unique"))

source_additional_info_mapping = Table("source_additional_info_mapping", DeclarativeBase.metadata,
                                       Column("id", Integer, primary_key=True),
                                       Column("additional_info_id", Integer, ForeignKey('additional_info.id',
                                                                                        ondelete='cascade'),
                                              nullable=False),
                                       Column("source_id", Integer, ForeignKey('source.id',
                                                                               ondelete='cascade'), nullable=False),
                                       Column("creation_date", DateTime, nullable=False, default=datetime.utcnow()),
                                       Column("last_modified", DateTime, nullable=True, onupdate=datetime.utcnow()),
                                       UniqueConstraint("additional_info_id",
                                                        "source_id",
                                                        name="_source_additional_info_mapping_unique"))

source_email_mapping = Table("source_email_mapping", DeclarativeBase.metadata,
                             Column("id", Integer, primary_key=True),
                             Column("email_id", Integer, ForeignKey('email.id',
                                                                    ondelete='cascade'), nullable=False),
                             Column("source_id", Integer, ForeignKey('source.id',
                                                                     ondelete='cascade'), nullable=False),
                             Column("creation_date", DateTime, nullable=False, default=datetime.utcnow()),
                             Column("last_modified", DateTime, nullable=True, onupdate=datetime.utcnow()),
                             UniqueConstraint("email_id", "source_id", name="_source_email_mapping_unique"))

source_company_mapping = Table("source_company_mapping", DeclarativeBase.metadata,
                               Column("id", Integer, primary_key=True),
                               Column("company_id", Integer, ForeignKey('company.id',
                                                                        ondelete='cascade'), nullable=False),
                               Column("source_id", Integer, ForeignKey('source.id',
                                                                       ondelete='cascade'), nullable=False),
                               Column("creation_date", DateTime, nullable=False, default=datetime.utcnow()),
                               Column("last_modified", DateTime, nullable=True, onupdate=datetime.utcnow()),
                               UniqueConstraint("company_id", "source_id", name="_source_company_mapping_unique"))

host_name_mapping = Table("host_name_mapping", DeclarativeBase.metadata,
                          Column("id", Integer, primary_key=True),
                          Column("host_id", Integer, ForeignKey('host.id',
                                                                ondelete='cascade'), nullable=False),
                          Column("host_name_id", Integer, ForeignKey('host_name.id',
                                                                     ondelete='cascade'), nullable=False),
                          Column("creation_date", DateTime, nullable=False, default=datetime.utcnow()),
                          Column("last_modified", DateTime, nullable=True, onupdate=datetime.utcnow()),
                          UniqueConstraint("host_id", "host_name_id", name="_host_name_mapping_unique"))

source_ipv4_network_mapping = Table("source_network_mapping", DeclarativeBase.metadata,
                                    Column("id", Integer, primary_key=True),
                                    Column("network_id", Integer, ForeignKey('network.id',
                                                                             ondelete='cascade'), nullable=False),
                                    Column("source_id", Integer, ForeignKey('source.id',
                                                                            ondelete='cascade'), nullable=False),
                                    Column("creation_date", DateTime, nullable=False, default=datetime.utcnow()),
                                    Column("last_modified", DateTime, nullable=True, onupdate=datetime.utcnow()),
                                    UniqueConstraint("network_id",
                                                     "source_id",
                                                     name="_source_network_mapping_unique"))

source_host_host_name_mapping = Table("source_host_host_name_mapping", DeclarativeBase.metadata,
                                      Column("id", Integer, primary_key=True),
                                      Column("host_host_name_mapping_id",
                                             Integer,
                                             ForeignKey('host_host_name_mapping.id', ondelete='cascade'),
                                             nullable=False),
                                      Column("source_id", Integer, ForeignKey('source.id',
                                                                              ondelete='cascade'), nullable=False),
                                      Column("creation_date", DateTime, nullable=False, default=datetime.utcnow()),
                                      Column("last_modified", DateTime, nullable=True, onupdate=datetime.utcnow()),
                                      UniqueConstraint("host_host_name_mapping_id",
                                                       "source_id",
                                                       name="_source_host_host_name_mapping_unique"))

source_host_name_host_name_mapping = Table("source_host_name_host_name_mapping", DeclarativeBase.metadata,
                                           Column("id", Integer, primary_key=True),
                                           Column("host_name_host_name_mapping_id",
                                                  Integer,
                                                  ForeignKey('host_name_host_name_mapping.id', ondelete='cascade'),
                                                  nullable=False),
                                           Column("source_id", Integer, ForeignKey('source.id',
                                                                                   ondelete='cascade'), nullable=False),
                                           Column("creation_date", DateTime, nullable=False, default=datetime.utcnow()),
                                           Column("last_modified", DateTime, nullable=True, onupdate=datetime.utcnow()),
                                           UniqueConstraint("host_name_host_name_mapping_id",
                                                            "source_id",
                                                            name="_source_host_name_host_name_mapping_unique"))

source_cert_info_mapping = Table("source_cert_info_mapping", DeclarativeBase.metadata,
                                 Column("id", Integer, primary_key=True),
                                 Column("cert_info_id",
                                        Integer,
                                        ForeignKey('cert_info.id', ondelete='cascade'),
                                        nullable=False),
                                 Column("source_id", Integer, ForeignKey('source.id',
                                                                         ondelete='cascade'), nullable=False),
                                 Column("creation_date", DateTime, nullable=False, default=datetime.utcnow()),
                                 Column("last_modified", DateTime, nullable=True, onupdate=datetime.utcnow()),
                                 UniqueConstraint("cert_info_id",
                                                  "source_id",
                                                  name="_source_cert_info_mapping_mapping_unique"))

source_tls_info_cipher_suite_mapping = Table("source_tls_info_cipher_suite_mapping", DeclarativeBase.metadata,
                                             Column("id", Integer, primary_key=True),
                                             Column("tls_info_cipher_suite_mapping_id",
                                                    Integer,
                                                    ForeignKey('tls_info_cipher_suite_mapping.id', ondelete='cascade'),
                                                    nullable=False),
                                             Column("source_id", Integer, ForeignKey('source.id',
                                                                                     ondelete='cascade'),
                                                    nullable=False),
                                             Column("creation_date",
                                                    DateTime,
                                                    nullable=False,
                                                    default=datetime.utcnow()),
                                             Column("last_modified",
                                                    DateTime, nullable=True,
                                                    onupdate=datetime.utcnow()),
                                             UniqueConstraint("tls_info_cipher_suite_mapping_id",
                                                              "source_id",
                                                              name="_tls_source_info_cipher_suite_mapping_unique"))

company_network_mapping = Table("company_network_mapping", DeclarativeBase.metadata,
                                Column("id", Integer, primary_key=True),
                                Column("company_id",
                                       Integer,
                                       ForeignKey('company.id', ondelete='cascade'),
                                       nullable=False),
                                Column("network_id", Integer, ForeignKey('network.id',
                                                                         ondelete='cascade'), nullable=False),
                                Column("creation_date", DateTime, nullable=False, default=datetime.utcnow()),
                                Column("last_modified", DateTime, nullable=True, onupdate=datetime.utcnow()),
                                UniqueConstraint("company_id",
                                                 "network_id",
                                                 name="_company_network_mapping_unique"))

company_domain_name_mapping = Table("company_domain_name_mapping", DeclarativeBase.metadata,
                                    Column("id", Integer, primary_key=True),
                                    Column("company_id",
                                           Integer,
                                           ForeignKey('company.id', ondelete='cascade'),
                                           nullable=False),
                                    Column("domain_name_id", Integer, ForeignKey('domain_name.id',
                                                                                 ondelete='cascade'), nullable=False),
                                    Column("creation_date", DateTime, nullable=False, default=datetime.utcnow()),
                                    Column("last_modified", DateTime, nullable=True, onupdate=datetime.utcnow()),
                                    UniqueConstraint("company_id",
                                                     "domain_name_id",
                                                     name="_company_domain_name_mapping_unique"))

#create unique index _host_index_address on host(address);
class Host(DeclarativeBase):
    """This class holds all information about a host."""

    __tablename__ = "host"
    id = Column("id", Integer, primary_key=True)
    mac_address = Column(MACADDR, nullable=True, unique=False)
    address = Column("address", INET, nullable=False, unique=False)
    _in_scope = Column("in_scope", Boolean, nullable=False, unique=False, server_default='FALSE')
    os_family = Column(Text, nullable=True, unique=False)
    is_up = Column(Boolean, nullable=False, unique=False, default=True)
    reason_up = Column(Text, nullable=True, unique=False)
    os_details = Column(Text, nullable=True, unique=False)
    workgroup = Column(Text, nullable=True, unique=False)
    workspace_id = Column(Integer, ForeignKey("workspace.id", ondelete='cascade'), nullable=False, unique=False)
    ipv4_network_id = Column("network_id", Integer, ForeignKey("network.id", ondelete='SET NULL'), nullable=True, unique=False)
    creation_date = Column(DateTime, nullable=False, default=datetime.utcnow())
    last_modified = Column(DateTime, nullable=True, onupdate=datetime.utcnow())
    services = relationship("Service",
                            backref=backref("host"),
                            cascade="all, delete-orphan",
                            order_by="desc(Service.protocol), asc(Service.port)")
    host_names = relationship('HostName',
                              secondary='host_host_name_mapping',
                              back_populates="hosts")
    __table_args__ = (UniqueConstraint('workspace_id', 'address', name='_host_unique'),)

    def __eq__(self, other):
        rvalue = False
        if other:
            rvalue = (self.mac_address == other.mac_address or self.address == other.address)
        return rvalue

    @property
    def ip(self):
        """
        :return: This method returns the IP type that is populated. If both IPs are populated, then the IPv4 address
        is returned.
        """
        return self.address

    @property
    def ip_address(self):
        return ipaddress.ip_address(self.address)

    @property
    def version(self) -> int:
        return self.ip_address.version

    @property
    def version_str(self) -> str:
        return "IPv{}".format(self.version)

    def supports_version(self, support: IpSupport) -> bool:
        version = self.version
        return version and (support == IpSupport.all or (
                support == IpSupport.ipv4 and version == 4) or (support == IpSupport.ipv6 and version == 6))

    @property
    def ipv4_address(self) -> str:
        result = None
        address = self.ip_address
        if address.version == 4:
            result = self.address
        return result

    @property
    def ipv6_address(self) -> str:
        result = None
        address = self.ip_address
        if address.version == 6:
            result = self.address
        return result

    @property
    def in_scope(self) -> bool:
        """
        Returns true if the host is in scope
        :return:
        """
        return self._in_scope

    @in_scope.setter
    def in_scope(self, value: bool):
        self._in_scope = value

    @property
    def sources_str(self) -> str:
        result = None
        if self.sources:
            result = ", ".join([item.name for item in self.sources])
        return result

    @property
    def in_scope_host_name(self) -> bool:
        """
        This method returns true, if one of the host names that resolve to this IP address are in scope.
        :return:
        """
        result = False
        mappings = self.get_host_host_name_mappings(types=[DnsResourceRecordType.a,
                                                           DnsResourceRecordType.aaaa])
        for item in mappings:
            if item.host_name._in_scope:
                result = True
                break
        return result

    def get_host_host_name_mappings(self, types: List[DnsResourceRecordType] = []) -> list:
        """
        Returns list of host names based on the given types. If types are empty, then all mappings are returned
        :param types:
        :return:
        """
        result = []
        if self.host_host_name_mappings:
            for item in self.host_host_name_mappings:
                if types:
                    for type in types:
                        if (item.type & type) == type:
                            result.append(item)
                            break
                else:
                    result.append(item)
        return result

    def get_host_host_name_mappings_str(self, types: List[DnsResourceRecordType] = []) -> str:
        """
        Returns list of host names based on the given types. If types are empty, then all mappings are returned
        :param types:
        :return:
        """
        result = []
        for item in self.get_host_host_name_mappings(types):
            if item.host_name.in_scope:
                result.append("{} [{}, In-Scope]".format(item.host_name.full_name, item.type_str))
            else:
                result.append("{} [{}]".format(item.host_name.full_name, item.type_str))
        return ", ".join(result)

    @property
    def summary(self) -> str:
        """
        Returns the IP address and the first DNS A record type that resolved to this IP address
        :return:
        """
        host_names = [item.host_name.full_name for item in self.get_host_host_name_mappings([DnsResourceRecordType.a,
                                                                                             DnsResourceRecordType.aaaa])]
        host_names.sort()
        length = len(host_names)
        if length == 1:
            result = "{} ({})".format(self.address, host_names[0])
        elif length > 1:
            result = "{} ({}, ...)".format(self.address, host_names[0])
        else:
            result = self.address
        return result

    def has_host_name(self, host_names: List[str]):
        """Returns true if the host has the given host name"""
        rvalue = False
        for host_name in host_names:
            for item in self.host_names:
                if host_name == item.full_name:
                    rvalue = True
                    break
        return rvalue

    def has_domain_name(self, domain_names: List[str]):
        """Returns true if the host has the given host name"""
        rvalue = False
        for domain_name in domain_names:
            for item in self.host_names:
                if domain_name == item.domain_name.name:
                    rvalue = True
                    break
        return rvalue

    def is_processable(self,
                       included_items: List[str],
                       excluded_items: List[str],
                       active_collector: bool = None,
                       scope: ReportScopeType = None,
                       include_host_names: bool = False) -> bool:
        """
        This method determines whether intel or report information should be collected from this host
        :param included_items: List of items to be processed
        :param excluded_items: List of items to be excluded
        :param active_collector: Value that specifies whether the given collector is active or passive
        :param scope: Value that specifies whether only in-scope items should be included into the report
        :param include_host_names: If false, filters only work on IPv4 addresses and networks, else filter works also
        on host names
        :return: True, if the host_name is in the filter list or the filter list is empty
        """
        if active_collector is not None and scope:
            raise ValueError("in scope and active collector parameters are mutual exclusive")
        rvalue = self.address not in excluded_items and \
                 (self.ipv4_network is None or self.ipv4_network.network not in excluded_items) and \
                 (not include_host_names or not self.has_host_name(excluded_items)) and \
                 (not include_host_names or not self.has_domain_name(excluded_items)) and \
                 (not included_items or (self.address in included_items or
                                    self.ipv4_network and self.ipv4_network.network in included_items or
                                    (include_host_names and self.has_host_name(included_items)) or
                                    (include_host_names and self.has_domain_name(included_items)))) and \
                 (scope is None or (scope == ReportScopeType.within and self.in_scope) or (
                         scope == ReportScopeType.outside and not self.in_scope)) and \
                 (active_collector is None or not active_collector or self.in_scope and active_collector)
        return rvalue

    def has_open_services(self, strict: bool = False) -> bool:
        """
        Determines whether the given host has open services.
        :param strict: If true, then only services with status 'open' and not 'open|filtered' are counted
        :return: Returns true, if the host has at least one open service
        """
        rvalue = False
        for service in self.services:
            if service.is_open(strict):
                rvalue = True
                break
        return rvalue

    def has_given_collectors(self, include_collectors: List[str] = [], **kwargs) -> bool:
        """
        Determines whether the given host has a collector listed in list include_collectors
        :param include_collectors:
        :param kwargs:
        :return: Returns true, if the host has a collector
        """
        rvalue = not include_collectors
        if not rvalue:
            for command in self.commands:
                if command.collector_name.name in include_collectors \
                        and command.status.value > CommandStatus.pending.value:
                    rvalue = True
                    break
        return rvalue

    def get_text(self,
                 ident: int = 0,
                 show_metadata: bool = True,
                 report_visibility: ReportVisibility = None,
                 color: bool = False,
                 **kwargs) -> List[str]:
        """
        :param ident: Number of spaces to indent
        :param show_metadata: True, if all meta information and not just command outputs shall be returned
        :param report_visibility: Specifies which information shall be shown
        :return: String for console output
        """
        rvalue = []
        has_open_services = self.has_open_services(strict=True)
        has_given_collectors = self.has_given_collectors(**kwargs)
        if has_given_collectors and ((has_open_services and report_visibility == ReportVisibility.relevant) or
                                     report_visibility is None or report_visibility == ReportVisibility.irrelevant):
            if show_metadata:
                host_names = self.get_host_host_name_mappings_str(types=[DnsResourceRecordType.a,
                                                                         DnsResourceRecordType.aaaa,
                                                                         DnsResourceRecordType.ptr])
                host_names = " ({})".format(host_names) if host_names else ""
                if self.ipv4_network:
                    network = self.ipv4_network.network
                    companies = [company.name for company in self.ipv4_network.companies]
                    companies = " ({})".format(", ".join(companies)) if companies else ""
                else:
                    companies = ""
                    network = ""
                full = report_visibility != ReportVisibility.relevant if ReportVisibility else True
                Utils.get_text(rvalue, ident, True, "KIS intel report for {}{}, ID: {}", self.ip, host_names, self.id,
                               color=FontColor.BLUE + FontColor.BOLD if color else None)
                Utils.get_text(rvalue, ident, True, "| In scope:        {}", self.in_scope)
                Utils.get_text(rvalue, ident, True, "| Workspace:       {}", self.workspace.name)
                Utils.get_text(rvalue, ident, full, "| MAC address:     {}", self.mac_address)
                Utils.get_text(rvalue, ident, full, "| IP address:      {}", self.address)
                Utils.get_text(rvalue, ident, full, "| IP network:      {}{}", network, companies)
                Utils.get_text(rvalue, ident, full, "| OS family:       {}", self.os_family)
                Utils.get_text(rvalue, ident, full, "| OS details:      {}", self.os_details)
                Utils.get_text(rvalue, ident, full, "| Workgroup:       {}", self.workgroup)
                sources = ", ".join([item.name for item in self.sources])
                Utils.get_text(rvalue, ident, full, "|_Sources:         {}", sources)
                rvalue.append("")
                Utils.get_text(rvalue, ident, full, "PORT        STATE              SERVICE          VERSION", "_",
                               color=FontColor.BOLD if color else None)
                for service in self.services:
                    items = service.get_text(ident, report_visibility=report_visibility, color=color, **kwargs)
                    if items:
                        rvalue.extend(items)
            hashes_dedup = {}
            for service in self.services:
                if service.has_given_collectors(**kwargs):
                    items = service.get_command_text(ident=ident,
                                                     hashes_dedup=hashes_dedup,
                                                     show_metadata=show_metadata,
                                                     report_visibility=report_visibility,
                                                     color=color,
                                                     **kwargs)
                    if items:
                        rvalue.extend(items)
            hashes_dedup = {}
            items = self.get_command_text(ident=ident,
                                          hashes_dedup=hashes_dedup,
                                          show_metadata=show_metadata,
                                          report_visibility=report_visibility,
                                          color=color,
                                          **kwargs)
            if items:
                rvalue.extend(items)
            rvalue.append(os.linesep * 2)
        return rvalue

    def get_command_text(self,
                         exclude_collectors: List[str] = [],
                         include_collectors: List[str] = [],
                         **args) -> List[str]:
        """
        :param exclude_collectors: List of collector names whose output should not be printed
        :param include_collectors: List of collector names whose output should be printed
        :return: String for console output
        """
        rvalue = []
        if self.commands:
            rvalue.append("")
        for item in self.commands:
            if (item.collector_name.name not in exclude_collectors and (not include_collectors or
                item.collector_name.name in include_collectors)) \
                    and not item.service:
                rvalue.extend(item.get_text(**args))
        return rvalue


class Network(DeclarativeBase):
    """This class contains information about domain names."""

    __tablename__ = "network"
    id = Column(Integer, primary_key=True)
    network = Column("address", INET, nullable=False, unique=False)
    scope = Column(Enum(ScopeType), nullable=True, unique=False)
    workspace_id = Column(Integer, ForeignKey("workspace.id", ondelete='cascade'), nullable=False, unique=False)
    creation_date = Column(DateTime, nullable=False, default=datetime.utcnow())
    last_modified = Column(DateTime, nullable=True, onupdate=datetime.utcnow())
    hosts = relationship("Host",
                         backref=backref("ipv4_network", uselist=False),
                         order_by="asc(Host.address)")
    __table_args__ = (UniqueConstraint('address', 'workspace_id', name='_network_unique'),)

    @property
    def in_scope(self) -> bool:
        return self.scope is not None and (self.scope == ScopeType.all)

    @property
    def ip_network(self):
        return ipaddress.ip_network(self.network)

    @property
    def version(self) -> int:
        return self.ip_network.version

    @property
    def version_str(self) -> str:
        return "IPv{}".format(self.version)

    def supports_version(self, support: IpSupport) -> bool:
        version = self.version
        return version and (support == IpSupport.all or (
                support == IpSupport.ipv4 and version == 4) or (support == IpSupport.ipv6 and version == 6))

    @property
    def ipv4_network(self) -> str:
        result = None
        network = self.ip_network
        if network.version == 4:
            result = self.network
        return result

    @property
    def ipv6_network(self) -> str:
        result = None
        network = self.ip_network
        if network.version == 6:
            result = self.addnetworkress
        return result

    @property
    def scope_str(self) -> str:
        return self.scope.name.lower() if self.scope else ScopeType.exclude.name

    @property
    def sources_str(self) -> str:
        result = None
        if self.sources:
            result = ", ".join([item.name for item in self.sources])
        return result

    @property
    def companies_str(self) -> str:
        result = None
        if self.companies:
            result = ", ".join(["{} (in scope: {})".format(item.name, item.in_scope) for item in self.companies])
        return result

    def is_in_network(self, address: str) -> bool:
        """This method verifies whether the given IPv4 address is in the network"""
        return ipaddress.ip_address(address) in self.ip_network

    def is_in_scope(self, address: str) -> bool:
        """This method verifies whether the given IPv4 address is in scope"""
        return self.in_scope and self.is_in_network(address)

    def is_processable(self,
                       included_items: List[str],
                       excluded_items: List[str],
                       active_collector: bool = None,
                       scope: bool = None) -> bool:
        """
        This method determines whether intel or report information should be collected from this network
        :param included_items: List of items to be processed
        :param excluded_items: List of items to be excluded
        :param active_collector: Value that specifies whether the given collector is active or passive
        :param scope: Value that specifies whether only in-scope items should be included into the report
        :return: True, if the host_name is in the filter list or the filter list is empty
        """
        if active_collector is not None and scope:
            raise ValueError("scope and active collector parameters are mutual exclusive")
        rvalue = self.network not in excluded_items and \
                 (not included_items or self.network in included_items) and \
                 (scope is None or (scope == ReportScopeType.within and self.in_scope) or (
                         scope == ReportScopeType.outside and not self.in_scope)) and \
                 (self.in_scope and active_collector or not active_collector)
        return rvalue

    def get_text(self,
                 ident: int = 0,
                 show_metadata: bool = True,
                 report_visibility: ReportVisibility = None,
                 color: bool = False,
                 **kwargs) -> List[str]:
        """
        :param ident: Number of spaces
        :param show_metadata: True, if all meta information and not just command outputs shall be returned
        :param report_visibility: Specifies which information shall be shown
        :return: String for console output
        """
        rvalue = []
        if show_metadata:
            full = report_visibility != ReportVisibility.relevant if ReportVisibility else True
            Utils.get_text(rvalue, ident, True, "KIS intel report for {}", self.network,
                           color=FontColor.BLUE + FontColor.BOLD if color else None)
            Utils.get_text(rvalue, ident, True, "| In scope:      {}", self.in_scope)
            Utils.get_text(rvalue, ident, True, "| Workspace:     {}", self.workspace.name)
            Utils.get_text(rvalue, ident, full, "| Companies:     {}",
                           ", ".join([company.name for company in self.companies]))
            Utils.get_text(rvalue, ident, full, "| Sources:       {}",
                           ", ".join([item.name for item in self.sources]))
            Utils.get_text(rvalue, ident, True, "|_Number of IPs: {}", len(self.hosts))
        hashes_dedup = {}
        items = self.get_command_text(ident=ident,
                                      hashes_dedup=hashes_dedup,
                                      report_visibility=report_visibility,
                                      show_metadata=show_metadata,
                                      color=color,
                                      **kwargs)
        if items:
            rvalue.extend(items)
        rvalue.append(os.linesep * 2)
        return rvalue

    def get_command_text(self,
                         exclude_collectors: List[str] = [],
                         include_collectors: List[str] = [],
                         **args) -> List[str]:
        """
        :param exclude_collectors: List of collector names whose output should not be printed
        :param include_collectors: List of collector names whose output should be printed
        :return: String for console output
        """
        rvalue = []
        for item in self.commands:
            if (item.collector_name.name not in exclude_collectors and (not include_collectors or
                item.collector_name.name in include_collectors)):
                rvalue.extend(item.get_text(**args))
        return rvalue


class HostName(DeclarativeBase):
    """This class contains information about domain names."""

    __tablename__ = "host_name"
    id = Column(Integer, primary_key=True)
    name = Column(Text, nullable=True, unique=False)
    _in_scope = Column("in_scope", Boolean, nullable=False, unique=False, server_default='FALSE')
    creation_date = Column(DateTime, nullable=False, default=datetime.utcnow())
    last_modified = Column(DateTime, nullable=True, onupdate=datetime.utcnow())
    emails = relationship("Email",
                          backref=backref("host_name"),
                          cascade="delete",
                          order_by="asc(Email.address)")
    domain_name_id = Column(Integer, ForeignKey("domain_name.id", ondelete='cascade'), nullable=False, unique=False)
    services = relationship("Service",
                            backref=backref("host_name"),
                            cascade="delete, delete-orphan",
                            order_by="desc(Service.protocol), asc(Service.port)")
    hosts = relationship('Host',
                         secondary='host_host_name_mapping',
                         back_populates="host_names")
    __table_args__ = (UniqueConstraint('name', 'domain_name_id', name='_host_name_unique'),)

    @property
    def full_name(self) -> str:
        return_value = self.name
        if self.domain_name and self.name:
            return_value = "{}.{}".format(self.name, self.domain_name.name)
        elif self.domain_name and not self.name:
            return_value = self.domain_name.name
        elif not self.domain_name and self.name:
            return_value = self.name
        return return_value

    def in_scope(self, collector_type: CollectorType) -> bool:
        result = self.domain_name is not None and (self.domain_name.scope == ScopeType.all or (
            (self.domain_name.scope == ScopeType.strict or self.domain_name.scope == ScopeType.vhost) and
            self._in_scope))
        if result and collector_type == CollectorType.host_name_service:
            result = result and self.resolves_to_in_scope_ipv4_address()
        return result

    def in_scope_ipv6(self, collector_type: CollectorType) -> bool:
        result = self.domain_name is not None and (self.domain_name.scope == ScopeType.all or (
            (self.domain_name.scope == ScopeType.strict or self.domain_name.scope == ScopeType.vhost) and
            self._in_scope))
        if result and collector_type == CollectorType.host_name_service:
            result = result and self.resolves_to_in_scope_ipv6_address()
        return result

    @property
    def workspace(self):
        return self.domain_name.workspace if self.domain_name else None

    @property
    def workspace_id(self):
        return self.workspace.id if self.workspace.id else None

    @property
    def sources_str(self) -> str:
        result = None
        if self.sources:
            result = ", ".join([item.name for item in self.sources])
        return result

    @property
    def companies(self) -> list:
        return self.domain_name.companies if self.domain_name else []

    @property
    def companies_str(self) -> str:
        result = None
        if self.domain_name and self.domain_name.companies:
            result = ", ".join(["{} (in scope: {})".format(item.name, item.in_scope) for item in self.domain_name.companies])
        return result

    @property
    def canonical_name_records(self) -> list:
        """Returns the list of canonical names"""
        result = [self]
        for resolved_to in self.resolved_host_name_mappings:
            if resolved_to and resolved_to.resolved_host_name:
                result += resolved_to.resolved_host_name.canonical_name_records
        return result

    def get_host_host_name_mappings(self, types: List[DnsResourceRecordType] = []) -> list:
        """
        Returns list of host names based on the given types. If types are empty, then all mappings are returned
        :param types:
        :return:
        """
        result = []
        if self.host_host_name_mappings:
            for item in self.host_host_name_mappings:
                if types:
                    for type in types:
                        if (item.type & type) == type:
                            result.append(item)
                            break
                else:
                    result.append(item)
        return result

    def get_host_host_name_mappings_str(self, types: List[DnsResourceRecordType] = []) -> str:
        """
        Returns list of host names based on the given types. If types are empty, then all mappings are returned
        :param types:
        :return:
        """
        result = []
        for item in self.get_host_host_name_mappings(types):
            if item.host.in_scope:
                result.append("{} [{}, In-Scope]".format(item.host.address, item.type_str))
            else:
                result.append("{} [{}]".format(item.host.address, item.type_str))
        return ", ".join(result)

    def resolves_to_in_scope_ipv4_address(self) -> bool:
        """
        This method returns True, if the given host name resolves to the host via a DNS resource record type A
        :return:
        """
        result = False
        for item in self.host_host_name_mappings:
            if item.resolves_to_in_scope_ipv4_address():
                result = True
                break
        return result

    def resolves_to_in_scope_ipv6_address(self) -> bool:
        """
        This method returns True, if the given host name resolves to the host via a DNS resource record type AAAA
        :return:
        """
        result = False
        for item in self.host_host_name_mappings:
            if item.resolves_to_in_scope_ipv6_address():
                result = True
                break
        return result

    @property
    def summary(self) -> str:
        """
        Returns the host name and the first DNS A record type that this host name resolves to
        :return:
        """
        ip_addresses = [item.host.address for item in self.get_host_host_name_mappings([DnsResourceRecordType.a,
                                                                                        DnsResourceRecordType.aaaa])]
        ip_addresses.sort()
        length = len(ip_addresses)
        if length == 1:
            result = "{} ({})".format(self.full_name, ip_addresses[0])
        elif length > 1:
            result = "{} ({}, ...)".format(self.full_name, ip_addresses[0])
        else:
            result = self.full_name
        return result

    def is_processable(self,
                       included_items: List[str],
                       excluded_items: List[str],
                       collector_type: CollectorType,
                       active_collector: bool = None,
                       scope: ReportScopeType = None,
                       include_ip_address: bool = False) -> bool:
        """
        This method determines whether intel or report information should be collected from this host name
        :param included_items: List of items to be processed
        :param excluded_items: List of items to be excluded
        :param collector_type: Specifies the collector type for which scope shall be determined
        :param active_collector: Value that specifies whether the given collector is active or passive
        :param scope: Value that specifies whether only in-scope items should be included into the report
        :param include_ip_address: If false, filters only work on domain names, else filter works also
        on IPv4/IPv6 addresses
        :return: True, if the host_name is in the filter list or the filter list is empty
        """
        if active_collector is not None and scope:
            raise ValueError("scope and active collector parameters are mutual exclusive")
        is_domain_name_none = self.domain_name is None
        is_in_scope = self.in_scope(collector_type) or self.in_scope_ipv6(collector_type)
        rvalue = self.full_name not in excluded_items and \
                 (is_domain_name_none or self.domain_name.name not in excluded_items) and \
                 (not include_ip_address or not self.has_ip_address(excluded_items)) and \
                 (not included_items or (self.full_name in included_items or
                                         (not is_domain_name_none and self.domain_name.name in included_items) or
                                         (include_ip_address and self.has_ip_address(included_items)))) and \
                 (scope is None or (scope == ReportScopeType.within and is_in_scope) or (
                         scope == ReportScopeType.outside and not is_in_scope)) and \
                 (active_collector is None or not active_collector or is_in_scope and active_collector)
        return rvalue

    def has_ip_address(self, ip_addresses: List[str]):
        """Returns true if the host name has one of the given IPv4/IPv6 addresses"""
        rvalue = False
        for ip_address in ip_addresses:
            for host in self.hosts:
                if host.address == ip_address:
                    rvalue = True
                    break
        return rvalue

    def has_open_services(self, strict: bool = False) -> bool:
        """
        Determines whether the given host has open services.
        :param strict: If true, then only services with status 'open' and not 'open|filtered' are counted
        :return: Returns true, if the host has at least one open service
        """
        rvalue = False
        for service in self.services:
            if service.is_open(strict):
                rvalue = True
                break
        return rvalue

    def has_given_collectors(self, include_collectors: List[str] = [], **kwargs) -> bool:
        """
        Determines whether the given host has a collector listed in list include_collectors
        :param include_collectors:
        :param kwargs:
        :return: Returns true, if the host has a collector
        """
        rvalue = not include_collectors
        if not rvalue:
            for command in self.commands:
                if command.collector_name.name in include_collectors \
                        and command.status.value > CommandStatus.pending.value:
                    rvalue = True
                    break
        return rvalue

    def get_text(self,
                 ident: int = 0,
                 companies: Dict[str, str] = {},
                 show_metadata: bool = True,
                 report_visibility: ReportVisibility = None,
                 color: bool = False,
                 **kwargs) -> List[str]:
        """
        :param ident: Number of spaces to indent
        :param show_metadata: True, if all meta information and not just command outputs shall be returned
        :param report_visibility: Specifies which information shall be shown
        :return: String for console output
        """
        rvalue = []
        has_open_services = self.has_open_services(strict=True)
        has_given_collectors = self.has_given_collectors(**kwargs)
        hosts = self.get_host_host_name_mappings_str(types=[DnsResourceRecordType.ptr,
                                                            DnsResourceRecordType.a,
                                                            DnsResourceRecordType.aaaa])
        if hosts:
            hosts = " ({})".format(hosts)
        if has_given_collectors and ((has_open_services and report_visibility == ReportVisibility.relevant) or
                                     report_visibility is None or report_visibility == ReportVisibility.irrelevant):
            if show_metadata:
                full = report_visibility != ReportVisibility.relevant if ReportVisibility else True
                Utils.get_text(rvalue, ident, True, "KIS intel report for {}{}", self.full_name, hosts,
                               color=FontColor.BLUE + FontColor.BOLD if color else None)
                Utils.get_text(rvalue, ident, True, "| In scope:        {}",
                               self.in_scope(CollectorType.host_name_service))
                Utils.get_text(rvalue, ident, True, "| Workspace:       {}", self.workspace.name)
                Utils.get_text(rvalue, ident, True, "| Host name:       {}", self.full_name)
                Utils.get_text(rvalue, ident, full, "| Companies:       {}", companies[self.domain_name.name])
                sources = ", ".join([item.name for item in self.sources])
                Utils.get_text(rvalue, ident, full, "|_Sources:         {}", sources)
                rvalue.append("")
                Utils.get_text(rvalue, ident, full, "PORT        STATE              SERVICE          VERSION", "_",
                               color=FontColor.BOLD if color else None)
            for service in self.services:
                items = service.get_text(ident=ident,
                                         show_metadata=show_metadata,
                                         report_visibility=report_visibility,
                                         color=color,
                                         **kwargs)
                if items:
                    rvalue.extend(items)
            hashes_dedup = {}
            for service in self.services:
                if service.has_given_collectors(**kwargs):
                    items = service.get_command_text(ident=ident,
                                                     hashes_dedup=hashes_dedup,
                                                     show_metadata=show_metadata,
                                                     report_visibility=report_visibility,
                                                     color=color,
                                                     **kwargs)
                    if items:
                        rvalue.extend(items)
            rvalue.append(os.linesep)
        return rvalue

    def get_command_text(self,
                         exclude_collectors: List[str] = [],
                         include_collectors: List[str] = [],
                         **args) -> List[str]:
        """
        :param exclude_collectors: List of collector names whose output should not be printed
        :param include_collectors: List of collector names whose output should be printed
        :return: String for console output
        """
        rvalue = []
        if self.commands:
            rvalue.append("")
        for item in self.commands:
            if item.collector_name.name not in exclude_collectors and (item.collector_name.name in include_collectors or
                                                                       not include_collectors):
                rvalue.extend(item.get_text(**args))
        return rvalue


class HostHostNameMapping(DeclarativeBase):
    """
    This class stores connection information between hosts and host names
    """

    __tablename__ = "host_host_name_mapping"
    __mapper_args__ = {'confirm_deleted_rows': False}
    id = Column("id", Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey('host.id', ondelete='cascade'), nullable=False)
    host_name_id = Column(Integer, ForeignKey('host_name.id', ondelete='cascade'), nullable=False)
    _type = Column("type", Integer, nullable=False)
    creation_date = Column(DateTime, nullable=False, default=datetime.utcnow())
    last_modified = Column(DateTime, nullable=True, onupdate=datetime.utcnow())
    host_name = relationship(HostName, backref=backref('host_host_name_mappings', cascade="delete, delete-orphan"))
    host = relationship(Host, backref=backref('host_host_name_mappings', cascade="delete, delete-orphan"))
    __table_args__ = (UniqueConstraint('host_id', 'host_name_id', name='_host_host_name_mapping_unique'),)

    @property
    def type(self) -> DnsResourceRecordType:
        if self._type is not None:
            result = DnsResourceRecordType(self._type)
        else:
            result = DnsResourceRecordType(0)
        return result

    @type.setter
    def type(self, value: DnsResourceRecordType) -> None:
        self._type = value.value

    @property
    def type_str(self) -> str:
        result = []
        for item in DnsResourceRecordType:
            if (self.type & item) == item:
                result.append(item.name.upper())
        return ", ".join(result) if result else None

    def resolves_to_in_scope_ipv4_address(self) -> bool:
        """
        This method returns True, if the given host name resolves to the host via a DNS resource record type A
        :return:
        """
        return self.resolves_to_ipv4_address() and self.host.in_scope

    def resolves_to_in_scope_ipv6_address(self) -> bool:
        """
        This method returns True, if the given host name resolves to the host via a DNS resource record type A
        :return:
        """
        return self.resolves_to_ipv6_address() and self.host.in_scope

    def resolves_to_ipv4_address(self) -> bool:
        """
        This method returns True, if the given host name resolves to the host via a DNS resource record type A
        :return:
        """
        return bool(self.type & DnsResourceRecordType.a)

    def resolves_to_ipv6_address(self) -> bool:
        """
        This method returns True, if the given host name resolves to the host via a DNS resource record type AAAA
        :return:
        """
        return bool(self.type & DnsResourceRecordType.aaaa)


class HostNameHostNameMapping(DeclarativeBase):
    """
    This class stores connection information between host names and host names
    """

    __tablename__ = "host_name_host_name_mapping"
    __mapper_args__ = {'confirm_deleted_rows': False}
    id = Column("id", Integer, primary_key=True)
    source_host_name_id = Column(Integer, ForeignKey('host_name.id', ondelete='cascade'), nullable=False)
    resolved_host_name_id = Column(Integer, ForeignKey('host_name.id', ondelete='cascade'), nullable=False)
    _type = Column("type", Integer, nullable=True)
    creation_date = Column(DateTime, nullable=False, default=datetime.utcnow())
    last_modified = Column(DateTime, nullable=True, onupdate=datetime.utcnow())
    source_host_name = relationship(HostName,
                                    foreign_keys=[source_host_name_id],
                                    backref=backref('resolved_host_name_mappings', cascade='all, delete-orphan'))
    resolved_host_name = relationship(HostName,
                                      foreign_keys=[resolved_host_name_id],
                                      backref=backref('source_host_name_mappings', cascade='all, delete-orphan'))
    __table_args__ = (UniqueConstraint('source_host_name_id',
                                       'resolved_host_name_id',
                                       name='_host_name_host_name_mapping_unique'),)

    @property
    def type(self) -> DnsResourceRecordType:
        if self._type is not None:
            result = DnsResourceRecordType(self._type)
        else:
            result = DnsResourceRecordType(0)
        return result

    @type.setter
    def type(self, value: DnsResourceRecordType) -> None:
        self._type = value.value

    @property
    def type_str(self) -> str:
        result = []
        for item in DnsResourceRecordType:
            if (self.type & item) == item:
                result.append(item.name.upper())
        return ", ".join(result) if result else None

    def resolves_to_in_scope_ipv4_address(self) -> bool:
        """
        This method returns True, if the given host name resolves to the host via a DNS resource record type A
        :return:
        """
        return self.resolves_to_ipv4_address() and self.host.in_scope

    def resolves_to_in_scope_ipv6_address(self) -> bool:
        """
        This method returns True, if the given host name resolves to the host via a DNS resource record type A
        :return:
        """
        return self.resolves_to_ipv6_address() and self.host.in_scope

    def resolves_to_ipv4_address(self) -> bool:
        """
        This method returns True, if the given host name resolves to the host via a DNS resource record type A
        :return:
        """
        return bool(self.type & DnsResourceRecordType.a)

    def resolves_to_ipv6_address(self) -> bool:
        """
        This method returns True, if the given host name resolves to the host via a DNS resource record type AAAA
        :return:
        """
        return bool(self.type & DnsResourceRecordType.aaaa)


class DomainName(DeclarativeBase):
    """This class contains information about domain names."""

    __tablename__ = "domain_name"
    id = Column(Integer, primary_key=True)
    name = Column(Text, nullable=False, unique=False)
    scope = Column(Enum(ScopeType), nullable=False, unique=False, server_default='exclude')
    workspace_id = Column(Integer, ForeignKey("workspace.id", ondelete='cascade'), nullable=False, unique=False)
    creation_date = Column(DateTime, nullable=False, default=datetime.utcnow())
    last_modified = Column(DateTime, nullable=True, onupdate=datetime.utcnow())
    host_names = relationship("HostName",
                              backref=backref("domain_name",
                                              order_by="asc(HostName.name)",
                                              uselist=False),
                              cascade="delete, delete-orphan", single_parent=True)
    __table_args__ = (UniqueConstraint('name', 'workspace_id', name='_domain_name_unique'),)

    @property
    def in_scope(self) -> bool:
        return self.scope is not None and (self.scope == ScopeType.all or
                                           self.scope == ScopeType.strict or
                                           self.scope == ScopeType.vhost)

    @property
    def scope_str(self) -> str:
        return self.scope.name.lower() if self.scope else ScopeType.exclude.name

    @property
    def companies_str(self) -> str:
        result = None
        if self.companies:
            result = ", ".join(["{} (in scope: {})".format(item.name, item.in_scope) for item in self.companies])
        return result

    def has_hosts(self):
        """Returns true if the domain name is assigned to at least one host"""
        rvalue = False
        for host_name in self.host_names:
            if host_name.hosts:
                rvalue = True
                break
        return rvalue

    def has_ip_address(self, ip_addresses: List[str]):
        """Returns true if the domain name has one of the given IPv4/IPv6 addresses"""
        rvalue = False
        for host_name in self.host_names:
            rvalue = host_name.has_ip_address(ip_addresses)
            if rvalue:
                break
        return rvalue

    def is_processable(self,
                       included_items: List[str],
                       excluded_items: List[str],
                       active_collector: bool = None,
                       scope: ReportScopeType = None,
                       include_ip_address: bool = False) -> bool:
        """
        This method determines whether intel or report information should be collected from this domain name
        :param included_items: List of items to be processed
        :param excluded_items: List of items to be excluded
        :param active_collector: Value that specifies whether the given collector is active or passive
        :param scope: Value that specifies whether only in-scope items should be included into the report
        :param include_ip_address: If false, filters only work on domain names, else filter works also
        on IPv4 addresses
        :return: True, if the host_name is in the filter list or the filter list is empty
        """
        if active_collector is not None and scope:
            raise ValueError("scope and active collector parameters are mutual exclusive")
        rvalue = self.name not in excluded_items and \
                 (not include_ip_address or not self.has_ip_address(excluded_items)) and \
                 (not included_items or (self.name in included_items or
                                         (include_ip_address and self.has_ip_address(included_items)))) and \
                 (scope is None or (scope == ReportScopeType.within and self.in_scope) or (
                         scope == ReportScopeType.outside and not self.in_scope)) and \
                 (active_collector is None or not active_collector or self.in_scope and active_collector)
        return rvalue

    def get_text(self,
                 ident: int = 0,
                 show_metadata: bool = True,
                 report_visibility: ReportVisibility = None,
                 color: bool = False,
                 **kwargs) -> List[str]:
        """
        :param ident: Number of spaces
        :param show_metadata: True, if all meta information and not just command outputs shall be returned
        :param report_visibility: Specifies which information shall be shown
        :return: String for console output
        """
        rvalue = []
        if show_metadata:
            full = report_visibility != ReportVisibility.relevant if ReportVisibility else True
            Utils.get_text(rvalue, ident, True, "KIS intel report for {}", self.name,
                           color=FontColor.BLUE + FontColor.BOLD if color else None)
            Utils.get_text(rvalue, ident, True, "| In scope:        {}", self.in_scope)
            Utils.get_text(rvalue, ident, True, "| Workspace:       {}", self.workspace.name)
            host_names = ", ".join([item.full_name for item in self.host_names if item.name])
            Utils.get_text(rvalue, ident, full, "| Host names:      {}", host_names)
            Utils.get_text(rvalue, ident, full, "| Companies:       {}", self.companies_str)
            emails = []
            for host_name in self.host_names:
                for email in host_name.emails:
                    emails.append(email.email_address)
            emails = ", ".join(emails)
            Utils.get_text(rvalue, ident, full, "| Emails:          {}", emails)
            dedup = {}
            for host_name in self.host_names:
                for source in host_name.sources:
                    dedup[source.name] = True
            sources = ", ".join(list(dedup.keys()))
            Utils.get_text(rvalue, ident, full, "|_Sources:         {}", sources)
        hashes_dedup = {}
        for host_name in self.host_names:
            items = host_name.get_command_text(ident=ident,
                                               hashes_dedup=hashes_dedup,
                                               show_metadata=show_metadata,
                                               color=color,
                                               **kwargs)
            if items:
                rvalue.extend(items)
        return rvalue


class Email(DeclarativeBase):
    """This class contains information about domain names."""

    __tablename__ = "email"
    id = Column(Integer, primary_key=True)
    address = Column(Text, nullable=False, unique=False)
    host_name_id = Column(Integer, ForeignKey("host_name.id", ondelete='cascade'), nullable=False, unique=False)
    creation_date = Column(DateTime, nullable=False, default=datetime.utcnow())
    last_modified = Column(DateTime, nullable=True, onupdate=datetime.utcnow())
    credentials = relationship("Credentials",
                               backref=backref("email"),
                               cascade="all",
                               order_by="asc(Credentials.domain), asc(Credentials.username), asc(Credentials.password)")
    __table_args__ = (UniqueConstraint('address', 'host_name_id', name='_email_unique'),)

    @property
    def email_address(self):
        return "{}@{}".format(self.address, self.host_name.full_name) \
            if self.address and self.host_name and self.host_name.full_name else None

    @property
    def domain_name(self):
        return self.host_name.full_name if self.host_name and self.host_name.full_name else None

    @property
    def in_scope(self) -> bool:
        return self.host_name is not None and \
               self.host_name.domain_name is not None and \
               self.host_name.domain_name.in_scope

    @property
    def sources_str(self) -> str:
        result = None
        if self.sources:
            result = ", ".join([item.name for item in self.sources])
        return result

    def is_processable(self,
                       included_items: List[str],
                       excluded_items: List[str],
                       active_collector: bool = None,
                       scope: ReportScopeType = None) -> bool:
        """
        This method determines whether intel or report information should be collected from this email
        :param included_items: List of items to be processed
        :param excluded_items: List of items to be excluded
        :param active_collector: Value that specifies whether the given collector is active or passive
        :param scope: Value that specifies whether only in-scope items should be included into the report
        :return: True, if the host_name is in the filter list or the filter list is empty
        """
        if active_collector is not None and scope:
            raise ValueError("scope and active collector parameters are mutual exclusive")
        is_host_name_none = self.host_name is None
        is_domain_name_none = self.host_name is not None and self.host_name.domain_name is None
        rvalue = self.email_address not in excluded_items and \
                 (is_host_name_none or self.host_name.full_name not in excluded_items) and \
                 (is_host_name_none or is_domain_name_none or self.host_name.domain_name.name not in excluded_items) and \
                 (not included_items or (self.email_address in included_items or \
                                       not is_host_name_none and self.host_name.full_name in included_items or \
                                       not is_domain_name_none and self.host_name.domain_name.name in included_items)) and \
                 (scope is None or (scope == ReportScopeType.within and self.in_scope) or (
                         scope == ReportScopeType.outside and not self.in_scope)) and \
                 (active_collector is None or not active_collector or self.in_scope and active_collector)
        return rvalue

    def get_command_text(self,
                         exclude_collectors: List[str] = [],
                         include_collectors: List[str] = [],
                         **args) -> List[str]:
        """
        :param exclude_collectors: List of collector names whose output should not be printed
        :param include_collectors: List of collector names whose output should be printed
        :return: String for console output
        """
        rvalue = []
        if self.commands:
            rvalue.append("")
        for item in self.commands:
            if item.collector_name.name not in exclude_collectors and (item.collector_name.name in include_collectors or
                                                                       not include_collectors):
                text = item.get_text(**args)
                rvalue.extend(text)
        return rvalue

    def get_text(self,
                 ident: int = 0,
                 show_metadata: bool = True,
                 report_visibility: ReportVisibility = None,
                 color: bool = False,
                 **args) -> List[str]:
        """
        :param ident: Number of spaces
        :param show_metadata: True, if all meta information and not just command outputs shall be returned
        :param report_visibility: Specifies which information shall be shown
        :return: String for console output
        """
        rvalue = []
        breaches = []
        for info in self.additional_info:
            if info.name == "breaches":
                breaches.extend(info.values)
        sources = [item.name for item in self.sources]
        breaches.sort()
        sources.sort()
        if show_metadata:
            full = report_visibility != ReportVisibility.relevant if ReportVisibility else True
            Utils.get_text(rvalue, ident, True, "KIS intel report for {}", self.email_address,
                           color=FontColor.BLUE + FontColor.BOLD if color else None)
            Utils.get_text(rvalue, ident, True, "| In scope:        {}", self.host_name.domain_name.in_scope)
            Utils.get_text(rvalue, ident, True, "| Workspace:       {}", self.host_name.domain_name.workspace.name)
            Utils.get_text(rvalue, ident, full, "| Breaches:        {}", ", ".join(breaches))
            Utils.get_text(rvalue, ident, full, "|_Sources:         {}", ", ".join(sources))
        hashes_dedup = {}
        items = self.get_command_text(ident=ident,
                                      hashes_dedup=hashes_dedup,
                                      show_metadata=show_metadata,
                                      report_visibility=report_visibility,
                                      color=color,
                                      **args)
        if items:
            rvalue.extend(items)
        rvalue.extend(["", ""])
        return rvalue


class Source(DeclarativeBase):
    """This class contains information about the source of the information (e.g., Nmap)."""

    NMAP = "Nmap"
    NESSUS = "Nessus"
    MASSCAN = "Masscan"
    RPCINFO = "rpcinfo"

    __tablename__ = "source"
    id = Column(Integer, primary_key=True)
    name = Column(Text, nullable=False, unique=True)
    creation_date = Column(DateTime, nullable=False, default=datetime.utcnow())
    last_modified = Column(DateTime, nullable=True, onupdate=datetime.utcnow())
    hosts = relationship("Host",
                         secondary=source_host_mapping,
                         backref=backref("sources", order_by="asc(Source.name)"))
    services = relationship("Service",
                            secondary=source_service_mapping,
                            backref=backref("sources", order_by="asc(Source.name)"))
    host_names = relationship("HostName",
                              secondary=source_host_name_mapping,
                              backref=backref("sources", order_by="asc(Source.name)"))
    credentials = relationship("Credentials",
                               secondary=source_credentials_mapping,
                               backref=backref("sources", order_by="asc(Source.name)"))
    ipv4_networks = relationship("Network",
                                 secondary=source_ipv4_network_mapping,
                                 backref=backref("sources", order_by="asc(Source.name)"))
    additional_info = relationship("AdditionalInfo",
                                   secondary=source_additional_info_mapping,
                                   backref=backref("sources", order_by="asc(Source.name)"))
    paths = relationship("Path",
                         secondary=source_path_mapping,
                         backref=backref("sources", order_by="asc(Source.name)"))
    service_methods = relationship("ServiceMethod",
                                   secondary=source_service_method_mapping,
                                   backref=backref("sources", order_by="asc(Source.name)"))
    emails = relationship("Email",
                          secondary=source_email_mapping,
                          backref=backref(name="sources", order_by="asc(Source.name)"))
    companies = relationship("Company",
                             secondary=source_company_mapping,
                             backref=backref("sources", order_by="asc(Source.name)"))
    host_host_name_mappings = relationship("HostHostNameMapping",
                                           secondary=source_host_host_name_mapping,
                                           backref=backref("sources", order_by="asc(Source.name)"))
    host_name_host_name_mappings = relationship("HostNameHostNameMapping",
                                                secondary=source_host_name_host_name_mapping,
                                                backref=backref("sources", order_by="asc(Source.name)"))
    tls_info_cipher_suite_mappings = relationship("TlsInfoCipherSuiteMapping",
                                                  secondary=source_tls_info_cipher_suite_mapping,
                                                  backref=backref("sources", order_by="asc(Source.name)"))
    cert_info = relationship("CertInfo",
                             secondary=source_cert_info_mapping,
                             backref=backref("sources", order_by="asc(Source.name)"))

    def __eq__(self, other) -> bool:
        return self.name == other.name


class ServiceMethod(DeclarativeBase):
    """This class holds all information about supported service methods like OPTIONS or PUT."""

    __tablename__ = "service_method"
    id = Column(Integer, primary_key=True)
    name = Column(Text, nullable=False, unique=False)
    service_id = Column(Integer, ForeignKey("service.id", ondelete='cascade'), nullable=False, unique=False)
    creation_date = Column(DateTime, nullable=False, default=datetime.utcnow())
    last_modified = Column(DateTime, nullable=True, onupdate=datetime.utcnow())
    __table_args__ = (UniqueConstraint('name', 'service_id', name='_service_method_unique'),)

    def get_text(self, ident: int = 0, is_last: bool = False, color: bool = False, **args) -> List[str]:
        """
        :param ident: Number of spaces
        :return: String for console output
        """
        rvalue = []
        prefix = "|_" if is_last else "| "
        Utils.get_text(rvalue, ident, False, "{}  {}{}", prefix, "", self.name,
                       FontColor.RED if self.name == "PUT" and color else None)
        return rvalue


class Service(DeclarativeBase):
    """This class holds all information about a service."""

    __tablename__ = "service"
    id = Column(Integer, primary_key=True)
    protocol = Column(Enum(ProtocolType), nullable=False, unique=False)
    port = Column(Integer, nullable=False, unique=False)
    nmap_service_name = Column(Text, nullable=True, unique=False)
    nessus_service_name = Column(Text, nullable=True, unique=False)
    nmap_service_confidence = Column(Integer, nullable=True, unique=False)
    nessus_service_confidence = Column(Integer, nullable=True, unique=False)
    nmap_service_name_original = Column(Text, nullable=True, unique=False)
    state = Column(Enum(ServiceState), nullable=False, unique=False)
    nmap_service_state_reason = Column(String(25), nullable=True, unique=False)
    nmap_product = Column(Text, nullable=True, unique=False)
    nmap_version = Column(Text, nullable=True, unique=False)
    nmap_extra_info = Column(Text, nullable=True, unique=False)
    nmap_tunnel = Column(Text, nullable=True, unique=False)
    nmap_os_type = Column(Text, nullable=True, unique=False)
    smb_message_signing = Column(Boolean, nullable=True, unique=False)
    rdp_nla = Column(Boolean, nullable=True, unique=False)
    host_id = Column(Integer, ForeignKey("host.id", ondelete='cascade'), nullable=True, unique=False)
    host_name_id = Column(Integer, ForeignKey("host_name.id", ondelete='cascade'), nullable=True, unique=False)
    creation_date = Column(DateTime, nullable=False, default=datetime.utcnow())
    last_modified = Column(DateTime, nullable=True, onupdate=datetime.utcnow())
    service_methods = relationship("ServiceMethod",
                                   backref=backref("service"),
                                   cascade="all",
                                   order_by="asc(ServiceMethod.name)")
    paths = relationship("Path",
                         backref=backref("service"),
                         cascade="all",
                         order_by="asc(Path.name)")
    credentials = relationship("Credentials",
                               backref=backref("service"),
                               cascade="all",
                               order_by="asc(Credentials.domain), asc(Credentials.username), asc(Credentials.password)")
    __table_args__ = (UniqueConstraint("port", "protocol", "host_id", name="_service_host_unique"),
                      UniqueConstraint("port", "protocol", "host_name_id", name="_service_host_name_unique"),
                      CheckConstraint('not host_id is null or not host_name_id is null',
                                      name='_service_mutex_constraint'),
                      CheckConstraint('host_id is null or host_name_id is null',
                                      name='_service_all_constraint'),)

    @property
    def tls(self) -> bool:
        return self.nmap_tunnel == "ssl"

    @property
    def address(self) -> str:
        rvalue = None
        if self.host:
            rvalue = self.host.address
        elif self.host_name:
            rvalue = self.host_name.full_name
        return rvalue

    @property
    def address_summary(self) -> str:
        rvalue = None
        if self.host:
            rvalue = self.host.summary
        elif self.host_name:
            rvalue = self.host_name.summary
        return rvalue

    @property
    def summary(self) -> str:
        result = self.address_summary
        if result:
            result += ": {}".format(self.protocol_port_str)
        return result

    @property
    def workspace_id(self) -> str:
        rvalue = None
        if self.host:
            rvalue = self.host.workspace_id
        elif self.host_name:
            rvalue = self.host_name.workspace_id
        return rvalue

    @property
    def workspace(self) -> Workspace:
        rvalue = None
        if self.host:
            rvalue = self.host.workspace
        elif self.host_name:
            rvalue = self.host_name.workspace
        return rvalue

    @property
    def protocol_port_str(self) -> str:
        result = None
        if self.protocol and self.port:
            result = "{}/{}".format(self.protocol_str, self.port)
        return result

    @property
    def state_str(self) -> str:
        return self.state.name.lower().replace("_", "/")

    @property
    def nmap_service_name_original_with_confidence(self) -> str:
        rvalue = None
        if self.nmap_service_name_original:
            rvalue = "{}{}".format(self.nmap_service_name_original,
                                   "?" if self.nmap_service_confidence and self.nmap_service_confidence < 10 else "")
        return rvalue

    @property
    def service_name(self) -> str:
        return self.nmap_service_name if self.nmap_service_name else self.nessus_service_name

    @property
    def service_confidence(self) -> str:
        return self.nmap_service_confidence if self.nmap_service_confidence else self.nessus_service_confidence

    @property
    def service_name_with_confidence(self) -> str:
        rvalue = None
        if self.nmap_service_name:
            rvalue = "{}{}".format(self.nmap_service_name,
                                   "?" if self.nmap_service_confidence and self.nmap_service_confidence < 10 else "")
        elif self.nessus_service_name:
            rvalue = "{}{}".format(self.nessus_service_name,
                                   "?" if self.nessus_service_confidence and self.nessus_service_confidence < 10 else "")
        return rvalue

    @property
    def protocol_str(self) -> str:
        return self.protocol.name.lower()

    @property
    def sources_str(self) -> str:
        result = None
        if self.sources:
            result = ", ".join([item.name for item in self.sources])
        return result

    @property
    def port_service_name(self) -> str:
        return "{} ({})".format(self.port, self.service_name_with_confidence if self.service_name else "unknown")

    @property
    def service_name_port(self) -> str:
        return "{} ({})".format(self.service_name_with_confidence if self.service_name else "unknown", self.port)

    @property
    def nmap_product_version(self) -> str:
        if self.nmap_extra_info:
            result = "{} {} {}".format(self.nmap_product if self.nmap_product else "",
                                         self.nmap_version if self.nmap_version else "",
                                         self.nmap_extra_info).strip()
        else:
            result = "{} {}".format(self.nmap_product if self.nmap_product else "",
                                    self.nmap_version if self.nmap_version else "").strip()
        return result

    @property
    def has_credentials(self) -> bool:
        return len([item for item in self.credentials if item.complete]) > 0

    @property
    def vulnerabilities(self) -> list:
        """
        Returns list of vulnerabilities
        """
        return [item for item in self.additional_info if item.name == "CVEs"]

    def has_given_collectors(self, include_collectors: List[str] = [], **kwargs) -> bool:
        """
        Determines whether the given host has a collector listed in list include_collectors
        :param include_collectors:
        :param kwargs:
        :return: Returns true, if the host has a collector
        """
        rvalue = not include_collectors
        if not rvalue:
            for command in self.commands:
                if command.collector_name.name in include_collectors \
                        and command.status.value > CommandStatus.pending.value:
                    rvalue = True
                    break
        return rvalue

    def get_completed_commands(self) -> list:
        """
        This method returns all commands that have a status above status collecting
        """
        return [item for item in self.commands if item.status.value > CommandStatus.collecting.value]

    def get_additional_info_by_name(self, key: str) -> List[str]:
        """
        Returns the values of the given key
        """
        result = []
        for item in self.additional_info:
            if item.name == key:
                result.extend(item.values)
        return result

    @staticmethod
    def _obtain_properties(collection, ident: int = 0, full: bool = False, **kwargs) -> List[str]:
        """
        This is a helper method to obtain the text output from list properties
        :param collection:
        :param ident:
        :param full:
        :param kwargs:
        :return:
        """
        rvalue = []
        i = 1
        count = len(collection)
        for item in collection:
            rvalue.extend(item.get_text(ident=ident, full=full, is_last=(i == count), **kwargs))
            i += 1
        return rvalue

    def get_text(self,
                 ident: int = 0,
                 show_metadata: bool = True,
                 report_visibility: ReportVisibility = None,
                 color: bool = False,
                 **kwargs) -> List[str]:
        """
        :param ident: Number of spaces
        :param show_metadata: True, if all meta information and not just command outputs shall be returned
        :param report_visibility: Specifies which information shall be shown
        :return: String for console output
        """
        rvalue = []
        has_given_collectors = self.has_given_collectors(**kwargs)
        is_open = self.is_open(strict=True)
        if show_metadata and has_given_collectors and ((
                is_open and report_visibility == ReportVisibility.relevant) or
                                                       report_visibility == ReportVisibility.irrelevant or
                                                       report_visibility is None):
            service_name = self.service_name_with_confidence if self.service_name_with_confidence else ""
            service_name += " ({})".format(self.nmap_tunnel) if self.nmap_tunnel else ""
            service_name = service_name.strip()
            full = report_visibility != ReportVisibility.relevant if ReportVisibility else True
            Utils.get_text(rvalue, ident, True, "{:<5}/{}   {:<16}   {:<16} {}", str(self.port),
                           self.protocol_str,
                           self.state_str if self.state else "",
                           service_name,
                           self.nmap_product_version,
                           color=FontColor.BOLD if color else None)
            if self.additional_info:
                max_len = max([len(item.name) for item in self.additional_info])
                rvalue.extend(self._obtain_properties(collection=self.additional_info,
                                                      ident=ident,
                                                      full=full,
                                                      name_max_with=max_len,
                                                      color=color))
            if self.paths:
                Utils.get_text(rvalue, ident, full, "| URLs:", "_")
                rvalue.extend(self._obtain_properties(collection=self.paths,
                                                      ident=ident,
                                                      full=full,
                                                      color=color))
            if self.credentials:
                Utils.get_text(rvalue, ident, full, "| Credentials:", "_")
                rvalue.extend(self._obtain_properties(collection=self.credentials,
                                                      ident=ident,
                                                      full=full,
                                                      color=color))
            if self.service_methods:
                Utils.get_text(rvalue, ident, full, "| Methods:", "_")
                rvalue.extend(self._obtain_properties(collection=self.service_methods,
                                                      ident=ident,
                                                      full=full,
                                                      color=color))
        return rvalue

    def get_command_text(self,
                         exclude_collectors: List[str] = [],
                         include_collectors: List[str] = [],
                         report_visibility: ReportVisibility = None,
                         **args) -> List[str]:
        """
        :param exclude_collectors: List of collector names whose output should not be printed
        :param include_collectors: List of collector names whose output should be printed
        :param report_visibility: Specifies which information shall be shown
        :return: String for console output
        """
        rvalue = []
        if self.commands:
            rvalue.append("")
        for item in self.commands:
            if item.collector_name.name not in exclude_collectors and \
                    (item.collector_name.name in include_collectors or not include_collectors):
                rvalue.extend(item.get_text(report_visibility=report_visibility, **args))
        return rvalue

    def is_open(self, strict: bool = True) -> bool:
        """
        Returns true, if the service's state is 'open' or 'open|filtered'.
        :param strict: If true, then the this method returns true only when the service's state is open.
        """
        return self.state == ServiceState.Open or \
               (not strict and self.state in [ServiceState.Open, ServiceState.Open_Filtered])

    def get_urlparse(self, ip_address: str = None, path: str = None, query: str = None) -> urllib.parse.ParseResult:
        """
        :return: This method returns a URL based on the given service and host information. If no host information is
        given, then this method returns None
        """
        url = None
        host = ip_address if ip_address else self.address
        try:
            host = host if ipaddress.ip_address(host).version == 4 else "[{}]".format(host)
        except:
            pass
        if host:
            if self.port in [80, 443]:
                url = "{}://{}".format("https" if self.nmap_tunnel == "ssl" else "http", host)
            else:
                url = "{}://{}:{}".format("https" if self.nmap_tunnel == "ssl" else "http", host, self.port)
            if path:
                name = path if path[0] == "/" else "/{}".format(path)
                url += name
            if query:
                name = query if query[0] == "?" else "?{}".format(query)
                url += name
            url = urlparse(url)
        return url

    def __repr__(self):
        return "<{} protocol={} port={} service={}/>".format(self.__class__.__name__,
                                                             self.protocol.name.lower(0),
                                                             self.port,
                                                             self.nmap_service_name)

    @staticmethod
    def get_protocol_type(status: str) -> ProtocolType:
        """This method converts the given string into enum"""
        status = status.lower()
        if status == 'tcp':
            rvalue = ProtocolType.tcp
        elif status == 'udp':
            rvalue = ProtocolType.udp
        elif status == 'icmp':
            rvalue = None
        else:
            raise NotImplementedError("Protocol '{}' not implemented.".format(status))
        return rvalue

    @staticmethod
    def get_service_state(state: str) -> ServiceState:
        """This method converts the given string into enum"""
        state = state.lower()
        if state == "internal":
            rvalue = ServiceState.Internal
        elif state == "open":
            rvalue = ServiceState.Open
        elif state == "closed":
            rvalue = ServiceState.Closed
        elif state == "open|filtered":
            rvalue = ServiceState.Open_Filtered
        elif state == "closed|filtered":
            rvalue = ServiceState.Closed_Filtered
        elif state == "filtered":
            rvalue = ServiceState.Filtered
        else:
            raise NotImplementedError("Service state '{}' not implemented.".format(state))
        return rvalue


class AdditionalInfo(DeclarativeBase):
    """This class holds all information about supported service methods like OPTIONS or PUT."""

    __tablename__ = "additional_info"
    id = Column(Integer, primary_key=True)
    name = Column(Text, nullable=False, unique=False)
    _values = Column("values", MutableList.as_mutable(ARRAY(Text)), nullable=False, default=[])
    service_id = Column(Integer, ForeignKey("service.id", ondelete='cascade'), nullable=True, unique=False)
    host_name_id = Column(Integer, ForeignKey("host_name.id", ondelete='cascade'), nullable=True, unique=False)
    email_id = Column(Integer, ForeignKey("email.id", ondelete='cascade'), nullable=True, unique=False)
    company_id = Column(Integer, ForeignKey("company.id", ondelete='cascade'), nullable=True, unique=False)
    host_id = Column(Integer, ForeignKey("host.id", ondelete='cascade'), nullable=True, unique=False)
    ipv4_network_id = Column("network_id",
                             Integer,
                             ForeignKey("network.id", ondelete='cascade'),
                             nullable=True,
                             unique=False)
    creation_date = Column(DateTime, nullable=False, default=datetime.utcnow())
    last_modified = Column(DateTime, nullable=True, onupdate=datetime.utcnow())
    host = relationship(Host,
                        backref=backref("additional_info",
                                        cascade='all, delete-orphan',
                                        order_by="asc(AdditionalInfo.name)"))
    service = relationship(Service,
                           backref=backref("additional_info",
                                           cascade='all, delete-orphan',
                                           order_by="asc(AdditionalInfo.name)"))
    host_name = relationship(HostName,
                             backref=backref("additional_info",
                                             cascade='all, delete-orphan',
                                             order_by="asc(AdditionalInfo.name)"))
    email = relationship("Email",
                         backref=backref("additional_info",
                                             cascade='delete, delete-orphan',
                                         order_by="asc(AdditionalInfo.name)"))
    company = relationship("Company",
                           backref=backref("additional_info",
                                           cascade='delete, delete-orphan',
                                           order_by="asc(AdditionalInfo.name)"))
    ipv4_network = relationship("Network",
                                backref=backref("additional_info",
                                                cascade='delete, delete-orphan',
                                                order_by="asc(AdditionalInfo.name)"))
    __table_args__ = (UniqueConstraint('name',
                                       'service_id', name='_additional_info_service_unique'),
                      UniqueConstraint('name',
                                       'host_name_id', name='_additional_info_host_name_unique'),
                      UniqueConstraint('name',
                                       'email_id', name='_additional_info_email_unique'),
                      UniqueConstraint('name',
                                       'company_id', name='_additional_info_company_unique'),
                      UniqueConstraint('name',
                                       'host_id', name='_additional_info_host_unique'),
                      UniqueConstraint('name',
                                       'network_id', name='_additional_info_network_unique'),
                      CheckConstraint('(case when service_id is null then 0 else 1 end'
                                      '+ case when host_id is null then 0 else 1 end'
                                      '+ case when network_id is null then 0 else 1 end'
                                      '+ case when email_id is null then 0 else 1 end'
                                      '+ case when company_id is null then 0 else 1 end'
                                      '+ case when host_name_id is null then 0 else 1 end) = 1',
                                      name='_additional_info_mutex_constraint'),)

    @property
    def values(self):
        if not self._values:
            self._values = []
        return self._values

    @property
    def sources_str(self) -> str:
        result = None
        if self.sources:
            result = ", ".join([item.name for item in self.sources])
        return result

    def is_processable(self,
                       included_items: List[str],
                       excluded_items: List[str],
                       scope: ReportScopeType = None) -> bool:
        """
        This method determines whether intel or report information should be collected from this additional info
        :param included_items: List of items to be processed
        :param excluded_items: List of items to be excluded
        :param scope: Value that specifies whether only in-scope items should be included into the report
        :return: True, if the host_name is in the filter list or the filter list is empty
        """
        if self.service is not None:
            if self.service.host_name is not None:
                rvalue = self.service.host_name.is_processable(included_items=included_items,
                                                               excluded_items=excluded_items,
                                                               collector_type=CollectorType.host_name_service,
                                                               scope=scope)
            elif self.service.host is not None:
                rvalue = self.service.host.is_processable(included_items=included_items,
                                                          excluded_items=excluded_items,
                                                          scope=scope)
            else:
                rvalue = True
        elif self.host_name is not None:
            rvalue = self.host_name.is_processable(included_items=included_items,
                                                   excluded_items=excluded_items,
                                                   collector_type=CollectorType.domain,
                                                   scope=scope)
        else:
            rvalue = True
        return rvalue

    def extend(self, values: List[str]):
        for item in values:
            if item not in self._values:
                self._values.append(item.strip().replace(os.linesep, " "))

    def append(self, value: str):
        if value and value not in self.values:
            self.values.append(str(value).strip().replace(os.linesep, " "))

    def get_text(self,
                 ident: int = 0,
                 is_last: bool = False,
                 name_max_with: int = None,
                 report_visibility: ReportVisibility = None,
                 **args) -> List[str]:
        """
        :param ident: Number of spaces
        :param report_visibility: Specifies which information shall be shown
        :return: String for console output
        """
        rvalue = []
        prefix = "|_" if is_last else "| "
        name_max_with += 1
        full = report_visibility != ReportVisibility.relevant if ReportVisibility else True
        if len(self.values) == 1:
            name = "{}{:<{name_max_with}}".format(prefix, self.name + ":", name_max_with=name_max_with)
            Utils.get_text(rvalue, ident, full, "{} {}", name, self.values[0])
        elif len(self.values) > 1:
            name = "{}{:<{name_max_with}}".format(prefix, self.name + ":", name_max_with=name_max_with)
            Utils.get_text(rvalue, ident, full, name)
            for item in self.values:
                Utils.get_text(rvalue, ident, full, "{}  {}", prefix, item)
        return rvalue


class CollectorName(DeclarativeBase):
    """This class holds all information about a task name."""
    __tablename__ = "collector_name"
    id = Column(Integer, primary_key=True)
    name = Column(String(50), nullable=False, unique=False)
    type = Column(Enum(CollectorType), nullable=False, unique=False)
    priority = Column(Integer, nullable=False, unique=False)
    creation_date = Column(DateTime, nullable=False, default=datetime.utcnow())
    last_modified = Column(DateTime, nullable=True, onupdate=datetime.utcnow())
    __table_args__ = (UniqueConstraint('name', 'type', name='_collector_name_unique'),)

    @property
    def type_str(self) -> str:
        result = None
        if self.type:
            result = self.type.name
        return result

    def __eq__(self, other):
        rvalue = False
        if other:
            rvalue = (self.name == other.name)
        return rvalue

    def __repr__(self):
        return "<{} name={} />".format(self.__class__.__name__, self.name)


class ExecutionInfoType(enum.Enum):
    xml_output_file = enum.auto()
    json_output_file = enum.auto()
    binary_output_file = enum.auto()
    output_path = enum.auto()
    input_file = enum.auto()
    input_file_2 = enum.auto()
    command_id = enum.auto()
    working_directory = enum.auto()
    username = enum.auto()

    @property
    def argument(self) -> str:
        return "{" + self.name + "}"


class Command(DeclarativeBase):
    """This class holds all information about a task including its results."""

    __tablename__ = "command"
    id = Column(Integer, primary_key=True)
    os_command = Column(MutableList.as_mutable(ARRAY(Text)), nullable=False, unique=False)
    description = Column(Text, nullable=True, unique=False)
    hide = Column(Boolean, nullable=False, unique=False, default=False)
    status = Column(Enum(CommandStatus), nullable=False, unique=False, default=CommandStatus.pending)
    _stdout_output = Column("stdout_output", MutableList.as_mutable(ARRAY(Text)), nullable=True, unique=False)
    _stderr_output = Column("stderr_output", MutableList.as_mutable(ARRAY(Text)), nullable=True, unique=False)
    xml_output = Column(Text, nullable=True, unique=False)
    json_output = Column(MutableList.as_mutable(CastingArray(JSON)), nullable=True, unique=False, default=[])
    binary_output = Column(BYTEA, nullable=True, unique=False)
    _execution_info = Column("execution_info", MutableDict.as_mutable(JSON), nullable=True, unique=False)
    hint = Column(MutableList.as_mutable(MutableList.as_mutable(ARRAY(Text))), nullable=True, unique=False, default=[])
    return_code = Column(Integer, nullable=True, unique=False)
    collector_name_id = Column(Integer,
                               ForeignKey("collector_name.id", ondelete='cascade'),
                               nullable=False,
                               unique=False)
    # todo: update for new collector
    host_id = Column(Integer, ForeignKey("host.id", ondelete='cascade'), nullable=True, unique=False)
    service_id = Column(Integer, ForeignKey("service.id", ondelete='cascade'), nullable=True, unique=False)
    host_name_id = Column(Integer, ForeignKey("host_name.id", ondelete='cascade'), nullable=True, unique=False)
    ipv4_network_id = Column("network_id",
                             Integer,
                             ForeignKey("network.id", ondelete='cascade'),
                             nullable=True,
                             unique=False)
    email_id = Column(Integer, ForeignKey("email.id", ondelete='cascade'), nullable=True, unique=False)
    company_id = Column(Integer, ForeignKey("company.id", ondelete='cascade'), nullable=True, unique=False)
    creation_date = Column(DateTime, nullable=False, default=datetime.utcnow())
    last_modified = Column(DateTime, nullable=True, onupdate=datetime.utcnow())
    start_time = Column(DateTime, nullable=True, unique=False)
    stop_time = Column(DateTime, nullable=True, unique=False)
    host = relationship(Host,
                        backref=backref("commands",
                                        cascade="all",
                                        order_by="asc(Command.collector_name_id)"))
    service = relationship(Service,
                           backref=backref("commands",
                                           cascade="all",
                                           order_by="asc(Command.collector_name_id)"))
    host_name = relationship(HostName,
                             backref=backref("commands",
                                             cascade="all",
                                             order_by="asc(Command.collector_name_id)"))
    ipv4_network = relationship(Network,
                                backref=backref("commands",
                                                cascade="all",
                                                order_by="asc(Command.collector_name_id)"))
    email = relationship(Email,
                         backref=backref("commands",
                                         cascade="all",
                                         order_by="asc(Command.collector_name_id)"))
    company = relationship("Company",
                           backref=backref("commands",
                                           cascade="all",
                                           order_by="asc(Command.collector_name_id)"))
    collector_name = relationship(CollectorName, backref=backref("commands"))
    files = relationship('File', cascade='all', secondary='command_file_mapping', back_populates="commands")
    # todo: update for new collector
    __table_args__ = (UniqueConstraint('os_command',
                                       'collector_name_id',
                                       'host_id',
                                       'service_id', name='_command_service_host_unique'),
                      UniqueConstraint('os_command',
                                       'collector_name_id',
                                       'network_id', name='_command_network_unique'),
                      UniqueConstraint('os_command',
                                       'collector_name_id',
                                       'email_id', name='_command_email_unique'),
                      UniqueConstraint('os_command',
                                       'collector_name_id',
                                       'company_id', name='_command_company_unique'),
                      UniqueConstraint('os_command',
                                       'collector_name_id',
                                       'service_id',
                                       'host_name_id', name='_command_service_host_name_unique'),
                      CheckConstraint('(case when not service_id is null and not host_id is null and host_name_id is null and network_id is null and email_id is null and company_id is null then 1 else 0 end'
                                      '+case when not service_id is null and host_id is null and not host_name_id is null and network_id is null and email_id is null and company_id is null then 1 else 0 end'
                                      '+case when service_id is null and not host_id is null and host_name_id is null and network_id is null and email_id is null and company_id is null then 1 else 0 end'
                                      '+case when service_id is null and host_id is null and not host_name_id is null and network_id is null and email_id is null and company_id is null then 1 else 0 end'
                                      '+case when service_id is null and host_id is null and host_name_id is null and not network_id is null and email_id is null and company_id is null then 1 else 0 end'
                                      '+case when service_id is null and host_id is null and host_name_id is null and network_id is null and not email_id is null and company_id is null then 1 else 0 end'
                                      '+case when service_id is null and host_id is null and host_name_id is null and network_id is null and email_id is null and company_id is not null then 1 else 0 end) = 1',
                                      name='_command_mutex_constraint'),)

    def __init__(self,
                 os_command: List[str],
                 collector_name: CollectorName,
                 service: Service = None,
                 host: Host = None,
                 host_name: Host = None,
                 ipv4_network: Network = None,
                 email: Email = None,
                 company = None):
        # todo: update for new collector
        self.os_command = os_command
        self.collector_name = collector_name
        if service:
            self.service = service
            if service.host:
                self.host = service.host
            elif service.host_name:
                self.host_name = service.host_name
            else:
                raise ValueError("service not assigned to host or host name")
        elif host:
            self.host = host
        elif host_name:
            self.host_name = host_name
        elif ipv4_network:
            self.ipv4_network = ipv4_network
        elif email:
            self.email = email
        elif company:
            self.company = company

    @property
    def workspace(self) -> Workspace:
        """
        returns the workspace
        :return:
        """
        # todo update new collector
        if self.collector_name.type == CollectorType.domain or \
                self.collector_name.type == CollectorType.host_name_service:
            workspace = self.host_name.domain_name.workspace
        elif self.collector_name.type == CollectorType.host or \
                self.collector_name.type == CollectorType.service:
            workspace = self.host.workspace
        elif self.collector_name.type == CollectorType.ipv4_network:
            workspace = self.ipv4_network.workspace
        elif self.collector_name.type == CollectorType.email:
            workspace = self.email.host_name.domain_name.workspace
        elif self.collector_name.type == CollectorType.company:
            workspace = self.company.workspace
        else:
            raise NotImplementedError("case not implemented")
        return workspace

    @property
    def target_name(self) -> str:
        """
        returns the workspace
        :return:
        """
        # todo update new collector
        if self.collector_name.type == CollectorType.domain or \
                self.collector_name.type == CollectorType.host_name_service:
            item = self.host_name.full_name
        elif self.collector_name.type == CollectorType.host or \
                self.collector_name.type == CollectorType.service:
            item = self.host.address
        elif self.collector_name.type == CollectorType.ipv4_network:
            item = self.ipv4_network.network
        elif self.collector_name.type == CollectorType.email:
            item = self.email.email_address
        elif self.collector_name.type == CollectorType.company:
            item = self.company.name
        else:
            raise NotImplementedError("case not implemented")
        return item

    @property
    def target_summary(self) -> str:
        """
        returns the workspace
        :return:
        """
        # todo update new collector
        if self.collector_name.type == CollectorType.host_name_service or \
            self.collector_name.type == CollectorType.service:
            result = "{} {}".format(self.service.address, self.service.protocol_port_str)
        else:
            result = self.target_name
        return result

    def get_file_name(self, file_type: FileType) -> str:
        """
        Returns the file name
        :param file_type:
        :return:
        """
        if file_type == FileType.binary and \
                ExecutionInfoType.binary_output_file.name in self.execution_info and \
                self.execution_info[ExecutionInfoType.binary_output_file.name]:
            rvalue = os.path.basename(self.execution_info[ExecutionInfoType.binary_output_file.name])
        elif file_type == FileType.json and \
                ExecutionInfoType.json_output_file.name in self.execution_info and \
                self.execution_info[ExecutionInfoType.json_output_file.name]:
            rvalue = os.path.basename(self.execution_info[ExecutionInfoType.json_output_file.name])
        elif file_type == FileType.xml and \
                ExecutionInfoType.xml_output_file.name in self.execution_info and \
                self.execution_info[ExecutionInfoType.xml_output_file.name]:
            rvalue = os.path.basename(self.execution_info[ExecutionInfoType.xml_output_file.name])
        elif file_type == FileType.text:
            rvalue = "{}.txt".format(self.file_name)
        else:
            raise NotImplementedError("case not implemented")
        return rvalue

    @property
    def stdout(self) -> List[str]:
        return self.stdout_output + self.stderr_output

    @property
    def start_time_str(self) -> str:
        return self.start_time.strftime("%Y-%m-%d %H:%M:%S") if self.start_time else None

    @property
    def stop_time_str(self) -> str:
        return self.stop_time.strftime("%Y-%m-%d %H:%M:%S") if self.stop_time else None

    @property
    def file_name(self) -> str:
        """
        returns the export file name for the scan results
        :return:
        """
        # todo update new collector
        if self.collector_name.type == CollectorType.domain:
            file_name = "{}-{}".format(self.collector_name.name, self.host_name.full_name)
        elif self.collector_name.type == CollectorType.host_name_service:
            file_name = "{}-{}-{}-{}".format(self.collector_name.name,
                                             self.host_name.full_name,
                                             self.service.protocol_str, self.service.port)
        elif self.collector_name.type == CollectorType.host:
            file_name = "{}-{}".format(self.collector_name.name, self.host.address)
        elif self.collector_name.type == CollectorType.service:
            file_name = "{}-{}-{}-{}".format(self.collector_name.name,
                                             self.host.address,
                                             self.service.protocol_str, self.service.port)
        elif self.collector_name.type == CollectorType.ipv4_network:
            file_name = "{}-{}".format(self.collector_name.name, self.ipv4_network.network.replace("/", "-"))
        elif self.collector_name.type == CollectorType.email:
            file_name = "{}-{}".format(self.collector_name.name, self.email.email_address)
        elif self.collector_name.type == CollectorType.company:
            file_name = "{}-{}".format(self.collector_name.name, self.company.name)
        else:
            raise NotImplementedError("case not implemented")
        return file_name

    @property
    def execution_info(self) -> Dict[str, str]:
        if self._execution_info is None:
            self._execution_info = {}
        return self._execution_info

    @execution_info.setter
    def execution_info(self, value: Dict[str, str]):
        self._execution_info = value

    @property
    def status_str(self) -> str:
        result = None
        if self.status:
            result = self.status.name
        return result

    @property
    def status_value(self) -> int:
        result = None
        if self.status:
            result = self.status.value
        return result

    def reset(self):
        """
        This method resets the commands content
        :return:
        """
        if self.status != CommandStatus.completed:
            self._stderr_output = None
            self._stdout_output = None
            self.binary_output = None
            self.json_output = []
            self.xml_output = None
            self.hint = []
            self.return_code = None

    def _update_execution_info_permissions(self,
                                           execution_info_type: ExecutionInfoType,
                                           user_info: pwd.struct_passwd):
        """
        Method is used by self.update_file_permissions as a helper to update file system permissions
        :param user_info: the new owner of the file/directory
        :return:
        """
        if user_info.pw_name != "root" and execution_info_type.name in self._execution_info:
            path = self._execution_info[execution_info_type.name]
            paths = []
            if os.path.isdir(path):
                # if the current item is a path, then we add the path to the list of paths for which the ownership
                # shall be updated
                paths.append(path)
            elif os.path.isfile(path):
                # if the current item is a file, then we update the file's ownership
                os.chown(path, uid=user_info.pw_uid, gid=user_info.pw_gid)
            else:
                path = os.path.dirname(path)
                paths.append(path)
            # now we update the directory ownerships
            for path in paths:
                for root, dirs, files in os.walk(path):
                    os.chown(root, uid=user_info.pw_uid, gid=user_info.pw_gid)
                    for item in dirs:
                        item = os.path.join(root, item)
                        if os.path.exists(item):
                            os.chown(item, uid=user_info.pw_uid, gid=user_info.pw_gid)
                    for item in files:
                        item = os.path.join(root, item)
                        if os.path.exists(item):
                            os.chown(item, uid=user_info.pw_uid, gid=user_info.pw_gid)

    def update_file_permissions(self):
        """
        If command is executed with low privileged user, then this method iterates through all files and directories
        in the command's execution info and updates their file permissions accordingly.
        :return:
        """
        username = self.username
        if username and username != "root":
            user_info = pwd.getpwnam(username)
            self._update_execution_info_permissions(ExecutionInfoType.xml_output_file,
                                                    user_info=user_info)
            self._update_execution_info_permissions(ExecutionInfoType.json_output_file,
                                                    user_info=user_info)
            self._update_execution_info_permissions(ExecutionInfoType.binary_output_file,
                                                    user_info=user_info)
            self._update_execution_info_permissions(ExecutionInfoType.output_path,
                                                    user_info=user_info)
            self._update_execution_info_permissions(ExecutionInfoType.input_file,
                                                    user_info=user_info)
            self._update_execution_info_permissions(ExecutionInfoType.input_file_2,
                                                    user_info=user_info)
            self._update_execution_info_permissions(ExecutionInfoType.working_directory,
                                                    user_info=user_info)

    @property
    def os_command_substituted(self) -> List[str]:
        """
        This method returns the actual OS command to be executed while os_command contains place holders for information
        that can change from execution to execution (e.g., XML output paths)
        """
        ignore = False
        os_command = []
        for item in self.os_command:
            tmp = item.strip()
            ignore = ignore or (len(tmp) > 0 and tmp[0] == "#")
            if not ignore:
                try:
                    value = item.format(**self.execution_info)
                except:
                    value = item
                os_command.append(value)
        return os_command

    @property
    def execution_time_delta(self) -> timedelta:
        rvalue = None
        if self.start_time and self.stop_time:
            rvalue = self.stop_time - self.start_time
        return rvalue

    @property
    def os_command_string(self) -> str:
        return subprocess.list2cmdline(self.os_command_substituted)

    @property
    def stdout_output(self) -> List[str]:
        if self._stdout_output is None:
            self._stdout_output = []
        return self._stdout_output

    @property
    def working_directory(self) -> str:
        result = None
        if ExecutionInfoType.working_directory.name in self.execution_info:
            result = self.execution_info[ExecutionInfoType.working_directory.name]
        return result

    @property
    def username(self) -> str:
        if ExecutionInfoType.username.name in self.execution_info:
            result = self.execution_info[ExecutionInfoType.username.name]
        else:
            result = "root"
        return result

    @stdout_output.setter
    def stdout_output(self, value: List[str]):
        value = value if value is not None else []
        self._stdout_output = [item.replace("\x00", "") for item in value]

    @property
    def stderr_output(self) -> List[str]:
        if self._stderr_output is None:
            self._stderr_output = []
        return self._stderr_output

    @stderr_output.setter
    def stderr_output(self, value: List[str]) -> None:
        value = value if value is not None else []
        self._stderr_output = [item.replace("\x00", "") for item in value]

    def is_processable(self,
                       included_items: List[str],
                       excluded_items: List[str],
                       exclude_collectors: List[str],
                       include_collectors: List[str],
                       scope: ReportScopeType = None):
        """
        This method determines whether intel or report information should be collected from this command
        :param included_items: List of items to be processed
        :param excluded_items: List of items to be excluded
        :param exclude_collectors: List of collector names to be processed
        :param include_collectors: List of collector names to be excluded
        :param scope: Value that specifies whether only in-scope items should be included into the report
        :return: True, if the host_name is in the filter list or the filter list is empty
        """
        # todo: update for new collector
        rvalue = True
        if self.collector_name and self.collector_name.name:
            collector_name = self.collector_name.name
            rvalue = (collector_name is None or collector_name not in exclude_collectors) and (
                not include_collectors or collector_name in include_collectors)
        if self.service is not None:
            if self.service.host_name is not None:
                rvalue = rvalue and self.service.host_name.is_processable(included_items=included_items,
                                                                          excluded_items=excluded_items,
                                                                          collector_type=CollectorType.host_name_service,
                                                                          scope=scope)
            elif self.service.host is not None:
                rvalue = rvalue and self.service.host.is_processable(included_items=included_items,
                                                                     excluded_items=excluded_items,
                                                                     scope=scope)
            else:
                rvalue = True
        if self.ipv4_network is not None:
            rvalue = rvalue and self.ipv4_network.is_processable(included_items=included_items,
                                                                 excluded_items=excluded_items,
                                                                 scope=scope)
        if self.email is not None:
            rvalue = rvalue and self.email.is_processable(included_items=included_items,
                                                          excluded_items=excluded_items,
                                                          scope=scope)
        if self.company is not None:
            rvalue = rvalue and self.company.is_processable(included_items=included_items,
                                                            excluded_items=excluded_items,
                                                            scope=scope)
        return rvalue

    def get_text(self,
                 ident: int = 0,
                 hashes_dedup: Dict[str, bool] = {},
                 show_metadata: bool = True,
                 report_visibility: ReportVisibility = None,
                 color: bool = False,
                 **args) -> List[str]:
        """
        :param ident: Number of spaces
        :param show_metadata: True, if all meta information and not just command outputs shall be returned
        :param report_visibility: Specifies which information shall be shown
        :return: String for console output
        """
        rvalue = []
        if self.status_value and self.status_value > CommandStatus.collecting.value and ((
                self.hide and report_visibility == ReportVisibility.irrelevant) or (
                not self.hide and report_visibility == ReportVisibility.relevant) or
                report_visibility is None):
            rvalue.append("")
            if show_metadata:
                delta = self.execution_time_delta
                delta = " ({}s)".format(delta.seconds) if delta else ""
                execution_time = "{} - {}{}".format(self.start_time_str, self.stop_time_str, delta) \
                    if self.start_time and self.stop_time else ""
                return_code = self.return_code if self.return_code is not None else ""
                status_color = None
                if color:
                    if self.status == CommandStatus.failed:
                        status_color = FontColor.RED
                    elif self.status == CommandStatus.completed:
                        status_color = FontColor.GREEN
                    else:
                        status_color = FontColor.GRAY
                hidden = " (hidden)" if self.hide else ""
                username = self.username
                Utils.get_text(rvalue, ident, True, "# Collector Name: {} -> {}",
                               self.collector_name.name,
                               self.target_summary,
                               color=FontColor.BOLD if color else None)
                Utils.get_text(rvalue, ident, True, "# Database ID:    {}", self.id)
                Utils.get_text(rvalue, ident, True, "# Execution time: {}", execution_time)
                Utils.get_text(rvalue, ident, True, "# Execution user: {}", username if username else "root")
                Utils.get_text(rvalue, ident, True, "# Status:         {}{}", self.status_str, hidden,
                               color=status_color)
                Utils.get_text(rvalue, ident, True, "# Return code:    {}", return_code)
                Utils.get_text(rvalue, ident, True, "$ {}", self.os_command_string)
                hint = []
                for item in self.hint:
                    hint.append("{}{}".format(" " * (ident + 2), item))
            command_output = []
            if self.stdout_output:
                for item in self.stdout_output:
                    command_output.append("{}{}".format(" " * ident, item))
            if self.stderr_output:
                for item in self.stderr_output:
                    command_output.append("{}{}".format(" " * ident, item))
            command_full_text = "".join(command_output).strip()
            if command_full_text:
                hash_dedup = hashlib.sha224(command_full_text.encode('utf-8')).hexdigest()
                if hash_dedup in hashes_dedup:
                    command_output =["{}<skipped (duplicate)>".format(" " * ident)]
                else:
                    hashes_dedup[hash_dedup] = True
            rvalue.extend(command_output)
        return rvalue

    def __repr__(self):
        return "<Command id={} os_command={}... status={}".format(self.id, self.os_command_string, self.status.name)


class Credentials(DeclarativeBase):
    """This class holds all information about identified credentials."""

    __tablename__ = "credential"
    id = Column(Integer, primary_key=True)
    username = Column(Text, nullable=True, unique=False)
    domain = Column(Text, nullable=True, unique=False)
    password = Column(Text, nullable=True, unique=False)
    type = Column(Enum(CredentialType), nullable=True, unique=False)
    complete = Column(Boolean, nullable=False, unique=False, default=False)
    service_id = Column(Integer, ForeignKey("service.id", ondelete='cascade'), nullable=True, unique=False)
    email_id = Column(Integer, ForeignKey("email.id", ondelete='cascade'), nullable=True, unique=False)
    creation_date = Column(DateTime, nullable=False, default=datetime.utcnow())
    last_modified = Column(DateTime, nullable=True, onupdate=datetime.utcnow())
    __table_args__ = (UniqueConstraint('username', 'password', 'type', 'service_id',
                                       name='_credential_service_unique'),
                      UniqueConstraint('username', 'password', 'type', 'email_id',
                                       name='_credential_email_unique'),
                      CheckConstraint('not service_id is null or not email_id is null',
                                      name='_credential_mutex_constraint'),
                      CheckConstraint('service_id is null or email_id is null',
                                      name='_credential_all_constraint'),
                      CheckConstraint('not service_id is null or not email_id is null', name='_credential_constraint'),)

    @property
    def type_str(self) -> str:
        return_value = None
        if self.type and self.type.name:
            return_value = self.type.name.replace("_", "-").lower()
        return return_value

    @property
    def sources_str(self) -> str:
        result = None
        if self.sources:
            result = ", ".join([item.name for item in self.sources])
        return result

    def is_processable(self,
                       included_items: List[str],
                       excluded_items: List[str],
                       scope: bool = None) -> bool:
        """
        This method determines whether intel or report information should be collected from this credential
        :param included_items: List of items to be processed
        :param excluded_items: List of items to be excluded
        :param scope: Value that specifies whether only in-scope items should be included into the report
        :return: True, if the host_name is in the filter list or the filter list is empty
        """
        if self.service is not None:
            if self.service.host_name is not None:
                rvalue = self.service.host_name.is_processable(included_items=included_items,
                                                               excluded_items=excluded_items,
                                                               collector_type=CollectorType.host_name_service,
                                                               scope=scope)
            elif self.service.host is not None:
                rvalue = self.service.host.is_processable(included_items=included_items,
                                                          excluded_items=excluded_items,
                                                          scope=scope)
            else:
                rvalue = True
        elif self.email is not None:
            rvalue = self.email.is_processable(included_items=included_items,
                                               excluded_items=excluded_items,
                                               scope=scope)
        else:
            rvalue = True
        return rvalue

    def get_text(self, ident: int = 0, is_last: bool = False, color: bool = False, **args) -> List[str]:
        """
        :param ident: Number of spaces
        :return: String for console output
        """
        rvalue = []
        prefix = "|_" if is_last else "| "
        msg = None
        complete = "Yes" if self.complete else "No"
        if self.username and not self.domain:
            msg = "User: {}".format(self.username)
        if self.username and self.domain:
            msg = "User: {}\\{}".format(self.domain, self.username)
        if self.password:
            msg = "{}, Password: {}".format(msg, self.password) if msg else "Password: {}".format(self.password)
        if self.type_str:
            msg = "{}, Type: {}".format(msg, self.type_str) if msg else "Type: {}".format(self.type_str)
        msg = "{}, Complete: {}".format(msg, complete) if msg else "Complete: {}".format(complete)
        msg = "{}  {}".format(prefix, msg) if msg else None
        if msg:
            Utils.get_text(rvalue, ident, True, msg, color=FontColor.RED if color else None)
        return rvalue


class Path(DeclarativeBase):
    """This class holds all information about identified paths."""

    __tablename__ = "path"
    id = Column(Integer, primary_key=True)
    name = Column(Text, nullable=False, unique=False)
    return_code = Column(Integer, nullable=True, unique=False)
    size_bytes = Column(Integer, nullable=True, unique=False)
    type = Column(Enum(PathType), nullable=False, unique=False)
    service_id = Column(Integer, ForeignKey("service.id", ondelete='cascade'), nullable=False, unique=False)
    creation_date = Column(DateTime, nullable=False, default=datetime.utcnow())
    last_modified = Column(DateTime, nullable=True, onupdate=datetime.utcnow())
    queries = relationship("HttpQuery",
                           backref=backref("path"),
                           order_by="asc(HttpQuery.query)",
                           cascade='delete, delete-orphan')
    __table_args__ = (UniqueConstraint('name', 'type', 'service_id', name='_path_unique'),)

    @property
    def type_str(self) -> str:
        rvalue = None
        if self.type and self.type.name:
            rvalue = self.type.name.replace("_", "-").lower()
        return rvalue

    @property
    def sources_str(self) -> str:
        result = None
        if self.sources:
            result = ", ".join([item.name for item in self.sources])
        return result

    def is_processable(self,
                       included_items: List[str],
                       excluded_items: List[str],
                       scope: bool = None) -> bool:
        """
        This method determines whether intel or report information should be collected from this path
        :param included_items: List of items to be processed
        :param excluded_items: List of items to be excluded
        :param scope: Value that specifies whether only in-scope items should be included into the report
        :return: True, if the host_name is in the filter list or the filter list is empty
        """
        if self.service is not None:
            if self.service.host_name is not None:
                rvalue = self.service.host_name.is_processable(included_items=included_items,
                                                               excluded_items=excluded_items,
                                                               collector_type=CollectorType.host_name_service,
                                                               scope=scope)
            elif self.service.host is not None:
                rvalue = self.service.host.is_processable(included_items=included_items,
                                                          excluded_items=excluded_items,
                                                          scope=scope)
            else:
                rvalue = True
        else:
            rvalue = True
        return rvalue

    def get_text(self, ident: int = 0, is_last: bool = False, color: bool = False, **args) -> List[str]:
        """
        :param ident: Number of spaces
        :return: String for console output
        """
        rvalue = []
        name = self.name
        prefix = "|_" if is_last else "| "
        sources = ", ".join([item.name for item in self.sources])
        if self.type == PathType.Http:
            name = self.get_urlparse().geturl()
        elif self.type == PathType.Smb_Share:
            name = self.get_share()
        msg = None
        if self.return_code:
            msg = "status: {}".format(self.return_code)
        if self.size_bytes:
            msg = "{}, size: {}".format(msg, self.size_bytes) if msg else "size: {}".format(self.size_bytes)
        if sources:
            msg = "{}, sources: {}".format(msg, sources) if msg else "sources: {}".format(sources)
        msg = " ({})".format(msg) if msg else ""
        Utils.get_text(rvalue, ident, False, "{}  {}{}", prefix, name, msg,
                       color=FontColor.GRAY if color and self.return_code and (self.return_code < 0 or
                                                                               300 <= self.return_code < 500) else None)
        return rvalue

    def get_path(self) -> str:
        """
        This method returns the appropriate string representation of the given file type
        :return:
        """
        if self.type == PathType.Smb_Share:
            rvalue = self.get_share()
        elif self.type == PathType.Http:
            rvalue = self.get_urlparse().geturl()
        elif self.type == PathType.Nfs_Share:
            rvalue = self.get_nfs_share()
        else:
            rvalue = self.name
        return rvalue

    def get_share(self) -> str:
        """
        :return: This method returns the given path as network share
        """
        host = "//{}".format(self.service.host.ip)
        path = self.name if self.name[0] == "/" else "/{}".format(self.name)
        return host + path

    def get_nfs_share(self) -> str:
        """
        :return: This method returns the given path as network share
        """
        host = self.service.host.ip
        path = ":{}".format(self.name) if self.name[0] == "/" else ":/{}".format(self.name)
        return host + path

    def get_urlparse(self, ip_address: str = None, query: str = None) -> urllib.parse.ParseResult:
        """This method returns the entire URL if service and host information is given, else None"""
        return_value = None
        if self.name:
            return_value = self.service.get_urlparse(ip_address, self.name, query=query)
        return return_value

    def get_queries(self, ip_address: str = None) -> List[urllib.parse.ParseResult]:
        """This method returns the entire URL together with the query"""
        rvalue = []
        for item in self.queries:
            url = self.get_urlparse(ip_address, query=item.query)
            if url:
                rvalue.append(url)
        return rvalue


class HttpQuery(DeclarativeBase):
    """This class holds all information about the query part of a URL."""

    __tablename__ = "http_query"
    id = Column(Integer, primary_key=True)
    query = Column(Text, nullable=False, unique=False)
    path_id = Column(Integer, ForeignKey("path.id", ondelete='cascade'), nullable=False, unique=False)
    creation_date = Column(DateTime, nullable=False, default=datetime.utcnow())
    last_modified = Column(DateTime, nullable=True, onupdate=datetime.utcnow())
    __table_args__ = (UniqueConstraint('query', 'path_id', name='_http_query_unique'),)

    def get_urlparse(self, ip_address: str = None) -> urllib.parse.ParseResult:
        """This method returns the entire URL if service and host information is given, else None"""
        return_value = None
        if self.path:
            return_value = self.path.get_urlparse(ip_address, self.query)
        return return_value


class File(DeclarativeBase):
    """This class holds all files"""

    __tablename__ = "file"
    id = Column(Integer, primary_key=True)
    content = Column(BYTEA, nullable=False, unique=False)
    workspace_id = Column(Integer, ForeignKey("workspace.id", ondelete='cascade'), nullable=False, unique=False)
    type = Column(Enum(FileType), nullable=False, unique=False)
    sha256_value = Column(Text, nullable=False, unique=False)
    commands = relationship('Command',
                            secondary='command_file_mapping',
                            back_populates="files",
                            cascade="all",
                            passive_deletes=True)
    __table_args__ = (UniqueConstraint('type', 'sha256_value', 'workspace_id', name='_file_unique'),)

    @property
    def type_str(self) -> str:
        result = None
        if self.type:
            result = self.type.name
        return result


class CommandFileMapping(DeclarativeBase):

    __tablename__ = "command_file_mapping"
    __mapper_args__ = {'confirm_deleted_rows': False}
    id = Column("id", Integer, primary_key=True)
    file_name = Column("file_name", Text, nullable=False)
    command_id = Column(Integer, ForeignKey('command.id', ondelete='cascade'), nullable=False)
    file_id = Column(Integer, ForeignKey('file.id', ondelete='cascade'), nullable=False)
    creation_date = Column(DateTime, nullable=False, default=datetime.utcnow())
    last_modified = Column(DateTime, nullable=True, onupdate=datetime.utcnow())
    command = relationship("Command", backref=backref('file_mappings', cascade='delete, delete-orphan'))
    file = relationship("File", backref=backref('command_mappings', cascade='delete, delete-orphan'))
    __table_args__ = (UniqueConstraint('file_id', 'command_id', name='_command_file_unique'),)


class Company(DeclarativeBase):
    """This class holds all information about a company."""

    __tablename__ = "company"
    id = Column("id", Integer, primary_key=True)
    name = Column(Text, nullable=False, unique=False)
    in_scope = Column("in_scope", Boolean, nullable=False, unique=False, server_default='FALSE')
    workspace_id = Column(Integer, ForeignKey("workspace.id", ondelete='cascade'), nullable=False, unique=False)
    creation_date = Column(DateTime, nullable=False, default=datetime.utcnow())
    last_modified = Column(DateTime, nullable=True, onupdate=datetime.utcnow())
    domain_names = relationship("DomainName",
                                secondary=company_domain_name_mapping,
                                backref=backref("companies", order_by="asc(Company.name)"))
    networks = relationship("Network",
                            secondary=company_network_mapping,
                            backref=backref("companies", order_by="asc(Company.name)"))
    __table_args__ = (UniqueConstraint('name', 'workspace_id', name='_company_unique'),)


    @property
    def sources_str(self) -> str:
        result = None
        if self.sources:
            result = ", ".join([item.name for item in self.sources])
        return result

    def is_processable(self,
                       included_items: List[str],
                       excluded_items: List[str],
                       active_collector: bool = None,
                       scope: ReportScopeType = None) -> bool:
        """
        This method determines whether intel or report information should be collected from this company
        :param included_items: List of items to be processed
        :param excluded_items: List of items to be excluded
        :param active_collector: Value that specifies whether the given collector is active or passive
        :param scope: Value that specifies whether only in-scope items should be included into the report
        :return: True, if the host_name is in the filter list or the filter list is empty
        """
        in_scope = self.in_scope
        name = self.name.lower()
        rvalue = name not in excluded_items and \
                 (not included_items or name in included_items) and \
                 (scope is None or (scope == ReportScopeType.within and in_scope) or (
                         scope == ReportScopeType.outside and not in_scope)) and \
                 (active_collector is None or not active_collector or in_scope and active_collector)
        return rvalue

    def get_command_text(self,
                         exclude_collectors: List[str] = [],
                         include_collectors: List[str] = [],
                         **args) -> List[str]:
        """
        :param exclude_collectors: List of collector names whose output should not be printed
        :param include_collectors: List of collector names whose output should be printed
        :return: String for console output
        """
        rvalue = []
        if self.commands:
            rvalue.append("")
        for item in self.commands:
            if item.collector_name.name not in exclude_collectors and (item.collector_name.name in include_collectors or
                                                                       not include_collectors):
                text = item.get_text(**args)
                rvalue.extend(text)
        return rvalue

    def get_text(self,
                 ident: int = 0,
                 show_metadata: bool = True,
                 report_visibility: ReportVisibility = None,
                 color: bool = False,
                 **args) -> List[str]:
        """
        :param ident: Number of spaces
        :param show_metadata: True, if all meta information and not just command outputs shall be returned
        :param report_visibility: Specifies which information shall be shown
        :return: String for console output
        """
        rvalue = []
        sources = [item.name for item in self.sources]
        sources.sort()
        if show_metadata:
            full = report_visibility != ReportVisibility.relevant if ReportVisibility else True
            Utils.get_text(rvalue, ident, True, "KIS intel report for {}", self.name,
                           color=FontColor.BLUE + FontColor.BOLD if color else None)
            Utils.get_text(rvalue, ident, True, "| In scope:        {}", self.in_scope)
            Utils.get_text(rvalue, ident, True, "| Workspace:       {}", self.workspace.name)
            Utils.get_text(rvalue, ident, full, "|_Sources:         {}", ", ".join(sources))
        hashes_dedup = {}
        items = self.get_command_text(ident=ident,
                                      hashes_dedup=hashes_dedup,
                                      show_metadata=show_metadata,
                                      report_visibility=report_visibility,
                                      **args)
        if items:
            rvalue.extend(items)
        rvalue.extend(["", ""])
        return rvalue


class CertInfo(DeclarativeBase):
    """This class holds general information about certificates."""

    __tablename__ = "cert_info"
    id = Column(Integer, primary_key=True)
    serial_number = Column(Text, nullable=False, unique=False)
    common_name = Column(Text, nullable=False, unique=False)
    issuer_name = Column(Text, nullable=False, unique=False)
    signature_asym_algorithm = Column(Enum(AsymmetricAlgorithm), nullable=False, unique=False)
    signature_bits = Column(Integer, nullable=False)
    hash_algorithm = Column(Enum(HashAlgorithm), nullable=False, unique=False)
    cert_type = Column(Enum(CertType), nullable=False, unique=False)
    valid_from = Column(DateTime, nullable=False, unique=False)
    valid_until = Column(DateTime, nullable=False, unique=False)
    _extension_info = Column("extension_info", MutableDict.as_mutable(JSON), nullable=True, unique=False, default={})
    creation_date = Column(DateTime, nullable=False, default=datetime.utcnow())
    last_modified = Column(DateTime, nullable=True, onupdate=datetime.utcnow())
    service_id = Column(Integer, ForeignKey("service.id", ondelete='cascade'), nullable=True, unique=False)
    company_id = Column(Integer, ForeignKey("company.id", ondelete='cascade'), nullable=True, unique=False)
    host_name_id = Column(Integer, ForeignKey("host_name.id", ondelete='cascade'), nullable=True, unique=False)
    service = relationship("Service", backref=backref("cert_info",
                                                      cascade='delete, delete-orphan',
                                                      order_by='asc(CertInfo.valid_from), asc(CertInfo.common_name)'))
    company = relationship("Company", backref=backref("cert_info",
                                                      cascade='delete, delete-orphan',
                                                      order_by='asc(CertInfo.valid_from), asc(CertInfo.common_name)'))
    host_name = relationship("HostName", backref=backref("cert_info",
                                                        cascade='delete, delete-orphan',
                                                        order_by='asc(CertInfo.valid_from), asc(CertInfo.common_name)'))
    __table_args__ = (UniqueConstraint('service_id', 'serial_number',
                                       name='_cert_info_unique'),
                      UniqueConstraint('service_id',
                                       'serial_number', name='_cert_info_service_unique'),
                      UniqueConstraint('company_id',
                                       'serial_number', name='_cert_info_company_unique'),
                      UniqueConstraint('host_name_id',
                                       'serial_number', name='_cert_info_host_name_unique'),
                      CheckConstraint(
                          '(case when not service_id is null and company_id is null and host_name_id is null then 1 else 0 end'
                          '+case when service_id is null and not company_id is null and host_name_id is null then 1 else 0 end'
                          '+case when service_id is null and company_id is null and not host_name_id is null then 1 else 0 end) = 1',
                          name='_cert_info_mutex_constraint'),)

    @property
    def signature_asym_algorithm_str(self) -> str:
        return self.signature_asym_algorithm.name.upper() if self.signature_asym_algorithm else None

    @property
    def signature_asym_algorithm_summary(self) -> str:
        result = self.signature_asym_algorithm_str
        if result and self.signature_bits:
            result += " {}".format(self.signature_bits)
        return result

    @property
    def hash_algorithm_str(self) -> str:
        return self.hash_algorithm.name.upper() if self.hash_algorithm else None

    @property
    def cert_type_str(self) -> str:
        return self.cert_type.name[0].upper() + self.cert_type.name[1:] if self.cert_type else None

    @property
    def valid_from_str(self) -> str:
        return self.valid_from.strftime("%Y-%m-%d") if self.valid_from else None

    @property
    def valid_until_str(self) -> str:
        return self.valid_until.strftime("%Y-%m-%d") if self.valid_until else None

    @property
    def extension_info(self) -> Dict[str, str]:
        if self._extension_info is None:
            self._extension_info = {}
        return self._extension_info

    @extension_info.setter
    def extension_info(self, value: Dict[str, str]):
        self._extension_info = value

    @property
    def subject_alt_names(self) -> List[str]:
        result = []
        if "subject_alt_name" in self.extension_info:
            result = [item.lower() for item in self.extension_info["subject_alt_name"]]
        return result

    @subject_alt_names.setter
    def subject_alt_names(self, value: List[str]):
        if "subject_alt_name" not in self.extension_info:
            self.extension_info["subject_alt_name"] = []
        self.extension_info["subject_alt_name"].extend(value)

    @property
    def subject_alt_names_str(self) -> str:
        return ", ".join(self.subject_alt_names)

    @property
    def all_names(self) -> List[str]:
        result = []
        if self.common_name:
            result.append(self.common_name.lower())
        result += self.subject_alt_names
        return result

    @property
    def all_names_re(self) -> List[re.Pattern]:
        result = []
        for item in self.all_names:
            item = item.strip().replace(".", "\.").replace("*", ".*")
            result.append(re.compile("^{}$".format(item), re.IGNORECASE))
        return result

    @property
    def key_usage(self) -> List[str]:
        result = []
        if "extended_key_usage1" in self.extension_info and "values" in self.extension_info["extended_key_usage"]:
            result = self.extension_info["extended_key_usage"]["values"]
        elif "key_usage" in self.extension_info and "values" in self.extension_info["key_usage"]:
            result = self.extension_info["key_usage"]["values"]
        return result

    @property
    def critical_extensions(self) -> list:
        return [item for item in self.extension_info.values() if "critical" in item and item["critical"]]

    @property
    def critical_extension_names(self) -> List[str]:
        return [item["name"] for item in self.critical_extensions if "name" in item]

    @property
    def key_usage_str(self) -> str:
        return ", ".join(self.key_usage)

    @property
    def validity_period_days(self):
        """
        Returns the total number of days the certificate is valid
        """
        return (self.valid_until - self.valid_from).days if self.valid_until and self.valid_from else None

    @property
    def sources_str(self) -> str:
        result = None
        if self.sources:
            result = ", ".join([item.name for item in self.sources])
        return result

    def is_self_signed(self) -> bool:
        """
        Returns true if the certificate is self signed
        """
        return self.common_name.lower() == self.issuer_name.lower()

    def has_weak_signature(self) -> bool:
        """
        Returns true if the certificate was created using a weak hash algorithm
        """
        return self.hash_algorithm in [HashAlgorithm.md5, HashAlgorithm.sha1]

    def is_valid(self) -> bool:
        """
        Returns true if the certificate has expired
        :return:
        """
        return (self.valid_from < datetime.now() < self.valid_until)

    def has_recommended_duration(self) -> bool:
        """
        Returns true if the certificate has expired
        :return:
        """
        result = None
        days = self.validity_period_days
        if days is not None and days > 0:
            years = days / 365
            result = (self.cert_type == CertType.identity and years <= 3) or \
                     (self.cert_type == CertType.intermediate and years <= 5) or \
                     (self.cert_type == CertType.root and years <= 10)
        return result

    def matches_host_name(self, host_name: HostName) -> bool:
        """
        Checks whether the given host name is covered by this certificate info object.
        :param host_name: The host name that shall be covered.
        :return: True if the host_name is covered by this certificate.
        """
        result = False
        for item in self.all_names_re:
            match = item.match(host_name.full_name)
            if match:
                result = True
                break
        return result

    def matches_host_names(self, host_names: List[HostName]) -> bool:
        """
        Checks whether the given host names are covered by this certificate info object.
        :param host_names: The host names that shall be covered.
        :return: True if all host_names are covered by this certificate.
        """
        if not host_names:
            return False
        return all([self.matches_host_name(item) for item in host_names])

    def is_processable(self,
                       included_items: List[str],
                       excluded_items: List[str],
                       scope: bool = None) -> bool:
        """
        This method determines whether intel or report information should be collected from this host
        :param included_items: List of items to be processed
        :param excluded_items: List of items to be excluded
        :param scope: Value that specifies whether only in-scope or out-of-scope items should be included into the
        report
        :return: True, if the host_name is in the filter list or the filter list is empty
        """
        if self.service is not None:
            if self.service.host_name is not None:
                rvalue = self.service.host_name.is_processable(included_items=included_items,
                                                               excluded_items=excluded_items,
                                                               collector_type=CollectorType.host_name_service,
                                                               scope=scope)
            elif self.service.host is not None:
                rvalue = self.service.host.is_processable(included_items=included_items,
                                                          excluded_items=excluded_items,
                                                          scope=scope)
            else:
                rvalue = True
        else:
            rvalue = True
        return rvalue

    def __repr__(self):
        return "<CertInfo service_id='{}' common_name='{}' issuer_name='{}' " \
               "valid_from='{}' valid_until='{}' />".format(self.service_id,
                                                            self.common_name,
                                                            self.issuer_name,
                                                            self.valid_from,
                                                            self.valid_until)


class CipherSuite(DeclarativeBase):
    """This class holds general information about TLS."""

    __tablename__ = "cipher_suite"
    id = Column(Integer, primary_key=True)
    iana_name = Column(Text, nullable=False, unique=True)
    gnutls_name = Column(Text, nullable=True, unique=True)
    openssl_name = Column(Text, nullable=True, unique=True)
    byte_1 = Column(Integer, nullable=False, unique=False)
    byte_2 = Column(Integer, nullable=False, unique=False)
    protocol_version = Column(Enum(CipherSuiteProtocolVersion), nullable=False, unique=False)
    security = Column(Enum(CipherSuiteSecurity), nullable=False, unique=False)
    kex_algorithm = Column(Enum(KeyExchangeAlgorithm), nullable=True, unique=False)
    auth_algorithm = Column(Enum(AuthenticationAlgorithm), nullable=True, unique=False)
    enc_algorithm = Column(Enum(SymmetricAlgorithm), nullable=False, unique=False)
    enc_algorithm_bits = Column(Integer, nullable=True, unique=False)
    aead = Column(Boolean, nullable=True, unique=False)
    hash_algorithm = Column(Enum(HashAlgorithm), nullable=False, unique=False)
    tls_info = relationship('TlsInfo', secondary='tls_info_cipher_suite_mapping')

    @property
    def pfs(self):
        return self.kex_algorithm in [KeyExchangeAlgorithm.ecdh_x25519,
                                      KeyExchangeAlgorithm.dh,
                                      KeyExchangeAlgorithm.dhe,
                                      KeyExchangeAlgorithm.ecdh,
                                      KeyExchangeAlgorithm.ecdhe,
                                      KeyExchangeAlgorithm.dh512,
                                      KeyExchangeAlgorithm.dh1024,
                                      KeyExchangeAlgorithm.dh2048,
                                      KeyExchangeAlgorithm.dh2240,
                                      KeyExchangeAlgorithm.dh3072,
                                      KeyExchangeAlgorithm.dh4096]

    @property
    def sources_str(self) -> str:
        result = None
        if self.sources:
            result = ", ".join([item.name for item in self.sources])
        return result

    @property
    def kex_algorithm_str(self) -> str:
        result = None
        if self.kex_algorithm:
            result = self.kex_algorithm.name.upper()
        return result

    @property
    def auth_algorithm_str(self) -> str:
        result = None
        if self.auth_algorithm:
            result = self.auth_algorithm.name.upper()
        return result

    @property
    def enc_algorithm_str(self) -> str:
        result = None
        if self.enc_algorithm:
            result = self.enc_algorithm.name.upper()
        return result

    @property
    def hash_algorithm_str(self) -> str:
        result = None
        if self.hash_algorithm:
            result = self.hash_algorithm.name.upper()
        return result

    @property
    def security_str(self) -> str:
        result = None
        if self.security:
            result = self.security.name
        return result

    @property
    def protocol_version_str(self) -> str:
        result = None
        if self.protocol_version:
            result = self.protocol_version.name
        return result


class TlsInfoCipherSuiteMapping(DeclarativeBase):

    __tablename__ = "tls_info_cipher_suite_mapping"
    id = Column("id", Integer, primary_key=True)
    cipher_suite_id = Column("cipher_suite_id",
                             Integer,
                             ForeignKey('cipher_suite.id', ondelete='cascade'),
                             nullable=False)
    tls_info_id = Column("tls_info_id",
                         Integer,
                         ForeignKey('tls_info.id', ondelete='cascade'),
                         nullable=False)
    kex_algorithm_details = Column(Enum(KeyExchangeAlgorithm), nullable=True, unique=False)
    kex_bits = Column(Integer, nullable=True)
    order = Column("order", Integer, nullable=True)
    prefered = Column(Boolean, nullable=True)
    creation_date = Column(DateTime, nullable=False, default=datetime.utcnow())
    last_modified = Column(DateTime, nullable=True, onupdate=datetime.utcnow())
    cipher_suite = relationship("CipherSuite", backref=backref('tls_info_mappings', cascade='all, delete-orphan'))
    tls_info = relationship("TlsInfo", backref=backref('cipher_suite_mappings', cascade='all, delete-orphan'))
    __table_args__ = (UniqueConstraint('tls_info_id',
                                       'cipher_suite_id',
                                       'kex_algorithm_details', name='_tls_info_cipher_suite_mapping_unique'),)

    @property
    def kex_algorithm_bits(self) -> int:
        if self.kex_bits:
            result = self.kex_bits
        elif self.kex_algorithm_details in [KeyExchangeAlgorithm.dh1024, KeyExchangeAlgorithm.rsa1024]:
            result = 512
        elif self.kex_algorithm_details in [KeyExchangeAlgorithm.dh1024, KeyExchangeAlgorithm.rsa1024]:
            result = 1024
        elif self.kex_algorithm_details in [KeyExchangeAlgorithm.dh2048, KeyExchangeAlgorithm.rsa2048]:
            result = 2048
        elif self.kex_algorithm_details in [KeyExchangeAlgorithm.dh2240]:
            result = 2240
        elif self.kex_algorithm_details in [KeyExchangeAlgorithm.dh3072, KeyExchangeAlgorithm.rsa3072]:
            result = 3072
        elif self.kex_algorithm_details in [KeyExchangeAlgorithm.dh4096, KeyExchangeAlgorithm.rsa4096]:
            result = 4096
        else:
            raise NotImplementedError("case not implemented")
        return result

    @property
    def sources_str(self) -> str:
        result = None
        if self.sources:
            result = ", ".join([item.name for item in self.sources])
        return result

    @property
    def kex_algorithm_details_str(self) -> str:
        result = None
        if self.kex_algorithm_details:
            result = self.kex_algorithm_details.name
        return result

    @staticmethod
    def get_kex_algorithm(text: str, source: Source = None) -> KeyExchangeAlgorithm:
        if not text:
            return KeyExchangeAlgorithm.anonymous
        text = text.lower()
        if text in ["dh 512"]:
            result = KeyExchangeAlgorithm.dh512
        elif text in ["dh 1024"]:
            result = KeyExchangeAlgorithm.dh1024
        elif text in ["dh 2048"]:
            result = KeyExchangeAlgorithm.dh2048
        elif text in ["dh 2240"]:
            result = KeyExchangeAlgorithm.dh2240
        elif text in ["dh 3072"]:
            result = KeyExchangeAlgorithm.dh3072
        elif text in ["dh 4096"]:
            result = KeyExchangeAlgorithm.dh4096
        elif text in ["rsa 512"]:
            result = KeyExchangeAlgorithm.rsa512
        elif text in ["rsa 1024"]:
            result = KeyExchangeAlgorithm.rsa1024
        elif text in ["rsa 2048"]:
            result = KeyExchangeAlgorithm.rsa2048
        elif text in ["rsa 3072"]:
            result = KeyExchangeAlgorithm.rsa3072
        elif text in ["rsa 4096"]:
            result = KeyExchangeAlgorithm.rsa4096
        elif text in ['ecdh_x25519', '25519', 'x25519']:
            result = KeyExchangeAlgorithm.ecdh_x25519
        elif text in ['secp256r1']:
            result = KeyExchangeAlgorithm.secp256r1
        elif text in ['secp384r1']:
            result = KeyExchangeAlgorithm.secp384r1
        elif text in ['secp521r1']:
            result = KeyExchangeAlgorithm.secp521r1
        elif text in ['p-256', "prime256v1"]:
            result = KeyExchangeAlgorithm.p_256
        elif text in ['p-384']:
            result = KeyExchangeAlgorithm.p_384
        elif text in ['p-521']:
            result = KeyExchangeAlgorithm.p_521
        else:
            result = None
        return result


class TlsInfo(DeclarativeBase):
    """This class holds general information about TLS."""

    __tablename__ = "tls_info"
    id = Column(Integer, primary_key=True)
    version = Column(Enum(TlsVersion), nullable=False, unique=False)
    service_id = Column(Integer, ForeignKey("service.id", ondelete='cascade'), nullable=False, unique=False)
    _compressors = Column("compressors", MutableList.as_mutable(ARRAY(Text)), nullable=True, unique=False, default=[])
    preference = Column(Enum(TlsPreference), nullable=True, unique=False)
    heartbleed = Column(Boolean, nullable=True, unique=False)
    cipher_suites = relationship(CipherSuite,
                                 secondary='tls_info_cipher_suite_mapping',
                                 order_by="asc(TlsInfoCipherSuiteMapping.order)")
    service = relationship("Service", backref=backref("tls_info", cascade='delete, delete-orphan'))
    __table_args__ = (UniqueConstraint('service_id', 'version', name='_tls_info_unique'),)

    @property
    def compressors(self) -> List[str]:
        if self._compressors is None:
            self._compressors = []
        return self._compressors

    @compressors.setter
    def compressors(self, value: List[str]) -> None:
        self._compressors = value

    @property
    def compressors_str(self) -> str:
        result = None
        if self.compressors:
            result = ", ".join([item for item in self.compressors])
        return result

    @property
    def preference_str(self) -> str:
        result = None
        if self.preference:
            result = self.preference.name
        return result

    @property
    def version_str(self) -> str:
        result = None
        if self.version == TlsVersion.ssl2:
            result = "SSLv2"
        elif self.version == TlsVersion.ssl3:
            result = "SSLv3"
        elif self.version == TlsVersion.tls10:
            result = "TLSv1.0"
        elif self.version == TlsVersion.tls11:
            result = "TLSv1.1"
        elif self.version == TlsVersion.tls12:
            result = "TLSv1.2"
        elif self.version == TlsVersion.tls13:
            result = "TLSv1.3"
        else:
            raise NotImplementedError("unknown TLS version {}".format(self.version.name))
        return result

    @staticmethod
    def get_tls_version(text: str) -> TlsVersion:
        text = text.upper()
        if text in ["SSL2.0", "SSLV2.0", "SSL2", "SSLV2", "SSL_2_0"]:
            rvalue = TlsVersion.ssl2
        elif text in ["SSL3.0", "SSLV3.0", "SSL3", "SSLV3", "SSL_3_0"]:
            rvalue = TlsVersion.ssl3
        elif text in ["TLS1.0", "TLSV1.0", "TLSV1", "TLS_1_0"]:
            rvalue = TlsVersion.tls10
        elif text in ["TLS1.1", "TLSV1.1", "TLSV1_1", "TLS_1_1"]:
            rvalue = TlsVersion.tls11
        elif text in ["TLS1.2", "TLSV1.2", "TLSV1_2", "TLS_1_2"]:
            rvalue = TlsVersion.tls12
        elif text in ["TLS1.3", "TLSV1.3", "TLSV1_3", "TLS_1_3"]:
            rvalue = TlsVersion.tls13
        else:
            rvalue = None
            logger.error("TLS version '{}' not found. update TlsVersion class and TlsInfo.get_tls_version in "
                         "database.model.py".format(text))
        return rvalue

    @staticmethod
    def get_tls_preference(text: str) -> TlsPreference:
        rvalue = None
        if text:
            text = text.lower()
            if text in TlsPreference.__members__:
                rvalue = TlsPreference[text]
            else:
                rvalue = None
                logger.error("TLS version '{}' not found. update TlsPreference class and TlsInfo.get_tls_preference in "
                             "database.model.py".format(text))
        return rvalue

    def is_processable(self,
                       included_items: List[str],
                       excluded_items: List[str],
                       scope: bool = None) -> bool:
        """
        This method determines whether intel or report information should be collected from this host
        :param included_items: List of items to be processed
        :param excluded_items: List of items to be excluded
        :param scope: Value that specifies whether only in-scope or out-of-scope items should be included into the
        report
        :return: True, if the host_name is in the filter list or the filter list is empty
        """
        if self.service is not None:
            if self.service.host_name is not None:
                rvalue = self.service.host_name.is_processable(included_items=included_items,
                                                               excluded_items=excluded_items,
                                                               collector_type=CollectorType.host_name_service,
                                                               scope=scope)
            elif self.service.host is not None:
                rvalue = self.service.host.is_processable(included_items=included_items,
                                                          excluded_items=excluded_items,
                                                          scope=scope)
            else:
                rvalue = True
        else:
            rvalue = True
        return rvalue

