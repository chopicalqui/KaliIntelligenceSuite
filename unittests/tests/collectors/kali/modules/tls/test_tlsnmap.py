#!/usr/bin/python3
"""
this file implements all unittests for collector tlsnmap
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

import tempfile
from database.model import CollectorType
from database.model import TlsInfo
from database.model import TlsInfoCipherSuiteMapping
from database.model import ScopeType
from typing import List
from unittests.tests.collectors.core import CollectorProducerTestSuite
from unittests.tests.collectors.kali.modules.scan.core import BaseNmapCollectorTestCase
from collectors.os.modules.tls.tlsnmap import CollectorClass as TlsNmapCollector


class BaseTlsNmapCollectorTestCase(BaseNmapCollectorTestCase):
    """
    This class implements all unittests for the given collector
    """
    def __init__(self, test_name: str, **kwargs):
        super().__init__(test_name,
                         collector_name="tlsnmap",
                         collector_class=TlsNmapCollector)

    @staticmethod
    def get_command_text_outputs() -> List[str]:
        """
        This method returns example outputs of the respective collectors
        :return:
        """
        return []

    @staticmethod
    def get_command_xml_outputs() -> List[str]:
        """
        This method returns example outputs of the respective collectors
        :return:
        """
        return ["""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<!-- Nmap 7.70 scan initiated Wed Oct  2 15:36:09 2019 as: /usr/bin/nmap -Pn -sS -n -sV -&#45;disable-arp-ping -&#45;script=ssl-enum-ciphers,ssl-dh-params,ssl-heartbleed,sslv2,ssl-known-key -p 443 192.168.1.1 -->
<nmaprun scanner="nmap" args="/usr/bin/nmap -Pn -sS -n -sV -&#45;disable-arp-ping -&#45;script=ssl-enum-ciphers,ssl-dh-params,ssl-heartbleed,sslv2,ssl-known-key -p 443 192.168.1.1" start="1570044969" startstr="Wed Oct  2 15:36:09 2019" version="7.70" xmloutputversion="1.04">
<scaninfo type="syn" protocol="tcp" numservices="1" services="443"/>
<verbose level="0"/>
<debugging level="0"/>
<host starttime="1570044969" endtime="1570044984"><status state="up" reason="user-set" reason_ttl="0"/>
<address addr="192.168.1.1" addrtype="ipv4"/>
<hostnames>
</hostnames>
<ports><port protocol="tcp" portid="443"><state state="open" reason="syn-ack" reason_ttl="127"/><service name="http" product="Apache httpd" version="2.4.39" extrainfo="(Win64) OpenSSL/1.1.1b PHP/7.3.4" tunnel="ssl" method="probed" conf="10"><cpe>cpe:/a:apache:http_server:2.4.39</cpe></service><script id="http-server-header" output="Apache/2.4.39 (Win64) OpenSSL/1.1.1b PHP/7.3.4"><elem>Apache/2.4.39 (Win64) OpenSSL/1.1.1b PHP/7.3.4</elem>
</script><script id="ssl-dh-params" output="&#xa;  VULNERABLE:&#xa;  Diffie-Hellman Key Exchange Insufficient Group Strength&#xa;    State: VULNERABLE&#xa;      Transport Layer Security (TLS) services that use Diffie-Hellman groups&#xa;      of insufficient strength, especially those using one of a few commonly&#xa;      shared groups, may be susceptible to passive eavesdropping attacks.&#xa;    Check results:&#xa;      WEAK DH GROUP 1&#xa;            Cipher Suite: TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA&#xa;            Modulus Type: Safe prime&#xa;            Modulus Source: RFC2409/Oakley Group 2&#xa;            Modulus Length: 1024&#xa;            Generator Length: 8&#xa;            Public Key Length: 1024&#xa;    References:&#xa;      https://weakdh.org&#xa;"><table key="NMAP-3">
<elem key="title">Diffie-Hellman Key Exchange Insufficient Group Strength</elem>
<elem key="state">VULNERABLE</elem>
<table key="description">
<elem>Transport Layer Security (TLS) services that use Diffie-Hellman groups&#xa;of insufficient strength, especially those using one of a few commonly&#xa;shared groups, may be susceptible to passive eavesdropping attacks.</elem>
</table>
<table key="check_results">
<elem>WEAK DH GROUP 1&#xa;      Cipher Suite: TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA&#xa;      Modulus Type: Safe prime&#xa;      Modulus Source: RFC2409/Oakley Group 2&#xa;      Modulus Length: 1024&#xa;      Generator Length: 8&#xa;      Public Key Length: 1024</elem>
</table>
<table key="refs">
<elem>https://weakdh.org</elem>
</table>
</table>
</script><script id="ssl-enum-ciphers" output="&#xa;  TLSv1.0: &#xa;    ciphers: &#xa;      TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (ecdh_x25519) - A&#xa;      TLS_DHE_RSA_WITH_AES_256_CBC_SHA (dh 1024) - A&#xa;      TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA (dh 1024) - A&#xa;      TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (ecdh_x25519) - A&#xa;      TLS_DHE_RSA_WITH_AES_128_CBC_SHA (dh 1024) - A&#xa;      TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA (dh 1024) - A&#xa;      TLS_RSA_WITH_AES_256_CBC_SHA (rsa 1024) - A&#xa;      TLS_RSA_WITH_CAMELLIA_256_CBC_SHA (rsa 1024) - A&#xa;      TLS_RSA_WITH_AES_128_CBC_SHA (rsa 1024) - A&#xa;      TLS_RSA_WITH_CAMELLIA_128_CBC_SHA (rsa 1024) - A&#xa;      TLS_DHE_RSA_WITH_SEED_CBC_SHA (dh 1024) - A&#xa;      TLS_RSA_WITH_SEED_CBC_SHA (rsa 1024) - A&#xa;      TLS_RSA_WITH_IDEA_CBC_SHA (rsa 1024) - A&#xa;    compressors: &#xa;      NULL&#xa;    cipher preference: server&#xa;    warnings: &#xa;      64-bit block cipher IDEA vulnerable to SWEET32 attack&#xa;      Weak certificate signature: SHA1&#xa;  TLSv1.1: &#xa;    ciphers: &#xa;      TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (ecdh_x25519) - A&#xa;      TLS_DHE_RSA_WITH_AES_256_CBC_SHA (dh 1024) - A&#xa;      TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA (dh 1024) - A&#xa;      TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (ecdh_x25519) - A&#xa;      TLS_DHE_RSA_WITH_AES_128_CBC_SHA (dh 1024) - A&#xa;      TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA (dh 1024) - A&#xa;      TLS_RSA_WITH_AES_256_CBC_SHA (rsa 1024) - A&#xa;      TLS_RSA_WITH_CAMELLIA_256_CBC_SHA (rsa 1024) - A&#xa;      TLS_RSA_WITH_AES_128_CBC_SHA (rsa 1024) - A&#xa;      TLS_RSA_WITH_CAMELLIA_128_CBC_SHA (rsa 1024) - A&#xa;      TLS_DHE_RSA_WITH_SEED_CBC_SHA (dh 1024) - A&#xa;      TLS_RSA_WITH_SEED_CBC_SHA (rsa 1024) - A&#xa;      TLS_RSA_WITH_IDEA_CBC_SHA (rsa 1024) - A&#xa;    compressors: &#xa;      NULL&#xa;    cipher preference: server&#xa;    warnings: &#xa;      64-bit block cipher IDEA vulnerable to SWEET32 attack&#xa;      Weak certificate signature: SHA1&#xa;  TLSv1.2: &#xa;    ciphers: &#xa;      TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (ecdh_x25519) - A&#xa;      TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 (dh 1024) - A&#xa;      TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (ecdh_x25519) - A&#xa;      TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (dh 1024) - A&#xa;      TLS_DHE_RSA_WITH_AES_256_CCM_8 (dh 1024) - A&#xa;      TLS_DHE_RSA_WITH_AES_256_CCM (dh 1024) - A&#xa;      TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 (ecdh_x25519) - A&#xa;      TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384 (dh 1024) - A&#xa;      TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (ecdh_x25519) - A&#xa;      TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 (dh 1024) - A&#xa;      TLS_DHE_RSA_WITH_AES_128_CCM_8 (dh 1024) - A&#xa;      TLS_DHE_RSA_WITH_AES_128_CCM (dh 1024) - A&#xa;      TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 (ecdh_x25519) - A&#xa;      TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256 (dh 1024) - A&#xa;      TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 (ecdh_x25519) - A&#xa;      TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 (dh 1024) - A&#xa;      TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 (ecdh_x25519) - A&#xa;      TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 (dh 1024) - A&#xa;      TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (ecdh_x25519) - A&#xa;      TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 (dh 1024) - A&#xa;      TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 (ecdh_x25519) - A&#xa;      TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 (dh 1024) - A&#xa;      TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (ecdh_x25519) - A&#xa;      TLS_DHE_RSA_WITH_AES_256_CBC_SHA (dh 1024) - A&#xa;      TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA (dh 1024) - A&#xa;      TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (ecdh_x25519) - A&#xa;      TLS_DHE_RSA_WITH_AES_128_CBC_SHA (dh 1024) - A&#xa;      TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA (dh 1024) - A&#xa;      TLS_RSA_WITH_AES_256_GCM_SHA384 (rsa 1024) - A&#xa;      TLS_RSA_WITH_AES_256_CCM_8 (rsa 1024) - A&#xa;      TLS_RSA_WITH_AES_256_CCM (rsa 1024) - A&#xa;      TLS_RSA_WITH_ARIA_256_GCM_SHA384 (rsa 1024) - A&#xa;      TLS_RSA_WITH_AES_128_GCM_SHA256 (rsa 1024) - A&#xa;      TLS_RSA_WITH_AES_128_CCM_8 (rsa 1024) - A&#xa;      TLS_RSA_WITH_AES_128_CCM (rsa 1024) - A&#xa;      TLS_RSA_WITH_ARIA_128_GCM_SHA256 (rsa 1024) - A&#xa;      TLS_RSA_WITH_AES_256_CBC_SHA256 (rsa 1024) - A&#xa;      TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 (rsa 1024) - A&#xa;      TLS_RSA_WITH_AES_128_CBC_SHA256 (rsa 1024) - A&#xa;      TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 (rsa 1024) - A&#xa;      TLS_RSA_WITH_AES_256_CBC_SHA (rsa 1024) - A&#xa;      TLS_RSA_WITH_CAMELLIA_256_CBC_SHA (rsa 1024) - A&#xa;      TLS_RSA_WITH_AES_128_CBC_SHA (rsa 1024) - A&#xa;      TLS_RSA_WITH_CAMELLIA_128_CBC_SHA (rsa 1024) - A&#xa;      TLS_DHE_RSA_WITH_SEED_CBC_SHA (dh 1024) - A&#xa;      TLS_RSA_WITH_SEED_CBC_SHA (rsa 1024) - A&#xa;    compressors: &#xa;      NULL&#xa;    cipher preference: server&#xa;    warnings: &#xa;      Weak certificate signature: SHA1&#xa;  least strength: A"><table key="TLSv1.0">
<table key="ciphers">
<table>
<elem key="kex_info">ecdh_x25519</elem>
<elem key="name">TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">dh 1024</elem>
<elem key="name">TLS_DHE_RSA_WITH_AES_256_CBC_SHA</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">dh 1024</elem>
<elem key="name">TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">ecdh_x25519</elem>
<elem key="name">TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">dh 1024</elem>
<elem key="name">TLS_DHE_RSA_WITH_AES_128_CBC_SHA</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">dh 1024</elem>
<elem key="name">TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">rsa 1024</elem>
<elem key="name">TLS_RSA_WITH_AES_256_CBC_SHA</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">rsa 1024</elem>
<elem key="name">TLS_RSA_WITH_CAMELLIA_256_CBC_SHA</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">rsa 1024</elem>
<elem key="name">TLS_RSA_WITH_AES_128_CBC_SHA</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">rsa 1024</elem>
<elem key="name">TLS_RSA_WITH_CAMELLIA_128_CBC_SHA</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">dh 1024</elem>
<elem key="name">TLS_DHE_RSA_WITH_SEED_CBC_SHA</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">rsa 1024</elem>
<elem key="name">TLS_RSA_WITH_SEED_CBC_SHA</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">rsa 1024</elem>
<elem key="name">TLS_RSA_WITH_IDEA_CBC_SHA</elem>
<elem key="strength">A</elem>
</table>
</table>
<table key="compressors">
<elem>NULL</elem>
</table>
<elem key="cipher preference">server</elem>
<table key="warnings">
<elem>64-bit block cipher IDEA vulnerable to SWEET32 attack</elem>
<elem>Weak certificate signature: SHA1</elem>
</table>
</table>
<table key="TLSv1.1">
<table key="ciphers">
<table>
<elem key="kex_info">ecdh_x25519</elem>
<elem key="name">TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">dh 1024</elem>
<elem key="name">TLS_DHE_RSA_WITH_AES_256_CBC_SHA</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">dh 1024</elem>
<elem key="name">TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">ecdh_x25519</elem>
<elem key="name">TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">dh 1024</elem>
<elem key="name">TLS_DHE_RSA_WITH_AES_128_CBC_SHA</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">dh 1024</elem>
<elem key="name">TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">rsa 1024</elem>
<elem key="name">TLS_RSA_WITH_AES_256_CBC_SHA</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">rsa 1024</elem>
<elem key="name">TLS_RSA_WITH_CAMELLIA_256_CBC_SHA</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">rsa 1024</elem>
<elem key="name">TLS_RSA_WITH_AES_128_CBC_SHA</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">rsa 1024</elem>
<elem key="name">TLS_RSA_WITH_CAMELLIA_128_CBC_SHA</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">dh 1024</elem>
<elem key="name">TLS_DHE_RSA_WITH_SEED_CBC_SHA</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">rsa 1024</elem>
<elem key="name">TLS_RSA_WITH_SEED_CBC_SHA</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">rsa 1024</elem>
<elem key="name">TLS_RSA_WITH_IDEA_CBC_SHA</elem>
<elem key="strength">A</elem>
</table>
</table>
<table key="compressors">
<elem>NULL</elem>
</table>
<elem key="cipher preference">server</elem>
<table key="warnings">
<elem>64-bit block cipher IDEA vulnerable to SWEET32 attack</elem>
<elem>Weak certificate signature: SHA1</elem>
</table>
</table>
<table key="TLSv1.2">
<table key="ciphers">
<table>
<elem key="kex_info">ecdh_x25519</elem>
<elem key="name">TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">dh 1024</elem>
<elem key="name">TLS_DHE_RSA_WITH_AES_256_GCM_SHA384</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">ecdh_x25519</elem>
<elem key="name">TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">dh 1024</elem>
<elem key="name">TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">dh 1024</elem>
<elem key="name">TLS_DHE_RSA_WITH_AES_256_CCM_8</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">dh 1024</elem>
<elem key="name">TLS_DHE_RSA_WITH_AES_256_CCM</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">ecdh_x25519</elem>
<elem key="name">TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">dh 1024</elem>
<elem key="name">TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">ecdh_x25519</elem>
<elem key="name">TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">dh 1024</elem>
<elem key="name">TLS_DHE_RSA_WITH_AES_128_GCM_SHA256</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">dh 1024</elem>
<elem key="name">TLS_DHE_RSA_WITH_AES_128_CCM_8</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">dh 1024</elem>
<elem key="name">TLS_DHE_RSA_WITH_AES_128_CCM</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">ecdh_x25519</elem>
<elem key="name">TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">dh 1024</elem>
<elem key="name">TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">ecdh_x25519</elem>
<elem key="name">TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">dh 1024</elem>
<elem key="name">TLS_DHE_RSA_WITH_AES_256_CBC_SHA256</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">ecdh_x25519</elem>
<elem key="name">TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">dh 1024</elem>
<elem key="name">TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">ecdh_x25519</elem>
<elem key="name">TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">dh 1024</elem>
<elem key="name">TLS_DHE_RSA_WITH_AES_128_CBC_SHA256</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">ecdh_x25519</elem>
<elem key="name">TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">dh 1024</elem>
<elem key="name">TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">ecdh_x25519</elem>
<elem key="name">TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">dh 1024</elem>
<elem key="name">TLS_DHE_RSA_WITH_AES_256_CBC_SHA</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">dh 1024</elem>
<elem key="name">TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">ecdh_x25519</elem>
<elem key="name">TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">dh 1024</elem>
<elem key="name">TLS_DHE_RSA_WITH_AES_128_CBC_SHA</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">dh 1024</elem>
<elem key="name">TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">rsa 1024</elem>
<elem key="name">TLS_RSA_WITH_AES_256_GCM_SHA384</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">rsa 1024</elem>
<elem key="name">TLS_RSA_WITH_AES_256_CCM_8</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">rsa 1024</elem>
<elem key="name">TLS_RSA_WITH_AES_256_CCM</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">rsa 1024</elem>
<elem key="name">TLS_RSA_WITH_ARIA_256_GCM_SHA384</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">rsa 1024</elem>
<elem key="name">TLS_RSA_WITH_AES_128_GCM_SHA256</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">rsa 1024</elem>
<elem key="name">TLS_RSA_WITH_AES_128_CCM_8</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">rsa 1024</elem>
<elem key="name">TLS_RSA_WITH_AES_128_CCM</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">rsa 1024</elem>
<elem key="name">TLS_RSA_WITH_ARIA_128_GCM_SHA256</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">rsa 1024</elem>
<elem key="name">TLS_RSA_WITH_AES_256_CBC_SHA256</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">rsa 1024</elem>
<elem key="name">TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">rsa 1024</elem>
<elem key="name">TLS_RSA_WITH_AES_128_CBC_SHA256</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">rsa 1024</elem>
<elem key="name">TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">rsa 1024</elem>
<elem key="name">TLS_RSA_WITH_AES_256_CBC_SHA</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">rsa 1024</elem>
<elem key="name">TLS_RSA_WITH_CAMELLIA_256_CBC_SHA</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">rsa 1024</elem>
<elem key="name">TLS_RSA_WITH_AES_128_CBC_SHA</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">rsa 1024</elem>
<elem key="name">TLS_RSA_WITH_CAMELLIA_128_CBC_SHA</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">dh 1024</elem>
<elem key="name">TLS_DHE_RSA_WITH_SEED_CBC_SHA</elem>
<elem key="strength">A</elem>
</table>
<table>
<elem key="kex_info">rsa 1024</elem>
<elem key="name">TLS_RSA_WITH_SEED_CBC_SHA</elem>
<elem key="strength">A</elem>
</table>
</table>
<table key="compressors">
<elem>NULL</elem>
</table>
<elem key="cipher preference">server</elem>
<table key="warnings">
<elem>Weak certificate signature: SHA1</elem>
</table>
</table>
<elem key="least strength">A</elem>
</script></port>
</ports>
<times srtt="11044" rttvar="11044" to="100000"/>
</host>
<runstats><finished time="1570044984" timestr="Wed Oct  2 15:36:24 2019" elapsed="15.29" summary="Nmap done at Wed Oct  2 15:36:24 2019; 1 IP address (1 host up) scanned in 15.29 seconds" exit="success"/><hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>"""]

    def test_verify_results(self):
        """
        This method checks whether the collector correctly verifies the command output
        :return:
        """
        self.init_db(load_cipher_suites=True)
        with tempfile.TemporaryDirectory() as temp_dir:
            test_suite = CollectorProducerTestSuite(engine=self._engine,
                                                    arguments={"workspace": self._workspaces[0],
                                                               "output_dir": temp_dir})
            with self._engine.session_scope() as session:
                source = self.create_source(session, source_str=self._collector_name)
                command = self.create_command(session=session,
                                              workspace_str=self._workspaces[0],
                                              command=["nmap", '-p', '443', '192.168.1.1'],
                                              collector_name_str="tlsnmap",
                                              collector_name_type=CollectorType.host_service,
                                              service_port=443,
                                              scope=ScopeType.all)
                command.xml_output = self.get_command_xml_outputs()[0]
                test_suite.verify_results(session=session,
                                          arg_parse_module=self._arg_parse_module,
                                          command=command,
                                          source=source,
                                          report_item=self._report_item)
        with self._engine.session_scope() as session:
            # TlsInfo
            tls_info = session.query(TlsInfo).all()
            results = [item.version_str for item in tls_info]
            results.sort()
            expected_results = ["TLSv1.0", "TLSv1.1", "TLSv1.2"]
            expected_results.sort()
            self.assertListEqual(expected_results, results)
            self.assertEqual("Apache httpd", tls_info[0].service.nmap_product)
            self.assertEqual("2.4.39", tls_info[0].service.nmap_version)
            self.assertEqual("Apache httpd 2.4.39 (Win64) OpenSSL/1.1.1b PHP/7.3.4",
                             tls_info[0].service.nmap_product_version)
            # TlsInfoCipherSuiteMapping
            results = session.query(TlsInfoCipherSuiteMapping).count()
            self.assertEqual(72, results)
