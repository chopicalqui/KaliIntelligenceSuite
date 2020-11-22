#!/usr/bin/python3

"""
this script loads all cipher suites from ciphersuite.info
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

import requests
import argparse
import json
import sys
import os
sys.path.append(os.path.abspath("../kis"))
from openpyxl import Workbook
from database.model import CipherSuiteSecurity


class CipherSuiteDownload:
    def __init__(self, excel_file: str):
        self._excel_file = excel_file
        self._header = ["ref",
                        "security",
                        "iana_name",
                        "gnutls_name",
                        "openssl_name",
                        "hex_byte_1",
                        "hex_byte_2",
                        "protocol_version",
                        "kex_algorithm",
                        "auth_algorithm",
                        "enc_algorithm",
                        "hash_algorithm",
                        "tls_version"]
        self._workbook = Workbook()
        self._worksheet = self._workbook.active
        self._worksheet.title = "Cipher Suites"
        self._worksheet.append(self._header)

    def _download(self) -> None:
        ref = 0
        for security in CipherSuiteSecurity.__members__:
            response = requests.get("https://ciphersuite.info/api/cs/security/{}/".format(security))
            if response.status_code == 200:
                json_object = json.loads(response.content)
                if "ciphersuites" in json_object:
                    for ciphersuite in json_object["ciphersuites"]:
                        for iana_name in ciphersuite.keys():
                            ref += 1
                            row_dict = {}
                            row_dict["ref"] = ref
                            row_dict["iana_name"] = iana_name
                            for item in self._header:
                                if item == "tls_version":
                                    row_dict[item] = ", ".join(ciphersuite[iana_name][item])
                                elif item in ciphersuite[iana_name]:
                                    row_dict[item] = ciphersuite[iana_name][item]
                            row = []
                            for item in self._header:
                                row.append(row_dict[item])
                            if row:
                                self._worksheet.append(row)

    def save(self):
        self._download()
        self._workbook.save(self._excel_file)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--excel', type=str, required=True, help='export cipher suite information to Excel file')
    args = parser.parse_args()
    if len(sys.argv) <= 1:
        parser.print_help()
        sys.exit(1)
    elif args.excel:
        CipherSuiteDownload(args.excel).save()
