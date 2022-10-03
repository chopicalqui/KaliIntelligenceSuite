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
import os
import sys
import json
import requests
import argparse
import openpyxl
import traceback
from openpyxl.worksheet.table import Table, TableStyleInfo


class CipherSuiteDownload:
    def __init__(self, args: argparse.Namespace):
        self._args = args
        self.config_file_path = os.path.join("..", "kis", "configs", "ciphersuites.json")

    def _save_excel(self, cipher_suites: dict):
        workbook = openpyxl.Workbook()
        worksheet = workbook.active
        worksheet.title = "ciphersuite.info"
        worksheet.append(["Ref.",
                          "Cipher Suite (IANA)",
                          "Cipher Suite (GNU TLS)",
                          "Cipher Suite (OpenSSL)",
                          "Hex Byte 1",
                          "Hex Byte 2",
                          "Protocol Version",
                          "KEX Algorithm",
                          "Auth Algorithm",
                          "Enc Algorithm",
                          "Hash Algorithm",
                          "Security",
                          "TLS Version"])
        i = 1
        for cipher_suite in cipher_suites["ciphersuites"]:
            for iana, items in cipher_suite.items():
                worksheet.append([i,  # Ref.
                                  iana,  # Cipher Suite (IANA)
                                  items["gnutls_name"],  # Cipher Suite (GNU TLS)
                                  items["openssl_name"],  # Cipher Suite (OpenSSL)
                                  items["hex_byte_1"],  # Hex Byte 1
                                  items["hex_byte_2"],  # Hex Byte 2
                                  items["protocol_version"],  # Protocol Version
                                  items["kex_algorithm"],  # KEX Algorithm
                                  items["auth_algorithm"],  # Auth Algorithm
                                  items["enc_algorithm"],  # Enc Algorithm
                                  items["hash_algorithm"],  # Hash Algorithm
                                  items["security"].capitalize(),  # Security
                                  ", ".join(items["tls_version"])])
                i += 1
        dimension = worksheet.calculate_dimension()
        dimension = "A{}:{}".format(1, dimension.split(":")[-1])
        table = Table(displayName="ciphersuite.info", ref=dimension)
        style = TableStyleInfo(name="TableStyleLight8")
        table.tableStyleInfo = style
        worksheet.add_table(table)
        workbook.save(self._args.file)

    def save(self):
        response = requests.get("https://ciphersuite.info/api/cs/")
        response.raise_for_status()
        if response.status_code == 200:
            json_object = json.loads(response.content)
            if self._args.module == "excel":
                self._save_excel(json_object)
                print("excel file '{}' successfully written.".format(self._args.file))
            else:
                with open(self.config_file_path, "w") as file:
                    file.write(json.dumps(json_object, indent=4))
                print("configuration file '{}' successfully updated.".format(downloader))

    def __repr__(self):
        return self.config_file_path

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    sub_parser = parser.add_subparsers(help="List of available download operations.", dest="module")
    excel_parser = sub_parser.add_parser('excel', help='instead of downloading the latest list of cipher suites for KIS,'
                                                       'write them to the given Excel file.')
    excel_parser.add_argument("file",
                              type=str,
                              help="the excel file where the cipher suites shall be stored.")
    args = parser.parse_args()

    try:
        downloader = CipherSuiteDownload(args)
        downloader.save()
    except Exception:
        traceback.print_exc(file=sys.stderr)
