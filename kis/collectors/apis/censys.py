# -*- coding: utf-8 -*-
"""
This module contains functionality to obtain information from the Censys API.
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

import censys.ipv4
import censys.certificates
import os
from collectors.apis.core import BaseApi
from collectors.core import BaseUtils


class CensysIpv4(BaseApi):
    """This class collects information from Censys Host API"""
    SOURCE = "censys"

    def __init__(self, **args):
        super().__init__(filename_template="censys_ipv4_{}", api_name=CensysIpv4.SOURCE, **args)
        self._api_uid = self._config.config.get(self._api_name, "api_uid")
        self._api_key = self._config.config.get(self._api_name, "api_key")

    def collect_api(self, query: str, output_directory: str=None) -> None:
        """
        This method collects information from the Censys IPv4 API
        :param query: The query in Censys syntax to collect the desired information from Censys
        :param output_directory: The directory where Censys results are stored
        :return:
        """
        query_results = []
        if not output_directory or not os.path.isdir(output_directory):
            raise NotADirectoryError("output directory '{}' does not exist".format(output_directory))
        print("[*] querying censys API")
        api = censys.ipv4.CensysIPv4(api_id=self._api_uid, api_secret=self._api_key)
        try:
            for overview in api.search(query, fields=["ip"]):
                details = api.view(overview["ip"])
                query_results.append(details)
        except Exception as ex:
            print("  [E] The following error occurred while searching the censys API: {}".format(ex))
        BaseUtils.add_json_results(self._command, query_results)
        self.write_filesystem(query_results=query_results, item=query, output_directory=output_directory)


class CensysCertificate(BaseApi):
    """
    This class collects information from Censys Certificate API
    """
    SOURCE = "censys"

    def __init__(self, **args):
        super().__init__(filename_template="censys_cert_{}", api_name=CensysCertificate.SOURCE, **args)
        self._api_uid = self._config.config.get(self._api_name, "api_uid")
        self._api_key = self._config.config.get(self._api_name, "api_key")

    def collect_api(self, domain: str, output_directory: str=None) -> None:
        """
        This method collects information from the Censys Certificate API
        :param domain: The query in Censys syntax to collect the desired information from Censys
        :param output_directory: The directory where Censys results are stored
        :return:
        """
        query_results = []
        print("[*] querying censys API")
        api = censys.certificates.CensysCertificates(api_id=self._api_uid, api_secret=self._api_key)
        try:
            for overview in api.search("parsed.names.raw:{}".format(domain), fields=["parsed.fingerprint_sha256"]):
                details = api.view(overview["parsed.fingerprint_sha256"])
                query_results.append({overview["parsed.fingerprint_sha256"]: details})
        except Exception as ex:
            print("[E]   the following error occurred while searching the censys API: {}".format(ex))
        BaseUtils.add_json_results(self._command, query_results)
        self.write_filesystem(query_results=query_results, item=domain, output_directory=output_directory)
