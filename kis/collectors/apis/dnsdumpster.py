# -*- coding: utf-8 -*-
"""
This module contains functionality to obtain information from the DNSDumpster API.
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
from collectors.core import BaseUtils
from collectors.apis.core import BaseApi
from dnsdumpster.DNSDumpsterAPI import DNSDumpsterAPI


class DnsDumpster(BaseApi):
    """This class collects information from Shodan"""

    SOURCE_NAME = "dnsdumpster"

    def __init__(self, **args):
        super().__init__(api_name=DnsDumpster.SOURCE_NAME,
                         filename_template="dnsdumpster_domain_{}",
                         **args)

    def collect_api(self, domain: str, output_directory: str=None) -> None:
        """
        This method collects information from the Shodan API
        :param domain: The query in Shodan syntax to collect the desired information from Shodan
        :param output_directory: The directory where Shodan results are stored
        :return:
        """
        if not output_directory or not os.path.isdir(output_directory):
            raise NotADirectoryError("output directory '{}' does not exist".format(output_directory))
        print("[*] querying dnsdumpster API")
        query_results = DNSDumpsterAPI({}).search(domain)
        if len(query_results) > 0:
            if "image_data" in query_results and isinstance(query_results["image_data"], bytes):
                query_results["image_data"] = query_results["image_data"].decode("utf-8")
            if "xls_data" in query_results and isinstance(query_results["xls_data"], bytes):
                query_results["xls_data"] = query_results["xls_data"].decode("utf-8")
            BaseUtils.add_json_results(self._command, query_results)
            self.write_filesystem(query_results=query_results, item=domain, output_directory=output_directory)
        else:
            print("No results found")
