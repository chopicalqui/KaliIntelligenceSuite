# -*- coding: utf-8 -*-
"""
This module contains functionality to obtain information via the viewdns.info web site
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
import json
from collectors.apis.core import ApiCollectionFailed
from collectors.apis.core import BaseApi
from collectors.core import BaseUtils


class ViewDns(BaseApi):
    """This class collects information from viewdns.info"""

    SOURCE_NAME = "viewdns"

    def __init__(self, **args):
        super().__init__(api_name=ViewDns.SOURCE_NAME,
                         filename_template="viewdns.info_domain_{}",
                         **args)

    def collect_api(self, company: str, output_directory: str = None) -> None:
        """
        This method collects information from the host.io API
        :param company: The company to collect information for
        :param output_directory: The directory where the results are stored
        :return:
        """
        if not output_directory or not os.path.isdir(output_directory):
            raise NotADirectoryError("output directory '{}' does not exist".format(output_directory))
        print("[*] querying viewdns.info API")
        response = self._get_request_info(api_url="https://viewdns.info/reversewhois/",
                                          params={"q": company})
        if response.status_code == 200:
            BaseUtils.add_binary_result(self._command, response.content)
            self.write_filesystem(query_results=response.content,
                                  item=company,
                                  output_directory=output_directory)
        else:
            raise ApiCollectionFailed("failed with status code: {}".format(response.status_code))
