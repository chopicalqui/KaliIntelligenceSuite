# -*- coding: utf-8 -*-
"""
This module contains functionality to obtain relationship information via the host.io API.
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
from collectors.apis.core import BaseApi
from collectors.apis.core import ApiCollectionFailed
from collectors.core import BaseUtils


class HostIo(BaseApi):
    """This class collects information from host.io"""

    SOURCE_NAME = "host.io"

    def __init__(self, **args):
        super().__init__(api_name=HostIo.SOURCE_NAME,
                         filename_template="host.io_domain_{}",
                         **args)
        self._api_url = self._config.config.get(self._api_name, "api_url")
        self._api_key = self._config.config.get(self._api_name, "api_key")
        self._api_limit = self._config.config.get(self._api_name, "api_limit")

    def collect_api(self, domain: str, output_directory: str = None) -> None:
        """
        This method collects information from the host.io API
        :param domain: The domain to collect information for
        :param output_directory: The directory where the results are stored
        :return:
        """
        if not output_directory or not os.path.isdir(output_directory):
            raise NotADirectoryError("output directory '{}' does not exist".format(output_directory))
        print("[*] querying host.io API")
        url = self._api_url if self._api_url[-1] != "/" else self._api_url[:-1]
        url += "/{}".format(domain)
        response = self._get_request_info(api_url=url,
                                          params={"limit": self._api_limit,
                                                  "token": self._api_key})
        if response.status_code == 200:
            query_results = json.loads(response.content)
            BaseUtils.add_json_results(self._command, query_results)
            self.write_filesystem(query_results=query_results,
                                  item=domain,
                                  output_directory=output_directory)
        else:
            raise ApiCollectionFailed("failed with status code: {}".format(response.status_code))
