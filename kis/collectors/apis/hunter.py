# -*- coding: utf-8 -*-
"""
This module contains functionality to obtain information from the Hunter.io API.
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


class Hunter(BaseApi):
    """
    This class implements the API to collect information from the Hunter.io API
    """
    SOURCE = "hunter"

    def __init__(self, **kwargs):
        super().__init__(api_name=Hunter.SOURCE,
                         filename_template="hunter_domain_{}",
                         **kwargs)
        self._api_url = self._config.config.get(self._api_name, "api_url")
        self._api_key = self._config.config.get(self._api_name, "api_key")

    def collect_api(self,
                    domain: str,
                    output_directory: str = None,
                    offset: int = 0,
                    limit: int = 1000) -> None:
        """This method collects information from the API"""
        if not output_directory or not os.path.isdir(output_directory):
            raise NotADirectoryError("output directory '{}' does not exist".format(output_directory))
        if not offset:
            print("[*] querying hunger.io API")
        response = self._get_request_info(api_url=self._api_url,
                                          params={"domain": domain,
                                                  "api_key": self._api_key,
                                                  "limit": limit,
                                                  "offset": (offset*limit)})
        if response.status_code == 200:
            query_results = json.loads(response.content)
            BaseUtils.add_json_results(self._command, query_results)
            self.write_filesystem(query_results=query_results,
                                  item=domain,
                                  number=offset,
                                  output_directory=output_directory)
            results = query_results["meta"]["results"]
            offset += 1
            if (offset*limit) <= results:
                self.collect_api(domain=domain,
                                 output_directory=output_directory,
                                 offset=offset,
                                 limit=limit)
        else:
            raise ApiCollectionFailed("failed with status code: {}".format(response.status_code))
