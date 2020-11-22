# -*- coding: utf-8 -*-
"""
This module contains functionality to obtain information from the Shodan API.
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

import shodan
import os
from collectors.core import BaseUtils
from collectors.apis.core import BaseApi


class BaseShodan(BaseApi):
    """This class collects information from Shodan"""

    SOURCE_NAME = "shodan"

    def __init__(self, **args):
        super().__init__(api_name=BaseShodan.SOURCE_NAME, **args)
        self._api_key = self._config.config.get(self._api_name, "api_key")


class ShodanSearch(BaseShodan):
    """This class collects information from Shodan"""

    def __init__(self, **args):
        super().__init__(**args)

    def collect_api(self, query: str, output_directory: str = None) -> None:
        """
        This method collects information from the Shodan API
        :param query: The query in Shodan syntax to collect the desired information from Shodan
        :param output_directory: The directory where Shodan results are stored
        :return:
        """
        if not output_directory or not os.path.isdir(output_directory):
            raise NotADirectoryError("output directory '{}' does not exist".format(output_directory))
        print("[*] querying shodan API")
        api = shodan.Shodan(self._api_key)
        query_results = api.search(query)
        BaseUtils.add_json_results(self._command, query_results)
        self.write_filesystem(query_results=query_results, item=query, output_directory=output_directory)


class ShodanHost(BaseShodan):
    """This class collects information from Shodan"""

    def __init__(self, **args):
        super().__init__(filename_template="shodan_host_{}", **args)

    def collect_api(self, host: str, output_directory: str = None) -> None:
        """
        This method collects information from the Shodan API
        :param host: The IP address for which information shall be obtained from Shodan
        :param output_directory: The directory where Shodan results are stored
        :return:
        """
        if not output_directory or not os.path.isdir(output_directory):
            raise NotADirectoryError("output directory '{}' does not exist".format(output_directory))
        print("[*] querying shodan API")
        api = shodan.Shodan(self._api_key)
        query_results = api.host(host)
        BaseUtils.add_json_results(self._command, query_results)
        self.write_filesystem(query_results=query_results, item=host, output_directory=output_directory)


class ShodanNetwork(ShodanSearch):
    """This class collects information from Shodan"""

    def __init__(self, **args):
        super().__init__(filename_template="shodan_network_{}", **args)

    def collect_api(self, query: str, output_directory: str = None) -> None:
        """
        This method collects information from the Shodan API
        :param query: The query for which information shall be obtained from Shodan
        :param output_directory: The directory where Shodan results are stored
        :return:
        """
        super().collect_api(query="net:{}".format(query), output_directory=output_directory)
