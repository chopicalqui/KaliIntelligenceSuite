# -*- coding: utf-8 -*-
"""
This module contains functionality to communicate with the Burp's REST API
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
from urllib.parse import urlparse


class BurpSuiteProfessional(BaseApi):
    """This class communicates with BurpSuite"""

    SOURCE_NAME = "burpsuiteprofessional"

    def __init__(self, **args):
        super().__init__(api_name=BurpSuiteProfessional.SOURCE_NAME,
                         filename_template="burpsuitepro_{}",
                         **args)
        self._api_url = self._config.config.get(self._api_name, "api_url")
        self._api_key = self._config.config.get(self._api_name, "api_key")
        self._api_version = self._config.config.get(self._api_name, "api_version")
        self._resource_pool = self._config.config.get(self._api_name, "resource_pool")
        self._scan_named_configuration = self._config.config.get(self._api_name,
                                                                 "scan_named_configuration").split(os.linesep)


    def collect_api(self, input_file: str, output_directory: str = None) -> None:
        """
        This method collects information from the host.io API
        :param input_file: File containing all URLs to scan
        :param output_directory: The directory where the results are stored
        :return:
        """
        if not output_directory or not os.path.isdir(output_directory):
            raise NotADirectoryError("output directory '{}' does not exist".format(output_directory))
        print("[*] push URLs to Burp Suite Professional")
        base_urls = {}
        final_urls = {}
        with open(input_file, "r") as file:
            urls = file.readlines()
            for item in urls:
                item = item.strip()
                final_urls[item] = None
                url_object = urlparse(item)
                if url_object.scheme and url_object.netloc:
                    base_urls["{}://{}/".format(url_object.scheme, url_object.netloc)] = None
                else:
                    raise NotImplementedError("missing scheme or netloc not implemented")
        json_object = {"urls": list(final_urls.keys()), "scope": {"type": "SimpleScope", "include": []}}
        for key in base_urls.keys():
            json_object["scope"]["include"].append({"rule": key})
        if self._resource_pool:
            json_object["resource_pool"] = self._resource_pool.strip()
        if self._scan_named_configuration:
            json_object["scan_configurations"] = []
            for config in self._scan_named_configuration:
                json_object["scan_configurations"].append({"name": config, "type": "NamedConfiguration"})
        print(json.dumps(json_object))
        response = self._post_request_info(api_url=self._api_url,
                                           url_extension="{}/{}/scan".format(self._api_key, self._api_version),
                                           json=json_object)
        if response.status_code != 201:
            error_message = None
            try:
                json_object = json.loads(response.content)
                if "error" in json_object:
                    error_message = json_object["error"]
            except Exception:
                pass
            if error_message:
                raise ApiCollectionFailed("failed with status code {} "
                                          "and error message: {}".format(response.status_code,
                                                                         error_message))
            else:
                raise ApiCollectionFailed("failed with status code: {}".format(response.status_code))

