# -*- coding: utf-8 -*-
"""This module implements core functionality which can be used by modules that obtain information from APIs."""

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
import requests
import json
import re
import ast
from typing import Dict
from typing import List
from database.model import Workspace
from database.model import Command
from collectors.core import DomainUtils
from collectors.core import IpUtils
from configs.config import ApiConfig
from configs.config import Collector as CollectorConfig
from sqlalchemy.orm.session import Session


class ApiCollectionFailed(Exception):
    """This exception shall be thrown, if collection fails"""
    def __init__(self, message: str):
        super().__init__(message)


class ApiCAnalysisFailed(Exception):
    """This exception shall be thrown, if analysis fails"""
    def __init__(self, message: str):
        super().__init__(message)


class BaseApi:
    """This class implements all base functionality for APIs"""

    def __init__(self, api_name: str,
                 workspace: Workspace,
                 session: Session,
                 filename_template: str,
                 command_id: int = None,
                 request_headers: dict = {},
                 **args):
        self._config = ApiConfig()
        self._collector_config = CollectorConfig()
        self._api_name = api_name
        self._domain_intel = DomainUtils()
        self._ipv4_utils = IpUtils()
        self._workspace = workspace
        self._session = session
        self._filename_template = filename_template
        self._args = args
        self._request_headers = request_headers
        self._request_headers["User-agent"] = self._collector_config.default_user_agent
        self._command = session.query(Command).filter_by(id=command_id).one_or_none() if command_id else None

    @staticmethod
    def get_json_attribute(json: dict, name: str):
        """Returns the given JSON attribute and None if it does not exist"""
        rvalue = json[name] if name in json else None
        rvalue = rvalue if rvalue != "" else None
        return rvalue

    @staticmethod
    def create_host_directory(*args):
        directory = os.path.join(*args)
        if not os.path.isdir(directory):
            os.makedirs(directory)
        return directory

    def log_item(self, type: str, item: str) -> None:
        """
        This method writes the given parameters to standard output.
        :return:
        """
        print("[I]  found {} '{}'".format(type, item))

    def write_filesystem(self, query_results: dict,
                         item: str,
                         output_directory: str = None,
                         number: int = 0) -> None:
        """This method writes the API results to the filesystem"""
        if output_directory:
            file_name = self._filename_template.format(re.sub("[:/\"''#@$%^&*(), \|\{\}\[\]]", "-", item))
            if number:
                file_name += "_{:03d}".format(number)
            file_name += ".json"
            with open(os.path.join(output_directory, file_name), "w") as f:
                try:
                    f.write(json.dumps(query_results, indent=4))
                except Exception:
                    f.write(str(query_results))

    def collect_filesystem(self, json_files: List[str], output_directory: str = None, **args) -> None:
        """
        This method parses the given files and imports the information into the database.
        :param json_files: The file containing the Censys results to be analyzed and imported
        :return:
        """
        for file in json_files:
            if not os.path.isfile(file):
                raise FileNotFoundError("The file '{}' does not exist!".format(file))
            with open(file, "r") as f:
                print("[*] importing {} file: {}".format(self._api_name, file))
                text = f.read()
                query_results = json.JSONDecoder().decode(text)
                self.analyse(query_results=query_results, file_name=file, output_directory=output_directory)

    def _get_request_info(self,
                          api_url: str,
                          url_extension: str = None,
                          params: Dict[str, str] = {}) -> requests.Response:
        """This method requests information via the given API function"""
        proxy_settings = self._config.proxy_settings
        verify = proxy_settings is None
        url = "{}/{}".format(api_url if api_url[-1] != "/" else api_url[:-1],
                             url_extension if url_extension else "") if url_extension else api_url
        return requests.get(url, headers=self._request_headers, params=params, proxies=proxy_settings, verify=verify)

    def _post_request_info(self,
                           api_url: str,
                           url_extension: str = None,
                           params: Dict[str, str] = {},
                           json: dict = {}) -> requests.Response:
        """This method requests information via the given API function"""
        proxy_settings = self._config.proxy_settings
        verify = proxy_settings is None
        url = "{}/{}".format(api_url if api_url[-1] != "/" else api_url[:-1],
                             url_extension if url_extension else "")
        return requests.post(url,
                             headers=self._request_headers,
                             data=params,
                             json=json,
                             proxies=proxy_settings,
                             verify=verify)

    def collect_api(self, **args) -> int:
        """This method collects information from the API"""
        raise NotImplementedError("This method is not implemented.")

    def analyse(self, **args) -> None:
        """This method analyses the collected information and updates the database accordingly"""
        raise NotImplementedError("This method is not implemented.")
