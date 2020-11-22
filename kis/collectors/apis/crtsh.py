# -*- coding: utf-8 -*-
"""
This module contains functionality to obtain sub-domains via crt.sh.
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
from collectors.apis.core import ApiCollectionFailed
from collectors.apis.core import BaseApi
from collectors.core import BaseUtils
from database.model import FileType
from collectors.os.modules.core import Delay
from collectors.core import DomainUtils
from bs4 import BeautifulSoup


class CrtshBase(BaseApi):
    """This class collects information from crt.sh"""

    SOURCE_NAME = "crtsh"

    def __init__(self, **args):
        super().__init__(api_name=CrtshBase.SOURCE_NAME,
                         **args)

    def collect_api(self, item: str, output_directory: str = None) -> None:
        """
        This method collects information from the host.io API
        :param item: The item to collect information for
        :param output_directory: The directory where the results are stored
        :return:
        """
        if not output_directory or not os.path.isdir(output_directory):
            raise NotADirectoryError("output directory '{}' does not exist".format(output_directory))
        print("[*] querying crt.sh")
        response = self._get_request_info(api_url="https://crt.sh/",
                                          params={"q": "%.{}".format(item)})
        if response.status_code == 200:
            BaseUtils.add_binary_result(self._command, response.content)
            self.write_filesystem(query_results=response.content,
                                  item=item,
                                  output_directory=output_directory)
        else:
            raise ApiCollectionFailed("failed with status code: {}".format(response.status_code))


class CrtshDomain(CrtshBase):
    """This class collects information from crt.sh"""

    def __init__(self, **args):
        super().__init__(filename_template="crtsh.com_domain_{}", **args)

    def collect_api(self, item: str, output_directory: str = None) -> None:
        """
        This method collects information from the host.io API
        :param item: The item to collect information for
        :param output_directory: The directory where the results are stored
        :return:
        """
        if not output_directory or not os.path.isdir(output_directory):
            raise NotADirectoryError("output directory '{}' does not exist".format(output_directory))
        print("[*] querying crt.sh")
        response = self._get_request_info(api_url="https://crt.sh/",
                                          params={"q": "%.{}".format(item)})
        if response.status_code == 200:
            BaseUtils.add_binary_result(self._command, response.content)
            self.write_filesystem(query_results=response.content,
                                  item=item,
                                  output_directory=output_directory)
        else:
            raise ApiCollectionFailed("failed with status code: {}".format(response.status_code))


class CrtshCompany(CrtshBase):
    """This class collects information from crt.sh"""

    def __init__(self, **args):
        super().__init__(filename_template="crtsh.com_company_{}", **args)
        self._delay = Delay(delay_min=2, delay_max=5)
        self._domain_utils = DomainUtils()

    def _parse_table(self, content: str):
        soup = BeautifulSoup(content, "html.parser")
        result = []
        for table in soup.find_all("table"):
            result.extend([item.get_text() for item in table.find_all("a") if item["href"].startswith("?id=")])
        for id in result:
            response = self._get_request_info(api_url="https://crt.sh/", params={"d": id})
            if response.status_code == 200:
                file_name = "{}_{}.pem".format(self._command.file_name, id)
                self._domain_utils.add_file_content(session=self._session,
                                                    workspace=self._command.workspace,
                                                    command=self._command,
                                                    file_name=file_name,
                                                    file_type=FileType.certificate,
                                                    content=response.content)
                self._session.commit()
            else:
                print("request failed with status code {}".format(response.status_code))
            self._delay.sleep()

    def collect_api(self, item: str, output_directory: str = None) -> None:
        """
        This method collects information from the host.io API
        :param item: The item to collect information for
        :param output_directory: The directory where the results are stored
        :return:
        """
        if not output_directory or not os.path.isdir(output_directory):
            raise NotADirectoryError("output directory '{}' does not exist".format(output_directory))
        print("[*] querying crt.sh")
        response = self._get_request_info(api_url="https://crt.sh/",
                                          params={"O": item,
                                                  "exclude": "expired"})
        if response.status_code == 200:
            BaseUtils.add_binary_result(self._command, response.content)
            self.write_filesystem(query_results=response.content,
                                  item=item,
                                  output_directory=output_directory)
            self._parse_table(response.content)
        else:
            raise ApiCollectionFailed("failed with status code: {}".format(response.status_code))
