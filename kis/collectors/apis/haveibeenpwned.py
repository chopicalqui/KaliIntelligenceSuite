# -*- coding: utf-8 -*-
"""
This module contains functionality to obtain information from haveibeenpwned.com API.
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
from urllib.parse import quote
from collectors.apis.core import BaseApi
from collectors.apis.core import ApiCollectionFailed
from collectors.core import BaseUtils


class HaveIBeenPwnedBase(BaseApi):
    """
    This class implements the API to collect information from the haveibeenpwned.com API
    """

    def __init__(self, **kwargs):
        super().__init__(filename_template="haveibeenpwned_email_{}",
                         **kwargs)
        self._api_url = None
        self._api_key = self._config.config.get("haveibeenpwned", "api_key")
        self._request_headers["hibp-api-key"] = self._api_key
        self._request_headers["user-agent"] = self._collector_config.default_user_agent

    def collect_api(self,
                    email: str,
                    output_directory: str = None,
                    offset: int = 0,
                    limit: int = 1000) -> None:
        """This method collects information from the API"""
        if not output_directory or not os.path.isdir(output_directory):
            raise NotADirectoryError("output directory '{}' does not exist".format(output_directory))
        if not offset:
            print("[*] querying haveibeenpwned.com API")
        response = self._get_request_info(api_url=self._api_url,
                                          url_extension=quote(email),
                                          params={"truncateResponse": "true"})
        if response.status_code == 200:
            query_results = json.loads(response.content)
            BaseUtils.add_json_results(self._command, query_results)
            self.write_filesystem(query_results=query_results,
                                  item=email,
                                  output_directory=output_directory)
        elif response.status_code == 400:
            raise ApiCollectionFailed("Bad request ({}) - the account does not comply with an acceptable format "
                                      "(i.e. it's an empty string)".format(response.status_code))
        elif response.status_code == 403:
            raise ApiCollectionFailed("Forbidden ({}) - no user agent has been specified "
                                      "in the request".format(response.status_code))
        elif response.status_code == 404:
            raise ApiCollectionFailed("Not found ({}) - the account could not be found and has therefore "
                                      "not been pwned".format(response.status_code))
        elif response.status_code == 429:
            raise ApiCollectionFailed("Too many requests ({}) - the rate limit has been "
                                      "exceeded".format(response.status_code))
        else:
            raise ApiCollectionFailed("failed with status code: {}".format(response.status_code))


class HaveIBeenPwnedBreachedAcccount(HaveIBeenPwnedBase):
    """
    This class implements the API to collect information from the haveibeenpwned.com API
    """
    SOURCE = "haveibeenbreach"
    NAME = "breaches"

    def __init__(self, **kwargs):
        super().__init__(api_name=HaveIBeenPwnedBreachedAcccount.SOURCE, **kwargs)
        self._api_url = self._config.config.get("haveibeenpwned", "api_breachedaccount_url")
        self._api_pasteaccount_url = self._config.config.get("haveibeenpwned", "api_pasteaccount_url")


class HaveIBeenPwnedPasteAcccount(HaveIBeenPwnedBase):
    """
    This class implements the API to collect information from the haveibeenpwned.com API
    """
    SOURCE = "haveibeenpaste"
    NAME = "pastes"

    def __init__(self, **kwargs):
        super().__init__(api_name=HaveIBeenPwnedPasteAcccount.SOURCE, **kwargs)
        self._api_url = self._config.config.get("haveibeenpwned", "api_pasteaccount_url")
