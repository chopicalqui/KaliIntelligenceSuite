# -*- coding: utf-8 -*-
"""
run tool kismanage on each identified in-scope second-level domain to identify relationships to other second-level
domains via host.io. depending on the number of domains in the current workspace, it might be desired to limit the
number of OS commands by using the optional argument --filter
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

import logging
from database.model import Source
from database.model import Command
from collectors.os.core import PopenCommand
from collectors.core import JsonUtils
from collectors.os.modules.osint.core import BaseKisImportDomain
from collectors.os.modules.core import DomainCollector
from collectors.apis.hostio import HostIo
from view.core import ReportItem
from sqlalchemy.orm.session import Session


logger = logging.getLogger('hostio')


class CollectorClass(BaseKisImportDomain, DomainCollector):
    """This class implements a collector module that is automatically incorporated into the application."""

    def __init__(self, **kwargs):
        super().__init__(priority=127,
                         timeout=0,
                         argument_name="--hostio",
                         source=HostIo.SOURCE_NAME,
                         delay_min=1,
                         **kwargs)
        self._json_utils = JsonUtils()

    @staticmethod
    def get_argparse_arguments():
        return {"help": __doc__, "action": "store_true"}

    def api_credentials_available(self) -> bool:
        """
        This method shall be implemented by sub classes. They should verify whether their API keys are set in the
        configuration file
        :return: Return true if API credentials are set, else false
        """
        return self._api_config.config.get("host.io", "api_url") and \
               self._api_config.config.get("host.io", "api_key") and \
               self._api_config.config.get("host.io", "api_limit")

    def _add_ipv4_address(self,
                          session: Session,
                          json_object: dict,
                          path: str,
                          command: Command,
                          source: Source,
                          report_item: ReportItem) -> None:
        value = self._json_utils.get_attribute_value(json_object, path)
        if value:
            if isinstance(value, list):
                for item in value:
                    host = self.add_host(session=session,
                                         command=command,
                                         address=item,
                                         source=source,
                                         report_item=report_item)
                    if not host:
                        logger.warning("could not add host name '{}' to database due to invalid format".format(item))
            elif isinstance(value, str):
                host = self.add_host(session=session,
                                     command=command,
                                     address=value,
                                     source=source,
                                     report_item=report_item)
                if not host:
                    logger.warning("could not add host name '{}' to database due to invalid format".format(value))
            else:
                raise NotImplementedError("case not implemented")

    def _add_host_name(self,
                       session: Session,
                       json_object: dict,
                       path: str,
                       command: Command,
                       source: Source,
                       report_item: ReportItem) -> None:
        value = self._json_utils.get_attribute_value(json_object, path)
        if value:
            if isinstance(value, list):
                new_source = self.add_source(session=session, name="{}_{}".format(source.name, path))
                for item in value:
                    host_name = self.add_host_name(session=session,
                                                   command=command,
                                                   host_name=item,
                                                   source=new_source,
                                                   verify=True,
                                                   report_item=report_item)
                    if not host_name:
                        logger.warning("could not add host name '{}' to database due to invalid format".format(item))
            elif isinstance(value, str):
                new_source = self.add_source(session=session, name="{}_{}".format(source.name, path))
                host_name = self.add_host_name(session=session,
                                               command=command,
                                               host_name=value,
                                               source=new_source,
                                               verify=True,
                                               report_item=report_item)
                if not host_name:
                    logger.warning("could not add host name '{}' to database due to invalid format".format(value))
            else:
                raise NotImplementedError("case not implemented")

    def verify_results(self, session: Session,
                       command: Command,
                       source: Source,
                       report_item: ReportItem,
                       process: PopenCommand = None, **kwargs) -> None:
        """This method analyses the results of the command execution.

        After the execution, this method checks the OS command's results to determine the command's execution status as
        well as existing vulnerabilities (e.g. weak login credentials, NULL sessions, hidden Web folders). The
        stores the output in table command. In addition, the collector might add derived information to other tables as
        well.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param command: The command instance that contains the results of the command execution
        :param source: The source object of the current collector
        :param report_item: Item that can be used for reporting potential findings in the UI
        :param process: The PopenCommand object that executed the given result. This object holds stderr, stdout, return
        code etc.
        """
        if command.return_code > 0:
            self._set_execution_failed(session=session, command=command)
            return
        for json_object in command.json_output:
            if "domain" in json_object and json_object["domain"] == command.host_name.full_name:
                if "web" in json_object:
                    item = json_object["web"]
                    self._add_host_name(session=session,
                                        json_object=item,
                                        path="redirect",
                                        command=command,
                                        source=source,
                                        report_item=report_item)
                if "dns" in json_object:
                    item = json_object["dns"]
                    # add A records
                    self._add_ipv4_address(session=session,
                                           json_object=item,
                                           path="a",
                                           command=command,
                                           source=source,
                                           report_item=report_item)
                    # add MX records
                    self._add_host_name(session=session,
                                        json_object=item,
                                        path="mx",
                                        command=command,
                                        source=source,
                                        report_item=report_item)
                    # add NS records
                    self._add_host_name(session=session,
                                        json_object=item,
                                        path="ns",
                                        command=command,
                                        source=source,
                                        report_item=report_item)
                if "domains" in json_object:
                    item = json_object["domains"]
                    # add A records
                    self._add_ipv4_address(session=session,
                                           json_object=item,
                                           path="ip",
                                           command=command,
                                           source=source,
                                           report_item=report_item)
                    self._add_host_name(session=session,
                                        json_object=item,
                                        path="domains",
                                        command=command,
                                        source=source,
                                        report_item=report_item)
                if "redirects" in json_object:
                    item = json_object["redirects"]
                    self._add_host_name(session=session,
                                        json_object=item,
                                        path="domains",
                                        command=command,
                                        source=source,
                                        report_item=report_item)
                if "backlinks" in json_object:
                    item = json_object["backlinks"]
                    self._add_host_name(session=session,
                                        json_object=item,
                                        path="domains",
                                        command=command,
                                        source=source,
                                        report_item=report_item)
                if "email" in json_object:
                    item = json_object["email"]
                    self._add_host_name(session=session,
                                        json_object=item,
                                        path="domains",
                                        command=command,
                                        source=source,
                                        report_item=report_item)
                if "adsense" in json_object:
                    item = json_object["adsense"]
                    self._add_host_name(session=session,
                                        json_object=item,
                                        path="domains",
                                        command=command,
                                        source=source,
                                        report_item=report_item)
                if "googleanalytics" in json_object:
                    item = json_object["googleanalytics"]
                    self._add_host_name(session=session,
                                        json_object=item,
                                        path="domains",
                                        command=command,
                                        source=source,
                                        report_item=report_item)
