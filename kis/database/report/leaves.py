# -*- coding: utf-8 -*-
"""
This module prints all data stored in all leaf nodes of JSON and XML objects.
"""

__author__ = "Lukas Reiter"
__license__ = "GPL v3.0"
__copyright__ = """Copyright 2022 Lukas Reiter

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
import re
import enum
import argparse
from typing import List
from database.model import Host
from database.model import Command
from database.model import HostName
from database.model import DomainName
from database.model import CollectorType
from database.model import ReportScopeType
from database.model import ReportVisibility
from database.report.core import BaseReport
from sqlalchemy import or_
from sqlalchemy.sql.expression import func
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import ParseError


class LeafType(enum.Enum):
    value = enum.auto()
    attribute = enum.auto()


class StatisticData:
    HEADER = ["Workspace",
              "Type",
              "Target Name",
              "Collector",
              "Command Status",
              "Full Path",
              "Leaf Name",
              "Leaf Type",
              "Depth",
              "Example Value",
              "Occurrences",
              "Command ID"]

    def __init__(self,
                 command: Command,
                 object_type: str,
                 full_path: str,
                 example_value: object,
                 command_id: int,
                 leaf_type: LeafType = None,
                 depth: int = None):
        path_items = full_path.split("/")
        self.object_type = object_type
        self.workspace = command.workspace.name
        self.target_name = command.target_name
        self.collector_name = command.collector_name.name
        self.command_status = command.status_str
        self.full_path = full_path
        self.leaf_type = leaf_type if leaf_type else LeafType.value
        self.leaf_name = path_items[-1],
        self.depth = depth if depth is not None else len(path_items) - 1,
        self.example_value = "\\n".join(str(example_value).split(os.linesep))
        self.command_id = command_id
        self.occurrences = 1

    @property
    def leaf_type_str(self):
        return self.leaf_type.name

    def get_row(self):
        result = [self.workspace,
                  self.object_type,
                  self.target_name,
                  self.collector_name,
                  self.command_status,
                  self.full_path,
                  self.leaf_name[0],
                  self.leaf_type_str,
                  self.depth[0],
                  self.example_value if self.example_value else "",
                  self.occurrences,
                  self.command_id]
        return result

    def get_key(self):
        return "{} {} {} {} {} {}".format(self.workspace,
                                          self.object_type,
                                          self.target_name,
                                          self.collector_name,
                                          self.full_path,
                                          self.leaf_type_str)


class ReportClass(BaseReport):
    """
    this module prints all data stored in all leaf nodes of JSON and XML objects. this report is usually used to
    get an overview about unique data stored in JSON and XML objects to improve collectors.
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(name="Leaf Data",
                         title="Overview Data Stored in JSON and XML Objects",
                         description="This sheet provides an overview about all data stored in all leaf nodes of JSON "
                                     "and XML objects.",
                         **kwargs)

    @staticmethod
    def get_add_argparse_arguments(parser: argparse.ArgumentParser):
        """
        This method adds the report's specific command line arguments.
        """
        # setup domain parser
        parser.add_argument("-w", "--workspaces",
                            metavar="WORKSPACE",
                            help="query the given workspaces",
                            nargs="+",
                            type=str)
        parser.add_argument('--csv',
                            default=True,
                            action='store_true',
                            help='returns gathered information in csv format')
        parser.add_argument('--filter', metavar='DOMAIN|HOSTNAME|IP|NETWORK|EMAIL', type=str, nargs='*',
                            help='list of second-level domains (e.g., megacorpone.com), host names '
                                 '(e.g., www.megacorpone.com), IP addresses (e.g., 192.168.1.1), networks (e.g., '
                                 '192.168.0.0/24), or email addresses (e.g., test@megacorpone.com) whose '
                                 'information shall be returned. per default, mentioned items are excluded. add + '
                                 'in front of each item (e.g., +192.168.0.1) to return only these items')
        parser.add_argument('--scope', choices=[item.name for item in ReportScopeType],
                            help='return only second-level domains that are in scope (within) or out of scope '
                                 '(outside). per default, all information is returned')
        parser.add_argument('--visibility', choices=[item.name for item in ReportVisibility],
                            help='return only relevant (relevant) or potentially irrelevant (irrelevant) '
                                 'information (e.g., executed commands that did not return any information) in text '
                                 'output (argument --text). per default, all information is returned')
        parser.add_argument('-X', '--exclude', metavar='COLLECTOR', type=str, nargs='+', default=[],
                            help='list of collector names (e.g., dnshost) whose outputs should not be returned in '
                                 'text mode (see argument --text). use argument value "all" to exclude all '
                                 'collectors. per default, no collectors are excluded')
        parser.add_argument('-I', '--include', metavar='COLLECTOR', type=str, nargs='+', default=[],
                            help='list of collector names whose outputs should be returned in text mode (see '
                                 'argument --text). per default, all collector information is returned')

    def _filter_csv(self, command: Command) -> bool:
        """
        Method determines whether the given item shall be included into the report
        """
        return command.is_processable(included_items=self._included_items,
                                      excluded_items=self._excluded_items,
                                      exclude_collectors=self._excluded_collectors,
                                      include_collectors=self._included_collectors,
                                      scope=self._scope)

    def _filter(self, item: object) -> bool:
        """
        Method determines whether the given item shall be included into the report
        """
        if isinstance(item, DomainName):
            result = item.is_processable(included_items=self._included_items,
                                         excluded_items=self._excluded_items,
                                         scope=self._scope,
                                         include_ip_address=True)
        elif isinstance(item, HostName):
            result = item.is_processable(included_items=self._included_items,
                                         excluded_items=self._excluded_items,
                                         collector_type=CollectorType.domain,
                                         scope=self._scope,
                                         include_ip_address=True)
        elif isinstance(item, Host):
            result = item.is_processable(included_items=self._included_items,
                                         excluded_items=self._excluded_items,
                                         scope=self._scope,
                                         include_host_names=True)
        else:
            result = item.is_processable(included_items=self._included_items,
                                         excluded_items=self._excluded_items,
                                         scope=self._scope)
        return result

    def _get_json_summary(self,
                          content: object,
                          command: Command,
                          deduplication: dict = {},
                          path: str = "/",
                          depth: int = 0):
        """
        This method recursively parses the given JSON object tag and returns the results in a two-dimensional list.
        """
        result = []
        if isinstance(content, dict):
            for key, value in content.items():
                result += self._get_json_summary(content=value,
                                                 command=command,
                                                 path=os.path.join(path, key),
                                                 deduplication=deduplication,
                                                 depth=depth + 1)
        elif isinstance(content, list):
            for item in content:
                result += self._get_json_summary(content=item,
                                                 command=command,
                                                 path=path,
                                                 deduplication=deduplication,
                                                 depth=depth + 1)
        else:
            item = StatisticData(command=command,
                                 object_type="JSON",
                                 full_path=path,
                                 example_value=content,
                                 command_id=command.id,
                                 depth=depth + 1)
            item_str = item.get_key()
            if item_str not in deduplication:
                deduplication[item_str] = item
            else:
                deduplication[item_str].occurrences += 1
        if depth == 0:
            result = list(deduplication.values())
        return result

    def _add_xml_statisitics(self, deduplication: dict, item: StatisticData):
        item_str = item.get_key()
        if item_str not in deduplication:
            deduplication[item_str] = item
        else:
            deduplication[item_str].occurrences += 1

    def _get_xml_summary(self,
                         xml_tag: ET,
                         command: Command,
                         deduplication: dict = {},
                         path: str = "/",
                         depth: int = 0):
        """
        This method recursively parses the given XML tag and returns the results in a two-dimensional list.
        """
        result = []
        tag_name = re.sub("^\{http://.*?\}", "", xml_tag.tag)
        new_path = os.path.join(path, tag_name)
        if len(list(xml_tag)) == 0:
            item = StatisticData(command=command,
                                 object_type="XML",
                                 full_path=new_path,
                                 leaf_type=LeafType.value,
                                 example_value=xml_tag.text,
                                 command_id=command.id,
                                 depth=depth + 1)
            self._add_xml_statisitics(deduplication, item)
            for attribute in xml_tag.items():
                item = StatisticData(command=command,
                                     object_type="XML",
                                     full_path="{}/@{}".format(new_path, attribute[0]),
                                     leaf_type=LeafType.attribute,
                                     example_value=attribute[1],
                                     command_id=command.id,
                                     depth=depth + 1)
                self._add_xml_statisitics(deduplication, item)
        else:
            for item in list(xml_tag):
                self._get_xml_summary(item, command, deduplication, new_path, depth + 1)
        if depth == 0:
            result = list(deduplication.values())
        return result

    def get_csv(self) -> List[List[str]]:
        """
        This method returns all information as CSV.
        :return:
        """
        result = [StatisticData.HEADER]
        workspace_ids = [item.id for item in self._workspaces]
        for command in self._session.query(Command) \
                .filter(Command.workspace_id.in_(workspace_ids)) \
                .filter(or_(Command.xml_output.is_not(None),
                            func.array_length(Command.json_output, 1) > 0)).all():
            json_deduplication = {}
            xml_deduplication = {}
            if self._filter_csv(command):
                if command.xml_output:
                    try:
                        xml_tag = ET.fromstring(command.xml_output)
                        result += [item.get_row() for item in self._get_xml_summary(xml_tag=xml_tag,
                                                                                    command=command,
                                                                                    deduplication=xml_deduplication)]
                    except ParseError:
                        pass
                for json_object in command.json_output:
                    result += [item.get_row() for item in self._get_json_summary(content=json_object,
                                                                                 command=command,
                                                                                 deduplication=json_deduplication)]
        return result
