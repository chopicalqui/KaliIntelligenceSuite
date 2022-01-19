# -*- coding: utf-8 -*-
"""This module allows querying information about collected files (e.g., raw scan results, certificates, etc.)."""

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
import sys
import json
import argparse
from database.model import FileType
from database.model import CommandFileMapping
from typing import List
from typing import Dict
from database.model import Command
from database.model import ReportScopeType
from database.report.core import BaseReport


class ReportClass(BaseReport):
    """
    this module allows querying information about collected files (e.g., raw scan results, certificates, etc.)
    """

    def __init__(self, args, **kwargs) -> None:
        super().__init__(args=args,
                         name="file info",
                         title="Overview of Collected Files",
                         description="The table provides an overview of all collected files (e.g., certificates or raw "
                                     "outputs of certain collectors). Note that file types (see column 'File Type') "
                                     "text, json, and xml are usually the raw outputs of the executed operating "
                                     "systems commands. Finally, file type certificate are the raw certificates files "
                                     "(e.g., PEM format) that were collected by tools like Nmap, Sslyze, OpenSSL, or "
                                     "Sslscan. The command kisreport allows exporting these files via the positional "
                                     "argument file.",
                         **kwargs)
        if "type" in args:
            if "all" in args.type:
                self._file_types = [FileType[item.name] for item in FileType]
            else:
                self._file_types = [FileType[item] for item in args.type]
        else:
            self._file_types = []

    @staticmethod
    def get_add_argparse_arguments(parser_file: argparse.ArgumentParser):
        """
        This method adds the report's specific command line arguments.
        """
        # setup file parser
        parser_file.add_argument("-w", "--workspaces",
                                 metavar="WORKSPACE",
                                 help="query the given workspaces",
                                 nargs="+",
                                 type=str)
        parser_file_group = parser_file.add_mutually_exclusive_group()
        parser_file_group.add_argument('--csv', default=True,
                                       action='store_true',
                                       help='returns gathered information in csv format')
        parser_file_group.add_argument('-o', '--export-path',
                                       type=str,
                                       metavar="DIR",
                                       help='exports files to output directory DIR')
        parser_file.add_argument('--type',
                                 choices=[item.name for item in FileType] + ["all"],
                                 default="all",
                                 nargs='+',
                                 help='return only files of type TYPE (e.g., screenshot or certificate). file types json, '
                                      'xml, binary, or text contain the raw scan results returned by the respective '
                                      'collector command')
        parser_file.add_argument('--filter', metavar='DOMAIN|HOSTNAME|IP|NETWORK|EMAIL', type=str, nargs='*',
                                 help='list of second-level domains (e.g., megacorpone.com), host names '
                                      '(e.g., www.megacorpone.com), IP addresses (e.g., 192.168.1.1), networks (e.g., '
                                      '192.168.0.0/24), or email addresses (e.g., test@megacorpone.com) whose '
                                      'information shall be returned. per default, mentioned items are excluded. add + '
                                      'in front of each item (e.g., +192.168.0.1) to return only these items')
        parser_file.add_argument('--scope', choices=[item.name for item in ReportScopeType],
                                 help='return only in scope (within) or out of scope (outside) items. per default, '
                                      'all information is returned')
        parser_file.add_argument('-X', '--exclude', metavar='COLLECTOR', type=str, nargs='+', default=[],
                                 help='list of collector names (e.g., httpnikto) whose outputs should not be returned in '
                                      'CSV (see argument --csv) or export (see argument -o) mode. use argument value "all" '
                                      'to exclude all collectors. per default, no collectors are excluded')
        parser_file.add_argument('-I', '--include', metavar='COLLECTOR', type=str, nargs='+', default=[],
                                 help='list of collector names whose outputs should be returned in CSV (see argument '
                                      '--csv) or export (see argument -o) mode. per default, all collector information is '
                                      'returned')

    def _filter(self, command: Command) -> bool:
        """
        Method determines whether the given item shall be included into the report
        """
        return command.is_processable(included_items=self._included_items,
                                      excluded_items=self._excluded_items,
                                      exclude_collectors=self._excluded_collectors,
                                      include_collectors=self._included_collectors,
                                      scope=self._scope)

    def _export_file(self, file_info: CommandFileMapping, deduplicated: Dict[str, str] = {}):
        """
        This method writes the given file_info to the filesystem
        :param file_info:
        :param deduplicated:
        :return:
        """
        deduplicated[file_info.file.sha256_value] = True
        file_name = self._get_unique_file_name(self._args.export_path, file_info.file_name)
        if os.path.isfile(file_name):
            print("file '{}' exists already but will be overwritten.".format(file_name),
                  file=sys.stderr)
        with open(file_name, "wb") as file:
            file.write(file_info.file.content)

    def _append_csv_row(self, csv_rows: List[List[str]], command: Command, file_type: FileType) -> None:
        service = command.service
        if not self._file_types or file_type in self._file_types:
            stdout = command.stdout
            content_length = None
            if file_type == FileType.xml and command.xml_output:
                content_length = len(str(command.xml_output))
            elif file_type == FileType.json and command.json_output:
                content_length = len(str(command.json_output))
            elif file_type == FileType.binary and command.binary_output:
                content_length = len(command.binary_output)
            elif file_type == FileType.text and stdout:
                content_length = len(os.linesep.join(stdout))
            if content_length:
                csv_rows.append([command.id,
                                 command.workspace.name,
                                 command.file_name,
                                 file_type.name.lower(),
                                 content_length,
                                 command.collector_name.name,
                                 command.collector_name.type_str,
                                 command.target_name,
                                 service.port if service else None,
                                 service.protocol_str if service else None,
                                 service.service_name if service else None,
                                 command.status_str])

    def _export_raw_scan_result(self, command: Command, file_type: FileType) -> None:
        """
        This method writes the raw scan results to the filesystem
        :param command:
        :param file_type:
        :return:
        """
        if not self._file_types or file_type in self._file_types:
            contents = []
            file_name = None
            stdout = command.stdout
            if file_type == FileType.xml and command.xml_output:
                file_name = "{}.xml".format(command.file_name)
                contents = [command.xml_output]
            elif file_type == FileType.json and command.json_output:
                file_name = "{}.json".format(command.file_name)
                contents = [json.dumps(item, indent=4) for item in command.json_output if item]
            elif file_type == FileType.binary and command.binary_output:
                file_name = "{}.bin".format(command.file_name)
                contents = [command.binary_output]
            elif file_type == FileType.text and stdout:
                file_name = "{}.txt".format(command.file_name)
                contents = [os.linesep.join(stdout)]
            for content in contents:
                file_path = self._get_unique_file_name(self._args.export_path, file_name)
                mode = "w" if isinstance(content, str) else "wb"
                with open(file_path, mode) as file:
                    file.write(content)

    def export_files(self) -> None:
        """
        Exports all files from the database.
        :return:
        """
        commands = self._session.query(Command)
        deduplicated = {}
        for command in commands.all():
            if command.workspace in self._workspaces:
                if self._filter(command):
                    self._export_raw_scan_result(command, FileType.text)
                    self._export_raw_scan_result(command, FileType.xml)
                    self._export_raw_scan_result(command, FileType.json)
                    self._export_raw_scan_result(command, FileType.binary)
                    for mapping in command.file_mappings:
                        if not self._file_types or mapping.file.type in self._file_types:
                            self._export_file(mapping, deduplicated)

    def get_csv(self) -> List[List[str]]:
        """
        This method returns all information as CSV.
        :return:
        """
        rows = [["DB ID",
                 "Workspace",
                 "File Name",
                 "File Type",
                 "File Size (bytes)",
                 "Collector",
                 "Collector Type",
                 "Address",
                 "Protocol",
                 "Port",
                 "Service Name",
                 "Status"]]
        commands = self._session.query(Command)
        for command in commands:
            if command.workspace in self._workspaces:
                if self._filter(command):
                    self._append_csv_row(rows, command, FileType.text)
                    self._append_csv_row(rows, command, FileType.xml)
                    self._append_csv_row(rows, command, FileType.json)
                    self._append_csv_row(rows, command, FileType.binary)
                    for mapping in command.file_mappings:
                        if not self._file_types or mapping.file.type in self._file_types:
                            service = command.service
                            rows.append([command.id,
                                         command.workspace.name,
                                         mapping.file_name,
                                         mapping.file.type_str,
                                         len(mapping.file.content),
                                         command.collector_name.name,
                                         command.collector_name.type_str,
                                         command.target_name,
                                         service.port if service else None,
                                         service.protocol_str if service else None,
                                         service.service_name if service else None,
                                         command.status_str])
        return rows
