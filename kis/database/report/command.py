# -*- coding: utf-8 -*-
"""This module allows querying information about executed OS commands."""

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
import argparse
from typing import List
from database.model import Command
from database.model import ReportScopeType
from database.model import ReportVisibility
from database.report.core import BaseReport


class ReportClass(BaseReport):
    """
    this module allows querying information about executed OS commands
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(name="command info",
                         title="Overview of Executed Operating System Commands",
                         description="The table provides an overview of all executed commands. You can use columns "
                                     "'Start Time [UTC]' and 'End Time [UTC]' to determine when a certain command was "
                                     "executed. You can use 'Stdout Size' or 'Stderr Size' to determine deviations "
                                     "from the average command output of a specific collector.",
                         **kwargs)

    @staticmethod
    def get_add_argparse_arguments(parser_command: argparse.ArgumentParser):
        """
        This method adds the report's specific command line arguments.
        """
        # setup command parser
        parser_command.add_argument("-w", "--workspaces",
                                    metavar="WORKSPACE",
                                    help="query the given workspaces",
                                    nargs="+",
                                    type=str)
        parser_command_group = parser_command.add_mutually_exclusive_group()
        parser_command_group.add_argument('--text', action='store_true',
                                          help='returns gathered information including all collector outputs as text')
        parser_command_group.add_argument('--csv', action='store_true', default=True,
                                          help='returns gathered information in csv format')
        parser_command.add_argument('--filter', metavar='DOMAIN|HOSTNAME|IP|NETWORK|EMAIL', type=str, nargs='*',
                                    help='list of second-level domains (e.g., megacorpone.com), host names '
                                         '(e.g., www.megacorpone.com), IP addresses (e.g., 192.168.1.1), networks (e.g., '
                                         '192.168.0.0/24), or email addresses (e.g., test@megacorpone.com) whose '
                                         'information shall be returned. per default, mentioned items are excluded. add + '
                                         'in front of each item (e.g., +192.168.0.1) to return only these items')
        parser_command.add_argument('--scope', choices=[item.name for item in ReportScopeType],
                                    help='return only in scope (within) or out of scope (outside) items. per default, '
                                         'all information is returned')
        parser_command.add_argument('--visibility', choices=[item.name for item in ReportVisibility],
                                    help='return only relevant (relevant) or potentially irrelevant (irrelevant) '
                                         'information (e.g., executed commands that did not return any '
                                         'information) in text output (argument --text). per default, all information '
                                         'is returned')
        parser_command.add_argument('-X', '--exclude', metavar='COLLECTOR', type=str, nargs='+', default=[],
                                    help='list of collector names (e.g., httpnikto) whose outputs should not be returned '
                                         'in text mode (see argument --text). use argument value "all" to exclude all '
                                         'collectors. per default, no collectors are excluded')
        parser_command.add_argument('-I', '--include', metavar='COLLECTOR', type=str, nargs='+', default=[],
                                    help='list of collector names whose outputs should be returned in text mode (see '
                                         'argument --text). per default, all collector information is returned')

    def _filter(self, command: Command) -> bool:
        """
        Method determines whether the given item shall be included into the report
        """
        return command.is_processable(included_items=self._included_items,
                                      excluded_items=self._excluded_items,
                                      exclude_collectors=self._excluded_collectors,
                                      include_collectors=self._included_collectors,
                                      scope=self._scope)

    def get_csv(self) -> List[List[str]]:
        """
        This method returns all information as CSV.
        :return:
        """
        rows = [["DB ID",
                 "Workspace",
                 "Collector",
                 "Type",
                 "Address",
                 "Protocol",
                 "Port",
                 "Service",
                 "Nmap Service Name",
                 "Nmap Service Name Original",
                 "Status",
                 "Start Time [UTC]",
                 "End Time [UTC]",
                 "Duration [s]",
                 "Return Code",
                 "Stdout Size",
                 "Stderr Size",
                 "OS Command"]]
        for workspace in self._workspaces:
            for command in self._session.query(Command).filter_by(workspace_id=workspace.id).all():
                service = command.service
                if self._filter(command):
                    execution_time = (command.stop_time - command.start_time).seconds \
                        if command.stop_time and command.start_time else None
                    start_time = command.start_time_str
                    stop_time = command.stop_time_str
                    stdout_count = len(os.linesep.join(command.stdout_output))
                    stderr_count = len(os.linesep.join(command.stderr_output))
                    rows.append([command.id,
                                 command.workspace.name,
                                 command.collector_name.name,
                                 command.collector_name.type_str,
                                 command.target_name,
                                 service.protocol_str if service else None,
                                 service.port if service else None,
                                 service.protocol_port_str if service else None,
                                 service.service_name_with_confidence if service else None,
                                 service.nmap_service_name_original_with_confidence if service else None,
                                 command.status_str,
                                 start_time,
                                 stop_time,
                                 execution_time,
                                 command.return_code,
                                 stdout_count,
                                 stderr_count,
                                 command.os_command_string])
        return rows

    def get_text(self) -> List[str]:
        """
        This method returns all information as a list of text.
        :return:
        """
        rvalue = []
        commands = self._session.query(Command)
        for command in commands:
            if command.workspace in self._workspaces:
                if self._filter(command):
                    rvalue += command.get_text(ident=0,
                                               report_visibility=self._visibility,
                                               color=self._color)
        return rvalue
