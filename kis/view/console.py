# -*- coding: utf-8 -*-
"""
This file contains all classes for creating and managing the comandline user interface.
"""

__author__ = "Lukas Reiter"
__license__ = "GPL v3.0"
__copyright__ = """Copyright 2021 Lukas Reiter

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
import enum
import numpy
import pandas
import shutil
import argparse
import traceback
import collections
from database.model import Command
from database.model import Workspace
from database.model import CollectorName
from database.model import CollectorType
from database.model import CommandStatus
from view.core import ReportItem
from view.core import BaseKisKollectConsole
from collectors.os.collector import CollectionStatus
from sqlalchemy.sql.expression import func


pandas.set_option('display.max_rows', None)


class InvalidInputException(Exception):
    def __init__(self, message: str):
        super().__init__(message)


class ThreadArgumentEnum(enum.Enum):
    add = enum.auto()
    command = enum.auto()
    stderr = enum.auto()
    stdout = enum.auto()


class CollectorArgumentEnum(enum.Enum):
    current = enum.auto()
    remaining = enum.auto()


class KisConsoleConsoleCommand(enum.Enum):
    clear = enum.auto()
    collector = enum.auto()
    info = enum.auto()
    kill = enum.auto()
    next = enum.auto()
    start = enum.auto()
    status = enum.auto()
    terminate = enum.auto()
    thread = enum.auto()


class KisCollectConsole(BaseKisKollectConsole):
    """
    This class implements the kiscollect console
    """

    def __init__(self, args: argparse.Namespace, **kwargs):
        super().__init__(args=args, **kwargs)
        self._buffer_size = 40
        self._report_items = collections.deque(maxlen=self._buffer_size)
        if self._args.autostart:
            self.do_start(input="")

    @property
    def _collection_status(self) -> CollectionStatus:
        return self._producer_thread.collection_status

    @property
    def _consumer_threads(self) -> list:
        return self._producer_thread.consumer_threads

    def notify_finished(self):
        """
        This method is called by the producer thread when collection is done.
        """
        print("collection finished")

    def notify_report_item(self, report_item: ReportItem) -> None:
        """
        Use this method to add a new report item to the console window Report Items
        :param report_item: The report item that shall be reported
        :return:
        """
        self._report_items.append(report_item)

    def _kill_process(self, thread_id: int) -> None:
        """
        This method kills the OS command started by the thread with the given ID.
        :param thread_id: The ID of the thread whose OS command shall be killed.
        :return:
        """
        if thread_id < len(self._consumer_threads):
            self._consumer_threads[thread_id].kill_current_command()

    def _terminate_process(self, thread_id: int) -> None:
        """
        This method kills the OS command started by the thread with the given ID.
        :param thread_id: The ID of the thread whose OS command shall be killed.
        :return:
        """
        if thread_id < len(self._consumer_threads):
            self._consumer_threads[thread_id].terminate_current_command()

    def _next_collector(self) -> None:
        """
        This method continues executing the OS commands of the next collector
        :return:
        """
        print("terminating current OS commands ...")
        self._engine.set_commands_incomplete(self._workspace, self._producer_thread.current_collector.name)
        print("emptying command queue ...")
        self._producer_thread.clear_commands_queue()
        print("terminating all threads ...")
        self._producer_thread.terminate_all_processes()

    def _process_input(self, command: KisConsoleConsoleCommand, input: str) -> list:
        """
        This method processes the user input.
        :param input: This is the user input which is analysed.
        :return: List containing the parsed arguments
        """
        result = input.strip().split()
        # Verify start command
        if command == KisConsoleConsoleCommand.start:
            if len(result) != 0:
                raise InvalidInputException("command does not accept an argument.")
            if self._collection_status == CollectionStatus.running:
                raise InvalidInputException("invalid command as collection has already been started.")
        # Verify status command
        elif command == KisConsoleConsoleCommand.status:
            if len(result) != 0:
                raise InvalidInputException("command does not accept an argument.")
            result = [self._producer_thread.collection_status.name.replace("_", " ")]
        # Verify next command
        elif command == KisConsoleConsoleCommand.next:
            if len(result) != 0:
                raise InvalidInputException("command does not accept an argument.")
            if self._collection_status != CollectionStatus.running:
                raise InvalidInputException("invalid command as collection is not running yet.")
        # Verify info command
        elif command == KisConsoleConsoleCommand.info:
            if len(result) != 0:
                raise InvalidInputException("command does not accept an argument.")
        # Verify clear command
        elif command == KisConsoleConsoleCommand.clear:
            if len(result) != 0:
                raise InvalidInputException("command does not accept an argument.")
        # Verify kill and terminate commands
        elif command in [KisConsoleConsoleCommand.kill, KisConsoleConsoleCommand.terminate]:
            if self._collection_status != CollectionStatus.running:
                raise InvalidInputException("invalid command as collection is not running yet.")
            if len(result) == 0:
                raise InvalidInputException("the command requires at least one integer argument.")
            tmp = []
            for item in result:
                if not str.isnumeric(item):
                    raise InvalidInputException("argument '{}' is not a number.".format(item))

                argument = int(item) - 1
                if 0 <= argument < len(self._consumer_threads):
                    tmp.append(argument)
                else:
                    raise InvalidInputException("argument '{}' must be a valid thread ID. run the following "
                                                "command to obtain list of valid IDs: "
                                                "{}".format(item, KisConsoleConsoleCommand.thread.name))
            result = tmp
        # Verify thread command
        elif command == KisConsoleConsoleCommand.thread:
            if len(result) > 0:
                if result[0] not in [item.name for item in ThreadArgumentEnum]:
                    raise InvalidInputException("subcommand '{}' is invalid for current command".format(result[0]))
                subcommand = ThreadArgumentEnum[result[0]]
                if subcommand in [ThreadArgumentEnum.stdout, ThreadArgumentEnum.stderr]:
                    if len(result) != 2:
                        raise InvalidInputException("subcommand '{}' requires one argument. run the following "
                                                    "command to obtain a list of valid IDs: "
                                                    "{}".format(subcommand.name, KisConsoleConsoleCommand.thread.name))
                    elif not result[1].isnumeric():
                        raise InvalidInputException("the subcommand's argument ({}) is not a number. run the following "
                                                    "command to obtain a list of valid IDs: "
                                                    "{}".format(result[1], KisConsoleConsoleCommand.thread.name))
                    thread_id = int(result[1]) - 1
                    if thread_id < 0 or thread_id >= len(self._consumer_threads):
                        raise InvalidInputException("argument '{}' must be a valid thread ID. run the following "
                                                    "command to obtain list of valid IDs: "
                                                    "{}".format(subcommand.name, KisConsoleConsoleCommand.thread.name))
                    result = [subcommand]
                    result.append(thread_id)
                else:
                    result = [subcommand]
                    result += result[1:]
        # Verify collector command
        elif command == KisConsoleConsoleCommand.collector:
            if len(result) > 0:
                if result[0] not in [item.name for item in CollectorArgumentEnum]:
                    raise InvalidInputException("subcommand '{}' is invalid for current command".format(result[0]))
                result = [CollectorArgumentEnum[result[0]]]
                result += result[1:]
        return result

    def default(self, input: str):
        arguments = " ".join(input.strip().split()[1:])
        if input == 'x' or input == 'q':
            return self.do_exit(arguments)
        else:
            print("invalid command")

    def help_exit(self):
        print("""usage: exit|x|q|Ctrl+D'

exit the application.""")

    def do_exit(self, input: str):
        self._producer_thread.stop()
        return True

    def help_start(self):
        print("""usage: {}

start the collection.""".format(KisConsoleConsoleCommand.start.name))

    def do_start(self, input: str):
        try:
            self._process_input(KisConsoleConsoleCommand.start, input)
            print("starting command producer thread ...")
            self._producer_thread.start()
        except Exception as ex:
            print(str(ex))

    def help_status(self):
        print("""usage: {}

print a summary of the collection status.""".format(KisConsoleConsoleCommand.status.name))

    def do_status(self, input: str):
        try:
            status = self._process_input(KisConsoleConsoleCommand.status, input)
            print(status[0])
        except Exception as ex:
            print(str(ex))

    def help_info(self):
        print("""usage: {}

display the last {} items collected by the worker threads.""".format(KisConsoleConsoleCommand.info.name,
                                                                     self._buffer_size))

    def do_info(self, input: str):
        try:
            self._process_input(KisConsoleConsoleCommand.info, input)
            for report_item in self._report_items:
                console_with, _ = shutil.get_terminal_size((80, 20))
                print(report_item.get_report(console_with))
        except Exception as ex:
            print(str(ex))

    def help_clear(self):
        print("""usage: {}

clear the terminal screen.""".format(KisConsoleConsoleCommand.clear.name))

    def do_clear(self, input: str):
        try:
            self._process_input(KisConsoleConsoleCommand.clear, input)
            os.system("clear")
        except Exception as ex:
            print(str(ex))

    def help_next(self):
        print("""usage: {}

kill all running threads and move to the next collector.""".format(KisConsoleConsoleCommand.next.name))

    def do_next(self, input: str):
        try:
            self._process_input(KisConsoleConsoleCommand.next, input)
            self._next_collector()
        except Exception as ex:
            print(str(ex))

    def help_kill(self):
        print("""usage: {} ID [ID ...]

kill the running thread of ID so that it can grep the next task. this is useful if a thread is running for too long.""".format(KisConsoleConsoleCommand.kill.name))

    def do_kill(self, input: str):
        try:
            arguments = self._process_input(KisConsoleConsoleCommand.kill, input)
            for item in arguments:
                self._kill_process(item)
        except Exception as ex:
            print(str(ex))

    def help_terminate(self):
        print("""usage: {} ID [ID ...]

terminate the running thread of ID so that it can grep the next task. this is useful if a thread is running for too long.""".format(KisConsoleConsoleCommand.terminate.name))

    def do_terminate(self, input: str):
        try:
            arguments = self._process_input(KisConsoleConsoleCommand.terminate, input)
            for item in arguments:
                self._terminate_process(item)
        except Exception as ex:
            print(str(ex))

    def help_thread(self):
        print("""usage: {} [{{{}}}]

this command does the following depending on the given subcommand:
- if no subcommand is given, then it print statistics about all current worker threads.
- {}: display the command that is currently executed by all threads.
- {}: add a new worker thread.
- {} TID: print current stdout of thread with ID TID.
- {} TID: print current stderr of thread with ID TID.""".format(KisConsoleConsoleCommand.thread.name,
                                                                "|".join([item.name for item in ThreadArgumentEnum]),
                                                                ThreadArgumentEnum.command.name,
                                                                ThreadArgumentEnum.add.name,
                                                                ThreadArgumentEnum.stdout.name,
                                                                ThreadArgumentEnum.stderr.name))

    def do_thread(self, input: str):
        try:
            arguments = self._process_input(KisConsoleConsoleCommand.thread, input)
            if len(arguments) == 0:
                console_with, _ = shutil.get_terminal_size((80, 20))
                for item in self._consumer_threads:
                    text = str(item)
                    if len(text) > console_with:
                        text = "{}...".format(text[:console_with-3])
                    print(text)
            elif arguments[0] == ThreadArgumentEnum.command:
                for item in self._consumer_threads:
                    command = item.current_os_command
                    print("{}: {}".format(item.thread_str, command if command else "n/a"))
            elif arguments[0] == ThreadArgumentEnum.add:
                self._producer_thread.add_consumer_thread()
            elif arguments[0] in [ThreadArgumentEnum.stdout, ThreadArgumentEnum.stderr]:
                current_process = self._consumer_threads[arguments[1]].current_process
                if current_process:
                    output = current_process.stdout_list if arguments[0] == ThreadArgumentEnum.stdout \
                        else current_process.stderr_list
                    if output is not None:
                        for line in output:
                            print(line)
                    else:
                        print("process not initialized.")
                else:
                    print("process not initialized.")
        except Exception as ex:
            print(str(ex))

    def help_collector(self):
        print("""usage: {} [{{{}}}]

this command does the following depending on the given subcommand:
- if no subcommand is given, then print statistics about all collectors within the given workspace for which OS
  commands have already been created.
- {}: print the name of the current collector.
- {}: print the names of the selected collectors that have not been processed yet.""".format(
            KisConsoleConsoleCommand.collector.name,
            "|".join([item.name for item in CollectorArgumentEnum]),
            CollectorArgumentEnum.current.name,
            CollectorArgumentEnum.remaining.name))

    def do_collector(self, input: str):
        try:
            arguments = self._process_input(KisConsoleConsoleCommand.collector, input)
            if len(arguments) == 0:
                with self._engine.session_scope() as session:
                    workspace_id = session.query(Workspace.id).filter_by(name=self._workspace)
                    query = session.query(CollectorName.name.label("collector"),
                                          CollectorName.type.label("type"),
                                          func.coalesce(Command.status, CommandStatus.pending.name).label("status"),
                                          CollectorName.priority,
                                          func.count(Command.status).label("count")) \
                        .outerjoin((Command, CollectorName.commands)) \
                        .filter(Command.workspace_id == workspace_id) \
                        .group_by(CollectorName.name,
                                  CollectorName.type,
                                  func.coalesce(Command.status, CommandStatus.pending.name),
                                  CollectorName.priority)
                    df = pandas.read_sql(query.statement, query.session.bind)
                    df["status"] = df["status"].apply(lambda x: CommandStatus(x).name)
                    df["type"] = df["type"].apply(lambda x: CollectorType(x).name)
                    results = pandas.pivot_table(df,
                                                 index=["collector", "type", "priority"],
                                                 columns=["status"],
                                                 values="count",
                                                 aggfunc=numpy.sum,
                                                 fill_value=0).sort_values(by="priority")
                    print(results)
            elif arguments[0] == CollectorArgumentEnum.current:
                if self._producer_thread.current_collector:
                    print(self._producer_thread.current_collector.name)
                else:
                    print("none")
            elif arguments[0] == CollectorArgumentEnum.remaining:
                for item in self._producer_thread.remaining_collectors:
                    print(item)
        except Exception:
            traceback.print_exc(file=sys.stderr)

    do_EOF = do_exit
    help_EOF = help_exit
