# -*- coding: utf-8 -*-
""""This file contains all classes for creating and managing the comandline user interface."""

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

import curses
import sqlalchemy
import re
import logging
import sys
import time
from database.model import CollectorName
from database.model import Command
from database.model import Host
from database.model import Service
from database.model import Workspace
from database.model import HostName
from database.model import DomainName
from database.model import Network
from database.model import Email
from database.model import Company
from database.model import Path
from database.model import CommandStatus
from collectors.os.collector import CollectorProducer
from collectors.os.modules.core import Ipv4NetworkCollector
from collectors.os.modules.core import HostCollector
from collectors.os.modules.core import ServiceCollector
from collectors.os.modules.core import DomainCollector
from collectors.os.modules.core import HostNameServiceCollector
from collectors.os.modules.core import EmailCollector
from collectors.os.modules.core import CompanyCollector
from collectors.os.modules.core import PathCollector
from view.core import ReportItem
from view.core import BaseUiManager
from sqlalchemy import and_
from sqlalchemy import func
from threading import Lock
from time import sleep

logger = logging.getLogger('report')


class WindowLayout:
    MIN_REPORT_WINDOW_HEIGHT = 4
    MIN_STATS_WINDOW_HEIGHT = 3
    MESSAGE_WINDOW_HEIGHT = 1
    PROMPT_WINDOW_HEIGHT = 1
    FRAME_HEIGHT = 2

    """This class calculates the layout of the curses windows"""
    def __init__(self, curses_object: curses, producer_thread: CollectorProducer):
        self._ui_initialized = False
        self.curses = curses_object
        self.producer_thread = producer_thread
        self.number_of_collectors = len(producer_thread.selected_collectors)
        self.current_console_height = 0
        self.current_console_width = 0
        self.stats_window_height = None
        self.thread_window_height = producer_thread.number_of_threads + WindowLayout.FRAME_HEIGHT
        self.report_window_height = None
        self.prompt_window_height = WindowLayout.PROMPT_WINDOW_HEIGHT
        self.message_window_height = WindowLayout.MESSAGE_WINDOW_HEIGHT
        self.stats_window_y_start = 0
        self.thread_window_y_start = None
        self.report_window_y_start = None
        self.prompt_window_y_start = None
        self.message_window_y_start = None
        self.report_buffer_size = None
        self.stats_buffer_size = None
        self.recaclulate()
        self._ui_initialized_lock = Lock()

    @property
    def ui_initialized(self):
        with self._ui_initialized_lock:
            return self._ui_initialized

    @ui_initialized.setter
    def ui_initialized(self, value):
        with self._ui_initialized_lock:
            self._ui_initialized = value

    def recaclulate(self):
        if self.current_console_height != self.curses.LINES:
            self.stats_window_height = self.number_of_collectors + WindowLayout.FRAME_HEIGHT
            self.report_window_height = self.curses.LINES - self.stats_window_height - self.thread_window_height - \
                                        self.prompt_window_height - self.message_window_height
            if self.report_window_height < WindowLayout.MIN_REPORT_WINDOW_HEIGHT:
                self.report_window_height = WindowLayout.MIN_REPORT_WINDOW_HEIGHT
                self.stats_window_height = self.curses.LINES - self.thread_window_height - self.report_window_height - \
                                           self.prompt_window_height - self.message_window_height
                if self.stats_window_height < WindowLayout.MIN_STATS_WINDOW_HEIGHT:
                    raise ValueError("Numbers of threads do not fit into user interface. Reduce number of threads.")
            self.stats_window_y_start = 0
            self.thread_window_y_start = self.stats_window_y_start + self.stats_window_height
            self.report_window_y_start = self.thread_window_y_start + self.thread_window_height
            self.prompt_window_y_start = self.report_window_y_start + self.report_window_height
            self.message_window_y_start = self.prompt_window_y_start + self.prompt_window_height
            self.report_buffer_size = self.report_window_height - WindowLayout.FRAME_HEIGHT
            self.stats_buffer_size = self.stats_window_height - WindowLayout.FRAME_HEIGHT
            self.current_console_height = self.curses.LINES
        if self.current_console_width != self.curses.COLS:
            self.current_console_width = self.curses.COLS


class BaseWindow:
    """This class implements base for functionality for UI windows"""

    def __init__(self, ui_manager: BaseUiManager, window) -> None:
        super().__init__()
        self._ui_manager = ui_manager
        self._window = window
        self._engine = ui_manager.layout.producer_thread.engine
        self._producer_thread = ui_manager.layout.producer_thread
        self._layout = ui_manager.layout
        self._window.clear()
        self._window.border()
        self._window.refresh()

    def init(self) -> None:
        """This method initializes the curses window"""
        raise NotImplementedError("Not implemented.")

    def addstr(self, y: int, x: int, text: str):
        try:
            text_length = len(text) + x
            details = "{}...".format(text_length[:text_length - 3]) \
                if text_length > self._layout.current_console_width else text
            self._window.addstr(y, x, details)
        except Exception:
            logger.exception(text, exc_info=True)

    def _prepare_report_line(self, line: str) -> str:
        """Before any line is written into the GUI, it should be sanitized via this method"""
        number_chars = self._layout.curses.COLS - 2
        return line if len(line) <= number_chars else "{}...".format(line[:number_chars - 3])

    def refresh(self) -> None:
        """This method refreshes the curses window"""
        raise NotImplementedError("Not implemented.")


class StatWindow(BaseWindow):
    """This class implements all functionalities for the stats window"""
    SHOW_STATS_AHEAD = 3

    def __init__(self, ui_manager: BaseUiManager, message_window) -> None:
        super().__init__(ui_manager, curses.newwin(ui_manager.layout.stats_window_height,
                                                   ui_manager.layout.current_console_width,
                                                   ui_manager.layout.stats_window_y_start,
                                                   0))
        self._stat_header = None
        self._stat_header_length = 0
        self._message_window = message_window

    def init(self) -> None:
        """This method initializes the curses window"""
        if self._layout.ui_initialized:
            self._window.clear()
            self._window.border()
            # here we draw the header row for the stats window
            if not self._stat_header:
                with self._engine.session_scope() as session:
                    self._stat_header = [item.name for item in CommandStatus]
                    self._stat_header_length = len(self._stat_header) + 1
            self.addstr(0, 1, "collector")
            i = 1
            for item in self._stat_header:
                self.addstr(0, int((self._layout.current_console_width - 10) / self._stat_header_length * i), item)
                i += 1
            self.addstr(0, int((self._layout.current_console_width - 10) / self._stat_header_length * i), "total")

    def refresh(self) -> None:
        """This method updates the content of the window"""
        if self._layout.ui_initialized:
            self.init()
            start = 1
            row = start
            from_index = 0
            if self._producer_thread.current_collector_index >= self._layout.stats_buffer_size:
                tmp = (self._producer_thread.current_collector_index + StatWindow.SHOW_STATS_AHEAD)
                to_index = tmp if tmp <= self._layout.number_of_collectors else \
                    self._layout.number_of_collectors
                from_index = to_index - self._layout.stats_buffer_size
            else:
                to_index = from_index + self._layout.stats_buffer_size
            with self._engine.session_scope() as session:
                command_status = [item for item in CommandStatus]
                for collector in self._producer_thread.selected_collectors[from_index:to_index]:
                    self.addstr(row, 1, collector.name)
                    i = 1
                    total = 0
                    for item in command_status:
                        try:
                            # todo: update for new collector
                            count = 0
                            if issubclass(collector.collector_class, HostCollector) or \
                               issubclass(collector.collector_class, ServiceCollector) or \
                               issubclass(collector.collector_class, HostNameServiceCollector):
                                count1 = session.query(func.count(Command.status)) \
                                    .join((CollectorName, Command.collector_name)) \
                                    .join((Host, Command.host)) \
                                    .join((Workspace, Host.workspace)) \
                                    .filter(and_(Workspace.name == self._producer_thread.workspace,
                                                 CollectorName.name == collector.name,
                                                 Command.status == item)) \
                                    .group_by(Command.status).scalar()
                                count2 = session.query(func.count(Command.status)) \
                                    .join((CollectorName, Command.collector_name)) \
                                    .join((Service, Command.service)) \
                                    .join((HostName, Service.host_name)) \
                                    .join((DomainName, HostName.domain_name)) \
                                    .join((Workspace, DomainName.workspace)) \
                                    .filter(and_(Workspace.name == self._producer_thread.workspace,
                                                 CollectorName.name == collector.name,
                                                 Command.status == item)) \
                                    .group_by(Command.status).scalar()
                                count1 = count1 if count1 else 0
                                count2 = count2 if count2 else 0
                                count = count1 + count2
                            if issubclass(collector.collector_class, DomainCollector):
                                count = session.query(func.count(Command.status)) \
                                    .join((CollectorName, Command.collector_name)) \
                                    .join((HostName, Command.host_name)) \
                                    .join((DomainName, HostName.domain_name)) \
                                    .join((Workspace, DomainName.workspace)) \
                                    .filter(and_(Workspace.name == self._producer_thread.workspace,
                                                 CollectorName.name == collector.name,
                                                 Command.status == item)) \
                                    .group_by(Command.status).scalar()
                            if issubclass(collector.collector_class, Ipv4NetworkCollector):
                                count = session.query(func.count(Command.status)) \
                                    .join((CollectorName, Command.collector_name)) \
                                    .join((Network, Command.ipv4_network)) \
                                    .join((Workspace, Network.workspace)) \
                                    .filter(and_(Workspace.name == self._producer_thread.workspace,
                                                 CollectorName.name == collector.name,
                                                 Command.status == item)) \
                                    .group_by(Command.status).scalar()
                            if issubclass(collector.collector_class, EmailCollector):
                                count = session.query(func.count(Command.status)) \
                                    .join((CollectorName, Command.collector_name)) \
                                    .join((Email, Command.email)) \
                                    .join((HostName, Email.host_name)) \
                                    .join((DomainName, HostName.domain_name)) \
                                    .join((Workspace, DomainName.workspace)) \
                                    .filter(and_(Workspace.name == self._producer_thread.workspace,
                                                 CollectorName.name == collector.name,
                                                 Command.status == item)) \
                                    .group_by(Command.status).scalar()
                            if issubclass(collector.collector_class, CompanyCollector):
                                count = session.query(func.count(Command.status)) \
                                    .join((CollectorName, Command.collector_name)) \
                                    .join((Company, Command.company)) \
                                    .join((Workspace, Company.workspace)) \
                                    .filter(and_(Workspace.name == self._producer_thread.workspace,
                                                 CollectorName.name == collector.name,
                                                 Command.status == item)) \
                                    .group_by(Command.status).scalar()
                            if issubclass(collector.collector_class, PathCollector):
                                count = session.query(func.count(Command.status)) \
                                    .join((CollectorName, Command.collector_name)) \
                                    .join((Path, Command.path)) \
                                    .join((Service, Path.service)) \
                                    .join((Host, Service.host)) \
                                    .join((Workspace, Host.workspace)) \
                                    .filter(and_(Workspace.name == self._producer_thread.workspace,
                                                 CollectorName.name == collector.name,
                                                 Command.status == item)) \
                                    .group_by(Command.status).scalar()
                                count += session.query(func.count(Command.status)) \
                                    .join((CollectorName, Command.collector_name)) \
                                    .join((Path, Command.path)) \
                                    .join((Service, Path.service)) \
                                    .join((HostName, Service.host_name)) \
                                    .join((DomainName, HostName.domain_name)) \
                                    .join((Workspace, Host.workspace)) \
                                    .filter(and_(Workspace.name == self._producer_thread.workspace,
                                                 CollectorName.name == collector.name,
                                                 Command.status == item)) \
                                    .group_by(Command.status).scalar()
                            count = count if count else 0
                            total += count
                        except sqlalchemy.orm.exc.NoResultFound as ex:
                            self._message_window.log_exception(ex)
                            count = 0
                        self.addstr(row,
                                    int((self._layout.current_console_width - 10) /
                                        self._stat_header_length * i),
                                    str(count))
                        i += 1
                    self.addstr(row,
                                int((self._layout.current_console_width - 10) /
                                    self._stat_header_length * i),
                                str(total))
                    row += 1
            self._window.refresh()


class ThreadWindow(BaseWindow):
    """This class implements all functionalities for the stats window"""
    HEADER_TEXT = "thread info"

    def __init__(self, ui_manager: BaseUiManager, consumer_threads) -> None:
        super().__init__(ui_manager, curses.newwin(ui_manager.layout.thread_window_height,
                                                   ui_manager.layout.current_console_width,
                                                   ui_manager.layout.thread_window_y_start,
                                                   0))
        self._consumer_threads = consumer_threads

    def init(self) -> None:
        """This method initializes the curses window"""
        if self._layout.ui_initialized:
            self._window.clear()
            self._window.border()
            self.addstr(0, 1, ThreadWindow.HEADER_TEXT)

    def refresh(self) -> None:
        """This method updates the content of the window"""
        if self._layout.ui_initialized:
            self.init()
            start = 1
            row = start
            for item in self._consumer_threads:
                line = self._prepare_report_line(str(item))
                self.addstr(row, 1, line)
                row += 1
            self._window.refresh()


class ReportWindow(BaseWindow):
    """This class implements all functionalities for the threads window"""
    HEADER_TEXT = "report items"

    def __init__(self, ui_manager: BaseUiManager) -> None:
        super().__init__(ui_manager, curses.newwin(ui_manager.layout.report_window_height,
                                                   ui_manager.layout.current_console_width,
                                                   ui_manager.layout.report_window_y_start,
                                                   0))
        self._report_items = []
        self._report_item_lock = Lock()

    def init(self) -> None:
        """This method initializes the curses window"""
        if self._layout.ui_initialized:
            self._window.clear()
            self._window.border()
            self.addstr(0, 1, ReportWindow.HEADER_TEXT)

    def add_report_item(self, report_item: ReportItem) -> None:
        """
        Use this method to add a new report item to the curse window Report Items
        :param report_item: The report item that shall be reported
        :return:
        """
        with self._report_item_lock:
            logger.info(report_item.get_report())
            self._report_items.append(report_item.get_report(self._layout.current_console_width))

    def refresh(self) -> None:
        """This method updates the content of the window"""
        self.init()
        start = 1
        row = start
        with self._report_item_lock:
            size = len(self._report_items)
            i = 0 if size < self._layout.report_buffer_size else (size - self._layout.report_buffer_size)
            for item in self._report_items[i:]:
                line = self._prepare_report_line(str(item))
                self.addstr(row, 1, line)
                row = row + 1
            self._window.refresh()


class PromptWindow(BaseWindow):
    """This class implements all functionalities for the prompt window"""
    COMMAND_PROMPT = "kis> "

    def __init__(self, ui_manager: BaseUiManager) -> None:
        super().__init__(ui_manager, curses.newwin(ui_manager.layout.prompt_window_height,
                                                   ui_manager.layout.current_console_width,
                                                   ui_manager.layout.prompt_window_y_start,
                                                   1))
        self._message_window = None

    def init(self) -> None:
        """This method initializes the curses window"""
        self._window.clear()
        self.addstr(0, 0, PromptWindow.COMMAND_PROMPT)
        self._window.refresh()

    def refresh(self):
        self._window.refresh()

    def register_message_window(self, message_window):
        self._message_window = message_window

    def process_user_input(self) -> None:
        """
        This method processes user input
        :return:
        """
        if self._layout.ui_initialized:
            re_kill = re.compile("^(k|t)([0-9]+)$")
            while not self._ui_manager.quit_collection:
                self.init()
                if not self._ui_manager.batch_mode:
                    user_input = self._window.getstr(0, len(CursesUiManager.COMMAND_PROMPT)).decode()
                    user_input = user_input.strip()
                    match = re_kill.match(user_input)
                    if match:
                        command = match.group(1)
                        thread_id = int(match.group(2)) - 1
                        if command == "k" and self._ui_manager.start_collection:
                            self._ui_manager.kill_process(thread_id)
                        elif command == "t" and self._ui_manager.start_collection:
                            self._ui_manager.terminate_process(thread_id)
                    elif user_input == "h" and self._ui_manager.start_collection:
                        self._message_window.set_message("s: start collection, q: quit collection, n: next collector, "
                                                         "t[0-9]+: terminate thread X, k[0-9]: kill thread X")
                    elif user_input == "s":
                        self._ui_manager.start_collection = True
                    elif user_input == "n" and self._ui_manager.start_collection:
                        self._ui_manager.next_collector(self._producer_thread.current_collector.name)
                    elif user_input == "q":
                        self._ui_manager.quit()
                else:
                    time.sleep(1)


class MessageWindow(BaseWindow):
    """This class implements all functionalities for the message window"""

    def __init__(self, ui_manager: BaseUiManager, prompt_window) -> None:
        super().__init__(ui_manager, curses.newwin(ui_manager.layout.message_window_height,
                                                   ui_manager.layout.current_console_width,
                                                   ui_manager.layout.message_window_y_start,
                                                   1))
        self._prompot_window = prompt_window
        self._message_lock = Lock()

    def init(self):
        pass

    def log_exception(self, exception: Exception):
        """This method logs the exception"""
        logger.exception(exception)
        self.set_message("exception - {}".format(str(exception)))

    def set_message(self, message: str, file=sys.stdout) -> None:
        """
        Use this method to set a message in the status bar
        :param message: The message
        :param file: File handle where the message shall be written to
        :return:
        """
        with self._message_lock:
            if self._layout.ui_initialized:
                message = message if len(message) < (self._layout.current_console_width - 2) else \
                    "{}...".format(message[:self._layout.current_console_width-10])
                self._window.clear()
                self.addstr(0, 0, str(message))
                self._window.refresh()
            else:
                print(message, file=file)


class CursesUiManager(BaseUiManager):
    """This class is responsible for the application's command line interface"""
    THREAD_HEADER = "thread info"
    REPORT_ITEM_HEADER = "report items"
    COMMAND_PROMPT = "kis> "

    def __init__(self, refresh_rate: int=2):
        """
        :param refresh_rate: Number of seconds between UI refreshs
        :param start_collection: If False the user first enter s to start collection, else the collection is
        automatically started
        """
        super().__init__(refresh_rate)
        self._layout = None
        self._stat_window = None
        self._thread_window = None
        self._report_window = None
        self._prompt_window = None
        self._message_window = None
        self._windows = []
        self._stdscr = None
        self._ui_initialized = False
        self._ui_initialized_lock = Lock()

    @property
    def ui_initialized(self):
        with self._ui_initialized_lock:
            return self._ui_initialized

    @ui_initialized.setter
    def ui_initialized(self, value):
        with self._ui_initialized_lock:
            self._ui_initialized = value
        if self._layout:
            self._layout.ui_initialized = value

    def start_ui(self) -> None:
        """
        This method should start the thread using self.start()
        :return:
        """
        self.start()

    def add_report_item(self, report_item: ReportItem) -> None:
        """
        Use this method to add a new report item to the curse window Report Items
        :param report_item: The report item that shall be reported
        :return:
        """
        self._report_window.add_report_item(report_item)

    def init_windows(self) -> None:
        """
        This method initializes the curses windows
        :return:
        """
        self._stdscr = curses.initscr()
        self._stdscr.clear()
        curses.echo()
        curses.start_color()
        curses.use_default_colors()
        curses.cbreak()
        self._stdscr.keypad(True)
        curses.curs_set(0)
        self.ui_initialized = True
        self._layout = WindowLayout(curses, self._producer_thread)
        self._prompt_window = PromptWindow(self)
        self._message_window = MessageWindow(self, self._prompt_window)
        self._prompt_window.register_message_window(self._message_window)
        self._stat_window = StatWindow(self, self._message_window)
        self._thread_window = ThreadWindow(self, self._consumer_threads)
        self._report_window = ReportWindow(self)
        self._windows = [self._stat_window,
                         self._thread_window,
                         self._report_window,
                         self._prompt_window]
        self._layout.ui_initialized = True

    def end_window(self) -> None:
        """
        This method runs cleanups before ending the UI
        :return:
        """
        try:
            if self.ui_initialized:
                curses.endwin()
        except Exception as ex:
            self.log_exception(ex)
        finally:
            if self._layout:
                self.ui_initialized = False

    def notify_finished(self):
        """
        This method is called by the producer thread to notify the UI that the collection has finished.
        :return:
        """
        self.refresh()
        self._message_window.set_message("Info - Collection finished. press q followed by return to exit.")
        self.quit_collection = True

    def log_exception(self, exception: Exception):
        """This method logs the exception"""
        if self._message_window:
            self._message_window.log_exception(exception)
        else:
            print(exception, file=sys.stderr)

    def set_message(self, message: str, file=sys.stdout) -> None:
        """
        Use this method to set a message in the status bar
        :param message: The message
        :param file: File handle where the message shall be written to
        :return:
        """
        if self._message_window:
            self._message_window.set_message(message, file=file)
        else:
            print(message)

    def quit(self) -> None:
        """
        This method performs cleanup before quitting the UI
        :return:
        """
        self._producer_thread.clear_commands_queue()
        self.kill_all_processes()
        self.quit_collection = True
        self.set_message("waiting for commands to complete and then quitting the application")

    def next_collector(self, command_name_id) -> None:
        """
        This method continues executing the OS commands of the next collector
        :return:
        """
        self._engine.set_commands_incomplete(self._producer_thread.workspace, command_name_id)
        self._producer_thread.clear_commands_queue()
        self.terminate_all_processes()

    def kill_all_processes(self) -> None:
        """
        This method kills all currently running processes.
        :return:
        """
        for thread in self._consumer_threads:
            thread.kill_current_command()

    def terminate_all_processes(self) -> None:
        """
        This method kills all currently running processes.
        :return:
        """
        for thread in self._consumer_threads:
            thread.terminate_current_command()

    def kill_process(self, thread_id: int) -> None:
        """
        This method kills the OS command started by the thread with the given ID.
        :param thread_id: The ID of the thread whose OS command shall be killed.
        :return:
        """
        if thread_id < len(self._consumer_threads):
            self._consumer_threads[thread_id].kill_current_command()

    def terminate_process(self, thread_id: int) -> None:
        """
        This method kills the OS command started by the thread with the given ID.
        :param thread_id: The ID of the thread whose OS command shall be killed.
        :return:
        """
        if thread_id < len(self._consumer_threads) and self.ui_initialized:
            self._consumer_threads[thread_id].terminate_current_command()

    def wait_for_start(self) -> None:
        """
        This method waits until the user gives the start signal for collection entering s and hitting enter
        :return:
        """
        self.set_message("info - press s to start or q to stop collection")
        while not self.start_collection and not self.quit_collection:
            sleep(1)
        self.set_message("info - collection ongoing. press h for help.")

    def process_user_input(self) -> None:
        """
        This method processes user input
        :return:
        """
        self._prompt_window.process_user_input()

    def refresh(self) -> None:
        """
        This method refreshes the UI.
        :return:
        """
        try:
            for item in self._windows:
                item.refresh()
        except Exception as ex:
            self.log_exception(ex)

    def run(self):
        """
        This method periodically updates the status of the application.
        :return:
        """
        while not self.quit_collection and self.ui_initialized:
            try:
                self.refresh()
                sleep(self._refresh_rate)
            except Exception as ex:
                self.log_exception(ex)
