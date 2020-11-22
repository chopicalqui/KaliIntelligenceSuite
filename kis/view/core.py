# -*- coding: utf-8 -*-
""""This file contains all base functionality classes for implementing a new user interface."""

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

import sys
import logging
import enum
from threading import Thread
from threading import Lock
from database.model import CollectorName
from typing import TypeVar

logger = logging.getLogger('report')

CollectorProducer = TypeVar('collectors.os.collector.CollectorProducer')
CollectorConsumer = TypeVar('collectors.os.collector.CollectorConsumer')
BaseReportItemListener = TypeVar('view.core.BaseReportItemListener')


class ReportCriticality(enum.Enum):
    info = enum.auto()
    low = enum.auto()
    medium = enum.auto()
    high = enum.auto()


class ReportItem:
    """
    This class is used to report information in the CursesUiManager as well as log it into the application's log file.
    """

    def __init__(self,
                 ip: str,
                 collector_name: str,
                 report_type: str = None,
                 details: str = None,
                 protocol: str = None,
                 port: int = None,
                 listener: BaseReportItemListener = None,
                 criticality: ReportCriticality = ReportCriticality.info):
        """
        :param ip: IPv4 or IPv6 address of the host on which the item was identified
        :param protocol: The layer 4 protocol
        :param port: The service port on which the item was identified
        :param collector_name: The collector that identified the information
        :param report_type: Type (e.g. CREDS, PATH, OS). Maximum is 5 letters
        :param details: The details like credentials
        :param listener: The listener that needs to be notified about this report item
        :param criticality: The criticality of the report item
        """
        name = collector_name.name if isinstance(collector_name, CollectorName) else collector_name
        self._ip = ip
        self._protocol = protocol if not protocol or isinstance(protocol, str) else protocol.name
        self._protocol = self._protocol.lower() if self._protocol else self._protocol
        self._port = port
        self._collector_name = name if name else ""
        self.criticality = criticality
        self.report_type = report_type
        self.details = details
        self.listener = listener

    def get_report(self, line_length: int = 0) -> str:
        if not self.details:
            raise ValueError("report item details cannot be none")
        if not self.report_type:
            raise ValueError("report item type cannot be none")
        max_length = 10
        host_info = self._ip if len(self._ip) < 25 else "{}".format(self._ip[:24])
        collector_name = self._collector_name if len(self._collector_name) <= max_length else \
            "{}".format(self._collector_name[:max_length])
        report_type = self.report_type if len(self.report_type) <= max_length else \
            "{}".format(self.report_type[:max_length])
        report_type = report_type.upper()
        protocol = self._protocol if self._protocol else "-"
        port = str(self._port) if self._port else "-"
        host_service_info = "{:25}  {:>3}/{:<5} [{:10}] [{:10}] - ".format(host_info,
                                                                           protocol,
                                                                           port,
                                                                           collector_name.upper(),
                                                                           report_type)
        line = host_service_info + self.details
        return "{}...".format(line[:line_length-3]) if line_length and len(line) > line_length else line

    def notify(self):
        """
        This method notifies the listener
        :return:
        """
        if self.listener:
            self.listener.add_report_item(self)


class BaseReportItemListener:
    """
    This class implements base functionality to report information
    """

    def __init__(self):
        pass

    def add_report_item(self, report_item: ReportItem) -> None:
        """
        Use this method to add a new report item to the curse window Report Items
        :param report_item: The report item that shall be reported
        :return:
        """
        raise NotImplementedError("This method is not implemented.")


class BaseUiManager(BaseReportItemListener, Thread):

    def __init__(self, refresh_rate: int = 1, start_collection=False):
        """
        :param refresh_rate: Number of seconds between UI refreshs
        :param start_collection: If False the user first enter s to start collection, else the collection is
        automatically started
        """
        Thread.__init__(self, daemon=True)
        BaseReportItemListener.__init__(self)
        self._refresh_rate = refresh_rate
        self._producer_thread = None
        self._consumer_threads = []
        self._start_collection = start_collection
        self._lock_start_collection = Lock()
        self._quit_collection = False
        self._lock_quit_collection = Lock()
        self._lock_batch_mode = Lock()
        self._report_items = []
        self._report_item_buffer_size = 0
        self._batch_mode = False
        self._report_item_lock = Lock()
        self._layout = None

    @property
    def layout(self):
        return self._layout

    @property
    def batch_mode(self):
        with self._lock_batch_mode:
            return self._batch_mode

    @batch_mode.setter
    def batch_mode(self, value):
        with self._lock_batch_mode:
            self._batch_mode = value
        self.start_collection = True

    @property
    def start_collection(self):
        with self._lock_start_collection:
            return self._start_collection

    @start_collection.setter
    def start_collection(self, value):
        with self._lock_start_collection:
            self._start_collection = value

    @property
    def quit_collection(self):
        with self._lock_quit_collection:
            return self._quit_collection

    @quit_collection.setter
    def quit_collection(self, value):
        with self._lock_quit_collection:
            self._quit_collection = value

    def notify_finished(self):
        """
        This method is called by the producer thread to notify the UI that the collection has finished.
        :return:
        """
        pass

    def add_consumer_thread(self, consumer_thread: CollectorConsumer) -> None:
        """
        This method adds the given consumer_thread to the list of threads, whose status is shown in the thread
        curses' thread window.
        :param consumer_thread: The thread whose status shall be reported
        :return:
        """
        self._consumer_threads.append(consumer_thread)

    def set_producer_thread(self, producer_thread: CollectorProducer) -> None:
        """
        This method sets the producer thread
        :param producer_thread: The producer thread to be set
        :return:
        """
        self._producer_thread = producer_thread
        self._engine = producer_thread.engine

    def init_windows(self) -> None:
        """
        This method initializes the curses windows
        :return:
        """
        raise NotImplementedError("This method is not implemented.")

    def end_window(self) -> None:
        """
        This method runs cleanups before ending the UI
        :return:
        """
        raise NotImplementedError("This method is not implemented.")

    def process_user_input(self) -> None:
        """
        This method processes user input
        :return:
        """
        raise NotImplementedError("This method is not implemented.")

    def log_exception(self, exception: Exception) -> None:
        """This method logs exceptions"""
        raise NotImplementedError("This method is not implemented.")

    def set_message(self, message: str, file=sys.stdout) -> None:
        """
        Use this method to set a message in the status bar
        :param message: The message
        :param file: File handle where the message shall be written to
        :return:
        """
        raise NotImplementedError("This method is not implemented.")

    def start_ui(self) -> None:
        """
        This method should start the thread using self.start()
        :return:
        """
        raise NotImplementedError("This method is not implemented.")

    def wait_for_start(self) -> None:
        """
        This method waits until the user gives the start signal for collection entering s and hitting enter
        :return:
        """
        raise NotImplementedError("This method is not implemented.")

    def refresh(self) -> None:
        """
        This method refreshes the UI.
        :return:
        """
        raise NotImplementedError("This method is not implemented.")


class PrintCommmandUi(BaseUiManager):
    """
    This UI is used if commands are printed to the console.
    """

    def __init__(self):
        super().__init__(1, True)

    def init_windows(self) -> None:
        """
        This method initializes the curses windows
        :return:
        """
        pass

    def end_window(self) -> None:
        """
        This method runs cleanups before ending the UI
        :return:
        """
        pass

    def process_user_input(self) -> None:
        """
        This method processes user input
        :return:
        """
        pass

    def add_report_item(self, report_item: ReportItem) -> None:
        """
        Use this method to add a new report item to the curse window Report Items
        :param report_item: The report item that shall be reported
        :return:
        """
        pass

    def log_exception(self, exception: Exception) -> None:
        """This method logs exceptions"""
        logger.exception(exception)
        print(exception)

    def set_message(self, message: str, file=sys.stdout) -> None:
        """
        Use this method to set a message in the status bar
        :param message: The message
        :param file: File handle where the message shall be written to
        :return:
        """
        print(message, file=file)

    def start_ui(self) -> None:
        """
        This method should start the thread using self.start()
        :return:
        """
        pass

    def wait_for_start(self) -> None:
        """
        This method waits until the user gives the start signal for collection entering s and hitting enter
        :return:
        """
        pass

    def refresh(self) -> None:
        """
        This method refreshes the UI.
        :return:
        """
        pass
