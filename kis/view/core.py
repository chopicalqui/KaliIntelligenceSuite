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

import enum
import logging
import argparse
from cmd import Cmd
from database.utils import Engine
from database.model import CollectorName
from typing import List

logger = logging.getLogger('report')


class ReportCriticality(enum.Enum):
    info = enum.auto()
    low = enum.auto()
    medium = enum.auto()
    high = enum.auto()


class BaseKisKollectConsole(Cmd):
    """
    This class implements all base functionalities for a kiscollect console.
    """
    prompt = 'kis> '

    def __init__(self, args: argparse.Namespace, producer_thread):
        super().__init__()
        self._args = args
        self._workspace = args.workspace
        self._producer_thread = producer_thread
        self._engine = Engine()
        self._producer_thread.register_console(self)
        self.prompt = 'kis ({})> '.format(self._workspace)

    def notify_finished(self):
        """
        This method is called by the producer thread when collection is done.
        """
        raise NotImplementedError("this method must be implemented by all subclasses.")

    def notify_report_item(self, report_item) -> None:
        """
        Use this method to add a new report item to the console window Report Items
        :param report_item: The report item that shall be reported
        :return:
        """
        raise NotImplementedError("This method is not implemented.")


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
                 listeners: List[BaseKisKollectConsole] = None,
                 criticality: ReportCriticality = ReportCriticality.info):
        """
        :param ip: IPv4 or IPv6 address of the host on which the item was identified
        :param protocol: The layer 4 protocol
        :param port: The service port on which the item was identified
        :param collector_name: The collector that identified the information
        :param report_type: Type (e.g. CREDS, PATH, OS). Maximum is 5 letters
        :param details: The details like credentials
        :param listeners: The listeners that need to be notified about this report item
        :param criticality: The criticality of the report item
        """
        name = collector_name.name if isinstance(collector_name, CollectorName) else collector_name
        self.ip = ip
        self.protocol = protocol if not protocol or isinstance(protocol, str) else protocol.name
        self.protocol = self.protocol.lower() if self.protocol else self.protocol
        self.port = port
        self.collector_name = name if name else ""
        self.criticality = criticality
        self.report_type = report_type
        self.details = details
        self._listeners = listeners if listeners else []

    def __eq__(self, other):
        return self.ip == other.ip and self.protocol == other.protocol and self.port == other.port and \
               self.collector_name == other.collector_name and self.criticality == other.criticality and \
               self.report_type == other.report_type

    @property
    def listeners(self) -> list:
        return self._listeners

    @listeners.setter
    def listeners(self, value: List[BaseKisKollectConsole]):
        self._listeners = value if value else []

    def get_report(self, line_length: int = 0) -> str:
        if not self.details:
            raise ValueError("report item details cannot be none")
        if not self.report_type:
            raise ValueError("report item type cannot be none")
        max_collector_name_length = 20
        max_host_length = 40
        host_info = self.ip if len(self.ip) < max_host_length else "{}".format(self.ip[:max_host_length])
        collector_name = self.collector_name if len(self.collector_name) <= max_collector_name_length else \
            "{}".format(self.collector_name[:max_collector_name_length])
        report_type = self.report_type if len(self.report_type) <= max_collector_name_length else \
            "{}".format(self.report_type[:max_collector_name_length])
        report_type = report_type.upper()
        protocol = self.protocol if self.protocol else "-"
        port = str(self.port) if self.port else "-"
        host_service_info = "{:40}  {:>3}/{:<5} [{:20}] [{:10}] - ".format(host_info,
                                                                           protocol,
                                                                           port,
                                                                           collector_name,
                                                                           report_type)
        line = host_service_info + self.details
        return "{}...".format(line[:line_length-3]) if line_length and len(line) > line_length else line

    def notify(self):
        """
        This method notifies the listener
        :return:
        """
        for item in self._listeners:
            item.notify_report_item(self)
