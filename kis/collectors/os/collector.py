# -*- coding: utf-8 -*-
"""This file contains all functionality to execute OS commands."""

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

import importlib
import os
import pkgutil
import subprocess
import logging
import sqlalchemy
import time
import enum
import sys
import pwd
import stat
from argparse import _ArgumentGroup
from view.core import BaseUiManager
from queue import Queue
from datetime import datetime
from threading import Lock
from threading import Thread
from configs.config import Collector
from database.model import Service
from database.model import Host
from database.model import HostName
from database.model import Network
from database.model import DomainName
from database.model import Workspace
from database.model import CollectorName
from database.model import Command
from database.model import Source
from database.model import CollectorType
from database.model import Email
from database.model import Company
from database.model import CommandStatus
from database.utils import Engine
from sqlalchemy import and_
from typing import Dict
from typing import List
from collectors.os.modules.core import DomainCollector
from collectors.os.modules.core import HostCollector
from collectors.os.modules.core import ServiceCollector
from collectors.os.modules.core import Ipv4NetworkCollector
from collectors.os.modules.core import HostNameServiceCollector
from collectors.os.modules.core import EmailCollector
from collectors.os.modules.core import CompanyCollector
from collectors.os.modules.core import ExecutionFailedException
from collectors.os.modules.core import Delay
from collectors.os.modules.core import BaseCollector

logger = logging.getLogger('collector')


class ArgParserModule:
    """This class manages the mapping between argparser arguments and the underlying collector classes."""

    def __init__(self, arg_option: str,
                 collector_class: BaseCollector,
                 instance: BaseCollector = None):
        self._arg_option = arg_option
        self._collector_class = collector_class
        self._instance = instance

    @property
    def name(self) -> str:
        return self._arg_option

    @property
    def collector_class(self) -> type:
        return self._collector_class

    @property
    def instance(self) -> BaseCollector:
        return self._instance

    def create_instance(self, **kwargs) -> None:
        """
        This method creates an instance of the current type using the given arguments.
        :param kwargs: The constractor arguments to initialize the class
        :return:
        """
        self._instance = self._collector_class(name=self._arg_option, **kwargs)

    def __lt__(self, other):
        """We need this method for the priority queue"""
        return self._instance.priority < other.instance.priority


class CommandQueueItem:
    """
    Information exchanged between producer and consumer threads

    Objects of this class represent items that are exchanged between CollectorProducer and CollectorConsumer
    threads via a command queue.
    """
    def __init__(self,
                 command_id: int,
                 timeout: int = None,
                 active_collector: bool = True):
        self._command_id = command_id
        self._timeout = timeout
        self._active_collector = active_collector

    @property
    def command_id(self):
        return self._command_id

    @property
    def timeout(self):
        return self._timeout

    @property
    def active_collector(self):
        return self._active_collector


class VhostChoice(enum.Enum):
    all = 0
    domain = 10


class CollectorProducer(Thread):
    """This class loads all modules and creates the desired commands."""

    def __init__(self,
                 engine: Engine,
                 command_queue: Queue = None,
                 ui_manager: BaseUiManager = None,
                 workspace: str = None,
                 restart_statuses: List[CommandStatus] = [],
                 analyze_results: bool = False,
                 strict_open: bool = False,
                 vhost: VhostChoice = None,
                 print_commands: bool = False,
                 number_of_threads: int = 1,
                 delay_min: int = None,
                 delay_max: int = None,
                 included_items: List[str] = [],
                 excluded_items: List[str] = [],
                 **kwargs):
        super().__init__()
        self.collector_config = Collector()
        self._collector_classes = self._load_modules()
        self._selected_collectors = []
        self._engine = engine
        self._number_of_threads = number_of_threads
        self._workspace = workspace
        self._print_commands = print_commands
        self._command_queue = command_queue
        self._current_collector = None
        self._current_collector_index = 0
        self._current_collector_lock = Lock()
        self._ui_manager = ui_manager
        self._included_items = included_items
        self._excluded_items = excluded_items
        self._restart_statuses = restart_statuses
        self._analyze_results = analyze_results
        self._strict_open = strict_open
        self._delay_min = delay_min
        self._delay_max = delay_max
        self._delay = None
        self._vhost = vhost
        self._continue_execution = False
        if ui_manager:
            self._ui_manager.set_producer_thread(self)

    @property
    def collector_classes(self) -> Dict[str, BaseCollector]:
        """
        :return: Dictionary
        """
        return self._collector_classes

    @property
    def selected_collectors(self) -> List[ArgParserModule]:
        return self._selected_collectors

    @property
    def engine(self) -> Engine:
        return self._engine

    @property
    def print_commands(self) -> bool:
        return self._print_commands

    @property
    def number_of_threads(self) -> int:
        return 1 if self._print_commands or self._delay_min or self._delay_max else self._number_of_threads

    @property
    def current_collector(self) -> ArgParserModule:
        with self._current_collector_lock:
            return self._current_collector

    @current_collector.setter
    def current_collector(self, value: ArgParserModule):
        with self._current_collector_lock:
            self._current_collector = value

    @property
    def current_collector_index(self) -> int:
        with self._current_collector_lock:
            return self._current_collector_index

    @current_collector_index.setter
    def current_collector_index(self, value: ArgParserModule):
        with self._current_collector_lock:
            self._current_collector_index = value

    @property
    def workspace(self) -> str:
        return self._workspace

    @property
    def ui_manager(self) -> BaseUiManager:
        return self._ui_manager

    @ui_manager.setter
    def ui_manager(self, value: BaseUiManager):
        if not value:
            raise ValueError("Value must not be None!")
        self._ui_manager = value
        self._ui_manager.set_producer_thread(self)

    @property
    def analyze_results(self) -> bool:
        return self._analyze_results

    @property
    def delay(self) -> Delay:
        if not self._delay:
            self._delay = Delay(self._delay_min, self._delay_max, self._print_commands, self._analyze_results)
        return self._delay

    def _load_modules(self) -> dict:
        """
        This method enumerates all collector plugins with name CollectorClass located in collectors.os

        These classes are then used to initialize the command line parser. Based on the user's selection, the desired
        classes are then initialized in method init for data collection.

        :return: A dictionary containing all collector classes
        """
        return_value = {}
        module_paths = [""]
        module_paths.extend(os.listdir(os.path.join(os.path.dirname(__file__), "modules")))
        for item in module_paths:
            module_path = os.path.join(os.path.dirname(__file__), "modules", item)
            if os.path.isdir(module_path) and item != "__pycache__":
                for importer, package_name, _ in pkgutil.iter_modules([module_path]):
                    import_string = "collectors.os.modules."
                    import_string += "{}.{}".format(item, package_name) if item else package_name
                    module = importlib.import_module(import_string)
                    if "CollectorClass" in vars(module):
                        class_ = getattr(module, "CollectorClass")
                        name = class_.__module__.split(".")[-1]
                        return_value[name] = ArgParserModule(name, class_)
        return return_value

    def log_exception(self, exception: Exception):
        """This method logs the exception"""
        logger.exception(exception)
        if self._ui_manager:
            self._ui_manager.log_exception(exception)
        else:
            print(exception, file=sys.stderr)

    def add_argparser_arguments(self, group: _ArgumentGroup) -> None:
        """
        This method adds all collector arguments to the given ArgumentParser class.
        :param group: The parser group where the arguments of all collectors shall be added
        :return:
        """
        for name, item in self._collector_classes.items():
            options = item.collector_class.get_argparse_arguments()
            group.add_argument("--{}".format(name), **options)

    def init(self, args: dict) -> None:
        """
        This method initializes the thread before it can start.
        :param args: The argparser arguments based on which the priority queue is created
        :return:
        """
        self._selected_collectors = []
        kwargs = {"ui_manager": self._ui_manager}
        to_instantiate = []
        for key, value in args.items():
            # If the key is in the dictionary, then we deal with a collector class, which we have to instantiate
            if value and key in self._collector_classes:
                to_instantiate.append(self._collector_classes[key])
            elif key == "threads" and value > 0:
                self._number_of_threads = value
            elif key == "workspace" and value:
                self._workspace = value
            elif key == "print_commands" and value:
                self._print_commands = value
            elif key == "filter" and value:
                self._included_items = [item[1:] for item in value if item[0] == '+'] if value else []
                self._excluded_items = [item for item in value if item[0] != '+'] if value else []
            elif key == "restart" and value:
                self._restart_statuses = [CommandStatus[item] for item in value]
            elif key == "analyze" and value:
                self._analyze_results = value
            elif key == "strict" and value:
                self._strict_open = value
            elif key == "delay_min" and value:
                self._delay_min = value
            elif key == "delay_max" and value:
                self._delay_max = value
            elif key == "batch_mode" and value:
                self._ui_manager.batch_mode = value
            elif key == "vhost" and value:
                self._vhost = VhostChoice[value]
            elif key == "continue" and value:
                self._continue_execution = value
            elif key == "output_dir" and value:
                os.chmod(value, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
            kwargs[key] = value
        for item in to_instantiate:
            item.create_instance(engine=self._engine, **kwargs)
            self._selected_collectors.append(item)
        self._selected_collectors.sort()

    def clear_commands_queue(self):
        """
        This method empties the command queue
        :return:
        """
        if self._command_queue:
            while self._command_queue.qsize() > 0:
                self._command_queue.get(block=False)
                self._command_queue.task_done()

    def _create(self, debug: bool = False):
        """This method creates all OS commands"""
        self._engine.delete_incomplete_commands(self._workspace)
        if self._ui_manager and not self.print_commands:
            self._ui_manager.start_ui()
            self._ui_manager.wait_for_start()
        continue_collection = True
        while continue_collection:
            self.current_collector_index = 0
            for collector in self._selected_collectors:
                uniq_command_ids = {}
                try:
                    # if the user enters q, then we quit collection
                    if self._ui_manager and self._ui_manager.quit_collection:
                        break
                    self.current_collector = collector
                    with self._engine.session_scope() as session:
                        try:
                            commands = []
                            # todo: update for new collector
                            if isinstance(collector.instance, DomainCollector):
                                collector_name = self._engine.get_or_create(session,
                                                                            CollectorName,
                                                                            name=collector.name,
                                                                            type=CollectorType.domain)
                                commands = commands + self._create_domain_name_commands(session, collector_name)
                            if isinstance(collector.instance, HostCollector):
                                collector_name = self._engine.get_or_create(session,
                                                                            CollectorName,
                                                                            name=collector.name,
                                                                            type=CollectorType.host)
                                commands = commands + self._create_host_commands(session, collector_name)
                            if isinstance(collector.instance, ServiceCollector):
                                collector_name = self._engine.get_or_create(session,
                                                                            CollectorName,
                                                                            name=collector.name,
                                                                            type=CollectorType.service)
                                commands = commands + self._create_service_commands(session, collector_name)
                            if isinstance(collector.instance, Ipv4NetworkCollector):
                                collector_name = self._engine.get_or_create(session,
                                                                            CollectorName,
                                                                            name=collector.name,
                                                                            type=CollectorType.ipv4_network)
                                commands = commands + self._create_ipv4_network_commands(session, collector_name)
                            if isinstance(collector.instance, HostNameServiceCollector):
                                collector_name = self._engine.get_or_create(session,
                                                                            CollectorName,
                                                                            name=collector.name,
                                                                            type=CollectorType.host_name_service)
                                commands = commands + self._create_host_name_service_commands(session, collector_name)
                            if isinstance(collector.instance, EmailCollector):
                                collector_name = self._engine.get_or_create(session,
                                                                            CollectorName,
                                                                            name=collector.name,
                                                                            type=CollectorType.email)
                                commands = commands + self._create_email_commands(session, collector_name)
                            if isinstance(collector.instance, CompanyCollector):
                                collector_name = self._engine.get_or_create(session,
                                                                            CollectorName,
                                                                            name=collector.name,
                                                                            type=CollectorType.company)
                                commands = commands + self._create_company_commands(session, collector_name)
                            self._engine.get_or_create(session, Source, name=collector.name)
                            for item in commands:
                                if (item.status_value <= CommandStatus.collecting.value or
                                    (self._restart_statuses and
                                     item.status in self._restart_statuses)) and item.id not in uniq_command_ids:
                                    uniq_command_ids[item.id] = CommandQueueItem(item.id,
                                                                                 self.current_collector.instance.timeout,
                                                                                 self.current_collector.instance.active_collector)
                        except Exception as ex:
                            if debug:
                                raise ex
                            session.rollback()
                            self.log_exception(ex)
                            break
                    if self._command_queue:
                        for key, value in uniq_command_ids.items():
                            self._command_queue.put(value)
                        self._command_queue.join()
                except Exception as ex:
                    if debug:
                        raise ex
                    self.log_exception(ex)
                    self.current_collector = None
                self.current_collector_index += 1
            continue_collection = self._ui_manager and not self._ui_manager.quit_collection and self._continue_execution
            if continue_collection:
                time.sleep(2)
        if self._ui_manager:
            self._ui_manager.notify_finished()

    def _verify_command(self, commands: List[Command]):
        if commands and commands[0].os_command and \
                not os.path.isfile(commands[0].os_command[0]):
            raise FileNotFoundError(
                "the command '{}' does not exist!".format(commands[0].os_command[0]))

    def _create_ipv4_network_commands(self, session, collector_name: CollectorName) -> List[Command]:
        """This method creates all OS commands that rely on IPv4 network information"""
        commands = []
        q = session.query(Network) \
            .join((Workspace, Network.workspace)) \
            .filter(Workspace.name == self._workspace)
        for ipv4_network in q:
            if ipv4_network.is_processable(self._included_items,
                                           self._excluded_items,
                                           self.current_collector.instance.active_collector) and \
                    (self._vhost is None or self._vhost == VhostChoice.all or
                     not isinstance(self.current_collector.instance, DomainCollector)):
                commands = commands + self.current_collector.instance.create_ipv4_network_commands(session,
                                                                                                   ipv4_network,
                                                                                                   collector_name)
                self._verify_command(commands)
        return commands

    def _create_domain_name_commands(self, session, collector_name: CollectorName) -> List[Command]:
        """This method creates all OS commands that rely on domain information"""
        commands = []
        q = session.query(HostName) \
            .join((DomainName, HostName.domain_name)) \
            .join((Workspace, DomainName.workspace)) \
            .filter(Workspace.name == self._workspace)
        for host_name in q:
            if not isinstance(self.current_collector.instance, Ipv4NetworkCollector):
                if host_name.is_processable(included_items=self._included_items,
                                            excluded_items=self._excluded_items,
                                            collector_type=CollectorType.domain,
                                            active_collector=self.current_collector.instance.active_collector):
                    commands = commands + self.current_collector.instance.create_domain_commands(session,
                                                                                                 host_name,
                                                                                                 collector_name)
                    self._verify_command(commands)
            elif self._vhost:
                if host_name.is_processable(included_items=self._included_items,
                                            excluded_items=self._excluded_items,
                                            collector_type=CollectorType.host_name_service,
                                            active_collector=self.current_collector.instance.active_collector):
                    commands = commands + self.current_collector.instance.create_domain_commands(session,
                                                                                                 host_name,
                                                                                                 collector_name)
                    self._verify_command(commands)
        return commands

    def _create_host_commands(self, session, collector_name: CollectorName) -> List[Command]:
        """This method creates all OS commands that rely on host information (e.g. IP address)"""
        commands = []
        q = session.query(Host) \
            .join((Workspace, Host.workspace)) \
            .filter(Workspace.name == self._workspace)
        for host in q:
            if host.is_processable(self._included_items,
                                   self._excluded_items,
                                   self.current_collector.instance.active_collector):
                commands = commands + self.current_collector.instance.create_host_commands(session,
                                                                                           host,
                                                                                           collector_name)
                self._verify_command(commands)
        return commands

    def _create_service_commands(self,
                                 session,
                                 collector_name: CollectorName) -> List[Command]:
        """This method creates all OS commands that rely on service information (e.g. port number)"""
        commands = []
        # services for a host
        q = session.query(Service) \
            .join((Host, Service.host)) \
            .join((Workspace, Host.workspace)) \
            .filter(Workspace.name == self._workspace)
        for service in q:
            if service.is_open(self._strict_open) and \
                    service.host.is_processable(self._included_items,
                                                self._excluded_items,
                                                self.current_collector.instance.active_collector) and \
                    (not self._vhost or self._vhost == VhostChoice.all or
                     not isinstance(self.current_collector.instance, HostNameServiceCollector)):
                commands = commands + self.current_collector.instance.create_service_commands(session,
                                                                                              service,
                                                                                              collector_name)
                self._verify_command(commands)
        return commands

    def _create_host_name_service_commands(self,
                                           session,
                                           collector_name: CollectorName) -> List[Command]:
        """This method creates all OS commands that rely on service information (e.g. port number)"""
        commands = []
        q = session.query(Service) \
            .join((HostName, Service.host_name)) \
            .join((DomainName, HostName.domain_name)) \
            .join((Workspace, DomainName.workspace)) \
            .filter(Workspace.name == self._workspace)
        for service in q.all():
            if service.is_open(self._strict_open) and \
                    service.host_name.is_processable(self._included_items,
                                                     self._excluded_items,
                                                     CollectorType.host_name_service,
                                                     self.current_collector.instance.active_collector) and self._vhost:
                commands = commands + self.current_collector.instance.create_host_name_service_commands(session,
                                                                                                        service,
                                                                                                        collector_name)
                self._verify_command(commands)
        return commands

    def _create_email_commands(self,
                               session,
                               collector_name: CollectorName) -> List[Command]:
        """This method creates all OS commands that rely on email information (e.g. port number)"""
        commands = []
        q = session.query(Email) \
            .join((HostName, Email.host_name)) \
            .join((DomainName, HostName.domain_name)) \
            .join((Workspace, DomainName.workspace)) \
            .filter(Workspace.name == self._workspace)
        for email in q:
            if email.is_processable(self._included_items,
                                    self._excluded_items,
                                    self.current_collector.instance.active_collector):
                commands = commands + self.current_collector.instance.create_email_commands(session,
                                                                                            email,
                                                                                            collector_name)
                self._verify_command(commands)
        return commands

    def _create_company_commands(self,
                                 session,
                                 collector_name: CollectorName) -> List[Command]:
        """This method creates all OS commands that rely on email information (e.g. port number)"""
        commands = []
        q = session.query(Company) \
            .join((Workspace, Company.workspace)) \
            .filter(Workspace.name == self._workspace)
        for company in q:
            if company.is_processable(self._included_items,
                                      self._excluded_items,
                                      self.current_collector.instance.active_collector):
                commands = commands + self.current_collector.instance.create_company_commands(session,
                                                                                              company,
                                                                                              collector_name)
                self._verify_command(commands)
        return commands

    def _analyze(self):
        """Analyzes all collected information"""
        if self._ui_manager and not self.print_commands:
            self._ui_manager.start_ui()
            self._ui_manager.wait_for_start()
        self.current_collector_index = 0
        for argument in self._selected_collectors:
            try:
                # if the user enters q, then we quit collection
                if self._ui_manager and self._ui_manager.quit_collection:
                    break
                self.current_collector = argument
                with self._engine.session_scope() as session:
                    # todo: update for new collector
                    # Analyze host and service collectors
                    for command in session.query(Command) \
                         .join((CollectorName, Command.collector_name)) \
                         .join((Host, Command.host)) \
                         .join((Workspace, Host.workspace)) \
                         .filter(and_(Workspace.name == self._workspace,
                                      CollectorName.name == argument.name)).all():
                        if command.host.is_processable(self._included_items,
                                                       self._excluded_items):
                            try:
                                source = self._engine.get_or_create(session, Source, name=command.collector_name.name)
                                report_item = BaseCollector.get_report_item(command)
                                argument.instance.verify_command_execution(session,
                                                                           command=command,
                                                                           source=source,
                                                                           report_item=report_item)
                            except Exception as e:
                                session.rollback()
                                self.log_exception(e)
                    # Analyze host name and host name/service collectors
                    for command in session.query(Command) \
                         .join((CollectorName, Command.collector_name)) \
                         .join((HostName, Command.host_name)) \
                         .join((DomainName, HostName.domain_name)) \
                         .join((Workspace, DomainName.workspace)) \
                         .filter(and_(Workspace.name == self._workspace,
                                      CollectorName.name == argument.name)).all():
                        if command.host_name.is_processable(self._included_items,
                                                            self._excluded_items,
                                                            CollectorType.host_name_service):
                            try:
                                source = self._engine.get_or_create(session, Source, name=command.collector_name.name)
                                report_item = BaseCollector.get_report_item(command)
                                argument.instance.verify_command_execution(session,
                                                                           command=command,
                                                                           source=source,
                                                                           report_item=report_item)
                            except Exception as e:
                                session.rollback()
                                self.log_exception(e)
                    # Analyze network collectors
                    for command in session.query(Command) \
                         .join((CollectorName, Command.collector_name)) \
                         .join((Network, Command.ipv4_network)) \
                         .join((Workspace, Network.workspace)) \
                         .filter(and_(Workspace.name == self._workspace,
                                      CollectorName.name == argument.name)).all():
                        if command.ipv4_network.is_processable(self._included_items,
                                                               self._excluded_items):
                            try:
                                source = self._engine.get_or_create(session, Source, name=command.collector_name.name)
                                report_item = BaseCollector.get_report_item(command)
                                argument.instance.verify_command_execution(session,
                                                                           command=command,
                                                                           source=source,
                                                                           report_item=report_item)
                            except Exception as e:
                                session.rollback()
                                self.log_exception(e)
                    # Analyze email collectors
                    for command in session.query(Command) \
                         .join((CollectorName, Command.collector_name)) \
                         .join((Email, Command.email)) \
                         .join((HostName, Email.host_name)) \
                         .join((DomainName, HostName.domain_name)) \
                         .join((Workspace, DomainName.workspace)) \
                         .filter(and_(Workspace.name == self._workspace,
                                      CollectorName.name == argument.name)).all():
                        if command.email.is_processable(self._included_items,
                                                        self._excluded_items):
                            try:
                                source = self._engine.get_or_create(session, Source, name=command.collector_name.name)
                                report_item = BaseCollector.get_report_item(command)
                                argument.instance.verify_command_execution(session,
                                                                           command=command,
                                                                           source=source,
                                                                           report_item=report_item)
                            except Exception as e:
                                session.rollback()
                                self.log_exception(e)
                    # Analyze company collectors
                    for command in session.query(Command) \
                         .join((CollectorName, Command.collector_name)) \
                         .join((Company, Command.company)) \
                         .join((Workspace, Company.workspace)) \
                         .filter(and_(Workspace.name == self._workspace,
                                      CollectorName.name == argument.name)).all():
                        if command.company.is_processable(self._included_items,
                                                          self._excluded_items):
                            try:
                                source = self._engine.get_or_create(session, Source, name=command.collector_name.name)
                                report_item = BaseCollector.get_report_item(command)
                                argument.instance.verify_command_execution(session,
                                                                           command=command,
                                                                           source=source,
                                                                           report_item=report_item)
                            except Exception as e:
                                session.rollback()
                                self.log_exception(e)
            except Exception as ex:
                self.log_exception(ex)
                self.current_collector = None
            self.current_collector_index += 1
        self._ui_manager.notify_finished()

    def run(self) -> None:
        if self._analyze_results:
            self._analyze()
        else:
            self._create()


class CollectorConsumer(Thread):
    """This class executes all commands"""
    THREAD_COUNT = 0

    def __init__(self,
                 engine: Engine,
                 commands_queue: Queue,
                 producer_thread: CollectorProducer):
        super().__init__(daemon=True)
        self._engine = engine
        self._commands_queue = commands_queue
        self._producer_thread = producer_thread
        CollectorConsumer.THREAD_COUNT += 1
        self._id = CollectorConsumer.THREAD_COUNT
        self._current_host = None
        self._current_service = None
        self._current_start_time = None
        self._current_username = None
        self._ui_manager = producer_thread.ui_manager
        self._consumer_status_lock = Lock()
        self._current_process = None
        self._delay = producer_thread.delay
        if self._ui_manager and not self._producer_thread.print_commands:
            self._ui_manager.add_consumer_thread(self)

    def __repr__(self):
        with self._consumer_status_lock:
            collector_name = self._producer_thread.current_collector.name\
                if self._producer_thread.current_collector else "n/a"
            current_host = self._current_host if self._current_host else "n/a"
            current_host = current_host if len(current_host) < 25 else current_host[:24]
            current_service = self._current_service if self._current_service else "n/a"
            current_username = self._current_username if self._current_username else "n/a"
            duration = CollectorConsumer.strfdelta(datetime.utcnow() - self._current_start_time)\
                if self._current_start_time else "n/a"
            return "thread {:3d} ({:^6}) - [{}] {:25}  {:<9} - {}".format(self._id,
                                                                          current_username,
                                                                          collector_name,
                                                                          current_host,
                                                                          current_service,
                                                                          duration)

    @staticmethod
    def strfdelta(tdelta, fmt="{hours:02d}:{minutes:02d}:{seconds:02d}"):
        d = {"days": tdelta.days}
        d["hours"], rem = divmod(tdelta.seconds, 3600)
        d["minutes"], d["seconds"] = divmod(rem, 60)
        return fmt.format(**d)

    def kill_current_command(self) -> None:
        """
        This method kills the currently running OS command.using SIGTERM
        :return:
        """
        if self._current_process:
            self._current_process.kill()

    def terminate_current_command(self) -> None:
        """
        This method kills the currently running OS command.using SIGKILL
        :return:
        """
        if self._current_process:
            self._current_process.terminate()

    def run(self):
        while True:
            try:
                self._current_process = None
                command_item = self._commands_queue.get()
                # Check maximum number of threads
                if 0 < self._producer_thread.current_collector.instance.max_threads >= self._id or \
                        self._producer_thread.current_collector.instance.max_threads == 0:
                    executed_command = True
                    # Obtain the command to be executed and update its status to "in process"
                    with self._engine.session_scope() as session:
                        command = session.query(Command).filter_by(id=command_item.command_id).one()
                        working_directory = command.working_directory
                        username = command.username
                        os_command = command.os_command_substituted
                        self._current_username = username
                        if self._producer_thread.print_commands:
                            self._ui_manager.set_message(command.os_command_string)
                        elif not self._producer_thread.current_collector.instance.start_command_execution(session,
                                                                                                          command):
                            # Before we execute the command, we check whether it should be executed
                            os_command = []
                            command.status = CommandStatus.terminated
                            command.stop_time = datetime.utcnow()
                            executed_command = False
                        else:
                            # If the command does not require root privileges, then we have to udpate the command's
                            # input and output file permissions
                            command.update_file_permissions()
                            command.start_time = datetime.utcnow()
                            command.status = CommandStatus.collecting
                            # we reset the commands content
                            command.reset()
                            with self._consumer_status_lock:
                                # todo: update for new collector
                                if (isinstance(self._producer_thread.current_collector.instance, ServiceCollector) or
                                    isinstance(self._producer_thread.current_collector.instance, HostCollector)) and \
                                        command.host is not None:
                                    self._current_host = command.host.ip
                                    protocol, port = [command.service.protocol.name.lower(), command.service.port] \
                                        if command.service else ["-", "-"]
                                    self._current_service = "{}/{}".format(protocol, port)
                                elif isinstance(self._producer_thread.current_collector.instance,
                                                HostNameServiceCollector):
                                    self._current_host = command.host_name.full_name
                                    protocol, port = [command.service.protocol.name.lower(), command.service.port] \
                                        if command.service else ["-", "-"]
                                    self._current_service = "{}/{}".format(protocol, port)
                                elif isinstance(self._producer_thread.current_collector.instance, DomainCollector) and \
                                        command.host_name is not None:
                                    self._current_host = command.host_name.full_name
                                    self._current_service = "n/a"
                                elif isinstance(self._producer_thread.current_collector.instance,
                                                Ipv4NetworkCollector) and \
                                        command.ipv4_network is not None:
                                    self._current_host = command.ipv4_network.network
                                    self._current_service = "n/a"
                                elif isinstance(self._producer_thread.current_collector.instance,
                                                EmailCollector):
                                    self._current_host = command.email.email_address
                                    self._current_service = "n/a"
                                elif isinstance(self._producer_thread.current_collector.instance,
                                                CompanyCollector):
                                    self._current_host = command.company.name
                                    self._current_service = "n/a"
                                else:
                                    self._current_host = "undefined"
                                    self._current_service = "n/a"
                                self._current_start_time = command.start_time
                    if not self._producer_thread.print_commands and os_command:
                        # Now we run the process
                        self._current_process = self._producer_thread.\
                            current_collector.instance.execution_class(os_command,
                                                                       cwd=working_directory,
                                                                       stdout=subprocess.PIPE,
                                                                       stderr=subprocess.PIPE,
                                                                       username=username)
                        self._current_process.start()
                        self._current_process.wait(timeout=command_item.timeout)
                        if not self._current_process.killed:
                            self._current_process.stop_time = datetime.utcnow()
                            status_id = CommandStatus.completed
                        else:
                            self.terminate_current_command()
                            self._current_process.stop_time = datetime.utcnow()
                            status_id = CommandStatus.terminated
                        # Now we store the command's results in the database
                        try:
                            self._producer_thread.current_collector.instance.process_command_results(self._engine,
                                                                                                     command_item.command_id,
                                                                                                     status_id,
                                                                                                     self._current_process)
                        except sqlalchemy.orm.exc.NoResultFound as ex:
                            self._ui_manager.set_message("no command with ID {} found".format(command_item.command_id))
                            logger.critical("no command with ID {} found (see the following stacktrade)"
                                            .format(command_item.command_id))
                            self._producer_thread.log_exception(ex)
                        except ExecutionFailedException as ex:
                            command.status = CommandStatus.failed
                            self._producer_thread.log_exception(ex)
                        except Exception as ex:
                            self._producer_thread.log_exception(ex)
                        self._current_process.close()
                    with self._consumer_status_lock:
                        self._current_host = None
                        self._current_service = None
                        self._current_start_time = None
                    self._commands_queue.task_done()
                    # If the user entered q, then we quit the collection
                    if self._ui_manager and self._ui_manager.quit_collection:
                        return
                    if self._producer_thread.current_collector and \
                            self._producer_thread.current_collector.instance and executed_command:
                        self._producer_thread.current_collector.instance.sleep()
                else:
                    self._commands_queue.put(command_item)
                    self._commands_queue.task_done()
                    time.sleep(1)
            except Exception as ex:
                self._producer_thread.log_exception(ex)
