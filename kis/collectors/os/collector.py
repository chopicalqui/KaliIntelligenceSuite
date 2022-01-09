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

import enum
import importlib
import os
import pkgutil
import subprocess
import logging
import sqlalchemy
import time
import sys
import stat
import traceback
from argparse import _ArgumentGroup
from queue import Queue
from datetime import datetime
from threading import Lock
from threading import Thread
from database.config import Collector
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
from database.model import VhostChoice
from database.utils import Engine
from sqlalchemy import and_
from typing import Dict
from typing import List
from collectors.core import BaseUtils
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
from sqlalchemy.orm.session import Session

logger = logging.getLogger('collector')


class CollectionStatus(enum.Enum):
    not_started = enum.auto()
    running = enum.auto()
    stopped = enum.auto()
    finished = enum.auto()


class CollectorTypeCommandCreationMethodMapping:
    """
    This class contains the mapping between the given collector type and the method.
    """

    def __init__(self, collector_type: CollectorType, method_name: str, enabled: bool = True):
        self.collector_type = collector_type
        self.method_name = method_name
        self.enabled = enabled


class ArgParserModule:
    """This class manages the mapping between argparser arguments and the underlying collector classes."""

    def __init__(self, arg_option: str,
                 collector_class: BaseCollector,
                 instance: BaseCollector = None):
        self._arg_option = arg_option
        self._collector_class = collector_class
        self._instance = instance
        # List of tuples containing the CollectorName.type information as the first element and the corresponding
        # collector creation method (type str) as the second element.
        self.collector_type_info = []

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


class CollectorProducer(Thread):
    """This class loads all modules and creates the desired commands."""

    def __init__(self,
                 engine: Engine,
                 command_queue: Queue = None,
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
        self._collection_status_lock = Lock()
        self._collection_status = CollectionStatus.not_started
        self._consumer_threads_lock = Lock()
        self._consumer_threads = []
        self.consoles = []
        # This is just for UI purposes.
        self._remaining_collectors_lock = Lock()
        self._remaining_collectors = []

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
    def collection_status(self) -> CollectionStatus:
        with self._collection_status_lock:
            return self._collection_status

    @collection_status.setter
    def collection_status(self, value: CollectionStatus):
        with self._collection_status_lock:
            self._collection_status = value

    @property
    def consumer_threads(self) -> list:
        with self._consumer_threads_lock:
            return self._consumer_threads

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
    def analyze_results(self) -> bool:
        return self._analyze_results

    @property
    def delay(self) -> Delay:
        if not self._delay:
            self._delay = Delay(self._delay_min, self._delay_max, self._print_commands, self._analyze_results)
        return self._delay

    @property
    def remaining_collectors(self) -> list:
        """
        This property returns the list of remaining collectors that have not been processed.
        """
        with self._remaining_collectors_lock:
            return list(self._remaining_collectors)

    def register_console(self, console) -> None:
        """
        This method is used by console implementations to register them for notification.
        """
        self.consoles.append(console)

    def add_consumer_thread(self):
        """
        This method adds a new consumer thread to speedup collection.
        """
        thread = CollectorConsumer(self._engine, self._command_queue, self)
        thread.start()
        with self._consumer_threads_lock:
            self._consumer_threads.append(thread)

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
        kwargs = {}
        to_instantiate = []
        for key, value in args.items():
            # If the key is in the dictionary, then we deal with a collector class, which we have to instantiate
            if value and key in self._collector_classes:
                to_instantiate.append(self._collector_classes[key])
            elif key == "threads" and value > 0:
                self._number_of_threads = value
            elif key == "workspace" and value:
                self._workspace = value
            elif key in ["print-commands", "print_commands"] and value:
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
            elif key == ["force-delay-min", "force_delay_min"] and value:
                self._delay_min = value
            elif key == ["force-delay-max", "force_delay_max"] and value:
                self._delay_max = value
            elif key == "vhost" and value:
                self._vhost = VhostChoice[value]
            elif key == "continue" and value:
                self._continue_execution = value
            elif key == ["output-dir", "output_dir"] and value:
                os.chmod(value, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
            kwargs[key.replace("-", "_")] = value
        with self._engine.session_scope() as session:
            for item in to_instantiate:
                item.create_instance(engine=self._engine, **kwargs)
                item.collector_type_info = self.get_collector_types(item, vhost=self._vhost)
                self._selected_collectors.append(item)
                for mapping in item.collector_type_info:
                    BaseUtils.add_collector_name(session=session,
                                                 name=item.name,
                                                 type=mapping.collector_type,
                                                 priority=item.instance.priority)
        self._selected_collectors.sort()
        # Register all selected collectors
        for item in self._selected_collectors:
            with self._remaining_collectors_lock:
                self._remaining_collectors.append(item.name)

    def clear_commands_queue(self):
        """
        This method empties the command queue
        :return:
        """
        if self._command_queue:
            while self._command_queue.qsize() > 0:
                self._command_queue.get(block=False)
                self._command_queue.task_done()

    @staticmethod
    def get_collector_types(collector: ArgParserModule, vhost: VhostChoice) -> list:
        """
        This method determines the collector types of the given ArgParserModule object in combination with the vhost
        setting.
        :return: List of tuples containing the collector type as the first element and the name of the command creation
        method as the second element.
        """
        # todo: update for new collector
        mapping = {CollectorType.domain: CollectorTypeCommandCreationMethodMapping(CollectorType.domain,
                                                                                   "_create_domain_name_commands"),
                   CollectorType.host: CollectorTypeCommandCreationMethodMapping(CollectorType.host,
                                                                                 "_create_host_commands"),
                   CollectorType.host_service: CollectorTypeCommandCreationMethodMapping(CollectorType.host_service,
                                                                                    "_create_service_commands"),
                   CollectorType.network: CollectorTypeCommandCreationMethodMapping(CollectorType.network,
                                                                                         "_create_ipv4_network_commands"),
                   CollectorType.vhost_service: CollectorTypeCommandCreationMethodMapping(CollectorType.vhost_service,
                                                                                              "_create_host_name_service_commands"),
                   CollectorType.email: CollectorTypeCommandCreationMethodMapping(CollectorType.email,
                                                                                  "_create_email_commands"),
                   CollectorType.company: CollectorTypeCommandCreationMethodMapping(CollectorType.company,
                                                                                    "_create_company_commands")}
        result = []
        # todo: update for new collector
        # Test for vhost settings
        if isinstance(collector.instance, ServiceCollector) and isinstance(collector.instance, HostNameServiceCollector):
            # If the vhost argument has not been specified or is all, then service collectors are used.
            mapping_object = mapping[CollectorType.host_service]
            mapping_object.enabled = not vhost or vhost == VhostChoice.all
            result.append(mapping_object)
            # If the vhost argument is set to domain, then only vhost service collectors are allowed.
            mapping_object = mapping[CollectorType.vhost_service]
            mapping_object.enabled = vhost and (vhost == VhostChoice.domain or vhost == VhostChoice.all)
            result.append(mapping_object)
        # Test for vhost settings: Special case for BurpSuite collector, which submits scans per host to reduce scanning
        # tasks in Burp.
        elif isinstance(collector.instance, DomainCollector) and isinstance(collector.instance, HostCollector):
            # If the vhost argument has not been specified or is all, then service collectors are used.
            mapping_object = mapping[CollectorType.host]
            mapping_object.enabled = not vhost or vhost == VhostChoice.all
            result.append(mapping_object)
            # If the vhost argument is set to domain, then only vhost service collectors are allowed.
            mapping_object = mapping[CollectorType.domain]
            mapping_object.enabled = vhost and (vhost == VhostChoice.domain or vhost == VhostChoice.all)
            result.append(mapping_object)
        elif isinstance(collector.instance, HostNameServiceCollector) and \
                not isinstance(collector.instance, ServiceCollector):
            raise NotImplementedError("collector '{}' is a HostNameServiceCollector but not a ServiceCollector. "
                                      "this is most likely a coding error.")
        else:
            if isinstance(collector.instance, DomainCollector):
                result.append(mapping[CollectorType.domain])
            if isinstance(collector.instance, HostCollector):
                result.append(mapping[CollectorType.host])
            if isinstance(collector.instance, ServiceCollector):
                result.append(mapping[CollectorType.host_service])
            if isinstance(collector.instance, Ipv4NetworkCollector):
                result.append(mapping[CollectorType.network])
            if isinstance(collector.instance, EmailCollector):
                result.append(mapping[CollectorType.email])
            if isinstance(collector.instance, CompanyCollector):
                result.append(mapping[CollectorType.company])
            if len(result) > 1 or len(result) == 0:
                raise NotImplementedError("collector '{}' has the following types, which "
                                          "is not implemented: {}".format(collector.name,
                                                                          ", ".join([item[0].name for item in result])))
        return result

    def _create(self, debug: bool = False):
        """This method creates all OS commands"""
        self._engine.delete_incomplete_commands(self._workspace)
        continue_collection = True
        while continue_collection:
            self.current_collector_index = 0
            for collector in self._selected_collectors:
                uniq_command_ids = {}
                try:
                    # if the user enters q, then we quit collection
                    if self.collection_status == CollectionStatus.stopped:
                        break
                    self.current_collector = collector
                    collector_types = [item.collector_type for item in collector.collector_type_info]
                    with self._engine.session_scope() as session:
                        try:
                            commands = []
                            for mapping in collector.collector_type_info:
                                # Obtain the collector name object from the database (the table was already populated
                                # during the initialization of this object)
                                collector_name = BaseUtils.add_collector_name(session=session,
                                                                              name=collector.name,
                                                                              type=mapping.collector_type,
                                                                              priority=collector.instance.priority)
                                # Create the OS commands
                                if mapping.enabled:
                                    command_creation_method = getattr(self, mapping.method_name)
                                    commands += command_creation_method(session, collector_name, collector_types)
                            BaseUtils.add_source(session=session, name=collector_name.name)
                            # Populate the queue
                            for item in commands:
                                if (item.status_value <= CommandStatus.collecting.value or
                                    (self._restart_statuses and
                                     item.status in self._restart_statuses)) and item.id not in uniq_command_ids:
                                    uniq_command_ids[item.id] = CommandQueueItem(item.id,
                                                                                 self.current_collector.instance.timeout,
                                                                                 self.current_collector.instance.active_collector)
                        except Exception as ex:
                            traceback.print_exc(file=sys.stderr)
                            session.rollback()
                            self.log_exception(ex)
                            break
                    if self._command_queue:
                        # We remove already completed collectors from list
                        with self._remaining_collectors_lock:
                            if collector.name in self._remaining_collectors:
                                index = self._remaining_collectors.index(collector.name)
                                self._remaining_collectors = self._remaining_collectors[index:]
                        # We add new command IDs to the queue
                        for key, value in uniq_command_ids.items():
                            self._command_queue.put(value)
                        self._command_queue.join()
                except Exception as ex:
                    traceback.print_exc(file=sys.stderr)
                    self.log_exception(ex)
                    self.current_collector = None
                self.current_collector_index += 1
            continue_collection = self.collection_status == CollectionStatus.running and self._continue_execution
            if continue_collection:
                time.sleep(2)
        if not self.print_commands:
            for console in self.consoles:
                console.notify_finished()

    def _verify_command(self, commands: List[Command]):
        if commands and commands[0].os_command and \
                not os.path.isfile(commands[0].os_command[0]):
            raise FileNotFoundError(
                "the command '{}' does not exist!".format(commands[0].os_command[0]))

    def _create_ipv4_network_commands(self,
                                      session: Session,
                                      collector_name: CollectorName,
                                      collector_types: list) -> List[Command]:
        """This method creates all OS commands that rely on IPv4 network information"""
        commands = []
        q = session.query(Network) \
            .join((Workspace, Network.workspace)) \
            .filter(Workspace.name == self._workspace)
        for ipv4_network in q:
            if ipv4_network.is_processable(self._included_items,
                                           self._excluded_items,
                                           self.current_collector.instance.active_collector):
                commands = commands + self.current_collector.instance.create_ipv4_network_commands(session,
                                                                                                   ipv4_network,
                                                                                                   collector_name)
                self._verify_command(commands)
        return commands

    def _create_domain_name_commands(self,
                                     session: Session,
                                     collector_name: CollectorName,
                                     collector_types: list) -> List[Command]:
        """This method creates all OS commands that rely on domain information"""
        commands = []
        q = session.query(HostName) \
            .join((DomainName, HostName.domain_name)) \
            .join((Workspace, DomainName.workspace)) \
            .filter(Workspace.name == self._workspace)
        for host_name in q:
            collector_type_count = len(collector_types)
            if collector_type_count == 1:
                if host_name.is_processable(included_items=self._included_items,
                                            excluded_items=self._excluded_items,
                                            collector_type=CollectorType.domain,
                                            active_collector=self.current_collector.instance.active_collector):
                    commands = commands + self.current_collector.instance.create_domain_commands(session,
                                                                                                 host_name,
                                                                                                 collector_name)
                    self._verify_command(commands)
            elif collector_type_count == 2:
                # This case address the collector httpburpsuiteprofessional
                if CollectorType.domain in collector_types and \
                    CollectorType.host in collector_types and \
                    host_name.is_processable(included_items=self._included_items,
                                             excluded_items=self._excluded_items,
                                             collector_type=CollectorType.vhost_service,
                                             active_collector=self.current_collector.instance.active_collector):
                    commands = commands + self.current_collector.instance.create_domain_commands(session,
                                                                                                 host_name,
                                                                                                 collector_name)
            else:
                raise NotImplementedError("this collector '{}' implements the following collector types, which is not "
                                          "implemented: {}".format(collector_name,
                                                                   ", ".join([item.name for item in collector_types])))
        return commands

    def _create_host_commands(self,
                              session: Session,
                              collector_name: CollectorName,
                              collector_types: list) -> List[Command]:
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
                                 session: Session,
                                 collector_name: CollectorName,
                                 collector_types: list) -> List[Command]:
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
                                           session: Session,
                                           collector_name: CollectorName,
                                           collector_types: list) -> List[Command]:
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
                                                     CollectorType.vhost_service,
                                                     self.current_collector.instance.active_collector) and self._vhost:
                commands = commands + self.current_collector.instance.create_host_name_service_commands(session,
                                                                                                        service,
                                                                                                        collector_name)
                self._verify_command(commands)
        return commands

    def _create_email_commands(self,
                               session: Session,
                               collector_name: CollectorName,
                               collector_types: list) -> List[Command]:
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
                                 session: Session,
                                 collector_name: CollectorName,
                                 collector_types: list) -> List[Command]:
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
        """
        Analyzes all collected information
        """
        self.current_collector_index = 0
        for argument in self._selected_collectors:
            try:
                # if the user enters q, then we quit collection
                if self.collection_status == CollectionStatus.stopped:
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
                                                            CollectorType.vhost_service):
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

    def terminate_all_processes(self) -> None:
        """
        This method kills all currently running processes.
        :return:
        """
        for thread in self.consumer_threads:
            thread.terminate_current_command()

    def stop(self) -> None:
        # Signal that collection stopped
        self.collection_status = CollectionStatus.stopped
        print("emptying command queue ...")
        self.clear_commands_queue()
        print("terminating all threads ...")
        self.terminate_all_processes()

    def run(self) -> None:
        # Signal that collection started
        self.collection_status = CollectionStatus.running

        # Start all worker threads
        for i in range(0, self.number_of_threads):
            self.add_consumer_thread()

        # Create commands or just analyse already collecte data
        if self._analyze_results:
            self._analyze()
        else:
            self._create()

        with self._consumer_threads_lock:
            self._consumer_threads = []
        if self.collection_status == CollectionStatus.running:
            self.collection_status = CollectionStatus.finished


class CollectorConsumer(Thread):
    """
    This class executes all commands
    """

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
        self._consumer_status_lock = Lock()
        self._current_process_lock = Lock()
        self._current_process = None
        self._delay = producer_thread.delay
        self._consoles = producer_thread.consoles
        self._current_os_command_lock = Lock()
        self._current_os_command = None

    def __repr__(self):
        with self._consumer_status_lock:
            collector_name = self._producer_thread.current_collector.name\
                if self._producer_thread.current_collector else "n/a"
            collector_name = collector_name if len(collector_name) < 20 else collector_name[:20]
            current_host = self._current_host if self._current_host else "n/a"
            current_service = self._current_service if self._current_service else "n/a"
            current_username = self._current_username if self._current_username else "n/a"
            duration = CollectorConsumer.strfdelta(datetime.utcnow() - self._current_start_time)\
                if self._current_start_time else "n/a"
            return "{} ({:^6}) - [{:<15}] - {:<8} - {:<9} - {}".format(self.thread_str,
                                                                       current_username,
                                                                       collector_name,
                                                                       duration,
                                                                       current_service,
                                                                       current_host)

    @property
    def current_process(self):
        with self._current_process_lock:
            return self._current_process

    @current_process.setter
    def current_process(self, value):
        with self._current_process_lock:
            self._current_process = value

    @property
    def thread_str(self) -> str:
        return "thread {:3d}".format(self._id)

    @property
    def current_os_command(self) -> str:
        with self._current_os_command_lock:
            return self._current_os_command

    @current_os_command.setter
    def current_os_command(self, value: str):
        with self._current_os_command_lock:
            self._current_os_command = value

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
        with self._current_process_lock:
            if self._current_process:
                self._current_process.kill()

    def terminate_current_command(self) -> None:
        """
        This method kills the currently running OS command.using SIGKILL
        :return:
        """
        with self._current_process_lock:
            if self._current_process:
                self._current_process.terminate()

    def run(self):
        while self._producer_thread.collection_status == CollectionStatus.running:
            try:
                self.current_process = None
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
                        os_command_str = command.os_command_string
                        self._current_username = username
                        if self._producer_thread.print_commands:
                            print(os_command_str)
                        elif not self._producer_thread.current_collector.instance.start_command_execution(session,
                                                                                                          command):
                            # Before we execute the command, we check whether it should be executed
                            os_command = None
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
                        self.current_os_command = os_command_str
                        # Now we run the process
                        self.current_process = self._producer_thread.\
                            current_collector.instance.execution_class(os_command,
                                                                       timeout=command_item.timeout,
                                                                       cwd=working_directory,
                                                                       env=self._engine.config.db_envs,
                                                                       stdout=subprocess.PIPE,
                                                                       stderr=subprocess.PIPE,
                                                                       username=username)
                        self.current_process.start()
                        self.current_process.join()
                        if not self.current_process.killed:
                            self.current_process.stop_time = datetime.utcnow()
                            status_id = CommandStatus.completed
                        else:
                            self.terminate_current_command()
                            self.current_process.stop_time = datetime.utcnow()
                            status_id = CommandStatus.terminated
                        # Now we store the command's results in the database
                        try:
                            self._producer_thread.current_collector.instance.process_command_results(self._engine,
                                                                                                     command_item.command_id,
                                                                                                     status_id,
                                                                                                     self.current_process,
                                                                                                     listeners=self._consoles)
                        except sqlalchemy.orm.exc.NoResultFound as ex:
                            print("no command with ID {} found".format(command_item.command_id))
                            logger.critical("no command with ID {} found (see the following stacktrade)"
                                            .format(command_item.command_id))
                            self._producer_thread.log_exception(ex)
                        except ExecutionFailedException as ex:
                            command.status = CommandStatus.failed
                            self._producer_thread.log_exception(ex)
                        except Exception as ex:
                            self._producer_thread.log_exception(ex)
                        self.current_process.close()
                        self.current_os_command = None
                    with self._consumer_status_lock:
                        self._current_host = None
                        self._current_service = None
                        self._current_start_time = None
                    self._commands_queue.task_done()
                    if self._producer_thread.current_collector and \
                            self._producer_thread.current_collector.instance and executed_command:
                        self._producer_thread.current_collector.instance.sleep()
                else:
                    self._commands_queue.put(command_item)
                    self._commands_queue.task_done()
                    time.sleep(1)
            except Exception as ex:
                self.current_os_command = None
                traceback.print_exc(file=sys.stderr)
                self._producer_thread.log_exception(ex)
