#!/usr/bin/python3
"""
this file implements core functionalities to test collectors
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

import queue
from typing import List
from typing import Dict
from database.utils import Engine
from database.model import Command
from database.model import Source
from view.core import ReportItem
from collectors.os.modules.core import BaseCollector
from collectors.os.collector import CollectorProducer
from collectors.os.collector import CollectorConsumer
from collectors.os.collector import ArgParserModule
from unittests.tests.core import BaseKisTestCase
from sqlalchemy.orm.session import Session


class BaseCollectorTestCase(BaseKisTestCase):
    """
    This class represents the base class for all collector tests
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)


class CollectorProducerTestSuite:
    """
    This class can be used to create a collector producer for unittesting
    """

    def __init__(self, engine: Engine, arguments: Dict[str, str]):
        self._engine = engine
        self._arguments = arguments

    def create_collector_instance(self,
                                  arg_parse_module: ArgParserModule = None,
                                  collector_class: type = None,
                                  collector_name: str = None) -> BaseCollector:
        """
        This method creates a collector instance based on the given class and name
        """
        if arg_parse_module:
            arg_parse_module.create_instance(**self._arguments)
            result = arg_parse_module
        else:
            result = collector_class(engine=self._engine, name=collector_name, **self._arguments)
        return result

    def create_arg_parse_module(self, collector_class, collector_name: str) -> ArgParserModule:
        """
        This method creates an instance of class ArgParserModule based on the given class and name
        """
        instance = self.create_collector_instance(collector_class=collector_class,
                                                  collector_name=collector_name)
        return ArgParserModule(arg_option=collector_name,
                               collector_class=collector_class,
                               instance=instance)

    def create_collector_producer(self, command_queue: queue.Queue = None) -> CollectorProducer:
        """
        This method creates an instance of the CollectorProducer class
        """
        return CollectorProducer(engine=self._engine,
                                 command_queue=command_queue,
                                 **self._arguments)

    def verify_results(self,
                       session: Session,
                       arg_parse_module: ArgParserModule,
                       command: Command,
                       source: Source = None,
                       report_item: ReportItem = None) -> None:
        """
        This method calls the verify_results method of the given collector to verify the results of the given command
        """
        if not arg_parse_module.instance:
            arg_parse_module.create_instance(engine=self._engine, **self._arguments)
        arg_parse_module.instance.verify_results(session=session,
                                                 command=command,
                                                 source=source,
                                                 report_item=report_item)

    def create_commands(self, collectors: List[ArgParserModule]):
        """
        Creates commands based on the provided list of collectors
        """
        for module in collectors:
            if not module.instance:
                module.create_instance(engine=self._engine, **self._arguments)
        producer = self.create_collector_producer()
        producer.selected_collectors.extend(collectors)
        producer._create()

    def create_execute_commands(self, collectors: List[ArgParserModule]):
        """
        Creates and executes commands based on the provided list of collectors
        """
        command_queue = queue.Queue()
        for module in collectors:
            if not module.instance:
                module.create_instance(engine=self._engine, **self._arguments)
        producer = self.create_collector_producer(command_queue=command_queue)
        producer.selected_collectors.extend(collectors)
        consumer = CollectorConsumer(engine=self._engine, commands_queue=command_queue, producer_thread=producer)
        consumer.start()
        producer.start()
        producer.join()
