# -*- coding: utf-8 -*-
"""This module implements core functionality which can be used by modules that obtain information from files."""

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

import os
import xml
import logging
from sqlalchemy import and_
from sqlalchemy.orm.session import Session
from database.model import Workspace
from database.model import Host
from database.model import Service
from database.model import Source
from database.model import ServiceState
from collectors.core import DomainUtils
from collectors.core import IpUtils
from view.core import ReportItem
from typing import List

logger = logging.getLogger("filesystem.core")


class BaseDatabaseImporter:
    """
    Base class to import any scan results into database.
    """

    def __init__(self,
                 session: Session,
                 workspace: Workspace,
                 input_files: List[str],
                 source: str,
                 stdout = None,
                 report_item: ReportItem = None,
                 service_states: List[ServiceState] = None,
                 **kwargs):
        """

        :param session: The database session used to import the data
        :param workspace: The project into which the data shall be imported
        :param input_files: The list of XML file names that shall be imported
        :param source: The source application that created the files to be imported
        :param service_states: Only import hosts and services that one of the given ServiceStates
        """
        self._service_states = service_states if service_states else list(ServiceState)
        self._session = session
        self._workspace = workspace
        self._input_files = input_files
        self._source = source
        self._stdout = stdout
        self._domain_utils = DomainUtils()
        self._ip_utils = IpUtils()
        self._report_item = report_item
        for input_file in self._input_files:
            if not os.path.exists(input_file) or not os.path.isfile(input_file):
                raise FileNotFoundError("the file '{}' does not exist or is not a file!".format(input_file))

    def run(self) -> None:
        """This method imports the given input files into the database"""
        for input_file in self._input_files:
            try:
                print("[*] importing XML file: {}".format(input_file))
                self._import_file(input_file)
                self._session.commit()
            except xml.etree.ElementTree.ParseError as e:
                print("[E]   import failed due to exception: {}".format(e))

    def _import_file(self, input_file: str) -> None:
        """
        This method imports the given file into the database.
        :param input_file: The file to be imported
        :return:
        """
        raise NotImplementedError("This method has not been implemented.")

    @staticmethod
    def get_incomplete_hosts(session, workspace):
        """
        This method returns all hosts hat have not been scanned by Nmap, and, as a result, are incomplete.

        :param session: The database session used to import the data
        :param workspace: The project into which the data shall be imported
        :return: list of IP addresses that shall be scanned
        """
        incomplete_hosts = []
        for host in session.query(Host) \
            .join(Workspace) \
            .join((Source, Host.sources)) \
            .filter(and_(Workspace == workspace,
                         Host.id.notin_(
                             session.query(Host.id) \
                                 .join(Workspace) \
                                 .join((Source, Host.sources)) \
                                 .filter(and_(Workspace == workspace,
                                              Source.name == Source.NMAP))))).all():
            incomplete_hosts.append(host.address)
        return incomplete_hosts

    @staticmethod
    def get_incomplete_services(session, workspace):
        """
        This method returns all services that have not been scanned by Nmap, and, as a result, are incomplete.

        :param session: The database session used to import the data
        :param workspace: The project into which the data shall be imported
        :return: A dicionary of dictionaries of lists ;). The first dictionary contains the IP addresses of the host
        with incomplete services. The second dictionary, which is stored as values within the first dictionary contains
        the layer 4 protocol as keys. The values of this dictionary represent a list with all ports that have not
        been scanned by Nmap.
        """
        # select src.name, s.protocol, s.port from host h
        # inner join service s on s.host_id = h.id
        # inner join source_service_mapping ssm on s.id = ssm.service_id
        # inner join source src on src.id = ssm.source_id
        # where h.workspace_id = 2 and s.id not in (
        #   select s.id from host h
        #   inner join service s on s.host_id = h.id
        #   inner join source_service_mapping ssm on s.id = ssm.service_id
        #   inner join source src on src.id = ssm.source_id
        #   where src.name = 'Nmap' and h.workspace_id = 2
        # );
        incomplete_services = {}
        for item in session.query(Service)\
            .join(Host)\
            .join(Workspace)\
            .join((Source, Service.sources))\
            .filter(and_(Workspace == workspace,
                         Service.id.notin_(
                             session.query(Service.id) \
                                 .join(Host) \
                                 .join(Workspace) \
                                 .join((Source, Service.sources)) \
                                 .filter(and_(Workspace == workspace,
                                              Source.name == Source.NMAP)
                         )))).all():
            if item.host.address not in incomplete_services:
                incomplete_services[item.host.address] = {}
            if item.protocol not in incomplete_services[item.host.address]:
                incomplete_services[item.host.address][item.protocol] = []
            incomplete_services[item.host.address][item.protocol].append(item.port)
        return incomplete_services


class BaseDatabaseXmlImporter(BaseDatabaseImporter):
    """
    Base class to import any scan results into database.
    """

    def __init__(self, session, workspace: Workspace, input_files: List[str], source: str, **kwargs):
        """

        :param session: The database session used to import the data
        :param workspace: The project into which the data shall be imported
        :param input_files: The list of XML file names that shall be imported
        :param in_scope_networks: Networks that specify which networks are in scope
        :param source: The source application that created the files to be imported
        """
        super().__init__(session, workspace, input_files, source, **kwargs)

    @staticmethod
    def get_xml_attribute(attribute_name: str, attributes: dict) -> str:
        """
        This method returns the value of the given attribute name from a dictionary of attribute name value pairs.
        :param attribute_name: The attribute name for which the value shall be obtained.
        :param attributes: The dictionary containing all attributes.
        :return: Returns the value of the corresponding attribute name or none, if the name does not exist.
        """
        return_value = None
        if attributes is not None:
            if attribute_name in attributes:
                return_value = attributes[attribute_name].strip()
            return return_value

    @staticmethod
    def get_xml_text(tag_name: List) -> str:
        return_value = None
        if len(tag_name) == 1:
            return_value = tag_name[0].text.strip()
        elif len(tag_name) > 1:
            raise NotImplementedError("getText is not implemented for more than two elements.")
        return return_value
