# -*- coding: utf-8 -*-
"""
run tool kismanage on each company of an identified in-scope second-level domain or network to obtain additional host
names via the crt.sh web site. depending on the number of certificates the company has registered. note that this
command might take a long time to complete as between each certificate request, the command sleeps between 2 and 5
seconds
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

import logging
from database.model import Source
from database.model import Command
from database.model import FileType
from database.model import CertType
from database.model import CertInfo
from collectors.os.core import PopenCommand
from collectors.os.modules.osint.core import BaseKisImportCompany
from collectors.os.modules.core import CompanyCollector
from collectors.apis.crtsh import CrtshCompany
from view.core import ReportItem
from sqlalchemy.orm.session import Session

logger = logging.getLogger('crtshcompany')


class CollectorClass(BaseKisImportCompany, CompanyCollector):
    """This class implements a collector module that is automatically incorporated into the application."""

    def __init__(self, **kwargs):
        super().__init__(priority=540,
                         timeout=0,
                         argument_name="--crtshcompany",
                         source=CrtshCompany.SOURCE_NAME,
                         delay_min=2,
                         delay_max=5,
                         **kwargs)

    @staticmethod
    def get_argparse_arguments():
        return {"help": __doc__, "action": "store_true"}

    def api_credentials_available(self) -> bool:
        """
        This method shall be implemented by sub classes. They should verify whether their API keys are set in the
        configuration file
        :return: Return true if API credentials are set, else false
        """
        return True

    def verify_results(self, session: Session,
                       command: Command,
                       source: Source,
                       report_item: ReportItem,
                       process: PopenCommand = None, **kwargs) -> None:
        """This method analyses the results of the command execution.

        After the execution, this method checks the OS command's results to determine the command's execution status as
        well as existing vulnerabilities (e.g. weak login credentials, NULL sessions, hidden Web folders). The
        stores the output in table command. In addition, the collector might add derived information to other tables as
        well.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param command: The command instance that contains the results of the command execution
        :param source: The source object of the current collector
        :param report_item: Item that can be used for reporting potential findings in the UI
        :param process: The PopenCommand object that executed the given result. This object holds stderr, stdout, return
        code etc.
        """
        super().verify_results(session=session,
                               command=command,
                               source=source,
                               report_item=report_item,
                               process=process)
        for file in command.files:
            if file.type == FileType.certificate:
                self.add_cert_info(session=session,
                                   cert_info=CertInfo(pem=file.content.decode(), cert_type=CertType.identity),
                                   command=command,
                                   source=source,
                                   report_item=report_item)
