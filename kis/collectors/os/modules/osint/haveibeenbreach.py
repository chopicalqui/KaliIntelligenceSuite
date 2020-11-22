# -*- coding: utf-8 -*-
"""
run tool kismanage on each identified in-scope email address to determine breaches (using haveibeenpwned.com) in which
the email address appears. depending on the number of email addresses in the current workspace, it might be desired to
limit the number of OS commands by using the optional argument --filter
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
import json
from database.model import Source
from database.model import Command
from collectors.os.core import PopenCommand
from collectors.os.modules.osint.core import BaseKisImportEmail
from collectors.os.modules.core import EmailCollector
from collectors.apis.haveibeenpwned import HaveIBeenPwnedBreachedAcccount
from view.core import ReportItem
from sqlalchemy.orm.session import Session

logger = logging.getLogger('haveibeenbreach')


class CollectorClass(BaseKisImportEmail, EmailCollector):
    """This class implements a collector module that is automatically incorporated into the application."""

    def __init__(self, **kwargs):
        super().__init__(priority=420,
                         timeout=0,
                         argument_name="--haveibeenbreach",
                         source=HaveIBeenPwnedBreachedAcccount.SOURCE,
                         delay_min=2,
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
        return self._api_config.config.get("haveibeenpwned", "api_breachedaccount_url") and \
               self._api_config.config.get("haveibeenpwned", "api_key")

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
        for json_object in command.json_output:
            if "Name" in json_object:
                breaches = json_object["Name"]
                self.add_additional_info(session=session,
                                         command=command,
                                         name=HaveIBeenPwnedBreachedAcccount.NAME,
                                         values=breaches,
                                         email=command.email,
                                         source=source,
                                         report_item=report_item)
            else:
                logger.debug("could import json object for {0}: {1}".format(command.email.address,
                                                                            json.dumps(json_object, indent=4)))
