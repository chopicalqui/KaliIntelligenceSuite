#!/usr/bin/python3

"""
this script loads all cipher suites from ciphersuite.info
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
import os
import sys
import json
import requests
import argparse
import traceback


class CipherSuiteDownload:
    def __init__(self):
        self.config_file_path = os.path.join("..", "kis", "configs", "ciphersuites.json")

    def save(self):
        response = requests.get("https://ciphersuite.info/api/cs/")
        response.raise_for_status()
        if response.status_code == 200:
            json_object = json.loads(response.content)
            with open(self.config_file_path, "w") as file:
                file.write(json.dumps(json_object, indent=4))

    def __repr__(self):
        return self.config_file_path

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    try:
        downloader = CipherSuiteDownload()
        downloader.save()
        print("Configuration file '{}' successfully updated.".format(downloader))
    except Exception:
        traceback.print_exc(file=sys.stderr)
