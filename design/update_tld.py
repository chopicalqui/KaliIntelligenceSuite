#!/usr/bin/python3

"""
this script updates the list of top-level domains
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

import requests
import argparse
import json
import os

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    content = {"source": "https://raw.githubusercontent.com/publicsuffix/list/master/public_suffix_list.dat"}
    tlds = []
    response = requests.get(content["source"])
    if response.status_code == 200:
        data = response.content.decode('utf-8')
        for line in data.split(os.linesep):
            line = line.strip()
            line = line.lstrip("*.")
            line = line.lstrip(".")
            if len(line) != 0 and not line.startswith("//"):
                tlds.append(line)
        if tlds:
            tlds.append("local")
            content["data"] = sorted(tlds, key=len, reverse=True)
            with open("../kis/configs/top-level-domains.json", "w") as file:
                file.write(json.dumps(content, indent=4))
