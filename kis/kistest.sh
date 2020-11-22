#!/bin/bash
KISHOME=`dirname $(realpath kistest.sh)`
UNITTESTHOME=$KISHOME/../
export PYTHONPATH=$PYTHONPATH:$KISHOME:$UNITTESTHOME
if [[ $LOGNAME != "root" ]]; then
	echo "must be executed as root"
	exit 1
fi
python3 -m pytest -v "$UNITTESTHOME/unittests/tests"
