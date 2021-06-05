#!/bin/bash

function run_test {
	unittests=$(realpath $1)
	pytest -x "$unittests"
	if [[ $? -ne 0 ]]; then
		print "failed"
		exit 1
	fi
}

KISHOME=`dirname $(realpath kistest.sh)`
UNITTESTHOME=$KISHOME/../
export PYTHONPATH=$PYTHONPATH:$KISHOME:$UNITTESTHOME
if [[ $LOGNAME != "root" ]]; then
	echo "must be executed as root"
	exit 1
fi

# execute them one by one, else tests stall at a certain unittest
run_test "$UNITTESTHOME/unittests/tests/collectors"
for path in $(find $UNITTESTHOME/unittests/tests -maxdepth 1 -iname "test_*.py"); do
	run_test "$path"
done
