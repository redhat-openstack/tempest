#!/usr/bin/env bash

set -o pipefail

TESTRARGS=$@

if [ ! -d .testrepository ]; then
    testr init
fi
testr run --parallel --subunit $TESTRARGS | subunit2pyunit
retval=$?
testr slowest
exit $retval
