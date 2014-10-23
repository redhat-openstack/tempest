#!/usr/bin/env bash
set -eu
set -o pipefail

usage() {
    echo "$(basename $0) [--skip-file file] test-regex1 test-regex2 ..."
    echo "Format of skip file:\n"
    echo "Whitelist is applied first. The blacklist is executed against the set
 of tests returned by the whitelist.
If whitelist is empty, all available tests are fed to blacklist.
If blacklist is empty, all tests from whitelist are returned.

The syntax for white-list and black-list is as follows:
- lines starting with # or empty are ignored
- lines starting with "+" are whitelisted
- lines starting with "-" are blacklisted
- lines not matching any of the above conditions are blacklisted

The match for each line gets added a "^" in the beginning,
so the regular expression should account for that.

For example, the following scenario:

    run all the smoke tests and scenario tests,
    but exclude the api.volume tests.

is implemented as:

    +.*smoke
    +tempest\.scenario
    -tempest\.api\.volume.*
"
}

if [ "$#" == "0" ] || [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
    usage
    exit 1
fi

skip_file=/dev/null
if [[ $1 == '--skip-file' ]]; then
    shift
    skip_file=$1
    shift
fi

testr run --parallel --subunit $($(dirname $0)/tests2skip.py $skip_file $@) | tee >( subunit2junitxml --output-to=tempest.xml ) | $(dirname $0)/subunit-trace.py --no-failure-debug -f


