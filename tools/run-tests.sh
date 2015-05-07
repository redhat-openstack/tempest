#!/usr/bin/env bash
set -e
set -o pipefail

usage() {
    echo "$(basename $0) [--skip-file <file>] [--<any-testr-long-opts>, ...]  [test-regex-to-include ...]"
    echo ""
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
    [[ -z "$1" ]] || exit $1;
}

t2skip_args=()
skip_file=/dev/null
testr_args=("--parallel")

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            usage 0
            ;;
        # testr args (first with value, then bool flags)
        --concurrency|--load-list)
            testr_args=( "${testr_args[@]}" "$1" "$2" ); shift;
            ;;
        --concurrency=*|--load-list=*)
            testr_args=( "${testr_args[@]}" "$1" );
            ;;
        --failing|--parallel|--partial|--subunit|--full-results|--until-failure|--analyze-isolation|--isolated)
            testr_args=( "${testr_args[@]}" "$1" );
            ;;
        # tests2skip args
        --skip-file)
            if [[ ! -f "$2" ]]; then
                echo "Specified skip-file '$(readlink -f $2)' does not exists!" >&2
                exit 1
            fi
            skip_file="$2"
            shift;
            ;;
        *)
            t2skip_args=( "${t2skip_args[@]}" "$1" );
            ;;
    esac
    shift
done

t2skip_args=("$skip_file" "${t2skip_args[@]}");

if [ ! -d .testrepository ]; then
    testr init
fi

testr run "${testr_args[@]}" --subunit $($(dirname $0)/tests2skip.py "${t2skip_args[@]}") | tee >( subunit2junitxml --output-to=tempest.xml ) | subunit-trace --no-failure-debug -f

