#!/usr/bin/env bash

set -o pipefail -eux

declare -a args
IFS='/:' read -ra args <<< "$1"

group="${args[1]}"

if [ "${BASE_BRANCH:-}" ]; then
    base_branch="origin/${BASE_BRANCH}"
else
    base_branch=""
fi

if [ "${group}" == "extra" ]; then
    pip3 install https://github.com/felixfontein/ansible-changelog/archive/master.tar.gz --disable-pip-version-check
    tests/sanity/run.py
    exit
fi

# shellcheck disable=SC2086
ansible-test sanity --color -v --junit ${COVERAGE:+"$COVERAGE"} ${CHANGED:+"$CHANGED"} \
    --docker --base-branch "${base_branch}" \
    --allow-disabled
