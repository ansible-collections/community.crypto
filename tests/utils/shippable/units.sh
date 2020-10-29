#!/usr/bin/env bash

set -o pipefail -eux

if [[ "${COVERAGE:-}" == "--coverage" ]]; then
    timeout=90
else
    timeout=30
fi

ansible-test env --timeout "${timeout}" --color -v

# shellcheck disable=SC2086
ansible-test units --color -v --docker default ${COVERAGE:+"$COVERAGE"} ${CHANGED:+"$CHANGED"} \
