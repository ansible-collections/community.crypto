#!/usr/bin/env bash
# Aggregate code coverage results for later processing.

set -o pipefail -eux

agent_temp_directory="$1"

if [ "$2" ]; then
    # 2.9/rhel/7.8/1
    entry_point="$2"
    ansible_version=$( echo "${entry_point}" | cut -f 1 -d / )
fi

PATH="${PWD}/bin:${PATH}"

mkdir "${agent_temp_directory}/coverage/"

agent_temp_directory="$1"
options=(--venv --venv-system-site-packages --color -v)

if [ "${ansible_version}" == "2.9" ]; then
    ansible-test coverage xml --venv --color --group-by command --group-by version -vvvvvv --debug
    cp -a tests/output/reports/coverage=*.xml "${agent_temp_directory}/coverage/"
else
    ansible-test coverage combine --export "${agent_temp_directory}/coverage/" "${options[@]}"
    ansible-test coverage analyze targets generate "${agent_temp_directory}/coverage/coverage-analyze-targets.json" "${options[@]}"
fi
