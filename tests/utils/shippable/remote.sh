#!/usr/bin/env bash

set -o pipefail -eux

declare -a args
IFS='/:' read -ra args <<< "$1"

platform="${args[0]}"
version="${args[1]}"

if [ "${#args[@]}" -gt 2 ]; then
    target="shippable/posix/group${args[2]}/"
else
    target="shippable/posix/"
fi

stage="${S:-prod}"
provider="${P:-default}"

if [ "${platform}/${version}" == "freebsd/13.0" ]; then
    # On FreeBSD 13.0, installing PyOpenSSL 22.0.0 tries to upgrade cryptography, which
    # will fail due to missing Rust compiler.
    echo "pyopenssl < 22.0.0 ; python_version >= '3.8'" >> tests/utils/constraints.txt
fi

# shellcheck disable=SC2086
ansible-test integration --color -v --retry-on-error "${target}" ${COVERAGE:+"$COVERAGE"} ${CHANGED:+"$CHANGED"} ${UNSTABLE:+"$UNSTABLE"} \
    --remote "${platform}/${version}" --remote-terminate always --remote-stage "${stage}" --remote-provider "${provider}"
