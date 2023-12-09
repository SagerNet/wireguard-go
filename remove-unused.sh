#!/usr/bin/env bash

set -e -o pipefail

function remove_unused() {
  git rm -rf --ignore-unmatch \
    .github \
    tests \
    *_test.go \
    **/*_test.go \
    conn/bindtest \
    tun/netstack \
    tun/tuntest \
    tun/testdata \
    tun/checksum.go \
    tun/operateonfd.go \
    tun/offload_linux.go \
    tun/tun_*.go \
    main*.go \
    *.md
}

remove_unused
remove_unused

go mod tidy
git commit -a -m "Remove unused"
