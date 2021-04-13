#!/usr/bin/env bash

set -e

main() {
    cd "$(dirname "$(realpath "$0")")/.."
    local os=$(uname -s)
    if [ -n "$FSARCHS" ]; then
        local archs=()
        IFS=, read -ra archs <<< "$FSARCHS"
        for arch in "${archs[@]}" ; do
            run-tests "$arch"
        done
    else
        local os=$(uname -m -s)
        case $os in
            "Darwin arm64")
                run-tests darwin;;
            "Darwin x86_64")
                run-tests darwin;;
            "FreeBSD amd64")
                run-tests freebsd_amd64;;
            "Linux i686")
                run-tests linux32;;
            "Linux x86_64")
                run-tests linux64;;
            "OpenBSD amd64")
                run-tests openbsd_amd64;;
            *)
                echo "$0: Unknown OS architecture: $os" >&2
                exit 1
        esac
    fi
}

realpath () {
    if [ -x /bin/realpath ]; then
        /bin/realpath "$@"
    else
        python -c "import os.path, sys; print(os.path.realpath(sys.argv[1]))" \
               "$1"
    fi
}

run-tests () {
    local arch=$1
    echo
    echo "Run unit tests on $arch"
    echo
    stage/$arch/build/test/fstracecheck
    test/test_client.py $arch
}

main
