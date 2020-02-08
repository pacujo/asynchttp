#!/bin/bash

set -e

run-test () {
    local arch=$1
    shift
    case $arch in
        darwin | linux32)
            "$@"
            ;;
        *)
            valgrind --leak-check=full --error-exitcode=123 "$@"
            ;;
    esac
}

main() {
    cd "$(dirname "$(realpath "$0")")/.."
    local os=$(uname -s)
    if [ -n "$FSARCHS" ]; then
        local archs=()
        IFS=, read -ra archs <<< "$FSARCHS"
        for arch in "${archs[@]}" ; do
            run-tests "$arch"
        done
    elif [ "$os" = Linux ]; then
        local cpu=$(uname -m)
        if [ "$cpu" = x86_64 ]; then
            #run-tests linux32
            run-tests linux64
        elif [ "$cpu" = i686 ]; then
            run-tests linux32
        else
            echo "$0: Unknown CPU: $cpu" >&2
            exit 1
        fi
    elif [ "$os" = Darwin ]; then
        run-tests darwin
        :
    else
        echo "$0: Unknown OS: $os" >&2
        exit 1
    fi
}

realpath () {
    # reimplementation of "readlink -fw" for OSX
    python -c "import os.path, sys; print os.path.realpath(sys.argv[1])" "$1"
}

run-tests () {
    local arch=$1
    echo
    echo "Run unit tests on $arch"
    echo
    stage/$arch/build/test/fstracecheck
    run-test $arch ./stage/$arch/build/test/jsonop-request-quick-close
}

main
