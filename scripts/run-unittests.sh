#!/bin/bash

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
