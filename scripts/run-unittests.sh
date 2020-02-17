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
    if [ -x /bin/realpath ]; then
        /bin/realpath "$@"
    else
        python -c "import os.path, sys; print os.path.realpath(sys.argv[1])" \
               "$1"
    fi
}

test-client-system-bundle() {
    local arch=$1 openssl_dir
    openssl_dir=$(openssl version -d | awk '{ print $2 }' | tr -d '"')
    SSL_CERT_DIR=$openssl_dir/certs \
    SSL_CERT_FILE=$openssl_dir/cert.pem \
    run-test $arch stage/$arch/build/test/webclient https://github.com/
}

test-client-file-bundle() {
    local arch=$1
    run-test $arch stage/$arch/build/test/webclient \
        https://github.com/ \
        test/certs/DigiCert_High_Assurance_EV_Root_CA.pem
}

run-tests () {
    local arch=$1
    echo
    echo "Run unit tests on $arch"
    echo
    stage/$arch/build/test/fstracecheck
    run-test $arch ./stage/$arch/build/test/jsonop-request-quick-close
    test-client-system-bundle $arch
    test-client-file-bundle $arch
}

main
