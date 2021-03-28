#!/usr/bin/env python3

import argparse
import http.server
import json
from pathlib import Path
import socketserver
import ssl
import subprocess
import sys
import threading


def create_root_certificate(stem):
    cert_path = stem + ".pem"
    key_path = stem + ".key"
    cmd = (
        "openssl",
        "req",
        "-newkey",
        "rsa",
        "-nodes",
        "-keyout",
        key_path,
        "-x509",
        "-subj",
        "/CN=Test root CA",
        "-days",
        "1",
        "-out",
        cert_path,
    )
    status = subprocess.run(cmd)
    assert status.returncode == 0
    return cert_path, key_path


def create_csr(stem):
    csr_path = stem + ".csr"
    key_path = stem + ".key"
    cmd = (
        "openssl",
        "req",
        "-newkey",
        "rsa",
        "-nodes",
        "-keyout",
        key_path,
        "-subj",
        "/CN=Test certificate",
        "-out",
        csr_path,
    )
    status = subprocess.run(cmd)
    assert status.returncode == 0
    return csr_path, key_path


def create_certificate(stem, CA):
    cert_path = stem + ".pem"
    config_path = stem + ".cnf"
    with open(config_path, "w") as f:
        f.write("subjectAltName = DNS:127.0.0.1")
    csr_path, key_path = create_csr(stem)
    cmd = (
        "openssl",
        "x509",
        "-req",
        "-in",
        csr_path,
        "-CA",
        CA[0],
        "-CAkey",
        CA[1],
        "-CAcreateserial",
        "-extfile",
        config_path,
        "-days",
        "1",
        "-out",
        cert_path,
    )
    status = subprocess.run(cmd)
    assert status.returncode == 0
    return cert_path, key_path


def run(arch, args, env=None):
    if arch == "linux64":
        cmd = [
            "valgrind",
            "-q",
            "--leak-check=full",
            "--error-exitcode=123",
        ]
    else:
        cmd = []
    cmd += args
    return subprocess.run(cmd, stdout=subprocess.PIPE, env=env)


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        obj = {"key": "value"}
        content = json.dumps(obj).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.send_header("Content-Length", len(content))
        self.end_headers()
        try:
            self.wfile.write(content)
        except BrokenPipeError:
            pass


def test_https_linux(arch, stage_path):
    webclient_path = stage_path / "build" / "test" / "webclient"
    root_cert_files = create_root_certificate(str(stage_path / "root"))
    cert_files = create_certificate(str(stage_path / "test"), root_cert_files)
    httpd = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    httpd.socket = ssl.wrap_socket(
        httpd.socket,
        server_side=True,
        keyfile=cert_files[1],
        certfile=cert_files[0],
        ssl_version=ssl.PROTOCOL_TLS,
    )
    port = httpd.socket.getsockname()[1]
    url = "https://127.0.0.1:{}".format(port)
    thread = threading.Thread(target=httpd.serve_forever)
    thread.start()
    try:
        status = run(
            arch,
            [
                webclient_path,
                url,
            ],
            env={
                "SSL_CERT_FILE": root_cert_files[0],
            }
        )
        assert status.returncode == 0
        assert json.loads(status.stdout.decode()) == {"key": "value"}

        status = run(
            arch,
            [
                webclient_path,
                url,
                root_cert_files[0],
            ],
        )
        assert status.returncode == 0
        assert json.loads(status.stdout.decode()) == {"key": "value"}
    finally:
        httpd.shutdown()
        thread.join()


def test_https_darwin(arch, stage_path):
    webclient_path = stage_path / "build" / "test" / "webclient"
    status = run(
        arch,
        [
            webclient_path,
            "https://github.com/",
        ],
    )
    assert status.returncode == 0


def test_jsonop(arch, stage_path):
    webclient_path = stage_path / "build" / "test" / "webclient"
    httpd = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    port = httpd.socket.getsockname()[1]
    url = "http://127.0.0.1:{}".format(port)
    thread = threading.Thread(target=httpd.serve_forever)
    thread.start()
    try:
        status = run(
            arch,
            [
                webclient_path,
                "--json",
                "--timeout",
                "1",
                url,
            ],
        )
        assert status.returncode == 1

        status = run(
            arch,
            [
                webclient_path,
                "--json",
                url,
            ],
        )
        assert status.returncode == 0
        assert json.loads(status.stdout.decode()) == {"key": "value"}
    finally:
        httpd.shutdown()
        thread.join()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("arch")
    args = parser.parse_args()
    stage_path = (
        Path(sys.argv[0]).resolve().parent.parent
        / "stage"
        / args.arch
    )
    if args.arch == "darwin":
        test_https_darwin(args.arch, stage_path)
    else:
        test_https_linux(args.arch, stage_path)
    test_jsonop(args.arch, stage_path)


if __name__ == "__main__":
    main()
