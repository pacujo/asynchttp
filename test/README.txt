Clean Scan:

   ./icapscan icap://$ICAPDHOST/ </bin/ls


EICAR:

   base64 -d <<<WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo= | ./icapscan icap://$ICAPDHOST/

Get a web page:

   ./webget http://www.example.com/
   ./webget https://www.example.com/ \
       /etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt

or:

   ./webclient http://www.example.com/
   ./webclient https://www.example.com/
   ./webclient https://www.example.com/ \
       /etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt

To use system certificates with our embedded openssl you need to specify two environment variables:
  - SSL_CERT_DIR=$(openssl version -d | awk '{ print $2 }' | tr -d '"')/certs
  - SSL_CERT_FILE=$(openssl version -d | awk '{ print $2 }' | tr -d '"')/cert.pem
