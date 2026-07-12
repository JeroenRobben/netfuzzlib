# openssl s_server, the built-in TLS server in the openssl(1) binary.
# Exercises a full TLS handshake over our TCP bridge, plus the crypto
# operations a real TLS implementation does at startup (entropy reads
# from /dev/urandom, cert/key file I/O, RSA/ECDH key ops). The base
# image already has openssl installed. We add a self-signed cert at
# build time so the test scenario is fully self-contained.
#
# Build with: docker build -f test/integration/docker/openssl/Dockerfile \
#                          -t netfuzzlib-test-openssl .

FROM netfuzzlib-base

# Generate a self-signed RSA cert for the test. -nodes leaves the key
# unencrypted so s_server can read it without prompting. CN/SAN aren't
# checked by s_client when we pass -verify 0, so any subject is fine.
RUN mkdir -p /etc/nfl-tls \
    && openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout /etc/nfl-tls/server.key \
        -out /etc/nfl-tls/server.crt \
        -days 3650 \
        -subj "/CN=netfuzzlib-test"

COPY test/integration/docker/openssl/run.sh /opt/nfl/targets/openssl/run.sh
RUN chmod +x /opt/nfl/targets/openssl/run.sh

ENV NFL_TARGET_NAME=openssl \
    NFL_TARGET_RUN_SH=/opt/nfl/targets/openssl/run.sh

ENTRYPOINT ["/opt/nfl/bin/nfl-entrypoint"]
CMD ["test"]
