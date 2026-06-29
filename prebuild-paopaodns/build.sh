#!/bin/sh
set -e

# add tools
apk update
apk upgrade
apk add build-base flex byacc musl-dev gcc make git python3-dev swig libevent-dev openssl-dev expat-dev hiredis-dev go grep bind-tools

# build unbound
# Pinned to release-1.25.1: master tracks post-release work and may be unstable
# for production. release-1.25.1 includes fixes up to CVE-2026-44608 (UAF in RPZ)
# and a large batch of malloc-failure hardening fixes from Qifan Zhang @ PAN.
git clone https://github.com/NLnetLabs/unbound.git --depth 1 --branch release-1.25.1 /unbound
cd /unbound || exit
export CFLAGS="-O3"
./configure --with-libevent --with-pthreads --with-libhiredis --enable-cachedb \
    --disable-rpath --without-pythonmodule --disable-documentation \
    --disable-flto --disable-maintainer-mode --disable-option-checking --disable-rpath \
    --with-pidfile=/tmp/unbound.pid \
    --prefix=/usr --sysconfdir=/etc --localstatedir=/tmp --with-username=root --with-chroot-dir=""
make
make install
# Move compiled binaries to /src/. Some alpine packages create an /src
# directory in their post-install hooks, so ensure the destination
# is writable and free of stale entries. `rm -f` is safe if absent.
mkdir -p /src
rm -f /src/unbound /src/unbound-checkconf
mv /usr/sbin/unbound /src/
mv /usr/sbin/unbound-checkconf /src/

# build mosdns
# upbeat-backbone-bose/mosdns does not publish release tags; the binary identity check
# in Dockerfile relies on the kkkgo prefix, so we follow upstream master.
# mosdns's go.mod requires Go >= 1.26.3; alpine 3.21's `go` package is
# 1.23.x, so we must let the Go toolchain auto-download the required
# version. GOTOOLCHAIN=auto is the default for go >= 1.21 but the
# alpine package sets it to local; export it explicitly.
mkdir -p /mosdns-build
git clone https://github.com/upbeat-backbone-bose/mosdns --depth 1 /mosdns-build
cd /mosdns-build || exit
GOTOOLCHAIN=auto go build -ldflags "-s -w" -trimpath -o /src/mosdns

# No final cleanup needed: the Dockerfile that calls this script
# (prebuild-paopaodns/Dockerfile) ignores everything in /src/ and
# explicitly moves the three compiled binaries to /prebuild-out/. The
# original `rm /src/build.sh` here was for the old single-stage
# `COPY --from=builder /src/ /src/` design and broke the multi-stage
# build when this script was relocated to /build/ (it would error
# on `rm /src/build.sh` because no such file exists in /src/).
