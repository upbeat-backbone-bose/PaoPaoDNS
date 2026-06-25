#!/bin/sh

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
mv /usr/sbin/unbound /src/
mv /usr/sbin/unbound-checkconf /src/

# build mosdns
# kkkgo/mosdns does not publish release tags; the binary identity check
# in Dockerfile relies on the kkkgo prefix, so we follow upstream master.
mkdir -p /mosdns-build
git clone https://github.com/kkkgo/mosdns --depth 1 /mosdns-build
cd /mosdns-build || exit
go build -ldflags "-s -w" -trimpath -o /src/mosdns

#clean
rm /src/build.sh
