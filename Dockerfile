# Pinned to alpine 3.21 for both the prebuild/builder and runtime stages.
# This replaces the previous dependency on sliamb/prebuild-paopaodns
# (which used alpine:edge and forced the main image to track edge too).
# The prebuild step now runs in this same Dockerfile: we build unbound
# and mosdns locally against alpine 3.21's libhiredis 1.2.0, so the
# main image's runtime ABI matches. See .audit-docs/docs/audit-orchestration.md
# P0-5/P0-6/P0-7.
ARG ALPINE_VERSION=3.21

# ----- Stage 1: prebuild (compiles unbound + mosdns on alpine 3.21) -----
FROM alpine:${ALPINE_VERSION} AS prebuild
RUN apk add --no-cache \
        build-base flex byacc musl-dev gcc make git \
        python3-dev swig libevent-dev openssl-dev expat-dev \
        hiredis-dev go grep bind-tools
WORKDIR /build
# Pinned to release-1.25.1: see P0 (CVE-2026-44608 RPZ UAF and other
# post-1.19.3 hardening fixes from Qifan Zhang @ PAN).
RUN git clone --depth 1 --branch release-1.25.1 \
        https://github.com/NLnetLabs/unbound.git /build/unbound
WORKDIR /build/unbound
RUN export CFLAGS="-O3" && \
    ./configure --with-libevent --with-pthreads --with-libhiredis --enable-cachedb \
        --disable-rpath --without-pythonmodule --disable-documentation \
        --disable-flto --disable-maintainer-mode --disable-option-checking \
        --with-pidfile=/tmp/unbound.pid \
        --prefix=/usr --sysconfdir=/etc --localstatedir=/tmp \
        --with-username=root --with-chroot-dir="" && \
    make && make install
RUN mkdir -p /prebuild-out && \
    cp /usr/sbin/unbound /prebuild-out/unbound && \
    cp /usr/sbin/unbound-checkconf /prebuild-out/unbound-checkconf

# kkkgo/mosdns does not publish release tags; the binary identity check
# in the main Dockerfile relies on the "kkkgo" prefix in the version
# output. mosdns's go.mod requires Go >= 1.26.3; alpine 3.21's `go`
# package is 1.23.x, so we let the Go toolchain auto-download the
# required version. GOTOOLCHAIN=auto is the default for go >= 1.21
# but the alpine package sets it to local; export it explicitly.
WORKDIR /build
RUN git clone --depth 1 https://github.com/kkkgo/mosdns /build/mosdns
WORKDIR /build/mosdns
RUN GOTOOLCHAIN=auto go build -ldflags "-s -w" -trimpath -o /prebuild-out/mosdns

# ----- Stage 2: builder (assembles all artifacts into /src) -----
FROM alpine:${ALPINE_VERSION} AS builder
RUN apk update && apk upgrade --no-cache
#actions COPY build_test_ok /
COPY src/ /src/
COPY --from=prebuild /prebuild-out/unbound /src/unbound
COPY --from=prebuild /prebuild-out/unbound-checkconf /src/unbound-checkconf
COPY --from=prebuild /prebuild-out/mosdns /src/mosdns
RUN sh /src/build.sh
# build file check
RUN cp /src/Country-only-cn-private.mmdb.xz /tmp/ &&\
    cp /src/global_mark.dat /tmp/ &&\
    cp /src/data_update.sh /tmp/ &&\
    cp /src/dnscrypt-resolvers/public-resolvers.md /tmp/ &&\
    cp /src/dnscrypt-resolvers/public-resolvers.md.minisig /tmp/ &&\
    cp /src/dnscrypt-resolvers/relays.md /tmp/ &&\
    cp /src/dnscrypt-resolvers/relays.md.minisig /tmp/ &&\
    cp /src/dnscrypt.toml /tmp/ &&\
    cp /src/force_recurse_list.txt /tmp/ &&\
    cp /src/force_dnscrypt_list.txt /tmp/ &&\
    cp /src/init.sh /tmp/ &&\
    cp /src/mosdns /tmp/ &&\
    cp /src/mosdns.yaml /tmp/ &&\
    cp /src/named.cache /tmp/ &&\
    cp /src/redis.conf /tmp/ &&\
    cp /src/repositories /tmp/ &&\
    cp /src/unbound /tmp/ &&\
    cp /src/unbound-checkconf /tmp/ &&\
    cp /src/unbound.conf /tmp/ &&\
    cp /src/unbound_custom.conf /tmp/ &&\
    cp /src/custom_mod.yaml /tmp/ &&\
    cp /src/custom_env.ini /tmp/ &&\
    cp /src/trackerslist.txt.xz /tmp/ &&\
    cp /src/watch_list.sh /tmp/ &&\
    cp /src/redis-server /tmp/
# build binary check
RUN apk add --no-cache hiredis libevent libgcc && apk upgrade --no-cache
RUN if /src/mosdns version|grep kkkgo;then echo mosdns_check > /mosdns_check;else cp /mosdns_check /tmp/;fi
RUN if /src/unbound -V|grep libhiredis;then echo unbound_check > /unbound_check;else cp /unbound_check /tmp/;fi
RUN if /src/redis-server -v|grep build;then echo redis_check > /redis_check;else cp /redis_check /tmp/;fi

# ----- Stage 3: runtime -----
FROM alpine:${ALPINE_VERSION}
COPY --from=builder /src/ /usr/sbin/
RUN apk update && \
    apk upgrade --no-cache && \
    apk add --no-cache ca-certificates dcron tzdata hiredis libevent dnscrypt-proxy inotify-tools bind-tools libgcc xz && \
    mkdir -p /etc/unbound && \
    mv /usr/sbin/named.cache /etc/unbound/named.cache && \
    adduser -D -H unbound && \
    mv /usr/sbin/repositories /etc/apk/repositories && \
    rm -rf /var/cache/apk/*
ARG DEVLOG_SW
ENV TZ=Asia/Shanghai \
    DEVLOG=$DEVLOG_SW \
    UPDATE=weekly \
    DNS_SERVERNAME=PaoPaoDNS,blog.03k.org \
    DNSPORT=53 \
    CNAUTO=yes \
    CNFALL=yes \
    CN_TRACKER=yes \
    USE_HOSTS=no \
    IPV6=no \
    SOCKS5=IP:PORT \
    SERVER_IP=none \
    CUSTOM_FORWARD=IP:PORT \
    CUSTOM_FORWARD_TTL=0 \
    AUTO_FORWARD=no \
    AUTO_FORWARD_CHECK=yes \
    USE_MARK_DATA=yes \
    RULES_TTL=0 \
    HTTP_FILE=no \
    QUERY_TIME=2000ms \
    ADDINFO=no \
    SHUFFLE=no \
    EXPIRED_FLUSH=yes
VOLUME /data
WORKDIR /data
EXPOSE 53/udp 53/tcp 5304/udp 5304/tcp 7889/tcp
CMD /usr/sbin/init.sh
