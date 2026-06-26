# Pinned to alpine 3.21 for both the builder and runtime stages.
#
# Architecture: this Dockerfile pulls pre-compiled unbound and mosdns
# binaries from ghcr.io/upbeat-backbone-bose/prebuild-paopaodns:3.21,
# which is itself a multi-arch image (linux/386, amd64, arm/v6, arm/v7,
# arm64, ppc64le, s390x) built in prebuild-paopaodns/. The binaries
# are linked against alpine 3.21's libhiredis 1.2.0, matching the
# runtime stage's hiredis package, so the ABI is consistent.
#
# Buildx automatically selects the right prebuild layer for each
# platform via TARGETPLATFORM. We do not need to (and should not) copy
# from per-arch tags; the manifest list takes care of dispatch.
#
# This replaces the previous dependency on sliamb/prebuild-paopaodns
# (alpine:edge, no pinned tag, supply-chain risk). See
# .audit-docs/docs/audit-orchestration.md P0-5/P0-6/P0-7.
ARG ALPINE_VERSION=3.21

# Pull pre-compiled binaries from the multi-arch prebuild image.
# BuildKit does not support variable expansion in `COPY --from=`,
# so we use a dedicated FROM stage that re-references the ARG. See
# https://github.com/moby/buildkit/blob/master/frontend/dockerfile/docs/syntax.md#from
# "variable expansion is not supported for --from". The FROM below
# consumes the same ARG and creates a real build stage.
ARG PREBUILD_TAG=3.21
ARG PREBUILD_IMAGE=ghcr.io/upbeat-backbone-bose/prebuild-paopaodns:${PREBUILD_TAG}
FROM ${PREBUILD_IMAGE} AS prebuilt

# ----- Stage: builder (assembles all artifacts into /src) -----
FROM alpine:${ALPINE_VERSION} AS builder
RUN apk update && apk upgrade --no-cache
#actions COPY build_test_ok /
COPY src/ /src/
# Pull pre-compiled binaries (unbound, mosdns) from the multi-arch
# prebuild stage. buildx resolves this per TARGETPLATFORM via the
# prebuilt stage's manifest list.
COPY --from=prebuilt /prebuild-out/unbound /src/unbound
COPY --from=prebuilt /prebuild-out/unbound-checkconf /src/unbound-checkconf
COPY --from=prebuilt /prebuild-out/mosdns /src/mosdns
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
RUN if /src/mosdns version|grep upbeat-backbone-bose;then echo mosdns_check > /mosdns_check;else echo "ERROR: mosdns version mismatch" && exit 1;fi
RUN if /src/unbound -V|grep libhiredis;then echo unbound_check > /unbound_check;else cp /unbound_check /tmp/;fi
RUN if /src/redis-server -v|grep build;then echo redis_check > /redis_check;else cp /redis_check /tmp/;fi

# ----- Stage: runtime -----
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
