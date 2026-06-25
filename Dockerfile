# NOTE: This Dockerfile still pulls prebuilt binaries (unbound, mosdns,
# redis-server) from sliamb/prebuild-paopaodns. Those binaries are linked
# against alpine:edge's hiredis 1.3.0 and OpenSSL, so the runtime stage
# must use the same alpine:edge to keep the ABI compatible.
#
# Reverting from alpine:3.21 to alpine:edge here; full fix is P0-7 in
# .audit-docs/docs/audit-orchestration.md (build prebuild binaries
# inside this repo on alpine:3.21 so the main image can drop edge).
FROM alpine:edge AS builder
RUN apk update && \
    apk upgrade --no-cache
#actions COPY build_test_ok /
COPY --from=sliamb/prebuild-paopaodns /src/ /src/
COPY src/ /src/
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
# The sliamb/prebuild-paopaodns image ships the binaries as symlinks
# (e.g. /src/mosdns -> /src/mosdns-1.2.3). setcap refuses non-regular
# files with "Invalid argument" and rejects symlinks outright. We
# therefore:
#   1. resolve each symlink to its real target path with readlink -f;
#   2. mv the real target onto the symlink path (rename, keeps the
#      same inode and the existing xattr support);
#   3. setcap the now-regular file in place.
# mv across the same filesystem preserves the inode, so docker layer
# xattr semantics carry the capability through to the runtime stage.
RUN apk add --no-cache libcap && \
    unbound_real=$(readlink -f /src/unbound) && \
    mosdns_real=$(readlink -f /src/mosdns) && \
    mv "$unbound_real" /src/unbound && \
    mv "$mosdns_real" /src/mosdns && \
    setcap cap_net_bind_service=+ep /src/unbound /src/mosdns && \
    getcap /src/unbound /src/mosdns

# Runtime stage mirrors builder's alpine:edge to match hiredis 1.3.0 ABI.
# Full fix tracked in P0-7 (build prebuild binaries in-repo on alpine 3.21).
FROM alpine:edge
COPY --from=builder /src/ /usr/sbin/
RUN apk update && \
    apk upgrade --no-cache && \
    apk add --no-cache ca-certificates dcron tzdata hiredis libevent dnscrypt-proxy inotify-tools bind-tools libgcc xz setpriv libcap && \
    mkdir -p /etc/unbound /run/unbound && \
    mv /usr/sbin/named.cache /etc/unbound/named.cache && \
    adduser -D -H unbound && \
    chown unbound:unbound /run/unbound && \
    chmod 750 /run/unbound && \
    # CAP_NET_BIND_SERVICE was already set on the binaries in the builder
    # stage (see RUN above). Setting it in the runtime stage hits
    # "Invalid argument" on overlayfs; builder-stage xattrs survive
    # the COPY --from=builder into the final image.
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