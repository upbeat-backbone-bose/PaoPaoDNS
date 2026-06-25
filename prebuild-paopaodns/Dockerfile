# Prebuild stage: compile unbound and mosdns from source on alpine 3.21.
# Produces a minimal multi-arch image containing only the three
# binaries (unbound, unbound-checkconf, mosdns) at /prebuild-out/.
# The main Dockerfile in the repo root pulls these via
# `COPY --from=ghcr.io/upbeat-backbone-bose/prebuild-paopaodns:3.21`.
#
# Why a separate image:
#   - The main image needs ~5-10 minutes to build per platform just
#     downloading/configuring packages; compiling C from source adds
#     another 5-10 minutes per platform. With 7 platforms the main
#     workflow was 1+ hours. Pulling pre-compiled binaries drops
#     per-platform time back to ~30s.
#   - This image is rebuilt weekly by the docker-prebuild-schedule.yml
#     workflow; the main image rebuilds on every push, so we want the
#     hot path fast.
#   - Multi-arch manifest list is preserved end-to-end: buildx picks
#     the right platform-specific layer for each TARGETPLATFORM in
#     the main build.

FROM alpine:3.21 AS builder
RUN apk add --no-cache \
        build-base flex byacc musl-dev gcc make git \
        python3-dev swig libevent-dev openssl-dev expat-dev \
        hiredis-dev go grep bind-tools

WORKDIR /build
COPY build.sh /build/
RUN sh /build/build.sh && \
    # Move compiled binaries out of /src (which the build script
    # dumps them into by convention) into a dedicated /prebuild-out
    # directory. This makes the COPY --from in the main Dockerfile
    # explicit and avoids pulling the whole /src tree.
    mkdir -p /prebuild-out && \
    mv /src/unbound /src/unbound-checkconf /src/mosdns /prebuild-out/ && \
    ls -la /prebuild-out/

# Final image is FROM scratch: we ship only the binaries, not the
# entire alpine rootfs. Reduces pull size dramatically.
FROM scratch
COPY --from=builder /prebuild-out/ /prebuild-out/
