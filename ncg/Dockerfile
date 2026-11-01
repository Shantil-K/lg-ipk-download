# ARM cross-compiler for the N-API addon (ncg_native.c).
#
# ubuntu:20.04 (glibc 2.31) is deliberate, not a stale default; see
# ncg_native.c.
#
# Build: docker build -t ncgaddon:20 -f Dockerfile .
FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    binutils-arm-linux-gnueabi \
    gcc-arm-linux-gnueabi \
    libc6-dev-armel-cross \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /work
