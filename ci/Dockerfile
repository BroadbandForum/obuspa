
#
# file Dockerfile
#
# Used to create a docker image running OBUSPA for CI purposes

# Basic Usage
# Create a container with latest version of OBUSPA on GitHub and all library dependencies:
#   docker build --no-cache -f ci/Dockerfile -t obuspa:latest .
#
# NOTE: The --no-cache option ensures that the container always builds
#       the latest version of OBUSPA and libwebsockets
#

# Advanced Usage
# Multi-stage build:
# 1) Build OBUSPA and all necessary library dependencies:
#   docker build --no-cache -f Dockerfile -t obuspa:build-env --target build-stage .
# 2) Create a container with OBUSPA and all library dependencies
#   docker build --no-cache -f Dockerfile -t obuspa:latest --target exec-stage .
#
# Running the container with factory reset file mapped into the container from
# the host, and providing the command line arguments to use when invoking OBUSPA:
#   docker run --init -v [host-dir]:/usr/local/etc obuspa:latest -p -v4 -r /usr/local/etc/factory_reset.txt -f /tmp/usp.db
# where [host-dir] is a directory on the host containing the factory reset file
#
# Same as last, but additionally preserving the database between docker runs:
#   docker run --init -v [host-dir]:/usr/local/etc obuspa:latest -p -v4 -r /usr/local/etc/factory_reset.txt -f /usr/local/etc/usp.db
#
# Building OBUSPA in the build environment:
#   docker run --init -it obuspa:build-env
#   cd /usr/local/src/obuspa
#   make
#

FROM debian:stable AS build-stage

RUN apt update && apt -y install \
    build-essential autoconf automake libtool pkg-config cmake git \
    libssl-dev libcurl4-openssl-dev libsqlite3-dev libz-dev libmosquitto-dev

RUN mkdir -p /usr/local/src
WORKDIR /usr/local/src/
RUN git clone https://github.com/warmcat/libwebsockets.git libwebsockets
RUN cd libwebsockets && cmake . && make && make install
RUN ldconfig

COPY . /usr/local/src/obuspa
RUN cd obuspa && autoreconf --force --install && ./configure && make install

FROM debian:stable AS exec-stage
RUN apt update && apt -y install libssl-dev libsqlite3-dev libcurl4-openssl-dev libmosquitto-dev

WORKDIR /
COPY --from=build-stage /usr/local/lib/libwebsockets.* /usr/local/lib/
COPY --from=build-stage /usr/local/bin/obuspa /bin

COPY ci/configs /etc/obuspa/configs
COPY ci/certs /etc/obuspa/certs
RUN ldconfig

ENTRYPOINT ["/bin/obuspa"]
CMD ["-p", "-v4", "-r", "/etc/obuspa/configs/STOMP.txt", "-t", "/etc/obuspa/certs", "-f", "/tmp/usp.db"]
