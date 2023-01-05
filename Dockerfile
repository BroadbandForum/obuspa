 # Ubuntu 22.10 (Kinetic Kudu) includes libmosquitto 2.0.11 and libwebsockets 4.1.6
FROM ubuntu:kinetic

ENV MAKE_JOBS=8
ENV OBUSPA_ARGS="-v4"

# Install dependencies
RUN apt-get update &&\
    apt-get -y install \
        libssl-dev \
        libcurl4-openssl-dev\
        libsqlite3-dev \
        libc-ares-dev \
        libz-dev \
        autoconf \
        automake \
        libtool \
        libmosquitto-dev \
        libwebsockets-dev \
        pkg-config \
        make \
        &&\
        apt-get clean

# Copy in all of the code
# Then compile, as root.
COPY . /obuspa/
RUN cd /obuspa/ && \
    autoreconf -fi && \
    ./configure && \
    make -j${MAKE_JOBS} && \
    make install

# Then delete the code
# that's no longer needed
RUN rm -rf /obuspa

# Run obuspa with args expanded
CMD obuspa ${OBUSPA_ARGS}
