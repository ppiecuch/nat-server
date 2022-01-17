FROM ubuntu:20.04
MAINTAINER Pawel Piecuch <piecuch.pawel@gmail.com>

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG en_US.UTF-8

WORKDIR /build

# Install all the dependencies
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends apt-transport-https ca-certificates \
    && update-ca-certificates \
    && apt-get install -y --no-install-recommends curl git make cmake g++ \
    && apt-get purge --auto-remove -y \
    && apt-get clean

# Build and install required OpenSSL version:
RUN curl https://www.openssl.org/source/openssl-1.0.2u.tar.gz | tar xz && cd openssl-1.0.2u && ./config && make && make install \
    && ln -sf /usr/local/ssl/bin/openssl `which openssl` \
    && openssl version -v

# Compile the server
COPY src /build
RUN ls -l /build && mkdir /build/work && cd /build/work && \
    g++ --version && \
    cmake .. && make -j $(nproc)

WORKDIR /var/source

# Create the actual image
FROM ubuntu:20.04
MAINTAINER Pawel Piecuch <piecuch.pawel@gmail.com>

RUN apt-get update \
    && apt-get install -y --no-install-recommends supervisor \
    && apt-get purge --auto-remove -y && apt-get clean

# Pack everything we need for the NATServer
COPY --from=0 /build/work/natserver /var/app/natserver

WORKDIR /var/app

EXPOSE 61111/udp

CMD cd /var/app && ./natserver
