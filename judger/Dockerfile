FROM ubuntu:24.04
MAINTAINER Baoshuo <i@baoshuo.ren>
LABEL org.opencontainers.image.source=https://github.com/UniversalOJ/UOJ-System
LABEL org.opencontainers.image.description="UOJ Judger"
LABEL org.opencontainers.image.licenses=MIT

SHELL ["/bin/bash", "-c"]

ENV DEBIAN_FRONTEND=noninteractive
ARG CLONE_ADDFLAG

RUN \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    git vim ntp zip unzip curl wget build-essential ca-certificates \
    fp-compiler \
    python3 python3-requests \
    openjdk-8-jdk openjdk-11-jdk \
    gcc-14 g++-14 \
    libseccomp-dev \
    tzdata && \
    update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-14 100 && \
    update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-14 100 && \
    update-alternatives --install /usr/bin/cpp cpp-bin /usr/bin/cpp-14 100 && \
    cd /usr/src && \
    wget https://www.python.org/ftp/python/2.7.18/Python-2.7.18.tgz && \
    tar xzf Python-2.7.18.tgz && \
    cd Python-2.7.18 && \
    ./configure && \
    make -j"$(nproc)" && \
    make install && \
    cd / && \
    rm -rf /usr/src/Python-2.7.18.tgz /usr/src/Python-2.7.18 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

ADD . /opt/uoj_judger
WORKDIR /opt/uoj_judger

# Install environment and set startup script
RUN sh install.sh -p && sh install.sh -d

ENV LANG=C.UTF-8 TZ=Asia/Shanghai
EXPOSE 2333
CMD /opt/up
