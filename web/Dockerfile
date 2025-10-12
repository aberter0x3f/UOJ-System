FROM ubuntu:24.04
MAINTAINER Baoshuo <i@baoshuo.ren>

LABEL org.opencontainers.image.source="https://github.com/UniversalOJ/UOJ-System"
LABEL org.opencontainers.image.description="UOJ Web"
LABEL org.opencontainers.image.licenses="MIT"

ARG CLONE_ADDFLAG

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV TZ=Asia/Shanghai

# https://github.com/phpv8/v8js/issues/517
# Add an extra include to make phpv8 built on newer gcc
RUN \
    apt-get update && apt-get install -y --no-install-recommends software-properties-common gnupg curl ca-certificates && \
    echo "deb http://ppa.launchpad.net/stesie/libv8/ubuntu bionic main" | tee /etc/apt/sources.list.d/stesie-libv8.list && \
    apt-key adv --keyserver keyserver.ubuntu.com --recv-keys D858A0DF && \
    add-apt-repository ppa:ondrej/php && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
      git vim ntp zip unzip curl wget apache2 libapache2-mod-xsendfile \
      php7.4 libapache2-mod-php7.4 php7.4-dev php-pear php7.4-zip php7.4-mysql php7.4-mbstring php7.4-gd php7.4-intl php7.4-xsl \
      build-essential gcc g++ gcc-14 g++-14 make re2c \
      libv8-7.5-dev libyaml-dev libseccomp-dev && \
    update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-14 100 && \
    update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-14 100 && \
    update-alternatives --install /usr/bin/cpp cpp-bin /usr/bin/cpp-14 100 && \
    yes | pecl install yaml && \
    git clone https://github.com/phpv8/v8js.git --depth=1 -b 2.1.2 /tmp/pear/download/v8js-master && \
    cd /tmp/pear/download/v8js-master && \
    phpize && \
    ./configure --with-php-config=/usr/bin/php-config --with-v8js=/opt/libv8-7.5 && \
    sed -i '1i#include <stdexcept>' v8js_object_export.cc && \
    make -j"$(nproc)" && make install && \
    cd / && rm -rf /tmp/pear/download/v8js-master \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Add application files
ADD . /opt/uoj
WORKDIR /opt/uoj

# Install web environment and create startup script
RUN sh web/install.sh -p && \
    printf '%s\n' '#!/bin/sh' \
      'if [ ! -f "/var/uoj_data/.UOJSetupDone" ]; then' \
      '  cd /opt/uoj/web && sh install.sh -i' \
      'fi' \
      'apache2ctl -D FOREGROUND' > /opt/up && \
    chmod +x /opt/up

EXPOSE 80
CMD ["/opt/up"]
