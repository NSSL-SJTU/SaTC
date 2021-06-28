FROM ubuntu:xenial

MAINTAINER tt.jiaqi@gmail.com

RUN dpkg --add-architecture i386 && \
    apt-get update && \ 
    apt-get install -y virtualenvwrapper python2.7-dev build-essential libxml2-dev libxslt1-dev git libffi-dev cmake libreadline-dev libtool debootstrap debian-archive-keyring libglib2.0-dev libpixman-1-dev libqt4-dev graphviz-dev binutils-multiarch nasm libc6:i386 libgcc1:i386 libstdc++6:i386 libtinfo5:i386 zlib1g:i386 vim python-pip libssl-dev curl tmux net-tools software-properties-common dirmngr apt-transport-https lsb-release ca-certificates && \
    curl -sL https://deb.nodesource.com/setup_10.x | bash - && \
    add-apt-repository ppa:openjdk-r/ppa && \
    apt-get udpate

RUN apt-get install -y nodejs openjdk-11-jdk

RUN useradd -s /bin/bash -m satc

ADD * /home/satc/SaTC

WORKDIR /home/satc/SaTC/
