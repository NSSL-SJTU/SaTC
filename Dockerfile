FROM ubuntu:xenial

MAINTAINER tt.jiaqi@gmail.com

RUN dpkg --add-architecture i386 && \
    apt-get update && \ 
    apt-get install -y virtualenvwrapper python2.7-dev build-essential libxml2-dev libxslt1-dev git libffi-dev cmake libreadline-dev libtool debootstrap debian-archive-keyring libglib2.0-dev libpixman-1-dev libqt4-dev graphviz-dev binutils-multiarch nasm libc6:i386 libgcc1:i386 libstdc++6:i386 libtinfo5:i386 zlib1g:i386 vim python-pip libssl-dev curl tmux net-tools software-properties-common dirmngr apt-transport-https lsb-release ca-certificates && \
    curl -sL https://deb.nodesource.com/setup_10.x | bash - && \
    add-apt-repository -y ppa:openjdk-r/ppa && \
    apt-get update

RUN apt-get install -y nodejs openjdk-11-jdk

RUN useradd -s /bin/bash -m satc

COPY --chown=satc:satc src /home/satc/SaTC/
ADD --chown=satc:satc http://202.120.7.23:8888/deps/angr-dev.tar.xz /home/satc/deps/
ADD --chown=satc:satc http://202.120.7.23:8888/deps/ghidra.tar.xz /home/satc/deps/

WORKDIR /home/satc/SaTC/jsparse

RUN npm install

RUN su - satc -c "source /usr/share/virtualenvwrapper/virtualenvwrapper.sh && \ 
                mkvirtualenv SaTC && \
                pip install -r ~/SaTC/requirements.txt && \
		        tar -xvf /home/satc/deps/angr-dev.tar.xz -C /home/satc/deps/ && \
                /home/satc/deps/angr-dev/setup.sh && \
                pip install pyelftools==0.24 && \
                tar -xvf /home/satc/deps/ghidra.tar.xz -C /home/satc/SaTC/ && \
                echo 'workon SaTC' >> /home/satc/.bashrc"

ADD init.sh /home/satc/SaTC

ENTRYPOINT /home/satc/SaTC/init.sh
