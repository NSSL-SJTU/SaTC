from ubuntu:xenial
maintainer yans@yancomm.net

run dpkg --add-architecture i386
run apt-get update &&									\
	apt-get install -y virtualenvwrapper python2.7-dev build-essential libxml2-dev libxslt1-dev git libffi-dev cmake libreadline-dev libtool debootstrap debian-archive-keyring libglib2.0-dev libpixman-1-dev libqt4-dev graphviz-dev binutils-multiarch nasm libc6:i386 libgcc1:i386 libstdc++6:i386 libtinfo5:i386 zlib1g:i386 vim python-pip libssl-dev

run useradd -s /bin/bash -m angr

run su - angr -c "git clone https://github.com/angr/angr-dev && cd angr-dev && ./setup.sh -w -e angr && ./setup.sh -w -p angr-pypy"
run su - angr -c "echo 'workon angr' >> /home/angr/.bashrc"
cmd su - angr
