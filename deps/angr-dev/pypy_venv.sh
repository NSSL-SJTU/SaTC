#!/bin/bash -e

NAME=$1
DIR=$(dirname $0)
cd $DIR

#sudo apt-get install cmake libreadline-dev

# setup
mkdir -p pypy
cd pypy


if [ -f "/etc/arch-release" ]; then
    echo "This is an arch distro"
    ARCH=$(uname -m)
    SUBVERSION=$(pacman -Si pypy | grep "Version\s*:\s*[0-9.\-]*" | grep -o "[0-9.\-]*")
    VERSION=${2-pypy-$SUBVERSION-$ARCH}
    # get pypy
    [ ! -e $VERSION.pkg.tar.xz ] && wget https://mirrors.kernel.org/archlinux/community/os/$ARCH/$VERSION.pkg.tar.xz
    if [ ! -e $VERSION ]; then
        tar xf $VERSION.pkg.tar.xz
        mv ./opt/pypy ./$VERSION
    fi

    set +e
    source /usr/bin/virtualenvwrapper.sh
    set -e
else
    BEST_VERSION=$(wget https://bitbucket.org/pypy/pypy/downloads/ -O - | egrep -o 'href="/pypy/pypy/downloads/[^"]+' | cut -c 28- | grep linux64 | grep pypy2 | head -n 1)
    DOWNLOAD_URL=https://bitbucket.org/pypy/pypy/downloads/$BEST_VERSION

    # get pypy
    wget $DOWNLOAD_URL --local-encoding=utf-8 -O - | tar xj

    set +e
    source /etc/bash_completion.d/virtualenvwrapper
    set -e
fi


# virtualenv
set +e
mkvirtualenv -p $PWD/pypy2-*/bin/pypy $NAME
set -e
pip install -U setuptools

# readline
[ ! -e pyreadline-cffi ] && git clone https://github.com/yuyichao/pyreadline-cffi.git
cd pyreadline-cffi && cmake CMakeLists.txt && make && make install
rm -f $VIRTUAL_ENV/lib_pypy/readline.*
ln -s $VIRTUAL_ENV/site-packages/readline $VIRTUAL_ENV/lib_pypy/readline

echo "installed pypy in $NAME"
exit 0
