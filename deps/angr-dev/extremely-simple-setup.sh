#!/bin/bash

if [ -z "$VIRTUAL_ENV" ]; then
  echo "Are you sure you want to install angr outside a python virtual environment?"
  echo "It is highly recommended to use a virtualenv when working with angr."
  echo -n "y/N "
  read choice
  if ! [ "$choice" = y -o "$choice" = Y ]; then
    exit 1
  fi
fi

## BEGIN VERY COMPLICATED INSTALL PROCEDURE

git clone https://github.com/angr/archinfo.git
git clone https://github.com/angr/vex.git
git clone https://github.com/angr/pyvex.git
git clone https://github.com/angr/claripy.git
git clone https://github.com/angr/cle.git
git clone https://github.com/angr/angr.git
git clone https://github.com/angr/angr-doc.git
git clone https://github.com/angr/binaries.git

set -e

pip install -e ./archinfo
pip install -e ./pyvex
pip install -e ./claripy
pip install -e ./cle
pip install -e ./angr

## END VERY COMPLICATED INSTALL PROCEDURE

pip install nose ipython ipdb
pip install -I --no-use-wheel keystone-engine

set +e

echo "Do you want to install the extra mechaphish analysis components?"
echo "This will fail if your machine isn't 64bit x86"
echo -n "y/N "
read choice
if ! [ "$choice" = y -o "$choice" = Y ]; then
  exit 1
fi

# BEGIN EVEN MORE COMPLICATED INSTALL PROCEDURE

git clone https://github.com/angr/wheels.git
git clone https://github.com/mechaphish/colorguard.git
git clone https://github.com/mechaphish/compilerex.git
git clone https://github.com/shellphish/driller.git
git clone https://github.com/shellphish/fuzzer.git
git clone https://github.com/mechaphish/povsim.git
git clone https://github.com/shellphish/rex.git
git clone https://github.com/angr/tracer.git
git clone https://github.com/salls/angrop.git

set -e

pip install wheels/shellphish_afl*.whl
pip install wheels/shellphish_qemu*.whl

pip install -e ./angrop
pip install -e ./tracer
pip install -e ./driller
pip install -e ./fuzzer
pip install -e ./povsim
pip install -e ./compilerex
pip install -e ./rex
pip install -e ./colorguard

# END EVEN MORE COMPLICATED INSTALL PROCEDURE
