# Firm-TaintCheck

Firm-TaintCheck is a prototype of SaTC which can detect multi-binary vulnerabilities in embedded firmware.

## Overview

<img src="OverView.png" width="60%">

## Research paper

We present our approach and the findings of this work in the following research paper:

**SaTC: Semantic-aware Taint Checking for Detecting Bugs in Embedded Systems** 
[[PDF]](https://www.badnack.it/static/papers/University/karonte.pdf)  

## Repository Structure

There are four main directories:
- **tool**: Firm-TaintCheck python files
- **configs**: configuration files to analyze the firmware samples in the dataset
- **eval**: scripts to run the various evaluations on Firm-TaintCheck

## Run Firm-TaintCheck

Since we would like to compare with [karonte](https://github.com/ucsb-seclab/karonte), our most test are run on the same docker environment that [karonte provide](https://hub.docker.com/r/badnack/karonte)
.

the angr version in docker is:

```
angr                               7.7.9.21    /home/karonte/deps/angr-dev/angr
angrop                             7.7.9.21    /home/karonte/deps/angr-dev/angrop
archinfo                           7.7.9.14    /home/karonte/deps/angr-dev/archinfo
claripy                            7.7.9.21    /home/karonte/deps/angr-dev/claripy
cle                                7.7.9.21    /home/karonte/deps/angr-dev/cle
```

To  run Firm-TaintCheck, from the repo root directory, just run
> **SYNOPSIS**
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`python tool/main2.py <path_to_firmware> <path_to_config>`
>
> **DESCRIPTION**
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;runs SaTC on the firmware sample, and save the results in `result-firmwareName-xxx.txt`
>
> **EXAMPLE**
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`python tool/main2.py test/FullTest/AC18/httpd_ac18 test/FullTest/AC18/ac18.txt-alter2` It runs SaTC on the Tenda-AC18

## Docker
A dockerized version of Firm-TaintCheck ready to use can be found.

## Dataset
To obtain the dataset used in the paper please send an email to @sjtu
