# SaTC
A prototype of Shared-keywords aware Taint Checking, a novel static analysis approach that tracks the data flow of the user input between front-end and back-end to precisely detect security vulnerabilities. 

## Overview of SaTC

<img src="./SaTC-arch.png" width="60%">

## Research paper

We present our approach and the findings of this work in the following research paper:

**Sharing More and Checking Less: Leveraging Common Input Keywords to Detect Bugs in Embedded Systems** 
[[PDF]](https://www.usenix.org/system/files/sec21fall-chen-libo.pdf)  



This project includes two modules:

- satc_front: Front-end hanlder module
- satc_TaintCheck: Taint Engine 

### Running Environment

#### satc_front
1. Locate `satc_front/jsparse`

2. To install node.js，run `npm run start`;
   Docker running JS：
    > docker build . -t jsparse

    > docker run -itd 3000:3000 jsparse

Description of Commands :
[satc_front/readme.md](satc_front/readme.md)


#### satc_TaintCheck

> docker pull cpegg/satc:1.2.0

Command:
> time python tool/main.py \<path to binary> \<path to ghidra result>

Example：
> time python tool/main.py test/R7000P-V1.3.0.8/httpd test/R7000P-V1.3.0.8/httpd_ref2sink_bof.result
