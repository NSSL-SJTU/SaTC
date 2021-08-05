# SaTC
[Chinese version](README_CN.md)

A prototype of Shared-keywords aware Taint Checking(SaTC), a static analysis method that tracks user input between front-end and back-end for vulnerability discovery effectively and efficiently. 

## Overview of SaTC

<img src="SaTC-arch.png" width="60%">

## Research paper

We present our approach in the following research paper:

**Sharing More and Checking Less: Leveraging Common Input Keywords to Detect Bugs in Embedded Systems** 
[[PDF]](https://www.usenix.org/system/files/sec21fall-chen-libo.pdf)  


## Running Environment

We provide a usable Docker environment and a Dockerfile that can be used to build Docker images.

### Use Dockerfile build

```shell script
# Cd SaTC code directory
cd SaTC

# Use Dockerfile to build docker image
docker build . -t satc

# Run SaTC (Need to add mapping directory by yourself)
docker run -v <mapping>:<mapping> -it satc
```

### Use the compiled docker environment

```shell script
# Get image from Docker hub 
docker pull smile0304/satc

# Run SaTC (Need to add mapping directory by yourself)
docker run -v <mapping>:<mapping> -it smile0304/satc
```

## Instructions

```text
usage: satc.py [-h] -d /root/path/_ac18.extracted -o /root/output
               [--ghidra_script {ref2sink_cmdi,ref2sink_bof,share2sink,ref2share,all}]
               [--save_ghidra_project] --taint_check
               [-b /var/ac18/bin/httpd | -l 3]

SATC tool

optional arguments:
  -h, --help            help
  -d /root/path/_ac18.extracted, --directory /root/path/_ac18.extracted
                        File system obtained from firmware
  -o /root/output, --output /root/output
                        Output result save location
  --ghidra_script {ref2sink_cmdi,ref2sink_bof,share2sink,ref2share,all}
                        (Option) Specify the Ghidra script to be used. If you use the `all` command, the three scripts `ref2sink_cmdi`,`ref2sink_bof` and `ref2share` will be run at the same time
  --ref2share_result /root/path/ref2share_result 
                        (Option) When running the `share2sink` Ghidra script, you need to use this parameter to specify the output result of the `ref2share` script
  --save_ghidra_project (Option) Save the ghidra project directory generated during analysis
  --taint_check         (Option) Use taint analysis engine for analysis
  -b /var/ac18/bin/httpd, --bin /var/ac18/bin/httpd  OR `-b httpd` , `--bin httpd`    
                        (Option) Used to specify the program to be analyzed, if not specified, SaTC will use the built-in algorithm to confirm the program to be analyzed
  -l 3, --len 3         (Option) According to the analysis results, analyze the top N programs that may be the boundary [the default is 3]
```

#### Ghidra script

- `ref2sink_cmdi`: The script finds the path of the command injection type sink function from the reference of the given string.
- `ref2sink_bof` : The script finds the path of the buffer overflow type sink function from the reference of the given string.
- `ref2share` : This script is used to find parameters such as shared functions written in strings such as input, for example: `nvram_set`, `setenv` and other functions. Need to be used in conjunction with share2sink
- `share2sink` : This script is similar to the function of `ref2share`, except that the beginning is to read shared functions, such as: `nvram_get`, `getenv` and other functions. Need to be used in conjunction with `ref2share`; the input of using this script is the output of the `ref2share` script

#### Output 

Output directory structure：
```shell
|-- ghidra_extract_result
|   |-- httpd
|       |-- httpd
|       |-- httpd_ref2sink_bof.result
|       |-- httpd_ref2sink_cmdi.result
|       |-- httpd_ref2sink_cmdi.result-alter2
|-- keyword_extract_result
|   |-- detail
|   |   |-- API_detail.result
|   |   |-- API_remove_detail.result
|   |   |-- api_split.result
|   |   |-- Clustering_result_v2.result
|   |   |-- File_detail.result
|   |   |-- from_bin_add_para.result
|   |   |-- Not_Analysise_JS_File.result
|   |   |-- Prar_detail.result
|   |   |-- Prar_remove_detail.result
|   |-- info.txt
|   |-- simple
|       |-- API_simple.result
|       |-- Prar_simple.result
|-- result-httpd-ref2sink_cmdi-ctW8.txt
```

Need to follow the directory:

- keyword_extract_result/detail/Clustering_result_v2.result : The match of front-end keywords in bin. Input for the `Input Entry Recognition` module
- ghidra_extract_result/{bin}/* : Analysis result of ghidra script. Input for `Input Sensitive Taint Analysise` module
- result-{bin}-{ghidra_script}-{random}.txt: taint analysise result


Other:


```shell
|-- ghidra_extract_result # ghidra looks for the analysis results of the function call path, enabling the `--ghidra_script` option will output the directory
|   |-- httpd # Each bin analyzed will generate a folder with the same name
|       |-- httpd # Bin being analyzed
|       |-- httpd_ref2sink_bof.result # Locate the sink function path of the bof type
|       |-- httpd_ref2sink_cmdi.result # Locate cmdi type sink function path
|-- keyword_extract_result  # Keyword extraction results
|   |-- detail  # Front-end keyword extraction results (detailed analysis results)
|   |   |-- API_detail.result # Detailed results of the extracted API
|   |   |-- API_remove_detail.result # API information filtered out
|   |   |-- api_split.result  # Fuzzy matching API results
|   |   |-- Clustering_result_v2.result # Detailed analysis of the results (don't care about other processes and care about this file)
|   |   |-- File_detail.result  # The keywords extracted from each file are recorded
|   |   |-- from_bin_add_para.result # Keywords added during binary matching
|   |   |-- Not_Analysise_JS_File.result # Unanalyzed JS file
|   |   |-- Prar_detail.result # Detailed results of extracted Prar
|   |   |-- Prar_remove_detail.result # Prar results filtered out
|   |-- info.txt  # Record the front-end keyword extraction time and other information
|   |-- simple  # Deprecated
|       |-- API_simple.result # Deprecated
|       |-- Prar_simple.result  # Deprecated
|-- result-httpd-ref2sink_cmdi-ctW8.txt # taint analysis results, enable the `--taint-check` and `--ghidra_script` options to generate the file
```

#### Example

1.Analyze the vulnerabilities of command injection and buffer overflow in D-Link 878
> python satc.py -d /home/satc/dlink_878 -o /home/satc/res --ghidra_script=ref2sink_cmdi --ghidra_script=ref2sink_bof --taint_check

2.Analyze the vulnerability of `prog.cgi` command injection type in D-Link 878
> python satc.py -d /home/satc/dlink_878 -o /home/satc/res --ghidra_script=ref2sink_cmdi -b prog.cgi --taint_check

3.Analyze the command injection type vulnerability of `rc` in D-Link 878; in this case, use nvram_set to set variables in `prog.cgi`, and use nvram_get to extract in `rc`
> python satc.py -d /home/satc/dlink_878 -o /home/satc/res --ghidra_script=ref2share -b prog.cgi
> python satc.py -d /home/satc/dlink_878 -o /home/satc/res --ghidra_script=share2sink --ref2share_result=/home/satc/res/ghidra_extract_result/prog.cgi/prog.cgi_ref2share.result -b rc --taint_check
