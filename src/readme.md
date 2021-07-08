## SATC

Program Home:

![home](./img/satc.png)


Instructions:
```
usage: satc.py [-h] -d /root/path/_ac18.extracted -o /root/output
               [--ghidra_script {ref2sink_cmdi,ref2sink_bof,share2sink,ref2share,all} [{ref2sink_cmdi,ref2sink_bof,share2sink,ref2share,all} ...]] [--save_ghidra_project]
               (-b /var/ac18/bin/httpd | -l 3)

SATC tool

optional arguments:
  -h, --help            show this help message and exit
  -d /root/path/_ac18.extracted, --directory /root/path/_ac18.extracted
                        Directory of the file system after firmware decompression
  -o /root/output, --output /root/output
                        Folder for output results
  --ghidra_script {ref2sink_cmdi,ref2sink_bof,share2sink,ref2share,all} [{ref2sink_cmdi,ref2sink_bof,share2sink,ref2share,all} ...]
                        ghidra script to run
  --save_ghidra_project
                        whether to save the ghidra project
  -b /var/ac18/bin/httpd, --bin /var/ac18/bin/httpd
                        Input border bin
  -l 3, --len 3         Take the first few
```



-d 指定解压固件目录(必须)

-o 指定结果输出目录(必须)

-l 从前端分析结果中选择排名靠前到几位作为边界程序(可选)，默认为3

-b 指定边界程序路径(可选)，与`-l`参数冲突

--ghidra_script 指定要运行到ghidra脚本，具体参考`help`命令返回，默认不执行

--save_ghidra_project 是否保存，默认不保存

## 环境依赖
需要下载ghidra源代码框架到当前路径下，并重命名为ghidra

## 运行程序

1. 提取JS文件需要进入jsparse目录，运行`npm run install`, 或者使用docker运行

> docker build -t . jsparse

> docker run -itd 3000:3000 jsparse

2. 运行主程序satc.py即可