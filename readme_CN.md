# SaTC

<img src="SaTC-arch.png" width="60%">

## 研究论文

我们在下面这篇论文中介绍了我们的方法以及如何发现的这种方法:

**Sharing More and Checking Less: Leveraging Common Input Keywords to Detect Bugs in Embedded Systems** 
[[PDF]](https://www.usenix.org/system/files/sec21fall-chen-libo.pdf)  


## 工程实现


### 安装
建议通过使用Dockerfile来构建系统环境:
```shell
# 进入SaTC代码目录
cd SaTC 

# 构建Docker镜像
docker build . -t satc

# 进入Dokcer环境, 自行添加目录映射
docker run -it smile0304/satc
```

如果因为网络等原因无法构建，可使用我们提供等docker image

```shell
# 从docker hun拉去image
docker pull smile0304/satc

# 进入Dokcer环境, 自行添加目录映射
docker run -it smile0304/satc
```

### 使用方法


```python
usage: satc.py [-h] -d /root/path/_ac18.extracted -o /root/output
               [--ghidra_script {ref2sink_cmdi,ref2sink_bof,share2sink,ref2share,all}]
               [--save_ghidra_project] --taint_check
               [-b /var/ac18/bin/httpd | -l 3]

SATC tool

optional arguments:
  -h, --help            查看帮助
  -d /root/path/_ac18.extracted, --directory /root/path/_ac18.extracted
                        指定从固件中提取出的文件系统
  -o /root/output, --output /root/output
                        指定结果输出位置
  --ghidra_script {ref2sink_cmdi,ref2sink_bof,share2sink,ref2share,all}
                        (可选)指定要运行的ghidra分析脚本
  --save_ghidra_project
                        (可选)是否保存程序运行时产生的ghidra工程路径[默认不保存]
  --taint_check         (可选)指定是否启用污点分析[默认不启用]
  -b /var/ac18/bin/httpd, --bin /var/ac18/bin/httpd
                        (可选)指定要分析的二进制程序路径
  -l 3, --len 3         (可选)指定根据聚合结果分析可能为边界程序的前N个程序，默认为3
```

#### Ghidra_Script介绍

ref2sink_cmdi : 该脚本从给定的字符串的引用中找到命令注入类型sink函数的路径。
ref2sink_bof : 改脚本从给定的字符串的引用中找到缓冲区溢出类型sink函数的路径。


