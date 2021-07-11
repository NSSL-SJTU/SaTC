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
docker run -it satc
```

如果因为网络等原因无法构建，可使用我们提供等docker image

```shell
# 从docker hun拉去image
docker pull smile0304/satc:V1.0

# 进入Dokcer环境, 自行添加目录映射
docker run -it smile0304/satc:V1.0
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
                        (可选)指定要运行的ghidra分析脚本, all为运行`ref2sink_cmdi`,`ref2sink_bof`,`ref2share`三个脚本
  --ref2share_result /root/path/ref2share_result  (当要运行share2sink分析脚本时默许指定这个参数)
  --save_ghidra_project (可选)是否保存程序运行时产生的ghidra工程路径[默认不保存]
  --taint_check         (可选)指定是否启用污点分析[默认不启用]
  -b /var/ac18/bin/httpd, --bin /var/ac18/bin/httpd
                        (可选)指定要分析的二进制程序路径
  -l 3, --len 3         (可选)指定根据聚合结果分析可能为边界程序的前N个程序，默认为3
```

### 输出结果说明

输出结果:
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
|   |   |-- from_bin_add_para.result_v2
|   |   |-- Not_Analysise_JS_File.result
|   |   |-- Prar_detail.result
|   |   |-- Prar_remove_detail.result
|   |-- info.txt
|   |-- simple
|       |-- API_simple.result
|       |-- Prar_simple.result
|-- result-httpd-ref2sink_cmdi-ctW8.txt
```


说明:

```shell
|-- ghidra_extract_result # ghidra寻找函数调用路径的分析结果, 启用`--ghidra_script`选项会输出该目录
|   |-- httpd # 每个被分析的bin都会生成一个同名文件夹
|       |-- httpd # 被分析的bin
|       |-- httpd_ref2sink_bof.result # 定位bof类型的sink函数路径
|       |-- httpd_ref2sink_cmdi.result # 定位cmdi类型的sink函数路径
|-- keyword_extract_result  # 关键字提取结果
|   |-- detail  # 前端关键字提取结果(详细分析结果)
|   |   |-- API_detail.result # 提取的API详细结果
|   |   |-- API_remove_detail.result # 被过滤掉的API信息
|   |   |-- api_split.result  # 模糊匹配的API结果
|   |   |-- Clustering_result_v2.result # 详细分析结果(不关心其他过程关心此文件即可)
|   |   |-- File_detail.result  # 记录了从单独文件中提取的关键字
|   |   |-- from_bin_add_para.result # 在二进制匹配过程中新增的关键字
|   |   |-- from_bin_add_para.result_v2 # 同上,V2版本
|   |   |-- Not_Analysise_JS_File.result # 未被分析的JS文件
|   |   |-- Prar_detail.result # 提取的Prar详细结果
|   |   |-- Prar_remove_detail.result # 被过滤掉的Prar结果
|   |-- info.txt  # 记录前端关键字提取时间等信息
|   |-- simple  # 前端关键字提取结果, 比较简单
|       |-- API_simple.result # 在全部二进制中出现的全部API名称
|       |-- Prar_simple.result  # 在全部二进制中出现等的全部Prar
|-- result-httpd-ref2sink_cmdi-ctW8.txt # 污点分析结果,启用`--taint-check` 和 `--ghidra_script`选项才会生成该文件
```


#### Ghidra_Script介绍

ref2sink_cmdi : 该脚本从给定的字符串的引用中找到命令注入类型sink函数的路径。

ref2sink_bof : 改脚本从给定的字符串的引用中找到缓冲区溢出类型sink函数的路径。

##### ref2share, share2sink：

ref2share: 此脚本用来查找输入等字符串中被写入共享函数等参数，例如:`nvram_set`, `setenv`等函数设置在

share2sink: 此脚本与`ref2share`功能类似，只是开头是读取共享函数，例如:`nvram_get`。使用此脚本等输入为`ref2share`脚本的输出


