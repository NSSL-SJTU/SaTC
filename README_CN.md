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


```text
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
                        (可选) 指定要使用的 Ghidra 脚本。 如果使用`all`命令，`ref2sink_cmdi`、`ref2sink_bof`和`ref2share`三个脚本将同时运行
  --ref2share_result /root/path/ref2share_result  (可选) 运行`share2sink` Ghidra脚本时，需要使用该参数指定`ref2share`脚本的输出结果
  --save_ghidra_project (可选) 是否保存程序运行时产生的ghidra工程路径
  --taint_check         (可选) 指定是否启用污点分析
  -b /var/ac18/bin/httpd, --bin /var/ac18/bin/httpd
                        (可选) 用于指定需要分析的程序，如果不指定，SaTC将使用内置算法确认需要分析的程序
  -l 3, --len 3         (可选) 根据分析结果分析可能为边界的前N个程序，默认为3
```

#### Ghidra Script介绍

ref2sink_cmdi : 该脚本从给定的字符串的引用中找到命令注入类型sink函数的路径。

ref2sink_bof : 改脚本从给定的字符串的引用中找到缓冲区溢出类型sink函数的路径。

ref2share: 此脚本用来查找输入等字符串中被写入共享函数等参数，例如:`nvram_set`, `setenv`等函数。需要与share2sink来配合使用

share2sink: 此脚本与`ref2share`功能类似。需要与`ref2share`来配合使用；使用此脚本的输入为`ref2share`脚本的输出


#### 输出

输出结果目录结构:
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

需要关注的输出结果目录:
- 1.keyword_extract_result/detail/Clustering_result_v2.result : 前端关键字在bin中的匹配情况。为`Input Entry Recognition`模块的输入
- 2.ghidra_extract_result/{bin}/* : ghidra脚本的分析结果。为`Input Sensitive Taint Analysise`模块的输入
- 3.result-{bin}-{ghidra_script}-{random}.txt: 污点分析结果

其他文件说明:

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

#### 使用案例
1.分析D-Link 878中命令注入、缓冲区溢出类型的漏洞
```shell script
python satc.py -d /home/satc/dlink_878 -o /home/satc/res --ghidra_script=ref2sink_cmdi --ghidra_script=ref2sink_bof --taint_check
```

2.分析D-Link 878中`prog.cgi`命令注入类型的漏洞
```shell script
python satc.py -d /home/satc/dlink_878 -o /home/satc/res --ghidra_script=ref2sink_cmdi -b prog.cgi --taint_check
```

3.分析D-Link 878中`rc`的命令注入类型漏洞；在这个案例中`prog.cgi`中使用nvram_set设置变量，`rc`中使用nvram_get提取
```shell script
python satc.py -d /home/satc/dlink_878 -o /home/satc/res --ghidra_script=ref2share -b prog.cgi

python satc.py -d /home/satc/dlink_878 -o /home/satc/res --ghidra_script=share2sink --ref2share_result=/home/satc/res/ghidra_extract_result/prog.cgi/prog.cgi_ref2share.result -b rc --taint_check
```

#### 数据集合
[SaTC_dateset.zip](https://drive.google.com/file/d/1rOhjBlmv3jYmkKhTBJcqJ-G56HoHBpVX/view?usp=sharing)