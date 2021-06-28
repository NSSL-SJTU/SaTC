#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2020/4/29 下午11:13
# @Author  : TT
# @File    : config.py

from front_analysise.modules.parser import HTMLParser, JSParser, DlinkHNAPXMLParser
from front_analysise.modules.filter.b_filter import Keyword_max_in_bin
from front_analysise.modules.filter.f_filter import Para_repeattime_in_front

ANALYSIZER = {
    "html": HTMLParser,
    "asp": HTMLParser,
    "php": HTMLParser,
    "xml": DlinkHNAPXMLParser,
    "js": JSParser
}

B_FILTERS = [
    # Keyword_max_in_bin
]

F_FILTERS = [
    Para_repeattime_in_front
]

# 不对以下固件中的文件进行处理
SPECIAL_MID_NAME = [".so", ".ko"]
# SPECIAL_MID_NAME = [".ko"]

# 删除常见的命令，不会发起http请求的
SPECIAL_COMMAND = ['ls', "pwd", "cat", "vim", "whoami", "printf", "cp", "which", "top", "echo", "ps", "unzip", "fdisk", "sleep", "kill", "vi", "mkdir", "touch","ifconfig", "grep","df", "uname", "awk", "chmod", "find","ln", "netstat","mv", "ssh-keygen", "wget", "curl", "busybox"]

# 二进制文件字符串命中个数
BIN_KEYWORDS_HITS = 10
BIN_FUNCTION_HITS = 0

# 删除特定文件名
REMOVE_FILE = ["device.xml", "defaultvalue.xml", "jquery.js", "bootstrap.min.js", "bootstrap.js"]
# SPECIAL_PATH = ["help"]
SPECIAL_PATH = []

# API分割匹配 如/SetWebFilterSettings/WebFilterMethod 分割成两部分，看Para中存在不存在
API_SPLIT_MARCH = False

# 如果Para在bin的结果中部分匹配，是否需要保留匹配结果
FROM_BIN_ADD = True

# 是否启用UPNP分析
UPNP_ANALYSISE = False
