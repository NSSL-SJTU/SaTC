#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2020/5/6 下午7:38
# @Author  : TT
# @File    : filter_config.py

# 允许字符串在bin出现次数
KEYWORDS_REPEATTIME_IN_BIN = 5
# 允许字符串在Text出现次数
KEYWORDS_REPEATTIME_IN_TEXT = 3

# 允许Para最多出现在几个不同的文本文件中
PARA_MAX_FRONT = 10

# 是否启用JS引用限制模块, 如果开启则一定要分析HTML
JS_LIMITED_ACTIVATION = True
# 如果启用JS限制，最多允许JS文件被引用的次数
JS_FILE_LIMITED_NUMBER = 5

# API过滤特殊字符串
API_FILTER_STRINGS = ["@", "^", "&", "*", "(", ")", "{", "}", "[", "]", ":", ";", ",", "<", ">", "|", "，", "？", " ", "+", ".", "="]
# Para过滤特殊字符串
PARA_FILTER_STRINGS = [" ","!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "-", "+", "{", "}", "[", "]", ":", ";", "'", "\"", ",", ".", "?", "/", ",", "<", ">", "\\", "|", "，", "？", "！", "="]