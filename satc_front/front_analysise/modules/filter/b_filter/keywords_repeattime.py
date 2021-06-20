#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2020/5/6 上午10:57
# @Author  : TT
# @File    : keywords_repeattime.py
from front_analysise.lib.core import BaseFilter
from front_analysise.untils.filter_config import KEYWORDS_REPEATTIME_IN_BIN
from front_analysise.modules.parameter.keyword import args_set


import copy


class Keyword_max_in_bin(BaseFilter):
    """
        限制Para最多只允许出现在几个bin中
    """

    def __call__(self, num=KEYWORDS_REPEATTIME_IN_BIN):

        for kw_obj in args_set[::-1]:
            if kw_obj.binfile_count > num:
                self.remove_keyword.append(kw_obj)
                args_set.remove(kw_obj)
