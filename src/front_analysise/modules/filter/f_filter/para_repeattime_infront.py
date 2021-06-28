#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2020/5/8 下午3:10
# @Author  : TT
# @File    : para_repeattime_infront.py
from front_analysise.lib.core import BaseFilter
from front_analysise.untils.filter_config import PARA_MAX_FRONT
from front_analysise.modules.parameter.keyword import args_set


class Para_repeattime_in_front(BaseFilter):

    def __call__(self, num=PARA_MAX_FRONT):

        for kw_obj in args_set[::-1]:
            if kw_obj.textfile_count > num:
                self.remove_keyword.append(kw_obj)
                args_set.remove(kw_obj)