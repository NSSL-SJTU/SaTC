#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2020/4/28 下午12:16
# @Author  : TT
# @File    : keyword.py
from front_analysise.lib.core import BaseParameter
from front_analysise.modules.parameter.global_cls import Count
from front_analysise.untils.filter_config import PARA_FILTER_STRINGS

# EX : args_set(Keyword()), ...
args_set = list()


class Keyword(BaseParameter):

    def __init__(self, k, fpath):
        self.name = k
        self.keyword = k
        self.fpath = fpath

        self._fname = fpath.split("/")[-1]

        BaseParameter.__init__(self)

        self.TextFile.add(self.fpath)

    def __str__(self):
        return "keyword : {} | filepath : {}".format(self.keyword, self.fpath)

    def __repr__(self):
        return "Keyword : {}".format(self.keyword)

    @staticmethod
    def filter(name):
        # str = str.strip()

        # 判断其他字符
        if name.startswith("_"):
            return False, ""

        if len(name) <= 4:
            return False, ""

        if len(name) >= 25:
            return False, ""

        for filter_str in PARA_FILTER_STRINGS:
            if filter_str in name:
                return False, ""

        # if name.endswith("="):
        #     return True, name[:-1]

        return True, name

            # if not any(s in str for s in ["!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "-", "+", "{", "}", "[", "]", ":", ";", "'", "\"", ",", ".", "?", "/", ",", "<", ">", "\\", "|", "，", "？", " ", "！", '\'']):
            #     if name.endswith("="):
            #         return (True, name[:-1])
            #     return (True, name)
            #
            # return (False, "")

    @classmethod
    def factory_keyword(cls, k, fpath, check):
        Count.KEYWORDS_COUNT += 1
        for obj_s in args_set:
            if obj_s.name == k:
                obj_s.add_textfile(fpath)
                return obj_s

        if check:
            check_res_b, str = BaseParameter.baseFilter(k)
            check_res_f, str = cls.filter(k)
            check_res = check_res_b and check_res_f
            # check_res, str = BaseParameter.baseFilter(k)
        else:
            check_res, str = BaseParameter.baseFilter(k)

        if check_res:
            key_obj = cls(str, fpath)
            args_set.append(key_obj)
            return key_obj
        else:
            Count.BASE_FILTER_PARA = Count.BASE_FILTER_PARA + 1
        return None

    @staticmethod
    def get_keyword(k):
        for obj_s in args_set:
            if obj_s.name == k:
                return obj_s
        return None