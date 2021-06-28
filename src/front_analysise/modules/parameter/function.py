#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2020/4/28 下午12:29
# @Author  : TT
# @File    : function.py

from front_analysise.lib.core import BaseParameter
from front_analysise.modules.parameter.global_cls import Count
from front_analysise.untils.filter_config import API_FILTER_STRINGS

function_set = list()


class Function(BaseParameter):

    def __init__(self, f, fpath):
        self.name = f
        self.func = f
        self.fpath = fpath
        self.source = "JS"

        self.fname = fpath.split("/")[-1]
        BaseParameter.__init__(self)
        self.TextFile.add(self.fpath)

    def set_source_html(self):
        self.source = "HTML"

    def __str__(self):
        return "func : {} | filename : {} | filepath : {}".format(self.func, self.fname, self.fpath)

    def __repr__(self):
        return "func : {}".format(self.func)

    @staticmethod
    def filter(str):
        name = str.strip()

        if len(name) < 5:
            return False, ""

        for filter_str in API_FILTER_STRINGS:
            if filter_str in name:
                return False, ""

        if "/" in name:
            if name.endswith("?"):
                return True, name[:-1]
            return True, name

        return False, ""

    @classmethod
    def factory_function(cls, k, fpath, check=1):
        Count.FUNCTION_COUNT += 1

        for obj_s in function_set:
            if obj_s.name == k:
                obj_s.add_textfile(fpath)
                return obj_s

        if check:
            check_result, string = cls.filter(k)
            if check_result:
                func_obj = cls(string, fpath)
                function_set.append(func_obj)
            else:
                Count.BASE_FILTER_API = Count.BASE_FILTER_API + 1
                func_obj = None
        else:
            func_obj = cls(k, fpath)
            func_obj.set_source_html()
            function_set.append(func_obj)
        return func_obj
