#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2020/6/4 下午4:29
# @Author  : TT
# @File    : upnp_keyword.py
from front_analysise.lib.core import BaseParameter
from front_analysise.modules.parameter.global_cls import Count

# EX : upnp_args_set(Keyword()), ...
upnp_args_set = list()


class UPNPKeyword(BaseParameter):

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

    @classmethod
    def factory_keyword(cls, k, fpath):
        Count.KEYWORDS_COUNT += 1
        for obj_s in upnp_args_set:
            if obj_s.name == k:
                obj_s.add_textfile(fpath)
                return obj_s


        key_obj = cls(k, fpath)
        upnp_args_set.append(key_obj)

        return key_obj

    @staticmethod
    def get_keyword(k):
        for obj_s in upnp_args_set:
            if obj_s.name == k:
                return obj_s
        return None