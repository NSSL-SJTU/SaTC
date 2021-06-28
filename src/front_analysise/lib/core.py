#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2020/4/27 下午1:12
# @Author  : TT
# @File    : core.py

from front_analysise.untils.logger.logger import get_logger


class _Parser():

    # def __init__(self, traver):
    #     self.traver = traver
    def __init__(self, filepath):
        self.fpath = filepath
        self.fname = filepath.split("/")[-1]
        self.log = get_logger()
        self.keyword_name = []
        self.function_name = []

    def analysise(self):
        raise NotImplementedError("analysise function not implement")

    def get_justresult(self):
        raise NotImplementedError("get_justresult function not implement")

    def get_result(self):
        raise NotImplementedError("get_result function not implement")


class BaseParameter():
    COUNT = 0

    def __init__(self):
        self.TextFile = set()
        self.BinFile = set()
        self._match_str = set()
        self._bin_str = set()

    @property
    def binfile_count(self):
        return len(self.BinFile)

    @property
    def textfile_count(self):
        return len(self.TextFile)

    def get_textfile(self):
        return list(self.TextFile)

    def get_binfile(self):
        return list(self.BinFile)

    def add_textfile(self, fn):
        name = fn.split("/")[-1]
        self.TextFile.add(fn)

    def add_binFile(self, fn):
        name = fn.split("/")[-1]
        self.BinFile.add(fn)

    def set_match_str(self, str):
        self._match_str.add(str)

    def get_match_str(self):
        return self._match_str

    def set_bin_str(self, str):
        if not any(s in str[0].strip() for s in ["@","^","&","*","(",")","{","}","[","]",":",";",",","<",">","|","，","？", " ", "+", ".", "%", "-"]):
            if "/" in str[0]:
                self._bin_str.add(str)

    def set_upnp_bin_str(self, str):
        self._bin_str.add(str)

    def get_bin_str(self):
        return sorted(self._bin_str, key=lambda x: x[0])

    @staticmethod
    def baseFilter(str):
        if len(str) <= 3:
            return False, str
        try:
            int(str[0])
            return False, ""
        except Exception as e:
            return True, str


class BaseFilter():

    def __init__(self):
        self.remove_keyword = []
        self.remove_functions = []

    def get_remove_keyword(self):
        return self.remove_keyword

    def get_remove_functions(self):
        return self.remove_functions

    def __call__(self, *args, **kwargs):
        pass
