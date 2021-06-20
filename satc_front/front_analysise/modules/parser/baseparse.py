#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2020/4/29 下午3:16
# @Author  : TT
# @File    : baseparse.py
from front_analysise.lib.core import _Parser
from front_analysise.modules.parameter.function import Function
from front_analysise.modules.parameter.keyword import Keyword


class BaseParser(_Parser):

    def _get_keyword(self, keyword, check):

        keyword_obj = Keyword.factory_keyword(keyword, self.fpath, check)
        if keyword_obj:
            self.log.info("Find Keyword : {} PATH: {}".format(keyword, self.fpath))
            self.keyword_name.append(keyword_obj)
            return True
        return False

    def _get_function(self, path, check):
        func_obj = Function.factory_function(path, self.fpath, check)
        if func_obj:
            self.log.info("Find function : {} PATH".format(path, self.fpath))
            self.function_name.append(func_obj)
            return True
        return False

    def get(self, keyword, check):
        res = self._get_keyword(keyword, check)
        if not res:
            self._get_function(keyword, check)
