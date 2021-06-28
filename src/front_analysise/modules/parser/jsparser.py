#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2020/4/27 下午1:31
# @Author  : TT
# @File    : jsparser.py

from front_analysise.modules.parser.baseparse import BaseParser
from front_analysise.untils.logger.logger import get_logger

import requests
import json
import os
import re


class JSParser(BaseParser):
    filepath = ""

    def __init__(self, filepath):
        BaseParser.__init__(self, filepath)
        JSParser.filepath = filepath

    def analysise(self):
        if os.path.isfile(self.fpath):
            self.log.debug("Start Analysise : {}".format(self.fpath))
            with open(self.fpath, "rb") as f:
                content = f.read()
            tmp_keywords, tmp_functions = JSParser._js_reader(content)

            for tmp in tmp_keywords:
                self.get(tmp, check=1)

            for f in tmp_functions:
                self._get_function(f, check=0)

    @staticmethod
    def js_in_html_parse(jscode=""):
        # soapactions = JSParser._march_soapaction(jscode)
        tmp_keywords, tmp_functions = JSParser._js_reader(jscode)

        # tmp_keywords = [i for i in tmp_keywords if i not in soapactions]

        return tmp_keywords, tmp_functions

    @staticmethod
    def _js_reader(content, key=""):
        tmp_keywords = set()
        tmp_functions = set()

        content = content.decode('utf-8', "ignore")
        data_dict = {"engine": "acorn",
                     "code": content}
        headers = {'Content-Type': 'application/json'}
        try:
            response = requests.post("http://localhost:3000/codeparse", headers=headers, data=json.dumps(data_dict))
            data = response.json()
            if data["code"] != 200:
                raise Exception("解析错误")
            tree = data["data"]

            # esprima = js2py.require('esprima')
            # # acorn = js2py.require('acorn')
            # tree = esprima.parse(content).to_dict()

            if key:
                keywords, functions = JSParser.get_target_value(key, tree, [], [])
            else:
                keywords, functions = JSParser.get_target_value("name", tree, [], [])
                keywords1, function1 = JSParser.get_target_value("value", tree, [], [])
                keywords = keywords + keywords1
                functions = functions + function1

            for r in keywords:
                if isinstance(r, str):
                    tmp_keywords.add(r)
            for f in functions:
                if isinstance(f, str):
                    tmp_functions.add(f)

        except Exception as e:
            log = get_logger()
            log.error("Error parse JS file : " + JSParser.filepath)
        finally:
            return list(tmp_keywords), list(tmp_functions)

    @staticmethod
    def get_target_value(key, dic, tmp_list, func_list):
        """
        :param key: 目标key值
        :param dic: JSON数据
        :param tmp_list: 用于存储获取的数据
        :return: list
        """
        if not isinstance(dic, dict) or not isinstance(tmp_list, list):  # 对传入数据进行格式校验
            return 'argv[1] not an dict or argv[-1] not an list '

        if dic.get("type", "") == "CallExpression" and len(dic.get("arguments",[])) == 3:
            obj = dic.get("callee", None)
            if obj:
                soapaction = obj.get("property", None)
                if soapaction and soapaction.get("name", "") == "sendSOAPAction":
                    args = dic.get("arguments", [])
                    if args and args[0].get("type", "") == "Literal":
                        func_list.append(args[0].get("value", ""))


        if key in dic.keys() and dic.get("type", "") == "Literal":
            tmp_list.append(str(dic[key]))  # 传入数据存在则存入tmp_list

        for value in dic.values():  # 传入数据不符合则对其value值进行遍历
            if isinstance(value, dict):
                JSParser.get_target_value(key, value, tmp_list, func_list)  # 传入数据的value值是字典，则直接调用自身
            elif isinstance(value, (list, tuple)):
                if value:
                    JSParser._get_value(key, value, tmp_list, func_list)  # 传入数据的value值是列表或者元组，则调用_get_value

        return list(set(tmp_list)), list((func_list))

    @staticmethod
    def _get_value(key, val, tmp_list, func_list):
        for val_ in val:
            if isinstance(val_, dict):
                JSParser.get_target_value(key, val_, tmp_list, func_list)  # 传入数据的value值是字典，则调用get_target_value
            elif isinstance(val_, (list, tuple)):
                if val_:
                    JSParser._get_value(key, val_, tmp_list, func_list)  # 传入数据的value值是列表或者元组，则调用自身

    @staticmethod
    def _march_soapaction(code):
        code = code.decode('utf-8', "ignore")
        soapactions = re.findall(r'sendSOAPAction\("([\s\S]+?)",.*\)', code)
        return list(set(soapactions))