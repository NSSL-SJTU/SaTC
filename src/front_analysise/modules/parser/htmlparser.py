#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2020/4/27 下午3:35
# @Author  : TT
# @File    : htmlparser.py

from front_analysise.modules.parser.baseparse import BaseParser
from front_analysise.modules.parser.jsparser import JSParser
from front_analysise.tools.comm import JSFile

import os
import re


class HTMLParser(BaseParser):

    def __init__(self, filepath):
        self._js_codes = []
        self.jsfile_citations = {}
        BaseParser.__init__(self, filepath)

    def analysise(self):
        if os.path.isfile(self.fpath):
            content = ""
            self.log.debug("Start Analysise : {}".format(self.fpath))
            with open(self.fpath, "rb") as f:
                content = f.read()

            self.get_keyword(content)
            self.get_function(content)
            self.get_js_src(content)

            # 如何处理内嵌Javascript代码
            self._find_javascript_code(content)
            self.parse_jscode()

    def _find_javascript_code(self, html):
        """
        从HTML文件中寻找Javascript代码
        :param html: html代码
        :return: all 用户存放javascript代码片段的列表。
        """
        html_content = html.decode('utf-8', "ignore")
        js_codes = re.findall(r"<script>([\s\S]+?)</script>", html_content)
        js_codes = js_codes + re.findall(r"<script type=\"text/javascript\">([\s\S]+?)</script>", html_content)
        # js_codes = js_codes + re.findall(r"<script type=\"text/javascript\">([\s\S]+?)</script>", html_content)
        b_js_codes = []
        for js_code in js_codes:
            res = js_code.encode("utf-8")
            b_js_codes.append(res)
        self._js_codes = b_js_codes

    def get_keyword(self, html):
        html_content = html.decode('utf-8', "ignore")
        name_list = re.findall(r'name="(.*?)"', html_content)
        id_list = re.findall(r'id="(.*?)"', html_content)
        results = set(name_list) | set(id_list)
        for res in results:
            self._get_keyword(res, check=0)

    def get_function(self, html):
        html_content = html.decode('utf-8', "ignore")
        path_list = re.findall(r'action="(.*?)"', html_content)
        for path in path_list:
            self._get_function(path, check=0)

    def get_js_src(self, html):
        html_content = html.decode('utf-8', 'ignore')
        src_list = re.findall(r'<script src="(.*?)"></script>', html_content)
        for src in src_list:
            res = src.find("?")
            if res > 0:
                src = src[:res]
            src_file = src.split("/")[-1]
            js_obj = self.jsfile_citations.get(src_file, JSFile(src))
            js_obj.add_depend(self.fpath)
            self.jsfile_citations.update({src_file: js_obj})

    def parse_jscode(self):
        for js in self._js_codes:
            tmp_keyword , tmp_functions= JSParser.js_in_html_parse(js)
            for key in tmp_keyword:
                self.get(key, check=1)

            for action in tmp_functions:
                self._get_function(action, check=0)

    def get_jsfile_citations(self):
        return self.jsfile_citations


if __name__ == "__main__":
    pass