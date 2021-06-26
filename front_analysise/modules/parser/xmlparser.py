#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2020/4/27 下午3:36
# @Author  : TT
# @File    : xmlparser.py

from front_analysise.modules.parser.baseparse import BaseParser
import xml.etree.ElementTree as ET


class DlinkHNAPXMLParser(BaseParser):

    def analysise(self):
        level = 1  # 节点的深度从1开始
        try:
            tree = ET.parse(self.fpath)
            # 获得根节点
            root = tree.getroot()
            self.walkData(root, level)
        except Exception as e:  # 捕获除与程序退出sys.exit()相关之外的所有异常
            self.log.error("parse {} fail!".format(self.fpath))

    # 遍历所有的节点
    def walkData(self, root_node, level):
        """
        实现从xml文件中读取数据
        """
        if level == 3:
            index = root_node.tag.find("}")
            if index > 0:
                str = root_node.tag[index+1:]
            # print(temp_list)
            else:
                str = root_node.tag
            # self.function_name.append(str)
            self._get_function(str, check=0)
        elif level > 3:
            index = root_node.tag.find("}")
            if index > 0:
                str = root_node.tag[index+1:]
            # print(temp_list)
            else:
                str = root_node.tag
            # self.keyword_name.append(str)
            self._get_keyword(str, check=0)

        # 遍历每个子节点
        children_node = list(root_node)
        if len(children_node) == 0:
            return
        for child in children_node:
            self.walkData(child, level+1)
        return
