#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2020/6/12 下午10:34
# @Author  : TT
# @File    : TryFindBoarderBin.py

# 此脚本的作用用于尝试确定边界程序
import re


class File():

    def __init__(self, filename):
        self.filename = filename

    def readfile(self):
        with open(self.filename, 'r') as f:
            content = f.read().splitlines()
        return content


class ResultObj():

    def __init__(self, path, count):
        self.bin_path = path
        self.name = path.split("/")[-1]
        self.para_count = int(count)

    def getname(self):
        return self.name

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name


class TryFind(object):

    def __init__(self, file):
        self.file = file

    def parse_file(self):
        content = File(self.file).readfile()
        self.res = TryFind.parse_obj(content)

    def find(self):
        result = []
        self.res.sort(key=TryFind.count_sort, reverse=True)
        for r in self.res:
            n = r.getname().split(".")
            if not ("so" in n or "ko" in n):
                result.append(r)
            if len(result) >= 5:
                break
        return result


    @staticmethod
    def count_sort(elem):
        return elem.para_count

    @staticmethod
    def parse_obj(content):
        res = []
        content_len = len(content)
        next = True
        index = 0

        while next:
            end = index + 14
            if end <= content_len:
                result = content[index:end]
                index = end

                # 开始解析对象
                name = result[0].replace("Program name : ", "")
                count = result[2].replace("Para + API count : ","")
                res.append(ResultObj(name, count))
            else:
                next = False
                break
        return res


class ResultObj():

    def __init__(self, path, para_count, para_list, api_count, api_list):
        self.bin_path = path
        self.name = path.split("/")[-1]
        self.para_count = int(para_count)
        self.para_list = set(para_list)
        self.api_count = int(api_count)
        self.api_list = set(api_list)

    def getname(self):
        return self.name

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name


class ResultFile():

    def __init__(self, v2):
        self.v2 = v2
        self.v2_obj = []

    def parse_file(self):
        v2_content = File(self.v2).readfile()
        self.v2_res = ResultFile.parse_obj(v2_content)

    @staticmethod
    def parse_obj(content):
        res = []
        content_len = len(content)
        next = True
        index = 0

        while next:
            end = index + 14
            if end <= content_len:
                result = content[index:end]
                index = end

                # 开始解析对象
                name = result[0].replace("Program name : ", "")
                para_count = result[4].replace("\tHits Para count: ","")
                para_list = result[6].replace("\t\t", "").split(" ")
                api_count = result[9].replace("\tHits API count: ", "")
                api_list = result[11].replace("\t\t", "").split(" ")
                res.append(ResultObj(name, para_count, para_list, api_count, api_list))
            else:
                next = False
                break
        return res


border_bin_re = [
    "cgi",      # "*.cgi", "cgibin"
    "httpd",    # httpd, lighttpd
    "upnp",     # upnpd, miniupnpd
    "boa"       # boa
]

border_bin_list = []

if __name__ == "__main__":
    path = "/home/lin/Desktop/SATC_res/keyword_extract_result/NetGear_R7000"
    # c = TryFind(path+"/detail/Clustering_result_v2.result")
    # c.parse_file()
    c = ResultFile(path+"/detail/Clustering_result_v2.result")
    c.parse_file()

    for b in c.v2_res:
        for reg in border_bin_re:
            if re.search(reg, b.name):
                border_bin_list.append(b)

    for index, b in enumerate(border_bin_list):
        print("Possible border bin {} : {}".format(index+1, b.name))
    # res = c.find()
    # print("Boarder Bin : " + str(res))
