#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2020/5/13 上午12:02
# @Author  : TT
# @File    : compare_analysise_result.py

from itertools import islice


class Compare():

    def __init__(self, v2, v5):
        self.v2 = v2
        self.v5 = v5
        self.v2_obj = []
        self.v5_obj = []


    def parse_file(self):
        v2_content = File(self.v2).readfile()
        self.v2_res = Compare.parse_obj(v2_content)

        v5_content = File(self.v5).readfile()
        self.v5_res = Compare.parse_obj(v5_content)

    def compare(self):
        result = []
        for s in self.v2_res:
            for t in self.v5_res:
                if s.getname() == t.getname():
                    r = {}
                    comm = s.para_list & t.para_list
                    r["path"] = s.bin_path
                    r["name"] = s.getname()
                    r["comm"] = comm
                    r["comm_count"] = len(comm)
                    diff_s = s.para_list.difference(t.para_list)
                    r["v2-v5"] = diff_s
                    r["v2-v5_count"] = len(diff_s)
                    diff_t = t.para_list.difference(s.para_list)
                    r["v5-v2"] = diff_t
                    r["v5-v2_count"] = len(diff_t)
                    result.append(r)
                    break
                else:
                    continue
        return result

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


class File():

    def __init__(self, filename):
        self.filename = filename

    def readfile(self):
        with open(self.filename, 'r') as f:
            content = f.read().splitlines()
        return content


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


def outputer(f_path, res):
    with open(f_path, "w") as f:
        for r in res:
            f.write("name : {}\n".format(r["name"]))
            f.write("path : {}\n".format(r["path"]))
            f.write("comm count : {}\n".format(r["comm_count"]))
            f.write("comm : {}\n".format(str(r["comm_count"])))
            f.write("v2-v5_count : {}\n".format(r["v2-v5_count"]))
            f.write("v2-v5 : {}\n".format(r["v2-v5"]))
            f.write("v5-v2_count : {}\n".format(r["v5-v2_count"]))
            f.write("v5-v2 : {}\n".format(r["v5-v2"]))
            f.write("\n")

if __name__ == "__main__":
    c = Compare("/home/tt/qax/Firmware_Front_Analysise/output/Tenda-AC18_V2/detail/Clustering_result_v1.result",
                "/home/tt/qax/Firmware_Front_Analysise/output/Tenda-AC18_V5/detail/Clustering_result_v1.result")
    c.parse_file()
    res = c.compare()
    outputer("/home/tt/ac_15_v2-v5.txt", res)