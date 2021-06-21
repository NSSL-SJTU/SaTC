#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2020/5/3 下午2:50
# @Author  : TT
# @File    : output.py
from front_analysise.modules.parameter import args_set, function_set
from front_analysise.modules.parameter.global_cls import Count
from front_analysise.untils.config import FROM_BIN_ADD
from front_analysise.untils.tools import runtimer, b_total

import os
import datetime


class BaseOutput():
    def __init__(self, result, out_dir):
        self.baseoutdir = out_dir
        self.detailoutput = os.path.join(self.baseoutdir, "detail")
        self.simpleoutput = os.path.join(self.baseoutdir, "simple")
        if not os.path.isdir(self.detailoutput):
            os.makedirs(self.detailoutput)
        if not os.path.isdir(self.simpleoutput):
            os.makedirs(self.simpleoutput)
            os.makedirs(os.path.join(self.simpleoutput, ".data"))
        self.result = result

    def write_detail_function(self):
        pass

    def write_details_keyword(self):
        pass

    def write_back_result(self):
        pass

    def write_front_simple_keyword(self):
        pass

    def write_front_simple_function(self):
        pass

    def write_front_single_simple(self):
        pass


class Output(BaseOutput):

    def custom_write(self):
        self.write_detail_function()
        self.write_details_keyword()
        self.write_back_result()

        self.write_front_simple_function()
        self.write_front_simple_keyword()
        self.write_front_single_simple()

    def write_detail_function(self):
        with open(os.path.join(self.detailoutput, "API_detail.result"), "w") as f:
            function_set.sort(key=lambda elem: elem.name)
            for function in function_set:
                f.write("API name : {}\n".format(function.name))
                f.write("Source File : \n")
                f.write("\tText File: \n")
                for fp in function.TextFile:
                    f.write("\t\t{}\n".format(fp))
                f.write("\tBin File: \n")
                for fp in function.BinFile:
                    f.write("\t\t{}\n".format(fp))
                f.write("\n")

    def write_details_keyword(self):
        with open(os.path.join(self.detailoutput, "Prar_detail.result"), "w") as f:
            args_set.sort(key=lambda elem: elem.name)
            for args in args_set:
                f.write("Prar name : {}\n".format(args.name))
                f.write("Source File : \n")
                f.write("\tText File: \n")
                for fp in args.TextFile:
                    f.write("\t\t{}\n".format(fp))
                f.write("\tBin File: \n")
                for fp in args.BinFile:
                    f.write("\t\t{}\n".format(fp))
                f.write("\n")

    def write_front_simple_keyword(self):
        with open(os.path.join(self.simpleoutput, "Prar_simple.result"), "w") as f:
            for args in args_set:
                f.write("{}\n".format(args.name))

    def write_front_simple_function(self):
        with open(os.path.join(self.simpleoutput, "API_simple.result"), "w") as f:
            for function in function_set:
                f.write("{}\n".format(function.name))

    def write_front_single_simple(self):
        for res in self.result:
            with open(os.path.join(self.simpleoutput, ".data", res["name"].split("/")[-1]+".result"), "w") as f:
                for r in res["keywords"]:
                    string = r.get_match_str()
                    for _r in string:
                        f.write(_r+" ")

    def write_upnp_keywords(self, results):
        self.keywords = set()
        self.bin_add_keyword = set()
        with open(os.path.join(self.detailoutput, "upnp_Clustering_result.result"), "w") as f:
            for res in results:
                keywords = set()
                for r in res["upnpkeywords"]:
                    string = r.get_match_str()
                    for _r in string:
                        keywords.add(_r)

                    # TEST
                    if FROM_BIN_ADD:
                        string = r.get_bin_str()

                        for _r in string:
                            self.bin_add_keyword.add(_r[0])
                            keywords.add(_r[0])

                self.keywords = self.keywords | keywords
                f.write("Program name : {}\n".format(res["name"]))
                f.write("Upnp Para: \n")
                f.write("\tHits Para count: {}\n".format(len(keywords) + len(res["urn_start_str"])))
                f.write("\tHits Para : \n")
                f.write("\t\t")
                for r in keywords:
                    f.write("{} ".format(r))
                for s in res["urn_start_str"]:
                    f.write("{} ".format(s))
                    self.bin_add_keyword.add(s)
                f.write("\n\tNumber of UPnp Para source files: {}\n".format(res["upnpKeyword_source_files_count"]))
                f.write("\n")


    def write_back_result(self):
        self.keywords = set()
        self.function = set()
        self.other = set()
        self.other1 = set()
        with open(os.path.join(self.detailoutput, "Clustering_result_v2.result"), "w") as f:
            for res in self.result:
                keywords = set()
                function = set()
                for r in res["keywords"]:
                    string = r.get_match_str()
                    for _r in string:
                        keywords.add(_r)

                    # TEST
                    if FROM_BIN_ADD:
                        string = r.get_bin_str()

                        for _r in string:
                            self.other.add(_r[0])
                            self.other1.add(_r)
                            keywords.add(_r[0])

                for r in res["functions"]:
                    string = r.get_match_str()
                    for _r in string:
                        function.add(_r)
                self.keywords = self.keywords | keywords
                self.function = self.function | function
                f.write("Program name : {}\n".format(res["name"]))
                f.write("Strings count : {}\n".format(res["strings_count"]))
                f.write("Para + API count : {}\n".format(len(keywords)+len(function)))
                f.write("Para: \n")
                f.write("\tHits Para count: {}\n".format(len(keywords)))
                f.write("\tHits Para : \n")
                f.write("\t\t")
                for r in keywords:
                    f.write("{} ".format(r))
                f.write("\n\tNumber of Para source files: {}\n".format(res["Keyword_source_files_count"]))
                # f.write("\n\tKeyword source file: {}\n".format(str(res["Keyword_source_files"])))

                f.write("API: \n")
                f.write("\tHits API count: {}\n".format(len(function)))
                f.write("\tHits API : \n")
                f.write("\t\t")
                for r in function:
                    f.write("{} ".format(r))
                f.write("\n\tNumber of API source files: {}\n".format(res["Function_source_files_count"]))
                # f.write("\tFunction source file: {}\n".format(str(res["Function_source_files"])))
                f.write("\n")

    def write_file_info(self, res):
        with open(os.path.join(self.detailoutput, "File_detail.result"), "w") as f:
            for r in res:
                f.write("FileName: {}\n".format(r.fname))
                f.write("FilePath: {}\n".format(r.fpath))
                f.write("API: \n")
                f.write("\tcount: {}\n".format(len(r.function_name)))
                f.write("\tname:\n")
                r.function_name.sort(key=lambda elem: elem.name)
                for fun in r.function_name:
                    f.write("\t\t{}\n".format(fun.func))
                f.write("Para: \n")
                f.write("\tcount: {}\n".format(len(r.keyword_name)))
                f.write("\tname:\n")
                r.keyword_name.sort(key=lambda elem: elem.name)
                for k in r.keyword_name:
                    f.write("\t\t{}\n".format(k.keyword))

                f.write("\n")

    def write_remove_info(self, func_res, keyword_res):
        self._write_remove_func(func_res)
        self._write_remove_keyword(keyword_res)

    def _write_remove_func(self, res):
        with open(os.path.join(self.detailoutput, "API_remove_detail.result"), "w") as f:
            res.sort(key=lambda elem: elem.name)
            for function in res:
                f.write("API name : {}\n".format(function.name))
                f.write("Source File : \n")
                f.write("\tText File: \n")
                for fp in function.TextFile:
                    f.write("\t\t{}\n".format(fp))
                f.write("\tBin File: \n")
                for fp in function.BinFile:
                    f.write("\t\t{}\n".format(fp))
                f.write("\n")

    def _write_remove_keyword(self, res):
        with open(os.path.join(self.detailoutput, "Prar_remove_detail.result"), "w") as f:
            res.sort(key=lambda elem: elem.name)
            for args in res:
                f.write("Prar name : {}\n".format(args.name))
                f.write("Source File : \n")
                f.write("\tText File: \n")
                for fp in args.TextFile:
                    f.write("\t\t{}\n".format(fp))
                f.write("\tBin File: \n")
                for fp in args.BinFile:
                    f.write("\t\t{}\n".format(fp))
                f.write("\n")

    def write_info(self):
        with open(os.path.join(self.baseoutdir, "info.txt"), "w") as f:
            f.write("Analysie Time: {}\n\n".format(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')))

            f.write("Step1 Elapsed Time: {}S\n".format(runtimer.step1_time_consuming.total_seconds()))
            f.write("Step2 Elapsed Time: {}S\n".format(runtimer.step2_time_consuming.total_seconds()))
            f.write("Step3 Elapsed Time: {}S\n".format(runtimer.step3_time_consuming.total_seconds()))
            f.write("Step4 Elapsed Time: {}S\n".format(runtimer.step4_time_consuming.total_seconds()))
            f.write("ALL Elapsed Time: {}S\n\n".format(runtimer.total_time.total_seconds()))

            f.write("bin string toal : {}\n\n".format(b_total.get()))

            f.write("Para : \n\tStep1: \t{} \n\tStep2: \t{} \n\tStep3: \t{} \n\tStep4: \t{}\n".format(Count.KEYWORDS_COUNT, Count.KEYWORDS_COUNT - Count.BASE_FILTER_PARA ,len(args_set), len(self.keywords)))
            f.write("API : \n\tStep1: \t{} \n\tStep2: \t{} \n\tStep3: \t{} \n\tStep4: \t{}\n".format(Count.FUNCTION_COUNT, Count.FUNCTION_COUNT - Count.BASE_FILTER_API, len(function_set), len(self.function)))
            f.write("Count : \n\tStep1: \t{} \n\tStep2: \t{} \n\tStep3: \t{} \n\tStep4: \t{}\n".format(Count.FUNCTION_COUNT + Count.KEYWORDS_COUNT, (Count.KEYWORDS_COUNT - Count.BASE_FILTER_PARA) + (Count.FUNCTION_COUNT - Count.BASE_FILTER_API),len(function_set) + len(args_set), len(self.keywords) + len(self.function)))

    def write_remove_jsfile(self, js_files):
        with open(os.path.join(self.detailoutput, "Not_Analysise_JS_File.result"), "w") as f:
            for js in js_files:
                f.write("FileName: {}\n".format(js.name))
                f.write("Cited: {}\n".format(js.be_depend_count))
                f.write("FilePath: {}\n".format(js.fpath))
                f.write("Referenced file : \n")
                for be_dep in js.be_depend:
                    f.write("\t{}\n".format(be_dep))
                f.write("\n")

    def write_api_split(self,results):
        with open(os.path.join(self.detailoutput, "api_split.result"), "w") as f:
            for result in results:
                f.write("API Name: {}\n".format(result.api.name))
                f.write("from bin match: {}\n".format(" ".join(result.api.get_match_str())))
                f.write("Action: {}\n".format(result.action_str))
                f.write("Keyword: {}\n\n".format(result.keywords_str))

    def write_from_bin_add(self):
        with open(os.path.join(self.detailoutput, "from_bin_add_para.result"), "w") as f:
            f.write("ADD Count : {}\n\n".format(len(self.other)))
            for k in self.other:
                f.write("{}\n".format(k))

    def write_from_bin_add_v2(self):
        with open(os.path.join(self.detailoutput, "from_bin_add_para.result_v2"), "w") as f:
            for k, m in self.other1:
                f.write("{}\t{}\n".format(k,m))

    def write_upnp_analysise(self, args):
        with open(os.path.join(self.detailoutput, "upnp_args.result"), "w") as f:
            f.write("Count: {}\n".format(len(args)))
            for arg in args:
                f.write(arg + "\n")
            f.write("\n")

        with open(os.path.join(self.detailoutput, "upnp_from_bin_add_para.result"), "w") as f:
            f.write("ADD Para Count : {}\n\n".format(len(self.bin_add_keyword)))
            for k in self.bin_add_keyword:
                f.write("{}\n".format(k))


class JSONOutput(BaseOutput):

    def write_detail_function(self):
        pass

    def write_details_keyword(self):
        pass

    def write_back_result(self):
        pass
