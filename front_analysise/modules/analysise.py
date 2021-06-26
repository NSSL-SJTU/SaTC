#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2020/4/29 下午6:11
# @Author  : TT
# @File    : analysise.py

from front_analysise.untils.logger.logger import get_logger
from front_analysise.tools.traver import TraverFile

from front_analysise.modules.parameter import function_set, args_set, upnp_args_set
from front_analysise.modules.parser.htmlparser import HTMLParser
from front_analysise.untils.tools import AnalysisBinary, Tools, APISplit

from front_analysise.untils.config import BIN_FUNCTION_HITS, BIN_KEYWORDS_HITS
from front_analysise.untils.filter_config import JS_LIMITED_ACTIVATION, JS_FILE_LIMITED_NUMBER

import copy


class _BaseAnalysise():
    def __init__(self, firmware_dir):
        self.traver = TraverFile(firmware_dir)
        self.analysise_obj = []

        # 用于记录JS文件引用{“文件名”:"JSFile对象"}
        self.jsfile_citations = {}
        # 用于记录被删除（没有被分析）的文件
        self.remove_file = set()

        self.log = get_logger()

    def get_analysise_result(self):
        return self.analysise_obj

    def get_remove_file(self):
        return self.remove_file


class FrontAnalysise(_BaseAnalysise):

    # TODO
    #  self.jsfile_citations = {}
    #  self.remove_file = set(）
    #  不应该出现在方法内部，这个逻辑需要重新写，整理代码
    def analysise(self, ANALYSIZER):

        for suffix, parser in ANALYSIZER.items():
            self.log.info(" Start Analysise {} File".format(suffix))
            files = self.traver.get_file(suffix)
            # files = ["/home/tt/vmware_share/_DIR_878_FW120B05_decode.BIN.extracted/_A0.extracted/_8957DC.extracted/cpio-root/etc_ro/lighttpd/www/web/Network.html"]
            # 如果当前处理的是JS，需要特殊处理
            if suffix == "js" and JS_LIMITED_ACTIVATION:
                js_file = []
                for fn, jobj in self.jsfile_citations.items():
                    for file in files[::-1]:
                        # ROTS test
                        # js_file.append(file)
                        if file.split("/")[-1] == fn:
                            if jobj.be_depend_count < JS_FILE_LIMITED_NUMBER:
                                js_file.append(file)
                                # js_file.append("/home/lin/manjaro_back/firmware/_US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin.extracted/squashfs-root/webroot_ro/js/iptv.js")
                            else:
                                self.remove_file.add(jobj)

                files = js_file
                # files = ["/home/tt/firmware/_ac18_kf_V15.03.05.19(6318_)_cn.bin.extracted/squashfs-root/webroot_ro/iptv.js"]

            for file in files:
                parseobj = parser(file)
                parseobj.analysise()
                self.analysise_obj.append(parseobj)
                if isinstance(parseobj, HTMLParser) and JS_LIMITED_ACTIVATION:
                    jsfile_citations = parseobj.get_jsfile_citations()
                    for jsfile, jobg in jsfile_citations.items():
                        j_co = self.jsfile_citations.get(jsfile, None)
                        if j_co is None:
                            self.jsfile_citations.update({jsfile: jobg})
                        else:
                            self.jsfile_citations.update({jsfile: j_co+jobg})


class BackAnalysise(_BaseAnalysise):
    def __init__(self, firmware_dir, bin_name=None):
        _BaseAnalysise.__init__(self, firmware_dir)
        if bin_name is None:
            bin_name = []
        self.results = []
        self.upnp_results = []
        self.bin_name = bin_name

        self.effective_keyword = list()
        self.effective_function = list()
        self.effective_upnpkeyword = list()

        self.elf_result = []
        self.upnp_elf_result = []

    @property
    def effective_function_count(self):
        return len(self.effective_function)

    @property
    def effective_keyword_count(self):
        return len(self.effective_keyword)

    @property
    def effective_upnpkeyword_count(self):
        return len(self.effective_upnpkeyword)

    def analysise(self):
        if self.bin_name:
            elfs = self.traver.get_target_file(self.bin_name)
            self.bin_name = elfs
        else:
            elfs = self.traver.get_elffile()
        # elfs = ['/home/tt/firmware/_R7000P-V1.3.1.64_10.1.36.chk.extracted/squashfs-root/usr/sbin/upnpd',
        #         "/home/tt/firmware/_R7000P-V1.3.1.64_10.1.36.chk.extracted/squashfs-root/usr/sbin/transmission-cli",
        #         "/home/tt/firmware/_R7000P-V1.3.1.64_10.1.36.chk.extracted/squashfs-root/usr/sbin/minidlna.exe",
        #         ]
        for elf in elfs:
            analysis = AnalysisBinary(elf)
            elf_function_res = analysis.find_function(function_set)
            elf_keyword_res = analysis.find_keywords(args_set)
            elf_upnp_keyword_res = analysis.find_keywords(upnp_args_set)

            self.effective_function = self.effective_function + elf_function_res
            self.effective_upnpkeyword = self.effective_upnpkeyword + elf_upnp_keyword_res
            self.effective_keyword = self.effective_keyword + elf_keyword_res

            self.elf_result.append((elf, analysis, elf_keyword_res, elf_function_res))
            self.upnp_elf_result.append((elf, analysis, elf_upnp_keyword_res))

        self.effective_function = list(set(self.effective_function))
        self.effective_keyword = list(set(self.effective_keyword))
        self.effective_upnpkeyword = list(set(self.effective_upnpkeyword))


    def calculation_cover(self):
        for r in self.results[1:]:
            k_cover = Tools.cover(self.results[0].get("keywords", []), r.get("keywords", []))
            r.update({"keyword_cover": k_cover})

            f_cover = Tools.cover(self.results[0].get("functions", []), r.get("functions", []))
            r.update({"function_cover": f_cover})

    def get_effective_keyword(self):
        return self.effective_keyword

    def get_effective_function(self):
        return self.effective_function

    def delete_function(self, funcs):

        for func in funcs:
            for elf, _ , _, elf_func in self.elf_result:
                elf_fs = copy.copy(elf_func)
                for e_f in elf_fs:
                    if func.func == e_f.func:
                        if e_f in self.effective_function:
                            self.effective_function.remove(e_f)
                        elf_func.remove(e_f)

    def delete_keyword(self, keywords):
        for keyword in keywords:
            for elf, _, elf_keyword, _ in self.elf_result:
                for e_k in elf_keyword[::-1]:
                    if keyword.keyword == e_k.keyword:
                        if e_k in self.effective_keyword:
                            self.effective_keyword.remove(e_k)
                        elf_keyword.remove(e_k)

    def get_result(self):
        # sorted(self.results, key=lambda elem: (elem["functions_count"], elem["keywords_count"]), reverse=True)
        for elf, analysis, _keyword, _function in self.elf_result:
            r = {}
            _keyword = list(set(_keyword))
            _function = list(set(_function))
            if len(_keyword) >= BIN_KEYWORDS_HITS and len(_function) >= BIN_FUNCTION_HITS:
                r["name"] = elf
                r["strings_count"] = analysis.string_count
                r["Keyword_source_files"] = set()
                r["Function_source_files"] = set()
                for k_obj in _keyword:
                    for f in k_obj.get_textfile():
                        r["Keyword_source_files"].add(f)
                r["Keyword_source_files_count"] = len(r["Keyword_source_files"])

                for k_obj in _function:
                    for f in k_obj.get_binfile():
                        for v in f:
                            r["Function_source_files"].add(v)
                r["Function_source_files_count"] = len(r["Function_source_files"])

                r["keywords"] = _keyword
                r["functions"] = _function
                r["keywords_count"] = len(_keyword)
                r["functions_count"] = len(_function)
                self.results.append(r)
        self.results.sort(key=BackAnalysise.sort, reverse=True)

        return self.results

    def get_upnp_result(self):
        for elf, analysis, _keyword in self.upnp_elf_result:
            if len(_keyword) >= BIN_KEYWORDS_HITS:
            # if len(_keyword) >= 0:
                r = {}
                _keyword = list(set(_keyword))
                r["name"] = elf
                r["urn_start_str"] = set()
                r["upnpKeyword_source_files"] = set()
                for k_obj in _keyword:
                    for f in k_obj.get_textfile():
                        r["upnpKeyword_source_files"].add(f)
                r["upnpKeyword_source_files_count"] = len(r["upnpKeyword_source_files"])

                r["upnpkeywords"] = _keyword
                for s in analysis.upnp_args:
                    r["urn_start_str"].add(s)
                r["upnpkeywords_count"] = len(_keyword) + len(r["urn_start_str"])
                self.upnp_results.append(r)
        self.upnp_results.sort(key=BackAnalysise.upnp_sort, reverse=True)

        return self.upnp_results

    def get_effective_keyword_count(self):
        return self.effective_keyword_count

    def get_effective_function_count(self):
        return self.effective_function_count

    @staticmethod
    def upnp_sort(elem):
        return elem["upnpkeywords_count"]

    @staticmethod
    def sort(elem):
        """
        排序
        :param elem:
        :return:
        """
        return elem["keywords_count"], elem["functions_count"]

    def api_march(self):
        self.match_result = set()
        for function in self.effective_function:
            IS_ADD = False
            if function.source == "HTML":
                continue

            api_obj = APISplit(function)
            str_split_list = function.name.split("/")

            for str in str_split_list:

                for f in self.effective_function:
                    if function.source != "HTML":
                        continue

                    if f.name == str:
                        api_obj.add_action(f)
                        IS_ADD = True

                for k in self.effective_keyword:
                    if k.name == str:
                        api_obj.add_keyword(k)
                        IS_ADD = True
            if IS_ADD:
                self.match_result.add(api_obj)
        return self.match_result

    def getbinname_and_path(self):
        res = []
        if self.bin_name:
            for f in self.bin_name:
                name = f.split("/")[-1]
                path = f
                res.append((name, path))
        return res
