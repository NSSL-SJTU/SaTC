#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2020/4/26 上午11:49
# @Author  : TT
# @File    : tools.py
from front_analysise.untils.logger.logger import get_logger
from front_analysise.untils.config import FROM_BIN_ADD, UPNP_ANALYSISE

import re
import datetime


def execute(command):
    """
    Executes a command on the local host.
    :param str command: the command to be executed
    :return: returns the output of the STDOUT or STDERR
    """
    from subprocess import check_output, STDOUT
    print("Shell command : {}".format(command))
    command = "{}; exit 0".format(command)
    return check_output(command, stderr=STDOUT, shell=True).decode("utf-8")


class AnalysisBinary(object):

    def __init__(self, binaryfile):
        """
        具体的二进制程序分析模块
        :param binaryfile: 二进制文件路径
        :param commands -> set(): 用于比较的二进制命令
        """
        self.binaryfile = binaryfile
        self.log = get_logger()
        self.bin_strings = set()
        self.get_string()
        self.upnp_args = set()
        # self.read_binary()

    def get_name(self):
        return self.binaryfile.split("/")[-1]

    def read_binary(self):
        self.binarycontent = ""
        self.log.debug("Try to get binary program hex code : {}".format(self.binaryfile))
        try:
            with open(self.binaryfile, 'rb') as f:
                self.binarycontent = f.read().hex()
            self.log.info("[+] Finish read binary program : {}".format(self.binaryfile))
            # print(self.binary_content)
            # pass
            self.endpos = len(self.binarycontent)
        except:
            self.log.error("[+] File {} read Error".format(self.binaryfile))

    @staticmethod
    def check_lsb_or_msb(programpath):
        """
        判断程序是大端序还是小端序
        :param programpath: 二进制程序路径
        :return:
        """
        command_result = execute(programpath)
        if "LSB" in command_result:
            return "LSB"
        elif "MSB" in command_result:
            return "MSB"
        else:
            return "UNKNOW"

    @staticmethod
    def la_sm_swap(text_x16):
        """
        大端序与小端序相互转换
        Args:
            text_x16: 16进制数据

        Returns: 大端序转小端序，小端序转大端序

        """
        return text_x16.decode('hex')[::-1].encode('hex_codec')

    @staticmethod
    def str_to_hex(text):
        """
        将字符串转为16进制
        Args:
            text: 字符串
            binary_x16
        Returns:
            返回字符串的16进制
        """
        return ''.join([hex(ord(c)).replace('0x', '') for c in text])

    @staticmethod
    def hex_to_str(str_hex):
        "16进制转字符串"
        "aa bb cc dd"
        rule = re.compile('.{2}')
        str = ' '.join(rule.findall(str_hex))
        return ''.join([chr(i) for i in [int(b, 16) for b in str.split(' ')]])

    def find_keywords(self, keywords):
        result = set()
        for keyword in keywords:
            # 遍历commands中的全部可执行命令
            self.log.debug("[-] Analyzing {} : {}".format(self.binaryfile, keyword.name))
            # check_path = True if "/" in keyword else False

            for string in self.bin_strings:
                if FROM_BIN_ADD:
                    if "/" not in string:
                        if UPNP_ANALYSISE:
                            if string.find(keyword.name) >= 0:
                                # 整理结果Return
                                self.log.info("[+] From {} find {}".format(self.binaryfile, keyword.name))
                                keyword.add_binFile(self.binaryfile)
                                keyword.set_match_str(keyword.name)
                                result.add(keyword)
                                break
                            else:
                                if string.startswith("urn:"):
                                    self.upnp_args.add(string)

                        else:
                            if string.find(keyword.name) >= 0:
                                # 整理结果Return
                                self.log.info("[+] From {} find {}".format(self.binaryfile, keyword.name))
                                keyword.add_binFile(self.binaryfile)
                                keyword.set_match_str(keyword.name)
                                result.add(keyword)
                                break
                    else:
                        strings = string.split("/")
                        for _s in strings:
                            if _s == keyword.name:
                                # 整理结果Return
                                self.log.info("[+] From {} find {}".format(self.binaryfile, keyword.name))
                                keyword.add_binFile(self.binaryfile)
                                keyword.set_match_str(keyword.name)
                                # TEST
                                keyword.set_bin_str((string, keyword.name))
                                result.add(keyword)
                                break
                else:
                    if string.find(keyword.name) >= 0:
                        # 整理结果Return
                        self.log.info("[+] From {} find {}".format(self.binaryfile, keyword.name))
                        keyword.add_binFile(self.binaryfile)
                        keyword.set_match_str(keyword.name)
                        result.add(keyword)
                        break

        return list(result)

    def find_function(self, functions):
        result = set()
        for func in functions:
            # 遍历commands中的全部可执行命令
            res = False
            self.log.debug("[-] Analyzing {} : {}".format(self.binaryfile, func.name))
            # check_path = True if "/" in keyword else False
            FIND_FLAG = False
            for string in self.bin_strings:
                if string.find(func.name) >= 0:
                    # 整理结果Return
                    self.log.info("[+] From {} find {}".format(self.binaryfile, func.name))
                    func.add_binFile(self.binaryfile)
                    func.set_match_str(func.name)
                    result.add(func)
                    FIND_FLAG = True
                    break

            if "/" in func.name and not FIND_FLAG:
                paths = func.name.split("/")
                check_len = len(paths) > 1
                for path in paths:
                    if not path:
                        continue

                    # if check_len:
                    #     if len(path) < 7:
                    #         continue

                    for string in self.bin_strings:
                        if string.find(path) >= 0:
                            # 整理结果Return
                            self.log.info("[+] From {} find {}".format(self.binaryfile, path))
                            func.add_binFile(self.binaryfile)
                            func.set_match_str(path)
                            result.add(func)
                            break
        return list(result)

    def __call__(self, keywords):
        result = self.find_keywords(keywords)
        return result

    def get_string(self):
        res = execute("strings '{}'".format(self.binaryfile))
        self.bin_strings = set(res.split("\n"))
        b_total.add(len(self.bin_strings))
        return self.bin_strings

    @property
    def string_count(self):
        return len(self.bin_strings)


class Tools:

    @staticmethod
    def cover(base, target):
        base_len = len(base)
        target_len = len(target)

        base_set = set(base)
        target_set = set(target)
        res = list(base_set - target_set)
        res_len = len(res)

        ra = base_len-res_len
        if res_len:
            cover = format(float(ra)/float(res_len), '.2f')
        else:
            cover = 1
        return cover


class APISplit():
    def __init__(self, api):
        self.api = api
        self.keyword = set()
        self.action = set()

    def add_keyword(self, keyword):
        self.keyword.add(keyword)

    def add_action(self, action):
        self.action.add(action)

    @property
    def keywords_str(self):
        str = ""
        for keyword in self.keyword:
            str = str + " {}".format(keyword.name)
        return str

    @property
    def action_str(self):
        str = ""
        for action in self.action:
            str = str + " {}".format(action.name)
        return str


class RunTime:

    def __init__(self):
        self.start_time = datetime.datetime.now()

    def set_step1(self):
        self.step1_time = datetime.datetime.now()

    def set_step2(self):
        self.step2_time = datetime.datetime.now()

    def set_step3(self):
        self.step3_time = datetime.datetime.now()

    def set_step4(self):
        self.step4_time = datetime.datetime.now()

    def set_end_time(self):
        self.end_time = datetime.datetime.now()

    @property
    def step1_time_consuming(self):
        return self.step2_time - self.step1_time

    @property
    def step2_time_consuming(self):
        return self.step3_time - self.step2_time

    @property
    def step3_time_consuming(self):
        return self.step4_time - self.step3_time

    @property
    def step4_time_consuming(self):
        return self.end_time - self.step4_time

    @property
    def total_time(self):
        return self.end_time - self.start_time


class Binstringtotal():

    total = 0

    def add(self, num):
        self.total = self.total + num

    def get(self):
        return self.total


runtimer = RunTime()
b_total = Binstringtotal()


if __name__ == "__main__":
    ana = AnalysisBinary("/home/tt/firmware/_US_W20EV4.0br_V15.11.0.6(1068_1546_841)_CN_TDC.bin.extracted/squashfs-root/bin/httpd")
    res = ana([["enable", ""]])
    # res = execute("strings '{}'".format("/home/tt/firmware/_ac18_kf_V15.03.05.19(6318_)_cn.bin.extracted/squashfs-root/bin/httpd"))
    # res = res.split("\n")
    pass