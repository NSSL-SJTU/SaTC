#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2020/4/26 下午12:22
# @Author  : TT
# @File    : traver.py
import os
import stat
from copy import copy

from front_analysise.untils.logger.logger import get_logger
from front_analysise.untils.config import SPECIAL_COMMAND, SPECIAL_MID_NAME, REMOVE_FILE, SPECIAL_PATH


class TraverFile(object):
    """
        从文件夹中提取处固件的位置.
    """
    def __init__(self, dirname):
        """
        Args:
            dirname: 固件的总文件夹
        """
        self.log = get_logger()
        self._dirname = dirname
        self.allfile = []

        self._htmlfile = []
        self._xmlfile = []
        self._jsfile = []
        self._elffile = []

        self._elffiles_remove_so = []

        self.getallfile()

    def getallfile(self):
        self._alldir = os.walk(self._dirname)
        for file in self._alldir:
            for _fm_name in file[2]:
                suffix_name = TraverFile.get_suffix(_fm_name.lower())
                filepath = str(file[0])+ '/' +str(_fm_name)
                if any(s in str(file[0]) for s in SPECIAL_PATH):
                    continue
                if _fm_name in REMOVE_FILE:
                    continue
                if os.path.islink(filepath):
                    continue
                if suffix_name.lower() == "htm" or suffix_name.lower() == "html" or suffix_name.lower() == "shtml":
                    self._htmlfile.append(filepath)
                    self.log.debug("[*] Find HTML file : {}".format(filepath))
                elif suffix_name.lower() == "js":
                    self._jsfile.append(filepath)
                    # self._jsfile.append("/home/lin/manjaro_back/firmware/_US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin.extracted/squashfs-root/webroot_ro/js/iptv.js")
                    self.log.debug("[*] Find Javascript file : {}".format(filepath))
                elif suffix_name.lower() == "xml":
                    self._xmlfile.append(filepath)
                    self.log.debug("[*] Find XML file : {}".format(filepath))
                # 在此添加其他文件的处理
                elif TraverFile.is_ELFfile(filepath):
                    self._elffile.append(filepath)
                    self.log.debug("[*] Find Binary file : {}".format(filepath))
                self.allfile.append(filepath)

    @staticmethod
    def is_ELFfile(filepath):
        if not os.path.exists(filepath):
            return False
        # 文件可能被损坏，捕捉异常
        try:
            FileStates = os.stat(filepath)
            FileMode = FileStates[stat.ST_MODE]
            if not stat.S_ISREG(FileMode) or stat.S_ISLNK(FileMode):  # 如果文件既不是普通文件也不是链接文件
                return False
            with open(filepath, 'rb') as f:
                header = (bytearray(f.read(4))[1:4]).decode(encoding="utf-8")
                # logger.info("header is {}".format(header))
                if header in ["ELF"]:
                    # print header
                    return True
        except UnicodeDecodeError as e:
            # logger.info("is_ELFfile UnicodeDecodeError {}".format(filepath))
            # logger.info(str(e))
            pass

    def get_xmlfile(self):
        return self._xmlfile

    def get_htmlfile(self):
        return self._htmlfile

    def get_jsfile(self):
        return self._jsfile

    def get_elffile(self, filter=True):
        if filter:
            self._filter_some_command()
            self._filter_so()

        return self._elffile

    def _filter_so(self):
        elfs = copy(self._elffile)
        for mid_name in SPECIAL_MID_NAME:
            for file in elfs:
                if file.find(mid_name) > 0:
                    self._elffile.remove(file)

    def _filter_some_command(self):
        elfs = copy(self._elffile)
        for command in SPECIAL_COMMAND:
            for elf in elfs:
                if elf.endswith(command):
                    self._elffile.remove(elf)

    @staticmethod
    def get_suffix(filename):
        return filename.split('.')[-1]

    def get_file(self, suffix):
        if suffix == "js":
            return self.get_jsfile()
        elif suffix == "xml":
            return self.get_xmlfile()
        elif suffix == "html":
            return self.get_htmlfile()
        else:
            result = set()
            for file in self.allfile:
                file_suffix = TraverFile.get_suffix(file)
                if file_suffix == suffix:
                    result.add(file)
            return list(result)

    def get_target_file(self, files: list) -> list:
        wait_analysises = []
        for f in files:
            for file in self.allfile:
                if file.split("/")[-1] == f:
                    wait_analysises.append(file)
                    break
        return wait_analysises
