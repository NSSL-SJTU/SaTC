#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2020/8/21 上午11:29
# @Author  : TT
# @File    : satc.py

from front_analysise.untils.logger.logger import get_logger
from front_analysise.modules.analysise import FrontAnalysise, BackAnalysise
from front_analysise.untils.config import ANALYSIZER, F_FILTERS, UPNP_ANALYSISE
from front_analysise.untils.output import RTOSOutput
from front_analysise.untils.tools import runtimer
from front_analysise.tools.upnpanalysise import UpnpAnalysise

import subprocess
import shutil
import argparse
import uuid
import os

import sys
sys.setrecursionlimit(5000)


front_result_output = ""
ghidra_result_output = ""

# Init log
log = get_logger()


def argsparse():
    # Parse command line parameters
    parser = argparse.ArgumentParser(description="SATC tool",
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-d", "--directory", required=True, metavar="/root/path/_ac18.extracted",
                        help="Directory of the file system after firmware decompression")

    # TODO 添加默认输出路径，后续设置docker映射后设置
    parser.add_argument("-o", "--output", required=True, metavar="/root/output",
                        help="Folder for output results ")
    # execute ghidra ： command
    # parser.add_argument("--ghidra_script", required=False,
    #                     choices=["ref2sink_cmdi", "ref2sink_bof", "share2sink", "ref2share", "all"],
    #                     nargs="+",
    #                     action="extend",
    #                     help="ghidra script to run"
    #                     )
    # parser.add_argument("--save_ghidra_project", required=False, action="store_true",
    #                     help="whether to save the ghidra project")

    # TODO 添加指定前几个为边界程序，与 --bin互斥

    # Other command
    # 添加指定边界程序的方法
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-b", "--bin", required=False, nargs="+", action="extend", metavar="/var/ac18/bin/httpd", help="Input border bin")
    # group.add_argument("-l", "--len", required=False, default=3, type=int, metavar="3", help="Take the first few")

    args = parser.parse_args()

    # Init output dir
    # global ghidra_result_output, front_result_output
    global front_result_output
    front_result_output = os.path.join(args.output, "keyword_extract_result")
    # ghidra_result_output = os.path.join(args.output, "ghidra_extract_result")

    # check firmware directory is exist
    if not os.path.isdir(args.directory):
        log.error("Firmware path entered : {} not found".format(args.directory))
        sys.exit()

    # check output exist
    if not os.path.isdir(front_result_output):
        log.info("Init output keyword_extract_result directory : {} ".format(front_result_output))
        os.makedirs(front_result_output)

    # if args.ghidra_script:
    #     # If you want execute ghidra, perform output directory detection
    #     if not os.path.isdir(ghidra_result_output):
    #         log.info("Init output ghidra_extract_result directory : {} ".format(ghidra_result_output))
    #         os.makedirs(ghidra_result_output)

    return args


def front_analysise(args) -> list:
    # Run front-end keyword extraction, return border bin list
    remove_keyword_collection = []
    remove_function_collection = []

    runtimer.set_step1()
    f_analysise = FrontAnalysise(args.directory)
    f_analysise.analysise(ANALYSIZER)

    runtimer.set_step2()
    f_res = f_analysise.get_analysise_result()
    f_remove_file = f_analysise.get_remove_file()

    # 处理UPNP协议
    # upapanalysise = set()
    # if UPNP_ANALYSISE:
    #     upnpanaly = UpnpAnalysise(args.directory)
    #     upapanalysise = upnpanaly.get_result()

    runtimer.set_step3()
    for _F in F_FILTERS:
        f = _F()
        f()

        remove_keyword = f.get_remove_keyword()
        remove_func = f.get_remove_functions()

        remove_keyword_collection = list(set(remove_keyword + remove_keyword_collection))
        remove_function_collection = list(set(remove_func + remove_function_collection))

    runtimer.set_step4()


    if args.bin:
        b_analysise = BackAnalysise(args.directory, args.bin)
    else:
        b_analysise = BackAnalysise(args.directory)
    b_analysise.analysise()
    names = b_analysise.getbinname_and_path()

    # # 开始从结果中过滤
    # for _F in B_FILTERS:
    #     f = _F()
    #     f()
    #     remove_keyword = f.get_remove_keyword()
    #     remove_func = f.get_remove_functions()
    #
    #     remove_keyword_collection = list(set(remove_keyword + remove_keyword_collection))
    #     remove_function_collection = list(set(remove_func + remove_function_collection))
    #
    #     # 从b_analysise.elf_result里面删除上述结果
    #     b_analysise.delete_function(remove_func)
    #     b_analysise.delete_keyword(remove_keyword)

    # # 处理部分匹配
    # api_match_results = set()
    # if API_SPLIT_MARCH:
    #     api_match_results = b_analysise.api_march()

    runtimer.set_end_time()
    # 获取结果
    res = b_analysise.get_result()

    # 整理bin
    border_bin = []
    if not args.bin:
        for bin in res[:args.len]:
            pth = bin["name"]
            name = pth.split("/")[-1]
            border_bin.append((name, pth))
    else:
        for f_name, f_path in names:
            border_bin.append((f_name, f_path))

    # TODO 写结果  args.output可以加上随机路径
    o = RTOSOutput(res, front_result_output)
    o.write_high_precision()
    o.write_low_precision()

    # o.custom_write()

    # 可选项
    # o.write_file_info(f_res)
    # o.write_remove_info(remove_function_collection, remove_keyword_collection)

    # o.write_info()

    # o.write_remove_jsfile(f_remove_file)
    # o.write_api_split(api_match_results)

    # if FROM_BIN_ADD:
    #     o.write_from_bin_add()
    #     o.write_from_bin_add_v2()

    # if UPNP_ANALYSISE:
    #     res = b_analysise.get_upnp_result()
    #     o.write_upnp_keywords(res)
    #     o.write_upnp_analysise(upapanalysise)

    return border_bin


def main():
    args = argsparse()
    bin_list = front_analysise(args)


if __name__ == "__main__":
    main()

