#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2020/6/4 下午12:08
# @Author  : TT
# @File    : upnpanalysise.py

import re
from front_analysise.tools.traver import TraverFile
from front_analysise.tools.upnp import Service
from front_analysise.modules.parameter.upnp_keyword import UPNPKeyword

class UpnpAnalysise():

    def __init__(self, firmware_dir):
        traver = TraverFile(firmware_dir)
        self.desc_file = ""
        self.services = []
        self.waittryfiles = traver.get_file("xml")
        self._find_service_list()

    def test(self):
        result_set = set()
        UPNPKeyword.factory_keyword("WANEthLinkC1", "dfsa")
        result_set.add("WANEthLinkC1")
        return result_set

    def get_result(self):
        result_set = set()
        for service in self.services:
            result_set.add(service.service_type)
            result_set.add(service.service_id)
            result_set.add(service.name)
            UPNPKeyword.factory_keyword(service.name, self.desc_file)
            UPNPKeyword.factory_keyword(service.service_type, self.desc_file)
            UPNPKeyword.factory_keyword(service.service_id, self.desc_file)

            for action in service.actions:
                result_set.add(action.name)
                UPNPKeyword.factory_keyword(action.name, service.scpd_url)
                for args_in in action.argsdef_in:
                    result_set.add(args_in[0])
                    UPNPKeyword.factory_keyword(args_in[0], service.scpd_url)
                    result_set.add(args_in[1].get("name", ""))
                    UPNPKeyword.factory_keyword(args_in[1].get("name", ""), service.scpd_url)

        return result_set

    def _find_service_list(self):

        for file in self.waittryfiles:
            with open(file, 'r', errors="ignore") as f:
                content = f.read()

            servicelist = re.findall("<serviceList>([\s\S]+?)</serviceList>", content)

            if servicelist:
                self.desc_file = file

            for code in servicelist:
                res = code.strip().replace("\n","")
                res = re.findall("<service>([\s\S]+?)</service>", res)
                for r in res:
                    servicetype = self.__get_serviceType(r)[0]
                    serviceid = self.__get_serviceId(r)[0]
                    scpdurl = self.__get_SCPDURL(r)[0]
                    controlurl = self.__get_controlURL(r)[0]
                    envensuburl = self.__get_eventSubURL(r)[0]
                    for _f in self.waittryfiles:
                        if scpdurl in _f:
                            scpdurl = _f
                    s = Service(serviceid, servicetype, controlurl, scpdurl, envensuburl)
                    self.services.append(s)

    def __get_serviceType(self, code):
        return re.findall("<serviceType>(urn:[\s\S]+?)</serviceType>", code)

    def __get_serviceId(self, code):
        return re.findall("<serviceId>(urn:[\s\S]+?)</serviceId>", code)

    def __get_SCPDURL(self, code):
        return re.findall("<SCPDURL>([\s\S]+?)</SCPDURL>", code)

    def __get_controlURL(self, code):
        return re.findall("<controlURL>([\s\S]+?)</controlURL>", code)

    def __get_eventSubURL(self, code):
        return re.findall("<eventSubURL>([\s\S]+?)</eventSubURL>", code)
