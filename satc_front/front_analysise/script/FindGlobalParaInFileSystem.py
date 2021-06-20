#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2020/6/9 下午5:41
# @Author  : TT
# @File    : FindGlobalParaInFileSystem.py

from front_analysise.modules.parameter.keyword import Keyword
from front_analysise.modules.analysise import BackAnalysise
import argparse

Global_Para = [
    "WPAPSK2",
    "SSID1",
    "wan_wan2_gateway",
    "remotemange_iprange",
    "DDNSAccount",
    "wan_wan2_mtu",
    "wan_wan0_pppoe_autoreconn",
    "wan_wan_ifnames",
    "vlan_lan_dev1_service_mapping",
    "vlan_lan_dev4_service_mapping",
    "url_filter_mode",
    "wan_wan2_vlanidpri",
    "lan0_ipv6_ipaddr",
    "SysLogMail_SMTPServerPort",
    "wan_iptv_vlanid",
    "lan0_ipv6_route_lifetime",
    "QosManagementType",
    "lan0_domain",
    "wan_iptv_vlanidpri",
    "wan_wan1_vlanidpri",
    "wan_wan0_pppoe_username",
    "DDNSProvider",
    "lan1_netmask",
    "wan_wan0_pppoe_service",
    "FTP_Idletime",
    "wan_wan0_vpn_username",
    "SysLogRemote_IPAddress",
    "lan0_management_link",
    "wan_wan0_vpn_idletime",
    "lan1_ipaddr",
    "wan_wan3_vpn_dns",
    "mask_flag",
    "ntp_server",
    "wan_wan2_hostname",
    "firewall_ipv6_filter_rule",
    "wan_wan1_vlanid",
    "wan_wan0_vpn_client",
    "quickVPN_Password",
    "lan1_dhcps_start",
    "lan0_dhcps_start",
    "wifi24RootScheduleName",
    "portforward_rule",
    "vlan_wlan_service_mapping",
    "wifi58RootScheduleName",
    "SysLogMail_Auth_Password",
    "lan0_ipv6_dhcp_start",
    "wan_wan0_ifname",
    "vlan_lan_dev3_service_mapping",
    "Static_Arp_Number",
    "DDNSTimeout",
    "wan_wan0_vlanid",
    "DDNS",
    "wan_wan0_vpn_netmask",
    "wan_wan3_clone_mac",
    "UploadBandwidth",
    "wan_wan2_netmask",
    "lan0_ipv6_autoconf_type",
    "wan_wan2_vpn_dns",
    "wan_voip_vlanid",
    "wan_wan0_ipaddr",
    "time_TZ_location",
    "wan_wan2_vpn_netmask",
    "wan_wan0_vpn_mtu",
    "wan_wan3_vpn_netmask",
    "mac_filter_rule",
    "quickVPN_Username",
    "wan_wan0_vpn_gateway",
    "wan_wan3_dns",
    "DownloadBandwidth",
    "FTP_Port",
    "wan_wan3_vpn_gateway",
    "lan0_port_member",
    "wan_wan2_vpn_gateway",
    "wan_wan0_vpn_passwd",
    "lan1_port_member",
    "lan2_port_member",
    "fota_time_minute",
    "lan1_dhcps_end",
    "wan_wan2_dns",
    "lan3_port_member",
    "virtualserver_rule",
    "dmz_ipaddr",
    "SysLogMail_Auth_Name",
    "Arp_Static_Item",
    "lan0_dhcps_staticlist",
    "WorkMode",
    "wan_wan2_vpn_client",
    "url_filter_rule",
    "wan_wan3_netmask",
    "firewall_filter_rule",
    "wan_wan3_ifname",
    "vlan_lan_dev2_service_mapping",
    "wan_wan0_dns",
    "wan_wan0_pppoe_passwd",
    "wan_wan1_ifname",
    "wan_wan3_device_vendor_class",
    "wan_wan3_ipaddr",
    "lan0_dhcps_lease",
    "remotemange_port",
    "fota_time_hour",
    "wan_wan0_hostname",
    "wan_wan2_device_vendor_class",
    "wan_wan3_vpn_client",
    "quickVPN_MPPE",
    "lan0_dhcps_end",
    "lan1_dhcps_lease",
    "wan_wan0_pppoe_auth",
    "wan_wan3_vlanid",
    "wan_wan0_pppoe_idletime",
    "lan0_ipaddr",
    "ISPName",
    "SysLogMail_Schedule_Name",
    "wan_wan2_vlanid",
    "quickVPN_PSK",
    "wifi58Vap1ScheduleName",
    "wan_wan0_vpn_autoreconn",
    "SysLogMail_To",
    "remotemange_https_port",
    "lan0_ipv6_dhcp_end",
    "device_name",
    "wan_wan3_gateway",
    "quickVPN_AuthProtocol",
    "wan_wan0_vlanidpri",
    "Password",
    "wan_wan0_vpn_dns",
    "DDNSPassword",
    "http_passwd",
    "lan0_netmask",
    "wan_wan3_vlanidpri",
    "wan_wan2_ifname",
    "vlan_wlan_guest_service_mapping",
    "wan_wan0_pppoe_mtu",
    "sys_reboot_schedule",
    "wan_wan3_mtu",
    "wan_wan2_ipaddr",
    "wan_voip_vlanidpri",
    "SysLogMail_SMTPServerAddress",
    "lan0_ipv6_dhcp_lifetime",
    "wan_wan2_clone_mac",
    "wan_wan3_hostname",
    "wan_wan0_vpn_server",
    "SysLogMail_From"
]


def output(res, output):
    with open(output, 'w') as f:
        f.write("Para Count : {}\n".format(len(Global_Para)))
        f.write("Analysise Para: {}\n".format(Global_Para))
        f.write("\n")
        f.write("\n")
        f.write("\n")

        for r in res:
            f.write("Program : {}\n".format(r["name"]))
            f.write("Global Para Count : {}\n".format(r["keywords_count"]))
            f.write("Global Para : {}\n".format(r["keywords"]))
            f.write("\n")


if __name__ == "__main__":
    # a = len(Global_Para)
    """
        此脚本用于分析全局变量在文件系统中的出现情况
    """

    for k in Global_Para:
        Keyword.factory_keyword(k, "", 0)

    parser = argparse.ArgumentParser(description="Firmware front analysis",
                                     formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument("-d", "--directory", required=True, metavar="-d /root/path/_ac18.extracted",
                        help="Directory of the file system after firmware decompression")
    parser.add_argument("-o", "--output", required=True, metavar="-o /root/output.txt",
                        help="output results to file")

    args = parser.parse_args()
    b_analysise = BackAnalysise(args.directory)
    b_analysise.analysise()
    res = b_analysise.get_result()
    output(res, args.output)
