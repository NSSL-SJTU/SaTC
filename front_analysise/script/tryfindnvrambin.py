from front_analysise.tools.traver import TraverFile
from front_analysise.untils.tools import AnalysisBinary

results = {}


def main(firmware_path, need_find_keyword):

    trav = TraverFile(firmware_path)
    elfs = trav.get_elffile(False)

    for elf in elfs:
        a = AnalysisBinary(elf)
        bin_all_keys = a.get_string()
        res = set()
        for key in bin_all_keys:

            for n in need_find_keyword:
                if n == key:
                    res.add(n)
        if res:
            results[a.get_name()] = res

    print(len(need_find_keyword))
    used = set()
    for key, value in results.items():
        used = used | value
        print(key, "len: ", len(value), " : ", value)

    print(used)
    print(used - results["httpd"])
    print(len(used))

if __name__ == "__main__":
    firmware_path = "/home/lin/code/Get_form/Update_JSParse_Version/NetGear_XR300/_XR300-V1.0.3.38_10.3.30.chk.extracted/squashfs-root"
    need_find_keyword = "usb_http_protect_enable, usb_httpd_access_debug, leafp2p_run, passwordrecovered_debug, traffic_block_enable, auto_enable, autoBlock, http_passwd, gui_region, passwordrecovered_debug2, cgi_debug_msg, remote_access_debug, usb_wan_http_protect_enable, need_to_load_wireless, wan_status, router_TC_enable, http_timeout, openvpncrt_sha256, genie_page_whitelist_en, blank_state, http_rmenable, passwordrecovered_debug9, sku_name, enable_password_recovery, as_genie, traffic_warning_state"
    need_find_keyword = need_find_keyword.split(", ")
    main(firmware_path, need_find_keyword)
