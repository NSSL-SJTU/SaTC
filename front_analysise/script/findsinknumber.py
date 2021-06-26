import re


def main(file):

    data_dependency_set = set()

    with open(file, "r") as f:
        content = f.read().splitlines()

    for line in content:
        res = re.search(r'[Param "\w"\(0x[0-9a-fA-F]{8}\), Referenced at \w+ : (0x[0-9a-fA-F]{8})]', line)
        if res:
            data_dependency_set.add(res.group(1))
            print(res.group(1))

    print("res: ", len(data_dependency_set))

if __name__ == "__main__":
    file = "/home/lin/Desktop/SATC_res/Tenda_G3/ghidra_extract_result/httpd/httpd_ref2sink_bof.result"

    main(file)