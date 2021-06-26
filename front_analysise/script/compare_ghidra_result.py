import re


def analysie(b_content, a_content):
    res = set()
    for _b in b_content:
        if _b not in a_content:
            res.add(_b)
    return res


def match_content(content):
    result = set()
    for c in content:
        res = re.search(r'"(\w+)"', c)
        if res:
            result.add(c)
    return result


if __name__ == "__main__":

    B = "/home/lin/WeChatFiles/goahead_ref2sink_cmdi.result"
    A = "/home/lin/code/Get_form/Update_JSParse_Version/DIR-823G/ref2sink_cmdi.log"

    with open(A, "r") as f:
        c_a = f.readlines()

    a_content = match_content(c_a)

    with open(B, "r") as f:
        c_b = f.readlines()
    b_content = match_content(c_b)

    res = analysie(b_content, a_content)
    print(len(res))
