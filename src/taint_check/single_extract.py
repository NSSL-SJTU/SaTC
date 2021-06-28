import sys
import re

assert len(sys.argv) > 2, "usage: .py <path to *.result file> <path to result-* file>"
assert sys.argv[1].endswith(".result")
assert sys.argv[2].split('/')[-1].startswith("result-")
pat = re.compile("0x[0-9a-fA-F]+")
strs_addr = set()
with open(sys.argv[1], 'r') as f:
    cont = f.read()
    for i in cont.split('\n'):
        try:
            str_addr = int(pat.findall(i)[0], 16)
            strs_addr.update([str_addr])
        except:
            print i
with open(sys.argv[2], 'r') as f:
    cont = f.read()
out = ""
for i in cont.split('\n'):
    try:
        str_addr = int(i.split(' ')[0], 16)
        if str_addr not in strs_addr:
            out += i + '\n'
    except:
        out += i + '\n'
with open(sys.argv[2] + '-extracted', 'w') as f:
    f.write(out)
