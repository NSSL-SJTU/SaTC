#!/usr/bin/env python
# coding: utf-8
import re
import sys
filter_str=["Chinese","Spanish","japanese","english","korean","Vietnamese","Russian","Greek","Hungarian","OK","Cancel",'Allow','Add','resume',"safari",'chrome']
filter_str=[i.lower() for i in filter_str]
filter_chr="%$"
def main(filename=None):
    if filename==None:
        filename=sys.argv[1]
    with open(filename,'r') as f:
        cont=f.read()
    print "Converting Ghidra output to simple data..."
    cont=cont.split('\n')
    pattern=re.compile("0x[0-9a-fA-F]+")
    str_pattern=re.compile("\".*\"")

    calltraces={}
    sinks={}
    for i in cont:
        try:
            findlist = pattern.findall(i)
            if len(findlist)>2:
                str_arg = str_pattern.findall(i)[0][1:-1]
                str_arg = str_arg.lower()
                if len(str_arg)<=1:
                    continue
                if str_arg in filter_str:
                    continue
                if re.match("[0-9]+$",str_arg):
                    continue
                for ch in str_arg:
                    if ch in filter_chr:
                        continue
                if (findlist[0],findlist[1]) not in calltraces:
                    calltraces[(findlist[0],findlist[1])]=set(findlist[2:-1])
                    sinks[(findlist[0],findlist[1])]=set([findlist[-1]])
                else:
                    calltraces[(findlist[0],findlist[1])].update(findlist[2:-1])
                    sinks[(findlist[0],findlist[1])].update([findlist[-1]])
        except:
            print "The following line parse error:",i
    with open(filename+'-alter2','w') as f:
        for i in calltraces:
            #print i
            #print calltraces[i]
            #print sinks[i]
            f.write(i[0]+' '+i[1]+'\n')
            f.write(' '.join(calltraces[i])+'\n')
            f.write(' '.join(sinks[i])+'\n')
    print "Convert success, output in "+filename+'-alter2'
if __name__=='__main__':
    main()
