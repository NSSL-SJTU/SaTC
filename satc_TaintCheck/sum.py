import  sys
import subprocess
with open(sys.argv[1],'r') as f:
    cont=f.read().split('\n')

filter_str=["Chinese","Spanish","japanese","english","korean","Vietnamese","Russian","Greek","Hungarian","OK","Cancel",'Allow','Add','resume',"safari",'chrome']
check=True
configfile=cont[1][12:-7]
summ=0
print "\n\n-----------------------------"
for i in cont:
    if "found :" in i:
        addrs=i.split("found : ")[1]
        stradr,refadr=i.split(' ')[:2]
        stradr=stradr[2:]
#        print 'grep "%s" %s'%(stradr,configfile)
        grep=subprocess.Popen('grep "%s" %s'%(stradr,configfile),shell=True,stdout=subprocess.PIPE)
        grep_result=grep.stdout.read().split(stradr)[0]
        pas=False
        if check:
            for i in filter_str:
                if i.lower() in grep_result.lower():
                    pas=True
        if pas:
            continue
        print grep_result+stradr+"), referenced at] %s, sink at %s"%(refadr,addrs)
        summ+=len(addrs.split(' '))

print 'sum:',summ
print cont[0]
print cont[1]
print "-----------------------------\n\n"

