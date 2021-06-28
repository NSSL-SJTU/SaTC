from bug_finder.taint import main, setSinkTarget, setr4
from bug_finder.sinks import getfindflag, setfindflag
from taint_analysis.coretaint import setfollowTarget, set_no_calltrace_overlap
import sys
import angr
import random, string
import pickle
import os
import conv_Ghidra_output

lastfulltrace = []


def main_main():
    if len(sys.argv) < 3:
        print("python tool/main.py <path_to_firmware> <path_to_config>")
        exit(-1)
    binary = sys.argv[1]
    configfile = sys.argv[2]
    if len(sys.argv) >= 4:
        r4 = int(sys.argv[3], 0)
        setr4(r4)
    appe = binary.split('/')[-1] + "-" + ''.join(random.sample(string.ascii_letters + string.digits, 4))
    if '-alter2' not in configfile:
        conv_Ghidra_output.main(configfile)
        configfile = configfile + '-alter2'
    with open(configfile, 'r') as f:
        cont = f.read().split('\n')
    proj = angr.Project(binary, auto_load_libs=False, use_sim_procedures=True)
    cfg = proj.analyses.CFG()
    cases = 0
    find_cases = 0
    res = []
    with open('result-%s.txt' % appe, 'a') as f:
        f.write("binary: %s\n" % binary)
        f.write("configfile: %s\n" % configfile)
    for i in range(len(cont) / 3):
        # if len(i.split(' '))>2:
        try:
            cases += 1
            # func_addr=[int(j,0) for j in i.split(' ')[1:-1]] # functrace
            if cont[i * 3 + 1] != '':
                func_addr = [int(j, 0) for j in cont[i * 3 + 1].split(' ')]
            else:
                func_addr = []
            taint_addr = int(cont[i * 3].split(' ')[0], 0)
            sinkTargets = [int(j, 0) for j in cont[i * 3 + 2].split(' ')]
            # put it to the head of cfg node
            if proj.arch.name != "MIPS32":
                if not proj.loader.main_object.pic:
                    start_addr = cfg.get_any_node(int(cont[i * 3].split(' ')[1], 0), anyaddr=True).addr
                    callerbb = None
                else:
                    func_addr = [j - 0x10000 + 0x400000 for j in func_addr]
                    taint_addr = taint_addr - 0x10000 + 0x400000
                    sinkTargets = [j - 0x10000 + 0x400000 for j in sinkTargets]
                    start_addr = cfg.get_any_node(int(cont[i * 3].split(' ')[1], 0) - 0x10000 + 0x400000,
                                                  anyaddr=True).addr
                    callerbb = None
            else:
                if not proj.loader.main_object.pic or "system.so" in proj.filename:
                    print hex(int(cont[i * 3].split(' ')[1], 0))
                    print cfg.get_any_node(int(cont[i * 3].split(' ')[1], 0), anyaddr=True)
                    start_addr = cfg.get_any_node(int(cont[i * 3].split(' ')[1], 0), anyaddr=True).function_address
                    callerbb = cfg.get_any_node(int(cont[i * 3].split(' ')[1], 0), anyaddr=True).addr
                    with open(binary, 'rb') as f:
                        conttmp = f.read()
                        sec = proj.loader.main_object.sections_map['.got']
                        proj.loader.memory.write_bytes(sec.min_addr, conttmp[sec.offset: sec.offset + sec.memsize])
                else:
                    func_addr = [j - 0x10000 + 0x400000 for j in func_addr]
                    taint_addr = taint_addr - 0x10000 + 0x400000
                    sinkTargets = [j - 0x10000 + 0x400000 for j in sinkTargets]
                    start_addr = cfg.get_any_node(int(cont[i * 3].split(' ')[1], 0) - 0x10000 + 0x400000,
                                                  anyaddr=True).function_address
                    callerbb = cfg.get_any_node(int(cont[i * 3].split(' ')[1], 0) - 0x10000 + 0x400000,
                                                anyaddr=True).addr
                    with open(binary, 'rb') as f:
                        conttmp = f.read()
                        sec = proj.loader.main_object.sections_map['.got']
                        proj.loader.memory.write_bytes(sec.min_addr, conttmp[sec.offset: sec.offset + sec.memsize])

            sinkTargets = [cfg.get_any_node(j, anyaddr=True).addr for j in sinkTargets]
            for j in func_addr:
                print j
                print cfg.get_any_node(j, anyaddr=True).addr
            followtar = [cfg.get_any_node(j, anyaddr=True).addr for j in func_addr]

            setfindflag(False)
            setSinkTarget(sinkTargets)
            setfollowTarget(followtar)

            print "Analyzing %s from 0x%X, taint 0x%X, sinkTarget%s, functrace %s" % (
            binary, start_addr, taint_addr, str([hex(j) for j in sinkTargets]), str([hex(j) for j in followtar]))
            if not callerbb:
                main(start_addr, taint_addr, binary, proj, cfg)
            else:
                main(start_addr, taint_addr, binary, proj, cfg, callerbb)

            if getfindflag()[0]:
                find_cases += 1
                res = set(getfindflag()[1])
                res = "0x%x 0x%x " % (taint_addr, start_addr) + "  found : %s" % " ".join(
                    [hex(i) for i in set(getfindflag()[1])])
            else:
                res = "0x%x 0x%x " % (taint_addr, start_addr) + "  not found"
            with open('result-%s.txt' % appe, 'a') as f:
                f.write(res + '\n')
        except Exception as e:
            print e
    with open('result-%s.txt' % appe, 'a') as f:
        f.write("total cases: %d\n" % cases)
        f.write("find cases: %d\n" % find_cases)
        f.write("binary: %s\n" % binary)
        f.write("configfile: %s\n" % configfile)
    print("Saved in " + 'result-%s.txt' % appe)


def taint_stain_analysis(binary, ghidra_analysis_result, output):

    analysis_type = ""
    if "ref2sink_bof" in ghidra_analysis_result:
        analysis_type = "ref2sink_bof"
    elif "ref2sink_cmdi" in ghidra_analysis_result:
        analysis_type = "ref2sink_cmdi"

    appe = binary.split('/')[-1] + "-" + analysis_type + "-" + ''.join(random.sample(string.ascii_letters + string.digits, 4))
    if '-alter2' not in ghidra_analysis_result:
        conv_Ghidra_output.main(ghidra_analysis_result)
        ghidra_analysis_result = ghidra_analysis_result + '-alter2'
    with open(ghidra_analysis_result, 'r') as f:
        cont = f.read().split('\n')
    proj = angr.Project(binary, auto_load_libs=False, use_sim_procedures=True)
    cfg = proj.analyses.CFG()
    cases = 0
    find_cases = 0
    res = []
    result_file = os.path.join(output, "result-{}.txt".format(appe))
    with open(result_file, 'a') as f:
        f.write("binary: %s\n" % binary)
        f.write("configfile: %s\n" % ghidra_analysis_result)

    for i in range(len(cont) / 3):
        # if len(i.split(' '))>2:
        try:
            cases += 1
            # func_addr=[int(j,0) for j in i.split(' ')[1:-1]] # functrace
            if cont[i * 3 + 1] != '':
                func_addr = [int(j, 0) for j in cont[i * 3 + 1].split(' ')]
            else:
                func_addr = []
            taint_addr = int(cont[i * 3].split(' ')[0], 0)
            sinkTargets = [int(j, 0) for j in cont[i * 3 + 2].split(' ')]
            # put it to the head of cfg node
            if proj.arch.name != "MIPS32":
                if not proj.loader.main_object.pic:
                    start_addr = cfg.get_any_node(int(cont[i * 3].split(' ')[1], 0), anyaddr=True).addr
                    callerbb = None
                else:
                    func_addr = [j - 0x10000 + 0x400000 for j in func_addr]
                    taint_addr = taint_addr - 0x10000 + 0x400000
                    sinkTargets = [j - 0x10000 + 0x400000 for j in sinkTargets]
                    start_addr = cfg.get_any_node(int(cont[i * 3].split(' ')[1], 0) - 0x10000 + 0x400000,
                                                  anyaddr=True).addr
                    callerbb = None
            else:
                if not proj.loader.main_object.pic or "system.so" in proj.filename:
                    print hex(int(cont[i * 3].split(' ')[1], 0))
                    print cfg.get_any_node(int(cont[i * 3].split(' ')[1], 0), anyaddr=True)
                    start_addr = cfg.get_any_node(int(cont[i * 3].split(' ')[1], 0), anyaddr=True).function_address
                    callerbb = cfg.get_any_node(int(cont[i * 3].split(' ')[1], 0), anyaddr=True).addr
                    with open(binary, 'rb') as f:
                        conttmp = f.read()
                        sec = proj.loader.main_object.sections_map['.got']
                        proj.loader.memory.write_bytes(sec.min_addr, conttmp[sec.offset: sec.offset + sec.memsize])
                else:
                    func_addr = [j - 0x10000 + 0x400000 for j in func_addr]
                    taint_addr = taint_addr - 0x10000 + 0x400000
                    sinkTargets = [j - 0x10000 + 0x400000 for j in sinkTargets]
                    start_addr = cfg.get_any_node(int(cont[i * 3].split(' ')[1], 0) - 0x10000 + 0x400000,
                                                  anyaddr=True).function_address
                    callerbb = cfg.get_any_node(int(cont[i * 3].split(' ')[1], 0) - 0x10000 + 0x400000,
                                                anyaddr=True).addr
                    with open(binary, 'rb') as f:
                        conttmp = f.read()
                        sec = proj.loader.main_object.sections_map['.got']
                        proj.loader.memory.write_bytes(sec.min_addr, conttmp[sec.offset: sec.offset + sec.memsize])

            sinkTargets = [cfg.get_any_node(j, anyaddr=True).addr for j in sinkTargets]
            for j in func_addr:
                print j
                print cfg.get_any_node(j, anyaddr=True).addr
            followtar = [cfg.get_any_node(j, anyaddr=True).addr for j in func_addr]

            setfindflag(False)
            setSinkTarget(sinkTargets)
            setfollowTarget(followtar)

            print "Analyzing %s from 0x%X, taint 0x%X, sinkTarget%s, functrace %s" % (
                binary, start_addr, taint_addr, str([hex(j) for j in sinkTargets]), str([hex(j) for j in followtar]))
            if not callerbb:
                main(start_addr, taint_addr, binary, proj, cfg)
            else:
                main(start_addr, taint_addr, binary, proj, cfg, callerbb)

            if getfindflag()[0]:
                find_cases += 1
                res = set(getfindflag()[1])
                res = "0x%x 0x%x " % (taint_addr, start_addr) + "  found : %s" % " ".join(
                    [hex(i) for i in set(getfindflag()[1])])
            else:
                res = "0x%x 0x%x " % (taint_addr, start_addr) + "  not found"
            with open(result_file, 'a') as f:
                f.write(res + '\n')
        except Exception as e:
            print e

    with open(result_file, 'a') as f:
        f.write("total cases: %d\n" % cases)
        f.write("find cases: %d\n" % find_cases)
        f.write("binary: %s\n" % binary)
        f.write("configfile: %s\n" % ghidra_analysis_result)
    print("Saved in " + 'result-%s.txt' % appe)


if __name__ == '__main__':
    main_main()
