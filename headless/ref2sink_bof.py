# Find path to sink functions from reference of given strings. Different output format for the function calling certain check functions. Find more params heuristicly.
# @author tkmk
# @category Analysis

import time
import sys
from ghidra.util.classfinder import ClassSearcher
from ghidra.app.plugin.core.analysis import ConstantPropagationAnalyzer
from ghidra.program.util import SymbolicPropogator
from ghidra.program.model.mem import MemoryAccessException
from ghidra.util.exception import CancelledException
from collections import Counter, defaultdict
import re

DEBUG = False

heuristicMin = 4
sinks = ['strcpy']
digest = ['strcpy', 'sprintf', 'memcpy', 'strcat']

heuristicIgnoreFunctions = ['strcpy', 'strncpy', 'strcat', 'memcpy']


needCheckConstantStr = {
    'system': 0,
    'fwrite': 0,
    '___system': 0,
    'bstar_system': 0,
    'popen': 0,
    'execve': 0,
    'strcpy': 1,
    'strcat': 1,
    'strncpy': 1,
    'memcpy': 1,
    'twsystem': 0
}
needCheckFormat = {
    'sprintf': 1,
    'doSystemCmd': 0,
    'doShell': 0
}

syms = {}
newParam = defaultdict(set)
analyzer = None


def a2h(address):
    return '0x' + str(address)


def getAnalyzer():
    global analyzer
    for a in ClassSearcher.getInstances(ConstantPropagationAnalyzer):
        if a.canAnalyze(currentProgram):
            analyzer = a
            break
    else:
        assert 0


def getCallingArgs(addr, pos):
    if not 0 <= pos <= 3:
        return
    arch = str(currentProgram.language.processor)
    if arch == 'ARM':
        reg = currentProgram.getRegister('r%d' % pos)
    elif arch == 'MIPS':
        nextInst = getInstructionAt(addr).next
        if len(nextInst.pcode):  # not NOP
            addr = addr.add(8)
        reg = currentProgram.getRegister('a%d' % pos)
    else:
        return
    return getRegister(addr, reg)


def getRegister(addr, reg):
    if analyzer is None:
        getAnalyzer()

    func = getFunctionContaining(addr)
    if func is None:
        return

    if func in syms:
        symEval = syms[func]
    else:
        symEval = SymbolicPropogator(currentProgram)
        symEval.setParamRefCheck(True)
        symEval.setReturnRefCheck(True)
        symEval.setStoredRefCheck(True)
        analyzer.flowConstants(currentProgram, func.entryPoint, func.body, symEval, monitor)
        syms[func] = symEval

    return symEval.getRegisterValue(addr, reg)


def getStr(addr):
    ad = addr
    ret = ''
    try:
        while not ret.endswith('\0'):
            ret += chr(getByte(ad) % 256)
            ad = ad.add(1)
    except MemoryAccessException:
        return
    return ret[:-1]


def getStrArg(addr, argpos=0):
    rv = getCallingArgs(addr, argpos)
    if rv is None:
        return
    return getStr(toAddr(rv.value))


def checkConstantStr(addr, argpos=0):
    # empty string is not considered as constant, for it may be uninitialized global variable
    return bool(getStrArg(addr, argpos))


def checkSafeFormat(addr, offset=0):
    data = getStrArg(addr, offset)
    if data is None:
        return False

    fmtIndex = offset
    for i in range(len(data) - 1):
        if data[i] == '%' and data[i + 1] != '%':
            fmtIndex += 1
            if data[i + 1] == 's':
                if fmtIndex > 3:
                    return False
                if not checkConstantStr(addr, fmtIndex):
                    return False
    return True


def getCallee(inst):
    callee = None
    if len(inst.pcode):
        if inst.pcode[-1].mnemonic == 'CALL':
            callee = getFunctionAt(inst.getOpObjects(0)[0])
        elif inst.pcode[-1].mnemonic == 'CALLIND':
            regval = getRegister(inst.address, inst.getOpObjects(0)[0])
            if regval is not None:
                callee = getFunctionAt(toAddr(regval.value))
    return callee


searchStrArgDone = set()


def searchStrArg(func):
    if func in searchStrArgDone:
        return
    if DEBUG:
        print 'start search', func, '(heuristic)'
    searchStrArgDone.add(func)
    start = func.entryPoint
    end = func.body.maxAddress

    funcPosCounter = Counter()
    inst = getInstructionAt(start)
    while inst is not None and inst.address < end:
        callee = getCallee(inst)
        if callee is not None:
            maxpos = 4
            if callee.parameterCount > 0:
                maxpos = min(maxpos, callee.parameterCount)
            for pos in range(maxpos):
                if getStrArg(inst.address, pos) in paramTargets:
                    funcPosCounter[callee, pos] += 1
        inst = inst.next

    # newParamCount = 0
    inst = getInstructionAt(start)
    while inst is not None and inst.address < end:
        callee = getCallee(inst)
        if callee is not None and callee.name not in heuristicIgnoreFunctions:
            for pos in range(4):
                if funcPosCounter[callee, pos] >= heuristicMin:
                    s = getStrArg(inst.address, pos)
                    if s and re.search(r'[a-zA-Z_]{4}', s) and s not in paramTargets:
                        if DEBUG:
                            print 'new param', s
                        newParam[s].add(func)
                        # newParamCount += 1

        inst = inst.next
    if DEBUG:
        print 'finish search', func, '(heuristic)'
    return


callMap = {}
safeFuncs = set()
referenced = set()


def findSinkPath(refaddr, stringaddr, stringval):
    pending = []

    def search(func, start=None):
        if func in callMap:
            return
        callMap[func] = {}

        start = start or func.entryPoint
        end = func.body.maxAddress

        inst = getInstructionAt(start)
        while inst is not None and inst.address < end:
            callee = getCallee(inst)
            if callee is not None:
                callMap[func][inst.address] = callee
                if callee not in callMap:
                    pending.append(callee)
            inst = inst.next

    def printpath(path):
        print >>f, '[Param "%s"(%s), Referenced at %s : %s]' % (stringval, a2h(stringaddr), startFunc, a2h(refaddr)),
        for i in range(len(path)):
            addr, callee = path[i][:2]
            if i == len(path) - 1:
                print >>f, '>>', a2h(addr), '->', callee,
            else:
                calleeCallDigestFunc = path[i + 1][-1]
                if calleeCallDigestFunc:
                    print >>f, '>>', a2h(addr), '>>', callee,
                else:
                    print >>f, '>>', a2h(addr), '->', callee,

        print >>f

    def dfs(func, path, start=None):
        '''path: list of (addr of call, callee, callDigestFunc)'''
        if func.name in sinks and len(path):
            if func.name in needCheckConstantStr and checkConstantStr(path[-1][0], needCheckConstantStr[func.name]):
                return False
            if func.name in needCheckFormat and checkSafeFormat(path[-1][0], needCheckFormat[func.name]):
                return False
            printpath(path)
            return True
        callDigestFunc = False
        vulnerable = False
        for addr, callee in sorted(callMap[func].items()):
            if start is not None and addr < start:
                continue
            if not callDigestFunc and callee.name in digest:
                if callee.name in needCheckConstantStr and checkConstantStr(addr, needCheckConstantStr[callee.name]):
                    pass
                elif callee.name in needCheckFormat and checkSafeFormat(addr, needCheckFormat[callee.name]):
                    pass
                else:
                    callDigestFunc = True
            if callee in [x[1] for x in path] + [startFunc] or callee in safeFuncs:
                continue
            vulnerable = dfs(callee, path + [(addr, callee, callDigestFunc)]) or vulnerable
        if not vulnerable and func != startFunc:
            safeFuncs.add(func)
        return vulnerable

    startFunc = getFunctionContaining(refaddr)
    assert startFunc is not None

    pending.append(startFunc)
    while len(pending):
        search(pending.pop())

    vulnerable = dfs(startFunc, [], refaddr)
    if vulnerable:
        searchStrArg(startFunc)
    return vulnerable


def searchParam(target, refstart=None, refend=None):
    if DEBUG:
        print 'start searching "%s" ...' % target
    curAddr = currentProgram.minAddress
    end = currentProgram.maxAddress
    haveWayToSink = False
    checkedRefAddr = set()
    while curAddr < end:
        curAddr = find(curAddr, target)
        if curAddr is None:
            break
        if getByte(curAddr.add(len(target))) != 0:
            curAddr = curAddr.add(1)
            continue
        for ref in getReferencesTo(curAddr):
            if refstart is not None and refstart > ref.fromAddress:
                continue
            if refend is not None and refend < ref.fromAddress:
                continue
            if target not in newParam:
                referenced.add(target)
            caller = getFunctionContaining(ref.fromAddress)
            if caller is not None:
                if DEBUG:
                    print 'Reference From', a2h(ref.fromAddress), '(%s)' % caller,
                    print 'To', a2h(curAddr), '("%s")' % target
                if ref.fromAddress in checkedRefAddr:
                    continue
                haveWayToSink = findSinkPath(ref.fromAddress, curAddr, target) or haveWayToSink
                checkedRefAddr.add(ref.fromAddress)
            else:
                for ref2 in getReferencesTo(ref.fromAddress):
                    caller = getFunctionContaining(ref2.fromAddress)
                    if caller is None:
                        if DEBUG:
                            print 'Ignore', getSymbolAt(ref2.fromAddress), 'at', a2h(ref2.fromAddress)
                        continue
                    if DEBUG:
                        print 'Reference From', a2h(ref2.fromAddress), '(%s)' % caller,
                        print 'To', a2h(ref.fromAddress), '(%s)' % getSymbolAt(ref.fromAddress),
                        print 'To', a2h(curAddr), '("%s")' % target
                    if ref2.fromAddress in checkedRefAddr:
                        continue
                    haveWayToSink = findSinkPath(ref2.fromAddress, curAddr, target) or haveWayToSink
                    checkedRefAddr.add(ref2.fromAddress)

        curAddr = curAddr.add(1)
    if DEBUG:
        print 'finish searching "%s"' % target
    return haveWayToSink


if __name__ == '__main__':
    args = getScriptArgs()
    paramTargets = set(open(args[0]).read().strip().split())
    f = None
    if len(args) > 1:
        f = open(args[1], 'w')

    numOfParam = len(paramTargets)
    t = time.time()
    cnt = 0
    for i, param in enumerate(paramTargets):
        monitor.setMessage('Searching for "%s": %d of %d' % (param, i + 1, numOfParam))
        cnt += searchParam(param)

    for i, param in enumerate(newParam):
        monitor.setMessage('Searching for "%s": %d of %d' % (param, i + 1, len(newParam)))
        for func in newParam[param]:
            searchParam(param, func.body.minAddress, func.body.maxAddress)

    t = time.time() - t
    print 'Time Elapsed:', t
    print '%d of %d parameters are referenced' % (len(referenced), numOfParam)
    print '%d of %d parameters have way to sink function' % (cnt, numOfParam)
    print 'Find %d new params heuristicly:' % len(newParam)
    print ', '.join(newParam)

    if f is not None:
        print >>f, 'Time Elapsed:', t
        print >>f, '%d of %d parameters are referenced' % (len(referenced), numOfParam)
        print >>f, '%d of %d parameters have way to sink function' % (cnt, numOfParam)
        print >>f, 'Find %d new params heuristicly:' % len(newParam)
        print >>f, ', '.join(newParam)
        f.close()
