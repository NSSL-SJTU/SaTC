from taint_check.binary_dependency_graph.utils import are_parameters_in_registers, get_string
from taint_check.taint_analysis.utils import ordered_argument_regs, arg_reg_name
from .config import checkcommandinjection, checkbufferoverflow
import traceback

exe_funcs = ["system", "popen", "execve", "___system", "bstar_system", "doSystemCmd", "twsystem"]
findflag = False
retaddr = []

checkfwrite = False


def setfindflag(bo, addr=None):
    global findflag, retaddr
    findflag = bo
    if bo:
        retaddr.append(addr)
    else:
        retaddr = []


def getfindflag():
    global findflag, retaddr
    return findflag, retaddr


def checkstringtainted(p, core_taint, state, name, plt_path):
    reg = getattr(state.regs, name)
    # print "checkstringtainted",name,reg,plt_path.active[0]
    idx = 0
    if False:
        # print core_taint.safe_load(plt_path,reg.args[0]+idx),'is_tainted',core_taint.is_tainted(core_taint.safe_load(plt_path,reg.args[0]+idx),path=plt_path)
        while not core_taint.is_tainted(core_taint.safe_load(plt_path, reg.args[0] + idx), path=plt_path):
            byt = state.memory.load(reg.args[0] + idx, 1).args[0]
            # print idx,':',byt
            if byt == 0 or idx >= 0x200:  # consider implement this
                return False
            idx += 1
        return True
    else:
        return core_taint.is_or_points_to_tainted_data(reg, plt_path, unconstrained=False)


def doSystemCmd(p, core_taint, plt_path, *_, **__):
    """
    doSystemCmd function summary

    :param p: angr project
    :param core_taint: core taint engine
    :param plt_path: path to the plt entry
    :return: None
    """
    if not checkcommandinjection:
        print "return due to filtered"
        return False
    plt_state = plt_path.active[0]
    if are_parameters_in_registers(p):
        frmt_str = getattr(plt_state.regs, arg_reg_name(p, 0))
        str_val = get_string(p, frmt_str.args[0], extended=True)
        n_vargs = str_val.count('%')
        for i in range(1, 1 + n_vargs):
            name = p.arch.register_names[ordered_argument_regs[p.arch.name][i]]
            reg = getattr(plt_state.regs, name)
            print name, ':', reg
            if (core_taint.is_tainted(reg, path=plt_path) or checkstringtainted(p, core_taint, plt_state, name,
                                                                                plt_path)):
                print "doSystemCmd return True"
                setfindflag(True, plt_state.regs.lr.args[0])
                return True
        print "doSystemCmd return False"
        return False
    else:
        raise Exception("implement me")


def system(p, core_taint, plt_path, *_, **__):
    """
    system function summary

    :param p: angr project
    :param core_taint: core taint engine
    :param plt_path: path to the plt entry
    :return: None
    """
    if not checkcommandinjection:
        print "return due to filtered"
        return False
    plt_state = plt_path.active[0]
    if are_parameters_in_registers(p):
        name = p.arch.register_names[ordered_argument_regs[p.arch.name][0]]
        reg = getattr(plt_state.regs, name)
        state = plt_path.active[0]
        if core_taint.is_tainted(reg, path=plt_path):
            setfindflag(True, plt_state.regs.lr.args[0])
            return True
        ret = checkstringtainted(p, core_taint, state, name, plt_path)
        print "SYSTEM return ", ret
        if ret:
            setfindflag(True, plt_state.regs.lr.args[0])
        return ret
    else:
        raise Exception("implement me")


def popen(p, core_taint, plt_path, *_, **__):
    """
    popen function summary

    :param p: angr project
    :param core_taint: core taint engine
    :param plt_path: path to the plt entry
    :return: None
    """
    if not checkcommandinjection:
        print "return due to filtered"
        return False
    plt_state = plt_path.active[0]
    if are_parameters_in_registers(p):
        name = p.arch.register_names[ordered_argument_regs[p.arch.name][0]]
        reg = getattr(plt_state.regs, name)
        if (core_taint.is_tainted(reg, path=plt_path)):
            setfindflag(True, plt_state.regs.lr.args[0])
            return True
        ret = checkstringtainted(p, core_taint, plt_state, name, plt_path)
        if ret:
            setfindflag(True, plt_state.regs.lr.args[0])
        return ret
    else:
        raise Exception("implement me")


def execve(p, core_taint, plt_path, *_, **__):
    """
    execve function summary

    :param p: angr project
    :param core_taint: core taint engine
    :param plt_path: path to the plt entry
    :return: None
    """
    if not checkcommandinjection:
        print "return due to filtered"
        return False
    plt_state = plt_path.active[0]
    if are_parameters_in_registers(p):
        name0 = p.arch.register_names[ordered_argument_regs[p.arch.name][0]]
        reg0 = getattr(plt_state.regs, name0)
        name1 = p.arch.register_names[ordered_argument_regs[p.arch.name][1]]
        reg1 = getattr(plt_state.regs, name1)
        ret = (core_taint.is_tainted(reg0, path=plt_path) or
               checkstringtainted(p, core_taint, plt_state, name0, plt_path) or
               core_taint.is_tainted(reg1, path=plt_path) or
               checkstringtainted(p, core_taint, plt_state, name1, plt_path))
        if ret:
            print "execve return True"
            setfindflag(True, plt_state.regs.lr.args[0])
        return ret
    else:
        raise Exception("implement me")


def strcpy(p, core_taint, plt_path, size_con=None):
    """
    strcpy function summary

    :param p: angr project
    :param core_taint: core taint engine
    :param plt_path: path to the plt entry
    :return:  None
    """
    if not checkbufferoverflow:
        print "return due to filtered"
        return False
    plt_state = plt_path.active[0]
    if are_parameters_in_registers(p):
        name_reg_src = p.arch.register_names[ordered_argument_regs[p.arch.name][1]]
        reg_src = getattr(plt_state.regs, name_reg_src)
        if core_taint.is_tainted(reg_src, plt_path) or checkstringtainted(p, core_taint, plt_state, name_reg_src,
                                                                          plt_path):
            # if core_taint.is_or_points_to_tainted_data(reg_src, plt_path, unconstrained=False):
            print '1', reg_src
            setfindflag(True, plt_state.regs.lr.args[0])
            print "strcpy return True"
            return True
        # check the size of the two buffers
        name_reg_dst = p.arch.register_names[ordered_argument_regs[p.arch.name][0]]
        reg_dst = getattr(plt_state.regs, name_reg_dst)

        src = core_taint.safe_load(plt_path, reg_src)
        dst = core_taint.safe_load(plt_path, reg_dst)
        tainted = checkstringtainted(p, core_taint, plt_state, name_reg_src, plt_path)

        # we raise alerts also for equal size of src and dst, as the analysis might be under-constrained.
        ret = tainted and size_con >= (src.cardinality - 1) >= (dst.cardinality - 1)
        if ret:
            print "strcpy return True"
            setfindflag(True, plt_state.regs.lr.args[0])
        return ret
    else:
        raise Exception("implement me")


def memcpy(p, core_taint, plt_path, *_, **__):
    """
    memcpy function summary

    :param p: angr project
    :param core_taint: core taint engine
    :param plt_path: path to the plt entry
    :return: None
    """
    if not checkbufferoverflow:
        print "return due to filtered"
        return False
    plt_state = plt_path.active[0]
    if are_parameters_in_registers(p):
        name = p.arch.register_names[ordered_argument_regs[p.arch.name][2]]
        reg = getattr(plt_state.regs, name)
        ret = (core_taint.is_tainted(reg, path=plt_path) or checkstringtainted(p, core_taint, plt_state, name,
                                                                               plt_path))
        if ret:
            setfindflag(True, plt_state.regs.lr.args[0])
        return ret
    else:
        raise Exception("implement me")


def fwrite(p, core_taint, plt_path, *_, **__):
    """
    fwrite function summary

    :param p: angr project
    :param core_taint: core taint engine
    :param plt_path: path to the plt entry
    :return: None
    """
    if not checkfwrite:
        print "return due to filtered"
        return False
    plt_state = plt_path.active[0]
    if are_parameters_in_registers(p):
        name = p.arch.register_names[ordered_argument_regs[p.arch.name][0]]
        reg = getattr(plt_state.regs, name)
        ret = (core_taint.is_tainted(reg, path=plt_path) or checkstringtainted(p, core_taint, plt_state, name,
                                                                               plt_path))
        if ret:
            setfindflag(True, plt_state.regs.lr.args[0])
        return ret
    else:
        raise Exception("implement me")


def sprintf(p, core_taint, plt_path, *_, **__):
    """
    sprintf function summary

    :param p: angr project
    :param core_taint: core taint engine
    :param plt_path: path to the plt entry
    :return: None
    """
    if not checkbufferoverflow:
        print "return due to filtered"
        return False
    plt_state = plt_path.active[0]
    if are_parameters_in_registers(p):
        frmt_str = getattr(plt_state.regs, arg_reg_name(p, 1))
        str_val = get_string(p, frmt_str.args[0], extended=True)
        n_vargs = str_val.count('%s') + str_val.count('%d')
        for i in range(2, 2 + n_vargs):
            name = p.arch.register_names[ordered_argument_regs[p.arch.name][i]]
            reg = getattr(plt_state.regs, name)
            if (core_taint.is_tainted(reg, path=plt_path) or checkstringtainted(p, core_taint, plt_state, name,
                                                                                plt_path)):
                print "SPRINTF return True"
                setfindflag(True, plt_state.regs.lr.args[0])
                return True
            return False
    else:
        raise Exception("implement me")
