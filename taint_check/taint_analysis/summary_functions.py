"""
Though karonte relies on angr's simprocedures, sometimes these add in the current state some contraints to make the
used analysis faster. For example, if a malloc has an unconstraint size, angr add the constraint
size == angr-defined.MAX_SIZE. Though this makes the analysis faster, it makes impossible to reason about the maximum
buffer sizes (as needed by karonte).

In this module we wrap simprocedures to avoid them to add such constraints.

Note however, that the semantic of an expression might get lost.
Eg. strlen(taint_x) = taint_y, taint_y is an unconstrained variable
"""
from coretaint import *
import claripy
import traceback

simplify_memcpy = False

MIN_STR_LEN = 3
STR_LEN = 255
ALLOWED_CHARS = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-/_'
EXTENDED_ALLOWED_CHARS = ALLOWED_CHARS + "%,.;+=_)(*&^%$#@!~`?|<>{}[] \""
SEPARATOR_CHARS = ('-', '_')
def get_mem_string(mem_bytes, extended=False):
    """
    Return the set of consecutive ASCII characters within a list of bytes

    :param mem_bytes: list of bytes
    :param extended: use extended list of characters
    :return: the longest string found
    """

    tmp = ''
    chars = EXTENDED_ALLOWED_CHARS if extended else ALLOWED_CHARS

    for c in mem_bytes:
        if c not in chars:
            break
        tmp += c

    return tmp
def gs(p, mem_addr, extended=False):
    """
    Get a string from a memory address

    :param p: angr project
    :param mem_addr: memory address
    :param extended: use extended set of characters
    :return: the string
    """

    bin_bounds = (p.loader.main_object.min_addr, p.loader.main_object.max_addr)
    try:
        text_bounds = (p.loader.main_object.sections_map['.text'].min_addr,
                       p.loader.main_object.sections_map['.text'].max_addr)
    except:
        text_bounds = None

    # check if the address contain another address
    try:
        endianess = '<I' if 'LE' in p.arch.memory_endness else '>I'
        tmp_addr = struct.unpack(
            endianess, ''.join(p.loader.memory.read_bytes(mem_addr, p.arch.bytes))
        )[0]
    except:
        tmp_addr = None

    # if the .text exists, we make sure that the actual string
    # is someplace else.
    if text_bounds is not None and text_bounds[0] <= mem_addr <= text_bounds[1]:
        # if the indirect address is not an address, or it points to the text segment,
        # or outside the scope of the binary
        if not tmp_addr or text_bounds[0] <= tmp_addr <= text_bounds[1] or \
               tmp_addr < bin_bounds[0] or tmp_addr > bin_bounds[1]:
            return ''

    # get string representation at mem_addr
    cnt = p.loader.memory.read_bytes(mem_addr, STR_LEN)
    string_1 = get_mem_string(cnt, extended=extended)
    string_2 = ''

    try:
        if tmp_addr and bin_bounds[0] <= tmp_addr <= bin_bounds[1]:
            cnt = p.loader.memory.read_bytes(tmp_addr, STR_LEN)
            string_2 = get_mem_string(cnt)
    except:
        string_2 = ''

    # return the most probable string
    candidate = string_1 if len(string_1) > len(string_2) else string_2
    return candidate if len(candidate) >= MIN_STR_LEN else ''

def _get_function_name(addr, p):
    """
    Return a function name

    :param addr: function address
    :param p: angr project
    :return: function name
    """

    if addr in p.loader.main_object.reverse_plt:
        return p.loader.main_object.reverse_plt[addr]
    return None


def _restore_caller_regs(_core, old_path, new_path):
    """
    Restore the caller registers (this simulate a return from a summarized function)

    :param _core: core taint engine
    :param old_path: old angr path (the from where the function is returning from)
    :param new_path: new angr path (the program point where the execution is returning)
    :return:
    """

    p = _core.p
    new_state = new_path.active[0]
    old_state = old_path.active[0]

    lr = p.arch.register_names[link_regs[p.arch.name]]

    ret_addr = getattr(new_state.regs, lr)
    ret_func = getattr(old_state.regs, lr)

    new_path.active[0].ip = ret_addr
    setattr(new_path.active[0].regs, lr, ret_func)
    new_path.active[0].history.jumpkind = "Ijk_FakeRet"


def source_dummy(*_, **__):
    pass


def memcmp_unsized(_core, _, plt_path):
    """
    memcmp-like unsized (e.g., strlen) function summary

    :param _core: core taint engine
    :param _: not used
    :param plt_path:  path to the plt (i.e., call_site.step())
    :return: None
    """

    p = _core.p
    plt_path_cp = plt_path.copy(copy_states=True)

    dst_reg = arg_reg_name(p, 0)
    src_reg = arg_reg_name(p, 1)

    b1 = _core.safe_load(plt_path_cp, getattr(plt_path_cp.active[0].regs, dst_reg))
    b2 = _core.safe_load(plt_path_cp, getattr(plt_path_cp.active[0].regs, src_reg))

    if not _core.is_tainted(b1, plt_path_cp):
        b1 = None
    if not _core.is_tainted(b2, plt_path_cp):
        b2 = None

    # if either of the two is not tainted, we untaint the other
    if b1 is not None and b2 is None:
        _core.do_recursive_untaint(b1, plt_path)
    elif b2 is not None and b1 is None:
        _core.do_recursive_untaint(b2, plt_path)

    # step into it
    plt_path_cp.step()
    assert _core.p.is_hooked(plt_path_cp.active[0].addr), "memcmp_unsized: Summary function relies on angr's " \
                                                          "sim procedure, add option use_sim_procedures to the loader"
    plt_path.step().step()


def memcmp_sized(_core, _, plt_path):
    """
    memcmp-like sized (e.g., memcmp) function summary

    :param _core: core taint engine
    :param _: not used
    :param plt_path:  path to the plt (i.e., call_site.step())
    :return: None
    """

    p = _core.p
    plt_path_cp = plt_path.copy(copy_states=True)

    dst_reg = arg_reg_name(p, 0)
    src_reg = arg_reg_name(p, 1)
    reg_n = arg_reg_name(p, 2)

    b1 = _core.safe_load(plt_path_cp, getattr(plt_path_cp.active[0].regs, dst_reg))
    b2 = _core.safe_load(plt_path_cp, getattr(plt_path_cp.active[0].regs, src_reg))
    n = _core.safe_load(plt_path_cp, getattr(plt_path_cp.active[0].regs, reg_n))

    # we untaint buffers only if n is not tainted
    if not _core.is_tainted(n, plt_path_cp):

	n_val = getattr(plt_path_cp.active[0].regs, reg_n).args[0]

        if not _core.is_tainted(b1, plt_path_cp):
            b1 = None
        if not _core.is_tainted(b2, plt_path_cp):
            b2 = None

        # if either of the two is not tainted, we untaint the other
        if b1 is not None and b2 is None:
	    for i in range(n_val):
      	        b1 = _core.safe_load(plt_path_cp, getattr(plt_path_cp.active[0].regs, dst_reg) + i)
                _core.do_untaint(b1, plt_path)
		'''
	    for i in range(64):
		hay = getattr(plt_path_cp.active[0].regs, dst_reg) + i
		print "_core.safe_load(plt_path_cp,hay)",_core.safe_load(plt_path_cp,hay)
		print "after untaint, addr 0x%x is tainted:"%(hay.args[0]),_core.is_tainted(_core.safe_load(plt_path_cp,hay), plt_path_cp)
		'''
        elif b2 is not None and b1 is None:
	    for i in range(n_val):
	        b2 = _core.safe_load(plt_path_cp, getattr(plt_path_cp.active[0].regs, src_reg) + i)
                _core.do_untaint(b2, plt_path)

    # step into it
    plt_path_cp.step()
    assert _core.p.is_hooked(plt_path_cp.active[0].addr), "memcmp_sized: Summary function relies on angr's " \
                                                          "sim procedure, add option use_sim_procedures to the loader"
    plt_path.step().step()

def sprintf(_core, call_site_path, plt_path):
    p = _core.p
    plt_path_cp = plt_path.copy(copy_states=True)
    plt_state_cp = plt_path_cp.active[0]

    dst_reg = arg_reg_name(p, 0)
    fmt_reg = arg_reg_name(p, 1)
    dst_reg = getattr(plt_state_cp.regs, dst_reg)
    fmt_reg = getattr(plt_state_cp.regs, fmt_reg)

    str_val = gs(p, fmt_reg.args[0], extended=True)
    n_vargs = str_val.count('%s')+str_val.count('%d')
    gettmpflag=False
    for i in range(2, 2 + n_vargs):
	name = p.arch.register_names[ordered_argument_regs[p.arch.name][i]]
	reg = getattr(plt_state_cp.regs, name)
	if (_core.is_tainted(reg, path=plt_path_cp) or _core.is_tainted(_core.safe_load(plt_path_cp, reg), path=plt_path_cp)):
	    t = _core.get_sym_val(name=_core.taint_buf, bits=_core.taint_buf_size).reversed
	    gettmpflag=True
	    break
    if not gettmpflag:
	t = _core.get_sym_val(name="memcpy_unc_buff", bits=plt_state_cp.libc.max_buffer_size).reversed 	    
    plt_path.active[0].memory.store(dst_reg, t)
    _restore_caller_regs(_core, call_site_path, plt_path)
    
def snprintf(_core, call_site_path, plt_path):
    p = _core.p
    plt_path_cp = plt_path.copy(copy_states=True)
    plt_state_cp = plt_path_cp.active[0]

    dst_reg = arg_reg_name(p, 0)
    fmt_reg = arg_reg_name(p, 2)
    dst_reg = getattr(plt_state_cp.regs, dst_reg)
    fmt_reg = getattr(plt_state_cp.regs, fmt_reg)

    str_val = gs(p, fmt_reg.args[0], extended=True)
    n_vargs = str_val.count('%s')+str_val.count('%d')
    gettmpflag=False
    for i in range(3, 3 + n_vargs):
        name = p.arch.register_names[ordered_argument_regs[p.arch.name][i]]
        reg = getattr(plt_state_cp.regs, name)
        if (_core.is_tainted(reg, path=plt_path_cp) or _core.is_tainted(_core.safe_load(plt_path_cp, reg), path=plt_path_cp)):
            t = _core.get_sym_val(name=_core.taint_buf, bits=_core.taint_buf_size).reversed
            gettmpflag=True
            break
    if not gettmpflag:
        t = _core.get_sym_val(name="memcpy_unc_buff", bits=plt_state_cp.libc.max_buffer_size).reversed
    plt_path.active[0].memory.store(dst_reg, t)
    _restore_caller_regs(_core, call_site_path, plt_path)

def memcpy_sized(_core, call_site_path, plt_path):
    """
    memcpy-like sized (e.g., memcpy) function summary

    :param _core: core taint engine
    :param call_site_path: call site angr path
    :param plt_path:  path to the plt (i.e., call_site.step())
    :return: None
    """

    p = _core.p

    plt_path_cp = plt_path.copy(copy_states=True)

    # if the second parameter is tainted (or pointing to a tainted location)
    # or the third is tainted, we taint the first too
    plt_state_cp = plt_path_cp.active[0]

    dst_reg = arg_reg_name(p, 0)
    src_reg = arg_reg_name(p, 1)
    reg_n = arg_reg_name(p, 2)

    size = getattr(plt_state_cp.regs, reg_n)
    size_val=size.args[0]
    src = getattr(plt_state_cp.regs, src_reg)
    dst = getattr(plt_state_cp.regs, dst_reg)

    if simplify_memcpy and plt_state_cp.se.max_int(size) >= plt_state_cp.libc.max_memcpy_size:
        if (_core.is_tainted(src, path=plt_path_cp) or _core.is_tainted(_core.safe_load(plt_path_cp, src), path=plt_path_cp)):
            t = _core.get_sym_val(name=_core.taint_buf, bits=_core.taint_buf_size).reversed
        else:
            t = _core.get_sym_val(name="memcpy_unc_buff", bits=plt_state_cp.libc.max_memcpy_size).reversed

        plt_path.active[0].memory.store(getattr(plt_path.active[0].regs, dst_reg), t)

        # restore the register values to return the call
        _restore_caller_regs(_core, call_site_path, plt_path)

    else:
        plt_path_cp.step()
        assert _core.p.is_hooked(plt_path_cp.active[0].addr), "memcpy_sized: Summary function relies on angr's " \
                                                              "sim procedure, add option use_sim_procedures to the " \
                                                              "loader"
        plt_path.step().step()
        if not plt_path.active:
            raise Exception("size of function has no active successors, not walking this path...")

        # untaint if the size is constrained
        if (not _core.is_tainted(dst, path=plt_path_cp) and
            not _core.is_tainted(_core.safe_load(plt_path_cp, dst), path=plt_path_cp) and
	    not _core.is_tainted(size, path=plt_path_cp)):
            # do untaint
            _core.do_recursive_untaint(dst, plt_path)


def memcpy_unsized(_core, call_site_path, plt_path):
    """
    memcpy-like unsize (e.g., strcpy) function summary

    :param _core: core taint engine
    :param call_site_path: call site angr path
    :param plt_path:  path to the plt (i.e., call_site.step())
    :return: None
    """

    p = _core.p

    # FIXME do taint untaint!
    plt_path_cp = plt_path.copy(copy_states=True)
    plt_state_cp = plt_path_cp.active[0]

    src = getattr(plt_state_cp.regs, arg_reg_name(p, 1))

    if _core.is_tainted(src, path=plt_path_cp) or _core.is_tainted(_core.safe_load(plt_path_cp, src), path=plt_path_cp):
        # FIXME: make the actual copy so that taint dependency will be respected
        t = _core.get_sym_val(name=_core.taint_buf, bits=_core.taint_buf_size).reversed
    else:
        plt_path_cp.step()
        assert _core.p.is_hooked(plt_path_cp.active[0].addr), "memcpy_unsized: Summary function relies on angr's " \
                                                              "sim procedure, add option use_sim_procedures to the " \
                                                              "loader"
        plt_path.step().step()
        if not plt_path.active:
            raise Exception("size of function has no active successors, not walking this path...")
        return
    dst = getattr(plt_path.active[0].regs, arg_reg_name(p, 0))
    plt_path.active[0].memory.store(dst, t)

    # restore the register values to return the call
    _restore_caller_regs(_core, call_site_path, plt_path)

def is_size_taint(v):
    return '__size__' in str(v)

def sizeof(_core, call_site_path, plt_path):
    """
    sizeof-like (e.g., strlen) function summary

    :param _core: core taint engine
    :param call_site_path: call site angr path
    :param plt_path:  path to the plt (i.e., call_site.step())
    :return: None
    """

    p = _core.p
    plt_path_cp = plt_path.copy(copy_states=True)
    plt_state_cp = plt_path_cp.active[0]

    n = getattr(plt_state_cp.regs, arg_reg_name(p, 0))

    cnt = _core.safe_load(plt_path_cp, n, _core.taint_buf_size/8)
    # if parameter is tainted (or pointing to a tainted location)
    if _core.is_tainted(n, path=plt_path_cp) or _core.is_tainted(cnt, path=plt_path_cp):
        t = _core.get_sym_val(name=(_core.taint_buf + '__size__'), bits=_core.p.arch.bits).reversed
        _core.add_taint_glob_dep(t, cnt, plt_path)
        setattr(plt_path.active[0].regs, arg_reg_name(p, 0), t)

    # not tainted, but symbolic and huge
    elif cnt.symbolic:
        # check whether it has a limited size
        for i in xrange(0, plt_state_cp.libc.max_str_len):
            cnt_i = _core.safe_load(plt_path_cp, n + i, 1)
            vals = plt_state_cp.se.eval_upto(cnt_i, 2)
            if len(vals) == 1 and vals[0] == 0:
                t = claripy.BVV(i, _core.p.arch.bits)
                break
        else:
            # ok, uncontrain it
            t = _core.get_sym_val(name="ret_sizeof_kind", bits=_core.p.arch.bits)
        setattr(plt_path.active[0].regs, arg_reg_name(p, 0), t)

    # we use simprocedure for all the other cases
    else:
        plt_path_cp.step()
        assert _core.p.is_hooked(plt_path_cp.active[0].addr), "sizeof: Summary function relies on angr's " \
                                                              "sim procedure, add option use_sim_procedures to the " \
                                                              "loader"
        plt_path.step().step()
        if not plt_path.active:
            raise Exception("size of function has no active successors, not walking this path...")
        return

    # restore the register values to return the call
    _restore_caller_regs(_core, call_site_path, plt_path)

#
# Heap functions
#


def _malloc(_core, _, plt_path):
    """
    maclloc function summary

    :param _core: core taint engine
    :param plt_path: path to the plt (i.e., call_site.step())
    :return: None
    """

    p = _core.p

    state = plt_path.active[0]
    sim_size = getattr(state.regs, arg_reg_name(p, 0))

    if state.se.symbolic(sim_size):
        size = state.se.max_int(sim_size)
        if size > state.libc.max_variable_size:
            size = state.libc.max_variable_size
    else:
        size = state.se.eval(sim_size)

    addr = state.libc.heap_location
    state.libc.heap_location += size
    setattr(state.regs, arg_reg_name(p, 0), addr)
    return sim_size


def _realloc(_core, _, plt_path):
    """
    realloc function summary

    :param _core: core taint engine
    :param plt_path: path to the plt (i.e., call_site.step())
    :return: None
    """

    p = _core.p

    state = plt_path.active[0]
    sim_size = getattr(state.regs, arg_reg_name(p, 1))
    ptr = getattr(state.regs, arg_reg_name(p, 0))

    if state.se.symbolic(sim_size):
        size = state.se.max_int(sim_size)
        if size > state.libc.max_variable_size:
            size = state.libc.max_variable_size
    else:
        size = state.se.eval(sim_size)

    addr = state.libc.heap_location
    v = state.memory.load(ptr, size)
    state.memory.store(addr, v)
    state.libc.heap_location += size
    setattr(state.regs, arg_reg_name(p, 0), addr)
    return sim_size


def heap_alloc(_core, call_site_path, plt_path):
    """
    Heap allocation function stub

    :param _core: core taint engine
    :param call_site_path: call site angr path
    :param plt_path: path to the plt (i.e., call_site.step())
    :return: None
    """

    fname = _get_function_name(plt_path.active[0].addr, _core.p)

    # step over the plt
    plt_path.step()

    sim_size = None
    if fname == 'malloc':
        sim_size = _malloc(_core, call_site_path, plt_path)
    elif fname == 'realloc':
        sim_size = _realloc(_core, call_site_path, plt_path)
    else:
        print "Implement this heap alloc: " + fname

    if sim_size is not None:
        taint_args = [l for l in sim_size.recursive_leaf_asts if _core.is_tainted(l, call_site_path)]
        if taint_args and len(set(taint_args)) == 1:
            arg = taint_args[0]
            if is_size_taint(arg):
                _core.do_recursive_untaint(arg, plt_path)

    _restore_caller_regs(_core, call_site_path, plt_path)


#
# Env function
#
env_var = {}


def _setenv(_core, _, plt_path):
    """
    setenv function summary

    :param _core: core taint engine
    :param plt_path: path to the plt (i.e., call_site.step())
    :return: None
    """

    global env_var
    p = _core.p

    plt_path_cp = plt_path.copy(copy_states=True)
    plt_state_cp = plt_path_cp.active[0]

    key = getattr(plt_state_cp.regs, arg_reg_name(p, 0))
    env_var[str(key)] = getattr(plt_state_cp.regs, arg_reg_name(p, 1))


def _getenv(_core, call_site_addr, plt_path):
    """
    getenv function summary
    :param _core: core taint engine
    :param call_site_addr: call site angr path
    :param plt_path: path to the plt (i.e., call_site.step())
    :return: None
    """

    global env_var
    p = _core.p

    env_var_size = _core.taint_buf_size
    plt_path_cp = plt_path.copy(copy_states=True)
    plt_state_cp = plt_path_cp.active[0]

    reg = getattr(plt_state_cp.regs, arg_reg_name(p, 0))
    cnt_mem = _core.safe_load(plt_path_cp, reg)
    key = str(reg)

    # this info is passed by some user controllable source
    if _core.is_tainted(reg, path=plt_path_cp) or _core.is_tainted(cnt_mem, path=plt_path_cp):
        to_store = _core.get_sym_val(name=_core.taint_buf, bits=env_var_size)
    # it was set before
    elif key in env_var:
        to_store = env_var[key]
    # fresh symbolic var
    else:
        to_store = _core.get_sym_val(name="env_var", bits=env_var_size)

    setattr(plt_path.active[0].regs, arg_reg_name(p, 0), claripy.BVV(env_var_size, _core.p.arch.bits))
    _malloc(_core, call_site_addr, plt_path)
    addr = getattr(plt_path.active[0].regs, arg_reg_name(p, 0))
    plt_path.active[0].memory.store(addr, to_store)


def env(_core, call_site_path, plt_path):
    """
    Summarize environment functions (getenv, and setenv)
    :param _core: core taint engin
    :param call_site_path: call site angr path
    :param plt_path: path to the plt (i.e., call_site.step())
    :return:
    """

    fname = _get_function_name(plt_path.active[0].addr, _core.p)
    if fname == 'setenv':
        _setenv(_core, call_site_path, plt_path)
    elif fname == 'getenv':
        _getenv(_core, call_site_path, plt_path)
    else:
        print "Implement this Env function: " + fname

    _restore_caller_regs(_core, call_site_path, plt_path)

JSON_var={}
def cJSON_GetObjectItem(_core, call_site_addr, plt_path):
    """
    cJSON_GetObjectItem function summary
    :param _core: core taint engine
    :param call_site_addr: call site angr path
    :param plt_path: path to the plt (i.e., call_site.step())
    :return: None
    """
    global JSON_var
    p = _core.p

    env_var_size = _core.taint_buf_size
    plt_path_cp = plt_path.copy(copy_states=True)
    plt_state_cp = plt_path_cp.active[0]

    reg = getattr(plt_state_cp.regs, arg_reg_name(p, 1))
    cnt_mem = _core.safe_load(plt_path_cp, reg)
    key = str(reg)

    # this info is passed by some user controllable source
    if _core.is_tainted(reg, path=plt_path_cp) or _core.is_tainted(cnt_mem, path=plt_path_cp):
        to_store = _core.get_sym_val(name=_core.taint_buf, bits=env_var_size)
    # it was set before
    elif key in JSON_var:
        to_store = JSON_var[key]
    # fresh symbolic var
    else:
        to_store = _core.get_sym_val(name="getJSON_var", bits=env_var_size)

    setattr(plt_path.active[0].regs, arg_reg_name(p, 0), claripy.BVV(env_var_size, _core.p.arch.bits))
    _malloc(_core, call_site_addr, plt_path)
    addr = getattr(plt_path.active[0].regs, arg_reg_name(p, 0))
    plt_path.active[0].memory.store(addr, to_store)
    _restore_caller_regs(_core, call_site_addr, plt_path)


#
# Nvram function
#
nvram_var = {}


def _safe_set_nvram(_core, _, plt_path):
    """
    set nvram function summary

    :param _core: core taint engine
    :param plt_path: path to the plt (i.e., call_site.step())
    :return: None
    """

    global nvram_var
    p = _core.p

    plt_path_cp = plt_path.copy(copy_states=True)
    plt_state_cp = plt_path_cp.active[0]

    key = getattr(plt_state_cp.regs, arg_reg_name(p, 0))
    nvram_var[str(key)] = getattr(plt_state_cp.regs, arg_reg_name(p, 1))


def _safe_get_nvram(_core, call_site_addr, plt_path):
    """
    nvram_safe_get function summary
    :param _core: core taint engine
    :param call_site_addr: call site angr path
    :param plt_path: path to the plt (i.e., call_site.step())
    :return: None
    """

    global nvram_var
    p = _core.p

    nvram_var_size = _core.taint_buf_size
    plt_path_cp = plt_path.copy(copy_states=True)
    plt_state_cp = plt_path_cp.active[0]

    reg = getattr(plt_state_cp.regs, arg_reg_name(p, 0))
    cnt_mem = _core.safe_load(plt_path_cp, reg)
    key = str(reg)

    # this info is passed by some user controllable source
    if _core.is_tainted(reg, path=plt_path_cp) or _core.is_tainted(cnt_mem, path=plt_path_cp):
        to_store = _core.get_sym_val(name=_core.taint_buf, bits=nvram_var_size)
    # it was set before
    elif key in nvram_var:
        to_store = nvram_var[key]
    # fresh symbolic var
    else:
        to_store = _core.get_sym_val(name="nvram_var", bits=nvram_var_size)

    if p.arch.name=="MIPS32":
	setattr(plt_path.active[0].regs, 'v0', claripy.BVV(nvram_var_size, _core.p.arch.bits))
  	_malloc(_core, call_site_addr, plt_path)
	addr = getattr(plt_path.active[0].regs, 'v0')
	plt_path.active[0].memory.store(addr, to_store)
    else:
        setattr(plt_path.active[0].regs, arg_reg_name(p, 0), claripy.BVV(nvram_var_size, _core.p.arch.bits))
        _malloc(_core, call_site_addr, plt_path)
        addr = getattr(plt_path.active[0].regs, arg_reg_name(p, 0))
        plt_path.active[0].memory.store(addr, to_store)


def nvram(_core, call_site_path, plt_path):
    """
    Summarize nvram functions (nvram_safe_get, and nvram_safe_set)
    :param _core: core taint engin
    :param call_site_path: call site angr path
    :param plt_path: path to the plt (i.e., call_site.step())
    :return:
    """

    fname = _get_function_name(plt_path.active[0].addr, _core.p)
    if fname == 'nvram_safe_set':
        _safe_set_nvram(_core, call_site_path, plt_path)
    elif fname == 'nvram_safe_get':
        _safe_get_nvram(_core, call_site_path, plt_path)
    else:
        print "Implement this Nvram function: " + fname

    _restore_caller_regs(_core, call_site_path, plt_path)


#
# Numerical
#


def atoi(_core, _, plt_path):
    p = _core.p
    plt_path_cp = plt_path.copy(copy_states=True)

    state = plt_path.active[0]
    val = getattr(state.regs, arg_reg_name(p, 0))
    if _core.is_or_points_to_tainted_data(val, plt_path_cp):
        addr = plt_path.active[0].memory.load(val)
        _core.do_recursive_untaint(addr, plt_path)
    plt_path.step().step()
