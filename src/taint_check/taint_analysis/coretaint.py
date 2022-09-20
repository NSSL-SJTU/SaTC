import claripy
import logging
import simuvex
import random
import signal
from random import shuffle
from utils import *
from summary_functions import _malloc,_restore_caller_regs
import pickle
import sys
import traceback

logging.basicConfig()
log = logging.getLogger("CoreTaint")
log.setLevel("DEBUG")

no_calltrace_overlap=True
def set_no_calltrace_overlap(f,addr=None):
    global no_calltrace_overlap
    #no_calltrace_overlap=f
    no_calltrace_overlap=True

GLOB_TAINT_DEP_KEY = 'taint_deps'
UNTAINT_DATA = 'untainted_data'
UNTAINTED_VARS = 'untainted_vars'
SEEN_MASTERS = 'seen_masters'


followTarget=[]
def setfollowTarget(lis):
    global followTarget
    followTarget=lis
def getfollowTarget():
    global followTarget
    return followTarget

class MyFileHandler(object):

    def __init__(self, filename, handler_factory, **kw):
        kw['filename'] = filename
        self._handler = handler_factory(**kw)

    def __getattr__(self, n):
        if hasattr(self._handler, n):
            return getattr(self._handler, n)
        raise AttributeError, n


class TimeOutException(Exception):
    def __init__(self, message):
        super(TimeOutException, self).__init__(message)


class CoreTaint:
    """
    Perform a symbolic-execution-based taint analysis on a given binary to find whether
    it exists a tainted path between a source and a sink.
    """

    def __init__(self, p, interfunction_level=0, log_path='/tmp/coretaint.out', exploration_strategy=None,
                 smart_call=True, follow_unsat=False, try_thumb=False, white_calls=[], black_calls=[],
                 not_follow_any_calls=False, default_log=True, exit_on_decode_error=True, concretization_strategy=None,
                 force_paths=False, reverse_sat=False, only_tracker=False, shuffle_sat=False,
                 taint_returns_unfollowed_calls=False, taint_arguments_unfollowed_calls=False, allow_untaint=True,
                 logger_obj=None):
        """
        Initialialization function

        :param p: angr project
        :param interfunction_level: interfunction level
        :param log_path:  path where the analysis' log is created
        :param smart_call: if True a call is followed only if at least one of its parameters is tainted
        :param follow_unsat: if true unsat successors are also considered during path exploration. In this case
                             the collected constraints up to that point will be dropped.
        :param try_thumb: try to force thumb mode if some decoding error occurred
        :param white_calls: calls to follow in any case
        :param default_log: log info by default
        :param exit_on_decode_error: terminate the analysis in case of error
        :param concretization_strategy: concretization strategy callback
        :param force_paths: force a path to be followed even when some decode errors were found
        :param allow_untaint: allow to untaint variables.
        """
        global log

        self._old_signal_handler = None
        self._old_timer = 0
        self._count_var = 0
        self._use_smart_concretization = False
        self._back_jumps = {}
        self._N = 1
        self._keep_run = True
        self._timeout_triggered = False
        self._timer = 0
        self._force_exit_after = -1
        self._p = p
        self._taint_buf = "taint_buf"
        self._taint_applied = False
        self._taint_buf_size = 4096
        self._bogus_return = 0x41414141
        self._fully_taint_guard = []
        self._white_calls = white_calls
        self._black_calls = black_calls
        self._taint_returns_unfollowed_calls = taint_returns_unfollowed_calls
        self._taint_arguments_unfollowed_calls = taint_arguments_unfollowed_calls
        self._allow_untaint = allow_untaint
        self._not_follow_any_calls = not_follow_any_calls
        self._reverse_sat = reverse_sat
        self._shuffle_sat = shuffle_sat
        self._exploration_strategy = self._base_exploration_strategy if \
            exploration_strategy is None else exploration_strategy
        self._only_tracker = only_tracker
        self._try_to_avoid_z3 = 3

        if exploration_strategy is not None and (shuffle_sat or reverse_sat):
            log.warning("Exploration strategy takes precedence over state shuffling/reversing")

        self._deref_taint_address = False
        self._deref_instruction = None
        self._deref_addr_expr = None
        self._deref = (None, None)
        self._old_deref = self._deref
        self._old_deref_taint_address = self._deref_taint_address
        self._old_deref_addr_expr = self._deref_addr_expr

        #self._interfunction_level = interfunction_level
        self._interfunction_level = 5
        self._smart_call = smart_call
        self._follow_unsat = follow_unsat

        self._concretizations = {}
        self._summarized_f = {}

        self._fp = open(log_path, 'w')
        self._interesing_path = {'sink': [], 'deref': [], 'loop': []}
        self._try_thumb = try_thumb
        self._force_paths = force_paths

        self._default_log = default_log

        self._exit_on_decode_error = exit_on_decode_error
        self._concretization_strategy = self._default_concretization_strategy if concretization_strategy is None \
            else concretization_strategy

        # stats
        self._new_path = True
        self._n_paths = 0

        if logger_obj:
            log = logger_obj

        if type(log) == logging.Logger:
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            fileh = MyFileHandler(log_path + '._log', logging.FileHandler)
            fileh.setFormatter(formatter)
            log.addHandler(fileh)

    def triggered_to(self):
        return self._timeout_triggered

    def handler(self, _, frame):
        """
        Timeout handler

        :param signum: signal number
        :param frame:  frame
        :return:
        """
        log.info("Timeout triggered, %s left...." % str(self._force_exit_after))

        self._keep_run = False
        self._timeout_triggered = True
        self._force_exit_after -= 1
        signal.alarm(self._timer)

        if self._force_exit_after <= 0 and not self._keep_run:
            # raising an exception while the execution is in z3 might crash the program
            if 'z3' in frame.f_code.co_filename:
                log.info("Hard Timeout triggered, but we are in z3, trying again in 30 seconds")
                signal.alarm(30)
            else:
                log.info("Hard Timeout triggered, %s left...." % str(self._force_exit_after))
                raise TimeOutException("Hard timeout triggered")

    def _get_bb(self, addr):
        """
        Get a basic block of an address

        :param addr: address
        :return:  the basic block
        """

        try:
            bl = self._p.factory.block(addr)
        except:
            bl = None

        if bl is None or bl.vex.jumpkind == 'Ijk_NoDecode':
            try:
                bl = self._p.factory.block(addr, thumb=True)
            except:
                bl = None

        return bl

    def _save_taint_flag(self):
        """
        Save the tainting related flags

        :return:
        """

        self._old_deref = self._deref
        self._old_deref_taint_address = self._deref_taint_address
        self._old_deref_addr_expr = self._deref_addr_expr

    def _restore_taint_flags(self):
        """
        Restiore the tainting related flags

        :return:
        """

        self._deref = self._old_deref
        self._deref_taint_address = self._old_deref_taint_address
        self._deref_addr_expr = self._old_deref_addr_expr

    @property
    def n_paths(self):
        return self._n_paths

    @property
    def bogus_return(self):
        return self._bogus_return

    @property
    def taint_buf(self):
        return self._taint_buf

    @property
    def taint_buf_size(self):
        return self._taint_buf_size

    @property
    def taint_applied(self):
        return self._taint_applied

    @property
    def p(self):
        return self._p

    def safe_load(self, path, addr, size=None, unconstrained=False):
        """
        Loads bytes from memory, saving and restoring taint info

        :param path: path
        :param addr:  address
        :return: the content in memory at address addr
        """

        self._save_taint_flag()
        if not size:
            size = self._p.arch.bits / 8
        state = path.active[0] if not unconstrained else path.unconstrained[0]
        mem_cnt = state.memory.load(addr, size)
        self._restore_taint_flags()
        return mem_cnt

    def safe_store(self, path, addr, thing):
        """
        Stores bytes in memory, saving and restoring taint info

        :param path: path
        :param addr: address
        :param thing: thing to store
        :return:
        """

        self._save_taint_flag()
        path.active[0].memory.store(addr, thing)
        self._restore_taint_flags()

    def get_sym_val(self, **args):
        return self._get_sym_val(**args)

    def _set_deref_bounds(self, ast_node):
        """
        Check an ast node and if  contains a dereferenced address, it sets
        its bounds

        :param ast_node: ast node
        :return: None
        """

        lb = self._deref[0]
        ub = self._deref[1]

        if hasattr(ast_node, 'op') and ast_node.op == 'Extract' \
                and self.is_tainted(ast_node.args[2]):
            m = min(ast_node.args[0], ast_node.args[1])
            lb = m if lb is None or m < lb else lb
            m = max(ast_node.args[0], ast_node.args[1])
            ub = m if ub is None or m > ub else ub
            self._deref = (lb, ub)
        elif hasattr(ast_node, 'args'):
            for a in ast_node.args:
                self._set_deref_bounds(a)
        elif self.is_tainted(ast_node):
            self._deref = (0, 0)

    def addr_concrete_after(self, state):
        """
        Hook for address concretization

        :param state: Program state
        """

        addr_expr = state.inspect.address_concretization_expr

        if self._use_smart_concretization:
            state.inspect.address_concretization_result = [self._get_target_concretization(addr_expr, state)]
        else:
            if state.inspect.address_concretization_result is None:
                # current angr strategy didn't give result, trying next one
                return None

        # a tainted buffer's location is used as address
        if self.is_tainted(addr_expr, state=state):
            self._set_deref_bounds(addr_expr)
            self._deref_taint_address = True
            self._deref_addr_expr = addr_expr
            self._deref_instruction = state.ip.args[0]

            if state.inspect.address_concretization_action == 'load':
                # new fresh var
                name = "cnt_pt_by(" + self._taint_buf + '[' + str(self._deref[0]) + ', ' + \
                       str(self._deref[1]) + ']' + ")"
                bits = state.inspect.mem_read_length * 8
                if type(bits) not in (long, int) and hasattr(bits, 'symbolic'):
                    bits = state.se.max_int(bits)
                for conc_addr in state.inspect.address_concretization_result:
                    state_cp = state.copy()
                    var = self._get_sym_val(name=name, bits=bits)
                    old_val = state_cp.memory.load(conc_addr)
                    state.memory.store(conc_addr, var)
                    if self._only_tracker:
                        try:
                            state_cp.se.eval_atleast(old_val, 2)
                        except:
                            val = state_cp.se.eval(old_val)
                            state.add_constraints(var == val)

    def _default_concretization_strategy(self, state, cnt):
        """
        Default concretization strategy

        :param state: angr state
        :param cnt: variable to concretize
        :return: concretization value for the variable
        """

        extra_constraints = state.inspect.address_concretization_extra_constraints
        if not extra_constraints:
            extra_constraints = tuple()
        concs = state.se.any_n_int(cnt, 50, extra_constraints=extra_constraints)
        return random.choice(concs)

    def _get_target_concretization(self, var, state):
        """
        Concretization must be done carefully in order to perform
        a precise taint analysis. We concretize according the following
        strategy:
        * every symbolic leaf of an ast node is concretized to unique value, according on its name.

        In this way we obtain the following advantages:
        a = get_pts();
        b = a

        c = a + 2
        d = b + 1 + 1

        d = get_pts()

        conc(a) = conc(b)
        conc(c) = conc(d)
        conc(d) != any other concretizations

        :param var: ast node
        :param state: current state
        :return: concretization value
        """

        def get_key_cnt(x):
            # angr by default create a unique id for every new symbolic variable.
            # as in karonte we often have to copy the state, step and check some
            # quantities before step() with the current state, two identical variables might assume
            # two different names. Therefore, we should not consider the unique _id_ added to symbolic variables
            # created by angr
            ret = str(x)
            if '_' in str(x) and not self.is_tainted(x):
                splits = str(x).split('_')
                idx = splits[-2]

                if not idx.isdigit():
                    log.error("get_key_cnt: Symbolic ID parsing failed, using the whole id: %s" % ret)
                    return ret

                ret = '_'.join(splits[:-2]) + '_'
                ret += '_'.join(splits[-1:])
            return ret

        # chek if uncontrained
        state_cp = state.copy()
        se = state_cp.se
        leafs = [l for l in var.recursive_leaf_asts]

        if not leafs:
            conc = self._concretization_strategy(state_cp, var)

            if not se.solution(var, conc):
                conc = se.any_int(var)
            key_cnt = get_key_cnt(var)
            self._concretizations[key_cnt] = conc
            return conc

        for cnt in leafs:
            key_cnt = get_key_cnt(cnt)
            # concretize all unconstrained children
            if cnt.symbolic:
                # first check whether the value is already constrained
                if key_cnt in self._concretizations.keys():
                    conc = self._concretizations[key_cnt]
                    if state_cp.se.solution(cnt, conc):
                        state_cp.add_constraints(cnt == conc)
                        continue

                conc = self._concretization_strategy(state_cp, cnt)
                self._concretizations[key_cnt] = conc
                state_cp.add_constraints(cnt == conc)

        val = state_cp.se.any_int(var)
        return val

    def is_tainted(self, var, path=None, state=None, unconstrained=False):
        """
        Checks if a variable is tainted

        :param var: variable
        :param path: angr path
        :param state: state
        :param unconstrained: check unconstrained states
        :return:
        """
        def is_untaint_constraint_present(v, un_vars):
            for u in un_vars:
                # get argument name
                if v.args[0] in u:
                    # variable is untainted
                    return True
            # no untaint found, var is tainted!
            return False

        # Nothing is tainted
        if self._taint_buf not in str(var):
            return False

        #
        # something is tainted
        #

        if not self._allow_untaint or (not path and not state):
            return True

        # get contraints
        if path:
            state = path.active[0] if not unconstrained else path.unconstrained[0]

        untaint_var_strs = state.globals[UNTAINT_DATA][UNTAINTED_VARS]
        if not untaint_var_strs:
            return True

        if str(var) not in untaint_var_strs:
            return True
        return False
        '''
        taint_leafs = list(set([l for l in var.recursive_leaf_asts if self._taint_buf in str(l)]))
        taints = set()

        for l in taint_leafs:
            if l in taints:
                continue
            # search an untaint constraint for this taint variable
            if not is_untaint_constraint_present(l, untaint_var_strs):
                return True
            taints.add(l)
        return False
        '''

    def add_taint_glob_dep(self, master, slave, path):
        """
        Add a taint dependency: if master gets untainted, slave should be untainted
        :param master: master expression
        :param slave: slave expression
        :param path: path
        :return:
        """

        if not self.is_tainted(master):
            return
        leafs = list(set([l for l in master.recursive_leaf_asts if self.is_tainted(l)]))
        key = tuple(map(str, leafs))
        if key not in self.get_state(path).globals[GLOB_TAINT_DEP_KEY]:
            self.get_state(path).globals[GLOB_TAINT_DEP_KEY][key] = []
        self.get_state(path).globals[GLOB_TAINT_DEP_KEY][key].append(slave)
        
    def _do_untaint_core(self, dst, path):
        """
        Given an variable to untaint, only untaint the exp itself, this is freq used 
        in memory string untaint op.
        
        :param dst: variable to untaint
        :param path: angr path
        :return:
        """
        if not self._allow_untaint:
            return

        state = self.get_state(path)

        # then we use the collected untainted variables
        state.globals[UNTAINT_DATA][UNTAINTED_VARS].append(str(dst))
        deps = dict(state.globals[GLOB_TAINT_DEP_KEY])
        i = 0
        while i < len(deps.keys()):
            master, salve = deps.items()[i]

            # if not already untainted, let's consider it
            if master not in state.globals[UNTAINT_DATA][SEEN_MASTERS]:
                untainted_vars = set(state.globals[UNTAINT_DATA][UNTAINTED_VARS])
                set_master = set(master)

                # we can not untaint it
                if set_master.intersection(untainted_vars) == set_master:
                    state.globals[UNTAINT_DATA][SEEN_MASTERS].append(master)
                    for entry in deps[master]:
                        self._do_unrecursive_untaint(entry, path)
                    # restart!
                    i = 0
                    continue

            i += 1
    def _do_recursive_untaint_core(self, dst, path):
        """
        Given an expression to untaint, we untaint every single tainted variable in it.
        E.g., given (taint_x + taint_y) to untaint, both variables gets untainted as
        they cannot assume no longer arbitrary values down this path.

        :param dst: expression to untaint
        :param path: angr path
        :return:
        """

        if not self._allow_untaint:
            return

        state = self.get_state(path)
        leafs = list(set([l for l in dst.recursive_leaf_asts if self.is_tainted(l)]))

        # then we use the collected untainted variables
        # and check whether we should untaint some other variables
        state.globals[UNTAINT_DATA][UNTAINTED_VARS] += map(str, leafs)
        deps = dict(state.globals[GLOB_TAINT_DEP_KEY])
        i = 0
        while i < len(deps.keys()):
            master, salve = deps.items()[i]

            # if not already untainted, let's consider it
            if master not in state.globals[UNTAINT_DATA][SEEN_MASTERS]:
                untainted_vars = set(state.globals[UNTAINT_DATA][UNTAINTED_VARS])
                set_master = set(master)

                # we can not untaint it
                if set_master.intersection(untainted_vars) == set_master:
                    state.globals[UNTAINT_DATA][SEEN_MASTERS].append(master)
                    for entry in deps[master]:
                        self._do_recursive_untaint_core(entry, path)
                    # restart!
                    i = 0
                    continue

            i += 1
    def do_untaint(self,dst,path):
        return self._do_untaint_core(dst,path)
    def do_recursive_untaint(self, dst, path):
        """
        Perform the untaint operation (see do_recursive_untaint_core)

        :param dst: variable to untaint
        :param path: angr path
        :return:
        """

        return self._do_recursive_untaint_core(dst, path)

    def apply_taint(self, current_path, addr, taint_id, bit_size=None):
        """
        Applies the taint to an address addr

        :param current_path: angr current path
        :param addr: address to taint
        :param taint_id: taint identification
        :param bit_size: number of bites
        :return: tainted variable
        """
        self._save_taint_flag()
        bit_size = bit_size if bit_size else self._taint_buf_size
        t = self._get_sym_val(name=self._taint_buf + '_' + taint_id + '_', bits=bit_size).reversed
        self.get_state(current_path).memory.store(addr, t)
        self._restore_taint_flags()
        self._taint_applied = True
        return t

    def _get_sym_val(self, name='x_', bits=None, inc=True, explicit=False):
        """
        Creates a fresh symbolic variable

        :param name: variable name
        :param bits: number of bits
        :param inc: increment the global counter
        :param explicit: name should be exactly as reported (True, False)
        :return: a symbolic variable
        """

        if bits is None:
            bits = self._p.arch.bits

        if explicit:
            var = claripy.BVS(name=name, size=bits, explicit_name=True)
        else:
            var = claripy.BVS(name=(name + '_' + str(self._count_var) + '_' + str(self._p.arch.bits)), size=bits,
                              explicit_name=True)
            if inc:
                self._count_var += 1
        return var

    def get_addr(self, path):
        """
        Gets the path current address

        :param path: angr path
        :return: path current address
        """
        return path.active[0].ip.args[0]

    def get_state(self, path):
        """
        Gets the state from a path

        :param path: path
        :return: angr state
        """

        return path.active[0]

    def is_or_points_to_tainted_data(self, x, path, unconstrained=False):
        """
        Checks if a symbolic variable is or points to tainted data
        :param x: variable
        :param path: angr current path
        :param unconstrained: consider unconstrained data
        :return:
        """
        return self.is_tainted(x, path=path, unconstrained=unconstrained) or \
               self.is_tainted(self.safe_load(path, x, unconstrained=unconstrained), path=path,
                               unconstrained=unconstrained)

    def _set_fake_ret_succ(self, path, state, addr, ret, *_):
        """
        Create a fake ret successors of a given path.

        :param path: current path
        :param: state: state to set in the new succ
        :param addr: address where the fake ret block will return
        :param ret: return of the current function
        :return: angr path
        """

        new_s = state.copy()
        new_s.history.jumpkind = "Ijk_FakeRet"

        # check whether any of the function parameters are tainted
        nargs = get_arity(self._p, self.get_addr(path))
        next_cp = path.copy(copy_states=True).step()

        to_taint = False
        bl = self._p.factory.block(self.get_addr(path))
        if not len(next_cp.active) and len(next_cp.unconstrained) and bl.vex.jumpkind == 'Ijk_Call':
            cap = bl.capstone.insns[-1]
            reg_jump = cap.insn.op_str
            try:
                # this can throw exceptions, wtf!
                val = getattr(next_cp.unconstrained[0].regs, reg_jump)
                # If the register used for jumping is tainted, we check the function arguments
                if self.is_or_points_to_tainted_data(val, next_cp, unconstrained=True):
                    to_taint = True
            except:
                pass

        for i in xrange(nargs):
            name = self._p.arch.register_names[ordered_argument_regs[self._p.arch.name][i]]
            try:
                val_arg = getattr(self.get_state(next_cp).regs, name)
            except:
                break
            if self.is_or_points_to_tainted_data(val_arg, next_cp):
                to_taint = True
                break

        # return value
        name = 'reg_ret_'
        if self._taint_returns_unfollowed_calls and to_taint:
            name = self._taint_buf + '_' + name

        ret_reg = return_regs[self._p.arch.name]
        link_reg = link_regs[self._p.arch.name]

        new_s.regs.pc = addr
        setattr(new_s.regs, self._p.arch.register_names[link_reg], ret)
        setattr(new_s.regs, self._p.arch.register_names[ret_reg], self._get_sym_val(name=name))

        # function arguments
        if to_taint and self._taint_arguments_unfollowed_calls:
            for i in xrange(nargs):
                name_reg = self._p.arch.register_names[ordered_argument_regs[self._p.arch.name][i]]
                taint_name = self._taint_buf + '_' + name_reg
                setattr(new_s.regs, name_reg, self._get_sym_val(name=taint_name))

        return path.copy(
            stashes={'active': [new_s], 'unsat': [], 'pruned': [], 'unconstrained': [], 'deadended': []})

    def _is_summarized(self, prev_path, suc_path, *_):
        """
        Check if function is summarized, and execute it if so.

        :param prev_path: previous path
        :param suc_path: successor path
        :return:
        """

        # first check if function is summarized
        addr = self.get_addr(suc_path)

        if self._summarized_f:
            for s_addr in self._summarized_f.keys():
                if addr == s_addr:
                    try:
                        self._summarized_f[s_addr](self, prev_path, suc_path)
                        #print "0x%x is summartized"%self.get_addr(prev_path), self._summarized_f[s_addr]
                        return True
                    except Exception as e:
                        traceback.print_exc()
                        print (e)
        #print("return False")
        return False

    def _follow_call(self, prev_path, suc_path, current_depth):
        """
        Checks if a call should be followed or not: if any of its parameters is tainted
        and the current depth of transitive closure allows it yes, otherwise no.

        :param prev_path: previous path
        :param suc_path: successive path
        :param current_depth: current depth of transitive closure
        :return: True if call should be followed, false otherwise
        """
        debug=False
        if self._not_follow_any_calls:
            if debug:
                print ("ret fal 1")
            return False

        # first check if function is summarized
        addr = self.get_addr(suc_path)

        if addr in self._black_calls:
            if debug:
                print ("ret fal 2")
            return False

        # check if call falls within bound binary
        if addr > self._p.loader.max_addr or addr < self._p.loader.min_addr:
            if debug:
                print ("ret fal 3")
            return False

        # if the function is summarized by angr, we follow it
        if self._p._should_use_sim_procedures:
            # consider also next addr in case th current one is a trampoline (eg., plt)
            trp = suc_path.copy(copy_states=True)
            trp.step()
            trp_addr = self.get_addr(trp)
            if self._p.is_hooked(addr) or self._p.is_hooked(trp_addr):
                if debug:
                    print ("ret tru 1")
                return True

        if addr in self._white_calls:
            if debug:
                print ("ret tru 2")
            return True

        if current_depth <= 0:
            if debug:
                print( "ret fal 4")
            return False

        if not self._smart_call:
            if debug:
                print( "ret tru 3")
            return True

        if not self._taint_applied: 
            if debug:
                print ("ret fal 5")
            return False

        bl = self._get_bb(self.get_addr(prev_path))
        puts = [s for s in bl.vex.statements if s.tag == 'Ist_Put']

        expected = 0
        index = 0
        set_regs = []

        # type of regs we are looking for
        reg_ty = 'r' if self._p.arch.bits == 32 else 'x'

        while True:
            if index >= len(puts):
                break

            p = puts[index]
            #print self._p.arch.register_names[p.offset]
            if self._p.arch.register_names[p.offset] == reg_ty + str(expected):
                set_regs.append(reg_ty + str(expected))
                expected += 1
                index = 0
                continue

            index += 1

        self._save_taint_flag()

        for r in set_regs:
            reg_cnt = getattr(self.get_state(suc_path).regs, r)
            # check if it is pointing to a tainted location
            tmp_s = self.get_state(suc_path).copy()
            try:
                mem_cnt = tmp_s.memory.load(reg_cnt, 50)  # FIXME set this N to a meaningful value
            except TimeOutException as t:
                raise t
            except Exception as e:
                # state is unconstrained
                log.warning("Tried to defererence a non pointer!")
                continue

            # we might have dereferenced wrongly a tainted variable during the tests before
            #print "reg_cnt",reg_cnt
            #print "set_regs",set_regs
            #print "mem_cnt",mem_cnt
            if (self.is_tainted(reg_cnt) or self.is_tainted(mem_cnt)) and current_depth > 0:
                self._restore_taint_flags()
                if debug:
                    print ("ret tru 4")
                return True

        self._restore_taint_flags()
        if debug:
            print( "ret fal 6")
        return False

    def _follow_back_jump(self, current_path, next_path, guards_info):
        """
        Check if a back jump (probably a loop) should be followed.

        :param current_path:  current path
        :param next_path: next path
        :param guards_info:  guards information
        :return:  True if should back jump, False otherwise
        """

        key = hash(''.join(sorted(list(set([x[0] for x in guards_info])))))
        bj = (key, self.get_addr(next_path), self.get_addr(current_path))
        if bj not in self._back_jumps.keys():
            self._back_jumps[bj] = 1
        elif self._back_jumps[bj] > self._N:
            # we do not want to follow the same back jump infinite times
            return False
        else:
            self._back_jumps[bj] += 1
        return True

    def _check_sat_state(self, current_path, current_guards):
        """
        Check whether the state is SAT

        :param current_path: angr current path
        :param current_guards: current ITE guards
        :return: True is the state is SAT, False otherwise
        """

        # just try to concretize any variable
        cp_state = current_path.active[0].copy()
        try:
            reg_name = self._p.arch.register_names[return_regs[self._p.arch.name]]
            reg = getattr(cp_state.regs, reg_name)
            cp_state.se.any_int(reg)
            self.last_sat = (current_path.copy(copy_states=True), current_guards)
        except TimeOutException as t:
            raise t
        except Exception as e:
            print (str(e))
            return False
        return True

    def _vex_messed_up(self, current_path, next_path):
        """
        Checks whether the lifter messed up

        :param current_path: angr current path
        :param next_path: next path
        :return: True if an error is detected, False otherwise
        """

        current_path_addr = current_path.active[0].ip.args[0]
        next_path_addr = next_path.active[0].ip.args[0]

        bl = self._get_bb(current_path_addr)
        puts = [p for p in bl.vex.statements if p.tag == 'Ist_Put']

        lr = self._p.arch.register_names[link_regs[self._p.arch.name]]

        for p in puts:
            if self._p.arch.register_names[p.offset] == lr:
                break
        else:
            return False

        if next_path_addr == self._next_inst(bl):
            log.warning(" VEX fucked up big time!")
            return True
        return False

    def _drop_constraints(self, path):
        """
        Drop all the constraints within the symbolic engine
        
        :param path: angr current path 
        :return:  None
        """
        
        self.get_state(path).release_plugin('solver_engine')
        self.get_state(path).downsize()

    # FIXME: change offset according arch.
    def _next_inst(self, bl):
        """
        Get next instruction (sometimes angr messes up)
        
        :param bl: basic block 
        :return: 
        """
        
        return bl.instruction_addrs[-1] + 4

    def _base_exploration_strategy(self, _, next_states):
        """
        Base exploration strategy
        
        :param current_path: angr current path 
        :param next_states: next states
        :return: 
        """
        
        if self._reverse_sat:
            next_states.reverse()
        elif self._shuffle_sat:
            shuffle(next_states)
        return next_states

    def _flat_explore(self, current_path, check_path_fun, guards_info, current_depth, **kwargs):
        
        """
        Performs the symbolic-based exploration 
        
        :param current_path: current path
        :param check_path_fun: function to call for every block in the path
        :param guards_info: current info about the guards in the current path
        :param kwargs: additional arguments to pass to check_path_fun
        :return: the tainted path between the source and the sink, if any
        """

        global followTarget
        '''
        print "********* _flat_explore",hex(self.get_addr(current_path))
        print current_path.active[0].regs.a0, self.safe_load(current_path,current_path.active[0].regs.a0)
        print current_path.active[0].regs.a1, self.safe_load(current_path,current_path.active[0].regs.a1)
        print current_path.active[0].regs.a2, self.safe_load(current_path,current_path.active[0].regs.a2)
        '''
        if not self._keep_run:
            log.debug("Backtracking due to stop")
            return
        current_path_addr = self.get_addr(current_path)
        try:
            log.debug("%s: Analyzing block %s", self._p.filename.split('/')[-1], hex(current_path_addr))
        except:
            return

        if not self._check_sat_state(current_path, guards_info) and not self._timeout_triggered:
            log.error("State got messed up!")
            raise Exception("State became UNSAT")

        # check whether we reached a sink
        try:
            check_path_fun(current_path, guards_info, current_depth, **kwargs)
        except Exception as e:
            if not self._keep_run:
                return
            log.error("'Function check path errored out: %s" % str(e))

        try:
            succ_path = current_path.copy(copy_states=True).step()
        except Exception as e:
            log.error("ERROR: %s" % str(e))
            return

        # try thumb
        if succ_path and succ_path.errored and self._try_thumb and not self._force_paths:
            succ_path = current_path.copy(copy_states=True).step(thumb=True)

        if succ_path and succ_path.errored and self._try_thumb and not self._force_paths:
            if self._exit_on_decode_error:
                self._keep_run = False
            return
        succ_states_unsat = succ_path.unsat if self._follow_unsat else []
        succ_states_sat = succ_path.active

        if succ_path.deadended and not succ_states_sat and not succ_states_unsat:
            log.debug("Backtracking from dead path")
            return
        
        if not succ_states_sat:
            # check if it was un unconstrained call.
            # sometimes angr fucks it up
            bl = self._get_bb(current_path_addr)
            if not bl:
                return
            if bl.vex.jumpkind == 'Ijk_Call':
                # create a fake successors
                # which should have been created
                # before.
                # FIXME: I should use get_below_block
                # but as of now I don;t want to use CFG
                if not succ_path.unconstrained:
                    return
                unc_state = succ_path.unconstrained[0]
                ret_addr = self._next_inst(bl)
                link_reg = self._p.arch.register_names[link_regs[self._p.arch.name]]
                ret_func = getattr(self.get_state(current_path).regs, link_reg)
                tmp_path = self._set_fake_ret_succ(current_path, unc_state, ret_addr, ret_func)
                succ_states_sat = [self.get_state(tmp_path)]

        # register sat and unsat information so that later we can drop the constraints
        for s in succ_states_sat:
            s.sat = True
        for s in succ_states_unsat:
            s.sat = False

        # collect and prepare the successors to be analyzed
        succ_states_sat = self._exploration_strategy(current_path, succ_states_sat)
        succ_states = succ_states_sat + succ_states_unsat
        #print "succ_states",succ_states
        for next_state in succ_states:
            if self._new_path:
                self._n_paths += 1
                self._new_path = False

            if hasattr(next_state.ip, 'symbolic') and next_state.ip.symbolic:
                if next_state.sat:
                    log.error("Next state UNSAT")
                log.warning("Got a symbolic IP, perhaps a non-handled switch statement? FIX ME... ")
                continue

            next_path = succ_path.copy(stashes={'active': [next_state.copy()], 'unsat': [], 'pruned': [],
                                                'unconstrained': [], 'deadended': []})
            if not next_state.sat:
                # unsat successors, drop the constraints
                self._drop_constraints(next_path)

            next_depth = current_depth
            #print "cpegg111",current_depth
            # First, let's see if we can follow the calls
            try:
                if (self.get_state(next_path).history.jumpkind == 'Ijk_Call' and not self._vex_messed_up(current_path, next_path)):
                    #print "cpegg222"
                    if not self._is_summarized(current_path, next_path, current_depth):
                        #print "cpegg333"
                        if not self._follow_call(current_path, next_path, current_depth):
                            #print "cpegg444"
                            # if there is not fake ret we create one
                            if not any(s.history.jumpkind == "Ijk_FakeRet" for s in succ_states):
                                #print "cpegg555"
                                state = self.get_state(next_path)
                                link_reg = self._p.arch.register_names[link_regs[self._p.arch.name]]
                                ret_addr = getattr(state.regs, link_reg)
                                ret_func = getattr(self.get_state(current_path).regs, link_reg)
                                next_path = self._set_fake_ret_succ(current_path, state, ret_addr, ret_func)
                            else:
                                #print "cpegg666"
                                # the fake ret is already present, therefore we just skip
                                # the call
                                continue
                        else:
                            #print "cpegg777"
                            #print "followTarget",followTarget
                            if self.get_addr(next_path) not in self._p.loader.main_object.plt.values() and getBugFindingFlag() and self.get_addr(current_path) not in followTarget:
                                nargs = get_arity(self._p, self.get_addr(current_path))
                                print ("***** Not in functrace addr 0x%x"%self.get_addr(current_path))
                                #print "cpegg888",nargs
                                for i in xrange(nargs):
                                    name = self._p.arch.register_names[ordered_argument_regs[self._p.arch.name][i]]
                                    try:
                                        val_arg = getattr(self.get_state(next_path).regs, name)
                                        #print "cpegg999",name,val_arg
                                    except:
                                        break

                                    if self.is_or_points_to_tainted_data(val_arg, next_path):
                                        try:
                                            print ("some args are tainted", val_arg)
                                            callNextAddr=getattr(next_path.active[0].regs,self._p.arch.register_names[link_regs[self._p.arch.name]]).args[0]
                                            callNextIns=self._p.factory.block(callNextAddr).capstone.insns[0]
                                            to_store = self.get_sym_val(name=self.taint_buf, bits=self.taint_buf_size)
                                            if (callNextIns.insn.insn_name()=='str' and callNextIns.insn.op_str.startswith('r0')) or (callNextIns.insn.insn_name()=='mov' and callNextIns.insn.op_str.endswith('r0')) or (callNextIns.insn.insn_name()=='sub' and callNextIns.insn.op_str.endswith('r0, #0')): # the function return something, only taint the return value
                                                print( "return something, only taint r0")
                                                setattr(next_path.active[0].regs, arg_reg_name(self.p, 0), claripy.BVV(self.taint_buf_size, self.p.arch.bits))
                                                _malloc(self, self.get_addr(current_path), next_path)
                                                addr = getattr(next_path.active[0].regs, arg_reg_name(self.p, 0))
                                                next_path.active[0].memory.store(addr, to_store)
                                                #print "addr",addr
                                            else: # else taint all the args
                                                print ("return nothing, taint all writable args(%d)"%nargs)
                                                for j in xrange(0,nargs):
                                                    addr = getattr(next_path.active[0].regs, arg_reg_name(self.p, j))
                                                    cfg = getBugFindingCFG()
                                                    assert( cfg!=None)
                                                    print( addr,addr.symbolic)
                                                    if not addr.symbolic:
                                                        seg = cfg._addr_belongs_to_segment(addr.args[0])
                                                        #seg = self._p.loader.find_segment_containing(addr)
                                                        if seg and not seg.is_writable:
                                                            pass
                                                        else:
                                                            next_path.active[0].memory.store(addr, to_store)
                                                    else:
                                                        next_path.active[0].memory.store(addr, to_store)
                                                    #next_path.active[0].memory.store(addr, to_store)
                                            _restore_caller_regs(self,current_path,next_path)
                                            break
                                        except Exception as e:
                                            print("ERROR: %s"%str(e))
                            else:
                                #print("Following function call to %s" % hex(self.get_addr(next_path)))

                                # since memset may include memory crash, we check if the size of memset is too large
                                if self.get_addr(next_path)==self._p.loader.main_object.plt['memset']:
                                    name = self._p.arch.register_names[ordered_argument_regs[self._p.arch.name][2]]
                                    val_arg = getattr(self.get_state(next_path).regs, name)
                                    if val_arg.args[0]>0x1000:
                                        print ("memset size larger than 0x1000(0x%x), stop analysis"%val_arg.args[0])
                                        self._keep_run=False
                                else:
                                    next_depth = current_depth - 1
                    else:
                        pass
                        #next_depth = current_depth - 1
                        #print next_path.active
            except Exception as e:
                log.error("ERROR: %s" % str(e))
                return
                
            try:
                if self.get_state(next_path).history.jumpkind == 'Ijk_Ret':
                    next_depth = next_depth + 1
            except:
                continue

            # we have a back jump
            if self.get_state(next_path).history.jumpkind == 'Ijk_Boring' and \
               self.get_addr(next_path) <= self.get_addr(current_path) and \
               not self._follow_back_jump(current_path, next_path, guards_info):
                log.debug("breaking loop")
                self._new_path = True
                continue

            # the successor leads out of the function, we do not want to follow it
            if self.get_addr(next_path) == self._bogus_return:
                log.debug("hit a return")
                self._new_path = True
                continue

            # save the info about the guards of this path
            new_guards_info = list(guards_info)
            current_guards = [g for g in self.get_state(next_path).guards]
            if current_guards and len(new_guards_info) < len(current_guards):
                new_guards_info.append([hex(self.get_addr(current_path)), current_guards[-1]])

            # next step!
            self._flat_explore(next_path, check_path_fun, new_guards_info, next_depth, **kwargs)
            log.info ("Back to block %s", hex(self.get_addr(current_path)))
            self._new_path = True

        log.debug("Backtracking")

    def set_project(self, p):
        """
        Set the project
        
        :param p: angr project
        :return:
        """
        
        self._p = p

    def stop_run(self):
        """
        Stop the taint analysis
        
        :return: None
        """
        
        self._keep_run = False

    def flat_explore(self, state, check_path_fun, guards_info, force_thumb=False, **kwargs):
        """
        Run a symbolic-based exploration
        
        :param state: state 
        :param check_path_fun: function to call for each visited basic block 
        :param guards_info: guards ITE info
        :param force_thumb: start with thumb mode ON
        :param kwargs: kwargs
        :return: None 
        """
        global no_calltrace_overlap
        self._keep_run = True
        if no_calltrace_overlap:
            initial_path = self._p.factory.path(state)
            initial_path = self._p.factory.simgr(initial_path, save_unconstrained=True, save_unsat=True)
        current_depth = self._interfunction_level

        if force_thumb:
            # set thumb mode
            initial_path = initial_path.step(thumb=True)[0]
        self._flat_explore(initial_path, check_path_fun, guards_info, current_depth, **kwargs)

    def start_logging(self):
        """
        Start logging
        
        :return: None 
        """
        
        if not self._default_log:
            return

        self._fp.write("Log Start \n"
                       "Binary: " +
                       self._p.filename + '\n'
                       "=================================\n\n")

    def log(self, msg):
        """
        Log a message
        
        :param msg: message 
        :return: 
        """
        
        self._fp.write(msg)

    def stop_logging(self):
        """
        Stop the logging
        
        :return: None 
        """
        
        if self._default_log:
            log.info("Done.")
            log.info("Results in " + self._fp.name)
        self._fp.close()

    def _init_bss(self, state):
        """
        Initialize the bss section with symboli data (might be slow!).
        :param state: angr state
        :return: 
        """
        
        bss = [s for s in self._p.loader.main_bin.sections if s.name == '.bss']
        if not bss:
            return

        bss = bss[0]
        min_addr = bss.min_addr
        max_addr = bss.max_addr

        for a in range(min_addr, max_addr + 1):
            var = self._get_sym_val(name="bss_", bits=8)
            state.memory.store(a, var)

    def set_alarm(self, timer, n_tries=0):
        """
        Set the alarm to interrupt the analysis
        
        :param timer: timer
        :param n_tries: number of tries to stop the analysis gracefully
        :return: Non
        """
        
        if self._old_signal_handler is None:
            handler = signal.getsignal(signal.SIGALRM)
            assert handler != signal.SIG_IGN, "The coretaint alarm handler should never be SIG_IGN"
            self._old_signal_handler = handler

        # TODO save the time left by the previous analaysis
        # and restore it
        signal.signal(signal.SIGALRM, self.handler)
        self._old_timer = signal.alarm(timer)

        self._force_exit_after = n_tries
        self._timer = timer

    def unset_alarm(self):
        signal.alarm(0)

    def restore_signal_handler(self):
        """
        Restore the signal handler
        
        :return: None
        """
        
        if self._old_signal_handler is not None:
            signal.signal(signal.SIGALRM, self._old_signal_handler)
        if self._old_timer != 0:
            # someone else was looking at this time
            # let's restore it
            signal.alarm(self._old_timer)

    def run(self, state, sinks_info, sources_info, summarized_f=None, init_bss=True,
            check_func=None, force_thumb=False, use_smart_concretization=True):

        """
        Run the static taint engine
        
        :param state: initial state
        :param sinks_info: sinks info
        :param sources_info: sources info
        :param summarized_f: function summaries
        :param init_bss: initializ bss flag
        :param check_func: function to execute for each explored basic block
        :param force_thumb: start analysis in thumb mode
        :param use_smart_concretization: use smart concretization attempts to decrease imprecision due to spurious 
                                         pointer aliasing.
        :return: None
        """

        def null_fun(*_, **__):
            return None

        if summarized_f is None:
            summarized_f = {}

        self._use_smart_concretization = use_smart_concretization
        state.inspect.b(
            'address_concretization',
            simuvex.BP_AFTER,
            action=self.addr_concrete_after
        )

        state.globals[GLOB_TAINT_DEP_KEY] = {}
        state.globals[UNTAINT_DATA] = {UNTAINTED_VARS: [], SEEN_MASTERS: []}

        self._count_var = 0
        self._n_paths = 0
        self._new_path = True
        self._back_jumps = {}
        self._keep_run = True
        self._taint_applied = False
        self._fully_taint_guard = []
        self._deref_taint_address = False
        self._deref_addr_expr = None
        self._deref = (None, None)
        self._old_deref = self._deref
        self._old_deref_taint_address = self._deref_taint_address
        self._old_deref_addr_expr = self._deref_addr_expr
        self._concretizations = {}
        self._summarized_f = summarized_f
        self._timeout_triggered = False

        check_func = null_fun if check_func is None else check_func
        if init_bss:
            log.info("init .bss")
            self._init_bss(state)
        try:
            self.flat_explore(state,  check_func, [], force_thumb=force_thumb, sinks_info=sinks_info,
                              sources_info=sources_info)
        except TimeOutException:
            log.warning("Hard timeout triggered")

        if self._timeout_triggered:
            self.log("\nTimed out...\n")
            log.debug("Timeout triggered")
