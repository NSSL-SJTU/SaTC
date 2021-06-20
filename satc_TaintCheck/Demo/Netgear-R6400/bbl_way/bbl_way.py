import angr
import random
import claripy
import pickle
from treelib import Tree, Node

class cfgNode(object): #cfg node, bbl
    def __init__(self, bbl_node):
        self.bbl_node = bbl_node # addr of bbl first ins

'''
def DFS(start_node,end_node,path_addr,bb):
    if not start_node.block:
        return path_addr
    print(start_node)
    #print(path_addr)
    for addr in path_addr:
        print("0x%x" % addr)
    path_addr.append(start_node.block.addr)
    succ=start_node.successors
    c
    if succ==[]:
        succ=start_node.successors[0].successors
        for i in succ:
            if not i.block:
                continue
            if i==end_node or i.block.addr in path_addr:
                return path_addr
            if 'cmp' in '\n'.join(j.__str__() for j in i.block.capstone.insns):
                return DFS(i,end_node,path_addr,bb)
            continue
    return DFS(succ[0],end_node,path_addr,bb)
'''

'''
def DFS_new(start_node, end_node, path_addr, bb):
    if not start_node.block:
        return path_addr
    print(start_node, path_addr)
    succ = start_node.successors
    print(succ)
    if succ==[]:
        return path_addr
    for i in succ:
        if not i.block:
            continue
        if i == end_node:
            print("achieve end node")
            return path_addr
        if i.block.addr in path_addr:
            print("achieve loop node")
            for addr in path_addr[-1]:
                succ_back = addr.successors

            return path_addr
        if 'cmp' in '\n'.join(j.__str__() for j in i.block.capstone.insns):
            print("find cmp")
            print(i)
            path_addr[-1].append(i.block.addr)
            return DFS_new(i, end_node, path_addr, bb)
        if i == succ[-1]:
            print("not find cmp in any successors")
            for ii in succ:
                return DFS_new(ii, end_node, path_addr, bb)
'''
def get_intersting_trace(node_tree):
    paths = node_tree.paths_to_leaves()
    for trace in paths:
        for Node in trace:
            print(Node)

def enu_path_new(start_node, end_node, cfg_tree, bb):
    if not start_node.block:
        print("error node")
        return cfg_tree
    print("node: ")
    print(start_node)

    succ = start_node.successors

    if succ == []:
        print("no successors")
        return cfg_tree

    for node in succ:
        if node in cfg_tree:
            print("achieve loop node")
        elif node.block in bb:
            NodeData = cfgNode(node)
            cfg_tree.create_node(node, node, parent=start_node, data=NodeData)
            print("add node: ")
            print(node)
            bb.remove(node.block)
            print("now bbl:")
            print(bb)
            if node == end_node:
                print("achieve end node")
                if bb == []:
                    print("enu all bbl")
                    return cfg_tree
#                else:
#                    return enu_path(start_node, end_node, cfg_tree, bb)
            else:
                return enu_path_new(node, end_node, cfg_tree, bb)

    if bb == []:
        print("no bbl")
        return cfg_tree

def BFS_path(start_node, end_node, cfg_tree, basic_blocks):
    succ = start_node.successors
    if start_node == end_node:
        return cfg_tree, basic_blocks
    for node in succ:
        print("add node: ")
        print(node)
        print("parent node")
        if node.block in basic_blocks:
            NodeData = cfgNode(node)
            cfg_tree.create_node(node, node, parent=start_node, data=NodeData)
    return cfg_tree, basic_blocks

def DFS_path(start_node, end_node, cfg_tree, basic_blocks):
    print("node:")
    print(start_node)
    if start_node == end_node:
        print("achieve end node")
        if basic_blocks == []:
            print("enu all bbl")
            return cfg_tree, basic_blocks
    succ = start_node.successors
    if succ == []:
        print("no successors")
        return cfg_tree, basic_blocks
    for node in succ:
        if not node.block:
            continue
        #if node in cfg_tree:
            #print("achieve loop node: ")
            #print(node)
            #continue
        if node.block in basic_blocks:
            NodeData = cfgNode(node)
            cfg_tree.create_node(node, node, parent=start_node, data=NodeData)
            print("add node: ")
            print(node)
            print("parent node: ")
            print(start_node)
            print("Tree now: ")
            print(cfg_tree)
            basic_blocks.remove(node.block)
            print("bbl now:")
            print(basic_blocks)
            return DFS_path(node, end_node, cfg_tree, basic_blocks)
    return cfg_tree, basic_blocks

def check_succ(succ, basic_blocks):
    out_bbl = []
    for node in succ:
        if node.block not in basic_blocks:
            out_bbl.append(node)
            #print("need remove node:")
            #print(node)
            #print("basic_blocks")
            #print(basic_blocks)
    for node in out_bbl:
        if node in succ:
            succ.remove(node)
            #print("after succ:")
            #print(succ)
    return succ

def check_block(exec_blocks, basic_blocks):
    for bbl in basic_blocks:
        if bbl in exec_blocks:
            continue
        else:
            return False
    return True

def enu_path(start_node, end_node, cfg_tree, exec_blocks, basic_blocks):
    #print("node:")
    #print(start_node)
    if start_node == end_node:
        #print("achieve end node")
        #print("one path")
        return cfg_tree, exec_blocks
    succ = start_node.successors
    succ = check_succ(succ, basic_blocks)
    if succ == []:
        #print("no successors or out of function")
        #print("one path")
        return cfg_tree, exec_blocks
    nums = len(succ)
    for num in range(nums):
        nodelist = random.sample(succ, 1)
        #print("get a random node: ")
        node = nodelist.pop()
        #print(dir(node))
        if node.block.addr == 0x7b8e8:
            if succ.remove(node):
                tmp_node = succ.remove(node).pop()
                node = tmp_node
            else:
                continue
        if not node.block:
            print("not bbl")
            continue
        #if node in cfg_tree:
            #print("achieve loop node: ")
            #print(node)
            #continue
        if node not in cfg_tree:
            NodeData = cfgNode(node)
            cfg_tree.create_node(node, node, parent=start_node, data=NodeData)
            #print("add node: ")
            #print(node.block)
            #print("parent node: ")
            #print(start_node)
            if node.block not in exec_blocks:
                exec_blocks.append(node.block)
            #print("bbl now:")
            #print(exec_blocks)
            return enu_path(node, end_node, cfg_tree, exec_blocks, basic_blocks)
        else:
            #print("get a loop")
            #print("one path")
            return cfg_tree, exec_blocks
    return cfg_tree, exec_blocks

def get_max_cst(treelist):
    max_cst = []
    for list in treelist:
        if len(list) > len(max_cst):
            max_cst = list
    return max_cst

def main():
#    path_to_binary="./sub_7B83C"
    path_to_binary="../httpd"
    pickle_file="/tmp/bbl_way.pk"

    proj=angr.Project(path_to_binary, auto_load_libs=False)
    #start_addr=0x400596
    start_addr=0x7b83c
    avoid_addr=[]
    end_addr=0x7b90c
    #end_addr=0x400820
    '''
    try:
        with open(pickle_file,"rb") as f:
            cfg=pickle.load(pickle_file)
    except:
        cfg = proj.analyses.CFG()
        with open(pickle_file,"wb") as f:
            pickle.dump(cfg,f)
    '''
    cfg = proj.analyses.CFG()
    start_node = cfg.get_any_node(start_addr)
    end_node = cfg.get_any_node(end_addr)
#    print('\n'.join(j.__str__() for j in start_node.block.capstone.insns))

#    basic_blocks_set = cfg.kb.functions[start_addr].block_addrs_set

    basic_blocks = [i for i in cfg.kb.functions[start_addr].blocks]
    print(cfg.kb.functions[start_addr])
    print(basic_blocks)
    print("enu path from")
    print(start_node)
    print("to")
    print(end_node)
    basic_blocks.remove(start_node.block)

    #cfg_tree, basic_blocks = DFS_path(start_node, end_node, cfg_tree, basic_blocks)
    #cfg_tree, basic_blocks = BFS_path(start_node, end_node, cfg_tree, basic_blocks)
    exec_blocks = []
    time = 0
    pathlist= []
    cfg_tree = Tree()
    NodeData = cfgNode(start_node)
    while not check_block(exec_blocks, basic_blocks):
        cfg_tree.create_node(start_node, start_node, data=NodeData)
        cfg_tree, exec_blocks = enu_path(start_node, end_node, cfg_tree, exec_blocks, basic_blocks)
        time += 1
        print("times:%d" % time)
        if time > 50:
            print("more times")
            break
        path = cfg_tree.paths_to_leaves().pop()
        if path not in pathlist:
            print("current path:")
            print(cfg_tree)
            pathlist.append(path)
        else:
            print("the same path come again!")
        cfg_tree.remove_node(start_node)

    print("show all bbl already exe:")
    print(exec_blocks)
    print("show all bbl to exe:")
    print(basic_blocks)

    print("Tree list: ")
    print(pathlist)
    print("Tree list size: ")
    print(len(pathlist))
    print("-----")
    print(get_max_cst(pathlist))

    state=proj.factory.entry_state(addr=start_addr)
    x=claripy.BVS('arg1', 5*8)
    state.memory.store(0x300000,x)
    state.regs.r0=0x300000
    state.regs.r1=0x8000
    state.regs.r2=0x5
    #state.memory.store(state.regs.r0,0x300000)
    #state.memory.store(state.regs.r0,state.solver.BVV(0x300000,32))
    #state.memory.store(state.regs.r1,0x8000)
    #state.memory.store(state.regs.r1,state.solver.BVV(0x8000,32))
    state.memory.store(0x8000,state.solver.BVV(0,32))
    #state.memory.store(state.regs.r2,16)
    #state.memory.store(state.regs.r2,state.solver.BVV(0x10,32))
    path_nodes=get_max_cst(pathlist)
    path_addrs=[i.block.addr for i in path_nodes]
    func_addrs=[i.addr for i in cfg.kb.functions[start_addr].blocks]
    print("path_addrs",[hex(i) for i in path_addrs])
    avoid_addrs=[i for i in func_addrs if i not in path_addrs]
    sm=proj.factory.simulation_manager(state,threads=4)
    pathidx=0
    while True:
	#print "pathidx=%d before:"%pathidx,sm.active
	if pathidx<len(path_addrs):
  	    for i in sm.active:
	        if i.regs.pc.args[0]!=path_addrs[pathidx]:
		    sm.active.remove(i)
	    if len(sm.active)==0:
	        print("Not found")
	        exit(0)
            pathidx+=1
	#print "pathidx=%d after"%pathidx,sm.active
        print sm.active[0],sm.active[0].regs.r0,sm.active[0].regs.r1,sm.active[0].regs.r2
	if sm.active[0].addr==end_node.block.addr:
	    break
        sm.step()
    print "-----Constraints-----"
    print sm.active[0].solver.constraints
    print "---------Eval--------"
    print sm.active[0].solver.eval(x)
    exit(0)
    '''
    res=sm.explore(find=end_addr,avoid=avoid_addrs)
    print(res,res.found,len(res.found))
    for pp in res.found:
        addr=pp.memory.load(0x300000,endness=archinfo.Endness.BE)
        print pp.solver.eval(addr,cast_to=str)
	print pp.solver
    '''
'''
    # failed when the node was added to parent node already which is added by another child node
    cfg_tree, basic_blocks = DFS_path(start_node, end_node, cfg_tree, basic_blocks)
    print("show all tree2:")
    # cfg_tree.show()
    print(cfg_tree)
    print("show all bbl2:")
    print(basic_blocks)
'''


#    get_intersting_trace(cfg_tree)
#    print(path_addr)
#    for addr in path_addr:
#        print("0x%x"%addr)

'''
    print("path_addr: "+' '.join(hex(i) for i in path_addr))
    func_blocks=[i for i in cfg.kb.functions[start_addr].blocks]
    avoid_addr=[i.addr for i in func_blocks if i.addr not in path_addr]
    print("avoid_addr: "+' '.join(hex(i) for i in avoid_addr))
    inp=claripy.BVS('input',0x400*8)
    oup=claripy.BVS('output',0x400*8)
    state=proj.factory.call_state(start_addr,inp,oup,0x400)
    simgr = proj.factory.simgr(state)
    simgr.explore(find=path_addr[-1])#,avoid=avoid_addr)
    for i in simgr.found:
        print(i.solver.eval(inp,cast_to=str))
'''

if __name__=='__main__':
    main()
