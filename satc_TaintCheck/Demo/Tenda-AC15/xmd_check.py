import angr
import claripy

def main():
    path_to_binary = "./httpd"
    proj = angr.Project(path_to_binary, auto_load_libs=False)

    start_addr = 0xa6a74 # address of bl FUN_0002babc()
    # avoid_addr = [] # addresses we want to avoid
    avoid_addr = []
    success_addr = 0xa6a5c # address of code block leading to "That is correct!"

    block = proj.factory.block(start_addr)

    print(block.bytes)

    initial_state = proj.factory.blank_state(addr=start_addr)

    param1_length = 32 # amount of characters that compose the string
    param1 = claripy.BVS("param1", param1_length * 8) # create a symbolic bitvector
#    param1 = param1_chars.concat(claripy.BVV(b''))
    fake_param1_address = 0xffffcc80 # random address in the stack where we will store our string

    initial_state.memory.store(fake_param1_address, param1, endness='Iend_LE') # store symbolic bitvector to the address we specified before
    initial_state.regs.r0 = fake_param1_address # put address of the symbolic bitvector into r0

    param2_length = 32 # amount of characters that compose the string
    param2 = claripy.BVS("param2", param2_length * 8) # create a symbolic bitvector
#    param2 = param2_chars.concat(claripy.BVV(b''))
    fake_param2_address = 0xffffcc00 # random address in the stack where we will store our string

    initial_state.memory.store(fake_param2_address, param2, endness='Iend_LE') # store symbolic bitvector to the address we specified before
    initial_state.regs.r2 = fake_param2_address # put address of the symbolic bitvector into r2

    simulation = proj.factory.simgr(initial_state)

#    tech = angr.exploration_techniques

#    simgr.use_technique(tech)

    simulation.explore(find=success_addr, avoid=avoid_addr)

    if simulation.found:
        solution_state = simulation.found[0]

        solution = solution_state.solver.eval(param2, cast_to=bytes) # concretize the symbolic bitvector
        print("[+] Success! Solution is: {}".format(solution.decode("utf-8")))
        print(solution)

    else: print("[-] Bro, try harder.")

if __name__ == '__main__':
    main()
