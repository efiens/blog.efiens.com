import angr
import claripy
import time

def get_rip(state):
    return state.mem[0x6CA5B0].uint32_t.concrete

def get_cnt(state):
    return state.mem[0x400000].uint32_t.concrete

def filter(state):
    cur_state = state
    for i in range(500):
        if get_rip(cur_state) > 257 or get_rip(cur_state) < 255:
            return False
        cur_state = cur_state.history.state
        if cur_state == None:
            return False
    return True

if __name__ == '__main__':
    a = time.time()
    proj = angr.Project('BIGbadEASYvm.deflat')
    flag = claripy.BVS('flag', 100 * 8)        
    state = proj.factory.entry_state(args = ['BIGbadEASYvm.deflat', 'crackme.i'], stdin = flag)
    state.history.add_event
    state.mem[0x400000].uint32_t = 0
    for i in range(100):
        state.solver.add(claripy.Or(flag.get_byte(i) == 0, 
                                    claripy.And(flag.get_byte(i) >= 32, flag.get_byte(i) <= 127)))
    state.solver.add(flag.get_byte(0) == ord('i'))
    state.solver.add(flag.get_byte(1) == ord('n'))
    state.solver.add(flag.get_byte(2) == ord('c'))
    state.solver.add(flag.get_byte(3) == ord('t'))
    state.solver.add(flag.get_byte(4) == ord('f'))
    state.solver.add(flag.get_byte(5) == ord('{'))
    with open('crackme.i', 'rb') as bytecode:
        simfile = angr.SimFile('crackme.i', content=bytecode.read())
        simfile.set_state(state)
    state.fs.insert('crackme.i', simfile)
    
    @proj.hook(0x403190, length=5)
    def bad_block(state):
        self.exit(0)

    simgr = proj.factory.simgr(state)
    simgr.explore(find=0x403147, avoid=0x403190)
    # found = simgr.found[0]
    # found.solver.eval(simfile, cast_to=bytes)