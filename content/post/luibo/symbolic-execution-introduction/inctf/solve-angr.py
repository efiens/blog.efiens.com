import angr
import claripy
import time

def get_rip(state):
    return state.mem[0x6CA5B0].uint32_t.concrete

def get_cnt(state):
    # return state.mem[0x400000].uint32_t.concrete
    return state.hit_count.cnt

def filter(state):
    cur_state = state
    for i in range(500):
        if get_rip(cur_state) > 257 or get_rip(cur_state) < 255:
            return False
        cur_state = cur_state.history.state
        if cur_state == None:
            return False
    return True

class HitCount(angr.SimStatePlugin):
    
    def __init__(self, cnt):
        self.cnt = cnt
    
    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return HitCount(self.cnt)

if __name__ == '__main__':
    a = time.time()
    proj = angr.Project('BIGbadEASYvm.deflat')
    flag = claripy.BVS('flag', 100 * 8)        
    state = proj.factory.entry_state(args = ['BIGbadEASYvm.deflat', 'crackme.i'], stdin = flag)
    state.register_plugin('hit_count', HitCount(0))
    # state.mem[0x400000].uint32_t = 0
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
        print(simfile)
    state.fs.insert('crackme.i', simfile)
    simgr = proj.factory.simgr(state)
    while len(simgr.active) > 0:
        simgr.step()
        print(simgr)
        min_cnt = 0xFFFFFFFF
        for active in simgr.active:
            rip = get_rip(active)
            min_cnt = min(min_cnt, get_cnt(active))
            if rip <= 257 and rip >= 255:
                active.hit_count.cnt += 1
                # active.mem[0x400000].uint32_t = get_cnt(active) + 1
            print(f'{get_cnt(active)}: {active.posix.dumps(0)}')
            if b'Congratz your input was the flag' in active.posix.dumps(1):
                print(active.posix.dumps(0))
                print(active.solver.eval(flag))
                b = time.time()
                print('time cost: ', b - a)
                exit(0)
        if len(simgr.active) > 1:
            simgr.move(from_stash='active', to_stash='deadended', 
                        filter_func=lambda state: get_cnt(state) > min_cnt)
