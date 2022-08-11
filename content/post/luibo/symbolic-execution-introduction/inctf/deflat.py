import angr
import argparse
import sys
import logging
from angrmanagement.utils.graph import to_supergraph
from angr.state_plugins.inspect import BP_BEFORE
import pyvex
import claripy
from collections import defaultdict
from keystone import *

record = []

class Deflattener:
    
    def __init__(self, cfg):
        self.cfg = cfg
        self.flow = defaultdict(list)
        self.relevant_addrs = []
        self.block_info = {}

    def is_flattened(self):
        cfg = self.cfg
        if cfg.number_of_nodes() < 10:
            return False
        prologue_node = list(cfg.nodes)[0]
        if len(list(cfg.successors(prologue_node))) == 0:
            return False
        main_dispatcher_node = list(cfg.successors(prologue_node))[0]
        return len(list(cfg.predecessors(main_dispatcher_node))) == 2
        
    def analyse_cfg(self):
        cfg = self.cfg
        retn_nodes = []
        prologue_node = list(cfg.nodes)[0]
        for node in cfg.nodes:
            if cfg.out_degree(node) == 0:
                retn_nodes.append(node)
        main_dispatcher_node = list(cfg.successors(prologue_node))[0]
        for node in cfg.predecessors(main_dispatcher_node):
            if node.addr != prologue_node.addr:
                predispatcher_node = node
                break
        relevant_nodes = [prologue_node]
        sub_dispatcher_nodes = []
        for node in cfg.nodes:
            if node in cfg.predecessors(predispatcher_node) and cfg.in_degree(node) > 0:
                relevant_nodes.append(node)
            elif node != prologue_node and node not in retn_nodes:
                sub_dispatcher_nodes.append(node)
        return (
                prologue_node, 
                main_dispatcher_node, 
                sub_dispatcher_nodes, 
                retn_nodes, 
                relevant_nodes, 
                predispatcher_node
            )
        
    def symbolic_execute(self, block_addr, modify_cond=None):
        def modify_ITE_cond(state):
            expressions = list(state.scratch.irsb.statements[state.inspect.statement].expressions)
            if len(expressions) != 0 and isinstance(expressions[0], pyvex.expr.ITE):
                state.scratch.temps[expressions[0].cond.tmp] = modify_cond
                state.inspect._breakpoints['statement'] = []

        state = proj.factory.blank_state(addr=block_addr, remove_options={
                                        angr.sim_options.LAZY_SOLVES})
        if modify_cond is not None:
            state.inspect.b('statement',when=BP_BEFORE, action=modify_ITE_cond)
        simgr = proj.factory.simgr(state)
        simgr.step()
        while len(simgr.active):
            for active in simgr.active:
                if active.addr in self.relevant_addrs:
                    self.flow[block_addr].append(active.addr)
                    return
            simgr.step()
        logger.fatal('Can not find real successor of block %#x' % block_addr)
        
    def preprocess(self, node):
        def nop_proc(state):
            pass
        block_addr = node.addr
        has_branch = False
        while block_addr < node.addr + node.size:
            block = proj.factory.block(block_addr)
            block_addr += block.size
            for insn in block.capstone.insns:
                if insn.mnemonic == 'call':
                    proj.hook(insn.address, hook=nop_proc, length=5)
                    logger.debug('Hook [%s\t%s] at %#x' % (insn.mnemonic, insn.op_str, insn.address))
                elif insn.mnemonic.startswith('cmov'):
                    has_branch = True
                    self.block_info[node.addr] = (insn.address, insn.mnemonic)
        return has_branch
        
    def deflatten(self):
        cfg = self.cfg
        if self.is_flattened():
            logger.debug('Start deflatten (func_%x)', func_addr)
            logger.debug('Step-1 -> Static Analysis (1/3)')
            (
                prologue_node, 
                main_dispatcher_node, 
                sub_dispatcher_nodes, 
                retn_nodes, 
                relevant_nodes, 
                predispatcher_node
            ) = self.analyse_cfg()
            record.append(prologue_node.addr)
            logger.debug('[*] Prologue block at %#x' % prologue_node.addr)
            logger.debug('[*] Main dispatcher block at %#x' % main_dispatcher_node.addr)
            logger.debug('[*] Sub dispatcher blocks at %s' % [hex(node.addr) for node in sub_dispatcher_nodes])
            logger.debug('[*] Return blocks at %s' % [hex(node.addr) for node in retn_nodes])
            logger.debug('[*] Relevant blocks at %s' % [hex(node.addr) for node in relevant_nodes])
            logger.debug('[*] Predispatcher blocks at %#x' % predispatcher_node.addr)
            
            logger.debug('Step-2 -> Recover Control Flow (2/3)')
            self.relevant_addrs += [node.addr for node in relevant_nodes]
            self.relevant_addrs += [node.addr for node in retn_nodes]
            for node in relevant_nodes:
                block_addr = node.addr
                has_branch = self.preprocess(node)
                if has_branch:
                    self.symbolic_execute(block_addr, modify_cond=claripy.BVV(1, 1))
                    self.symbolic_execute(block_addr, modify_cond=claripy.BVV(0, 1))
                else:
                    self.symbolic_execute(block_addr)
            for node in relevant_nodes:
                block_addr = node.addr
                logger.debug('Real successors of block %#x: %s' 
                      % (block_addr, [hex(child) for child in self.flow[block_addr]]))
                
            logger.debug('Step-3 -> Patch Binary (3/3)')
            for node in sub_dispatcher_nodes:
                fill_nops(node.addr, node.size)
                logger.debug('Fill nops from %#x to %#x' % (node.addr, node.addr + node.size))
            for node in relevant_nodes:
                childs = self.flow[node.addr]
                if len(childs) == 1:
                    patch_addr = node.addr + node.size - 5
                    if node.addr == prologue_node.addr:
                        patch_addr = node.addr + node.size
                    fill_jmp(patch_addr, childs[0])
                    logger.debug('Patch jmp %#x at %#x' % (childs[0], patch_addr))
                elif len(childs) == 2:
                    patch_addr, cmov_type = self.block_info[node.addr]
                    fill_nops(patch_addr, node.addr + node.size - patch_addr)
                    fill_jx(patch_addr, childs[0], cmov_type)
                    fill_jmp(patch_addr + 6, childs[1])
                    logger.debug('Patch jz %#x at %#x' % (childs[0], patch_addr))
                    logger.debug('Patch jmp %#x at %#x' % (childs[1], patch_addr + 6))
                else:
                    logger.fatal('Error')
    
def get_cfg(func_addr):
    function_cfg = global_cfg.functions.get(func_addr).transition_graph
    super_cfg = to_supergraph(function_cfg)
    return super_cfg

def fill_nops(addr, size):
    offset = addr - base_addr
    binary[offset:offset + size] = b'\x90' * size

def fill_jmp(src, dest):
    offset = src - base_addr
    if dest != src + 5:
        binary[offset] = 0xE9
        binary[offset + 1:offset + 5] = (dest - src - 5).to_bytes(4, 'little', signed=True)
    else:
        fill_nops(src, 5)

def get_jx_opcode(jx_type):
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    code, count = ks.asm(f'{jx_type} 0xFFFFFFFF')
    return b''.join(map(lambda x: x.to_bytes(1, sys.byteorder), code[0:2]))

def fill_jx(src, dest, cmov_type):
    offset = src - base_addr
    binary[offset:offset + 2] = get_jx_opcode(cmov_type.replace('cmov', 'j'))
    binary[offset + 2:offset + 6] = (dest - src - 6).to_bytes(4, 'little', signed=True)
    
if __name__ == '__main__':
    logging.getLogger('angr').setLevel(logging.ERROR)
    logger = logging.getLogger('deflat')
    logger.setLevel(logging.DEBUG)
    parser = argparse.ArgumentParser(description='Deobfuscate OLLVM Control Flow Flattening')
    parser.add_argument('-f', '--file', help='input file path')
    parser.add_argument(
        '-s', '--start', 
        help='start address of the deobfuscation (optional, default: all functions)')
    parser.add_argument(
        '-o', '--out', 
        help='output file path (optional, default: file.deflat)')
    args = parser.parse_args()
    if args.file is None:
        parser.print_help()
        sys.exit(0)
    output_file = args.file + '.deflat'
    if args.out is not None:
        output_file = args.out
    logger.debug('Basic information:')
    logger.debug(f'[*] Input file: {args.file}')
    logger.debug(f'[*] Output file: {args.out}')
    # Prepare necessary variables for further operation
    proj = angr.Project(args.file)
    global_cfg = proj.analyses.CFGFast(normalize=True, force_complete_scan=False)
    functions = []
    obj = proj.loader.main_object
    base_addr = proj.loader.main_object.mapped_base
    with open(args.file, 'rb') as file:
        binary = bytearray(file.read())
    out = open(output_file, 'wb')
    if args.start is not None:
        functions.append(int(args.start, 16))
    else:
        for func_addr in list(global_cfg.functions):
            section = obj.find_section_containing(func_addr)
            if (section is not None and section.name == '.text' and 
                    func_addr not in obj.reverse_plt):
                functions.append(func_addr)
    logger.debug(f'[*] Selected functions: {[hex(func) for func in functions]}')
    for func_addr in functions:
        try:
            cfg = get_cfg(func_addr)
        except Exception:
            continue
        Deflattener(cfg).deflatten()
    out.write(binary)
    out.close()
    print([hex(addr) for addr in record])