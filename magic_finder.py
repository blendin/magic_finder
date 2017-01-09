#!/usr/bin/env python
from __future__ import print_function

import angr
import argparse
import binaryninja
import logging
import simuvex
import sys

parser = argparse.ArgumentParser(description='Find magic gadgets')
parser.add_argument('libc', metavar='<libc.so>', help='libc shared library')
parser.add_argument('-b', '--binja', metavar='<libc.bndb>', help='Binary Ninja database file (huge speed improvement)')
parser.add_argument('-v', '--verbose', action='store_true')
args = parser.parse_args()

# Binary Ninja and Angr initialization
if args.binja:
    fm = binaryninja.FileMetadata()
    db = fm.open_existing_database(args.binja)
    bv = db.get_view_of_type('ELF')
else:
    bv = binaryninja.BinaryViewType['ELF'].open(args.libc)

bv.update_analysis_and_wait()
b = angr.Project(args.libc, load_options={'main_opts': {'custom_base_addr': 0}})


# Helper functions for printing pretty
def red(string):
    return '\033[0;31m' + string + '\033[0m'


def line():
    return '----------------------------------------------'


# Binary ninja wrappers and helpers
def find_string(search_string):
    """
    Get the address of a string in the binary
    """
    for string in bv.strings:
        if bv.read(string.start, string.length) == search_string:
            return string.start
    return False


def same_function(address_a, address_b):
    """
    Cross reference two addresses are in the same function
    """
    a = bv.get_previous_function_start_before(address_a) 
    b = bv.get_previous_function_start_before(address_b)
    return a == b


def get_all_addrs(symbols):
    """
    Get all addresses of symbols
    """
    addrs = set()
    for symbol in symbols:
        addrs.add(bv.get_symbol_by_raw_name(symbol).address)
    return addrs


def get_all_funcs():
    """
    Get every function identified by binary ninja
    """
    return set([f.start for f in bv.functions])


def get_functions_containing(refs):
    """
    Get every function given by a list of cross references
    """
    addrs = []
    for ref in refs:
        start = bv.get_previous_function_start_before(ref.address)
        addrs.append(bv.get_function_at(bv.platform, start))
    return addrs


def find_magic_gadgets():
    """
    The bulk of the work here. Use angr and binary ninja to find the 
    magic gadgets.
    """

    def check_path(address):
        init_state = b.factory.blank_state(addr=address, remove_options={simuvex.o.LAZY_SOLVES})
        pg = b.factory.path_group(init_state)
        pg.explore(find=exec_functions, avoid=blacklist)

        for path in pg.found: 
            if path.state.se.any_int(path.state.regs.rdi) == binsh:
                print(red(hex(address)[:-1]))

                ins = []
                for action in path.actions:
                    if action.ins_addr not in ins:
                        ins.append(action.ins_addr)
                
                yield ins

    def find_paths(refs):
        for ref in refs:
            for path in check_path(ref.address):
                if args.verbose:
                    for ins_addr in path:
                        arch = binaryninja.Architecture['x86_64']
                        length = bv.get_instruction_length(bv.arch, ins_addr)
                        ins = arch.get_instruction_text(bv.read(ins_addr, ins_addr+length), ins_addr)
                        print(''.join([str(i) for i in ins[0]]))
                    print("")

    all_functions  = get_all_funcs()
    exec_functions = get_all_addrs(['execve', 'execl', 'execlp', 'execle', 'execv', 'execvp', 'execvpe'])
    blacklist = all_functions - exec_functions

    binsh = find_string("/bin/sh")
    environ = bv.get_symbol_by_raw_name("__environ@PLT").address

    environ_xrefs = bv.get_code_refs(environ)
    binsh_xrefs   = bv.get_code_refs(binsh)
    functions = get_functions_containing(binsh_xrefs)

    refs = binsh_xrefs + environ_xrefs
    
    print("/bin/sh found at " + red(hex(binsh)[:-1]))
    print("Magic Gadgets")
    print(line())
    find_paths(refs)

if __name__ == "__main__":
    logger = logging.getLogger("simuvex")
    logger.setLevel(logging.ERROR)
    find_magic_gadgets()
