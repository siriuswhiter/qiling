#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys


sys.path.append("../qiling")
from elftools.elf.elffile import ELFFile

from qiling.const import QL_INTERCEPT

from qiling.core import Qiling
from qiling.const import QL_VERBOSE
from qiling.extensions.mcu.stm32f4 import stm32f411
# from qiling.extensions.sanitizers.sanitizer import asan_malloc_call, asan_free
from qiling.extensions.sanitizers.memorysanitizer import memsan_free_call, memsan_malloc_call
from unicorn.unicorn_const import UC_MEM_READ, UC_MEM_WRITE


# def mem_write(ql: Qiling, access: int, address: int, size: int, value: int) -> None:
#     # only write accesses are expected here
#     assert access == UC_MEM_WRITE
#     # get bp
#     ql.log.info(ql.arch.regs)
#     raise Exception
#     # ql.log.debug(f'intercepted a memory write to {address:#x} (value = {value:#x})')
    
    

def hook_malloc(ql: Qiling):
    # find malloc/free address
    with open(sys.argv[1], 'rb') as f:
        elf_file = ELFFile(f)
        symbol_table = elf_file.get_section_by_name('.symtab')

        for symbol in symbol_table.iter_symbols():
            if symbol.name == "malloc":
                malloc_addr = symbol.entry.st_value - 1  # ?
            elif symbol.name == "free":
                free_addr = symbol.entry.st_value - 1
    
    # print(malloc_addr, free_addr)
    ql.hook_address(memsan_malloc_call, malloc_addr)
    ql.hook_address(memsan_free_call, free_addr)


def test_mcu_freertos_stm32f411():
    # ql = Qiling(["freertos-demo.elf"], archtype="cortex_m", ostype="mcu", env=stm32f411)
    ql = Qiling(sys.argv[1:], archtype="cortex_m", ostype="mcu", env=stm32f411)

    ql.hw.create('usart2').watch()
    ql.hw.create('rcc')
    ql.hw.create('gpioa').watch()

    count = 0
    def counter():
        nonlocal count
        count += 1

    # ql.hw.gpioa.hook_set(5, counter)

    ql.hw.systick.ratio = 0xff

    hook_malloc(ql)
    
    # for line in ql.mem.get_formatted_mapinfo():
    #     print(line)
    # ql.hook_mem_write(mem_write)
    ql.run()


if __name__ == "__main__":
    test_mcu_freertos_stm32f411()
