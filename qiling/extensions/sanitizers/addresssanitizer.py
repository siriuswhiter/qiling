import sys
sys.path.append("..")

from qiling import Qiling
from .error import AddressSanitizer
from .utils import *

canary_size = 4
canary_byte = b"\xCD"


def bo_handler(ql, access, addr, size, value):
    """
    Called when a buffer overflow/underflow is detected.
    """
    ...
    raise AddressSanitizer(ql, "buffer overflow/underflow is detected.")


def oob_handler(ql, access, addr, size, value):
    """
    Called when an out-of-bounds element is accessed.
    """
    ...
    raise AddressSanitizer(ql, "out-of-bounds element is accessed.")


def uaf_handler(ql, access, addr, size, value):
    """
    Called when a use-after-free is detected.
    """
    raise AddressSanitizer(ql, "use-after-free is detected.")


def bad_free_handler(ql: Qiling, addr):
    """
    Called when a bad/double free is detected.
    """
    raise AddressSanitizer(ql, "bad/double free is detected.")
 

   
def asan_malloc_call(ql: Qiling):
    size = get_arg_0(ql)
    set_arg_0(ql, size + canary_size * 2)

    # multi thread?
    callee_addr = get_ret_addr(ql)
    ql.hook_address(asan_malloc_ret, callee_addr, user_data=size)

def asan_malloc_ret(ql: Qiling, user_data):
    addr = get_arg_0(ql)
    set_arg_0(ql, addr + canary_size)
    
    size = user_data

    canary_begins = addr
    canary_ends = canary_begins + canary_size - 1

    ql.mem.write(canary_begins, canary_byte * canary_size)
    ql.hook_mem_write(bo_handler, begin=canary_begins, end=canary_ends)
    ql.hook_mem_read(oob_handler, begin=canary_begins, end=canary_ends)

    
    canary_begins = addr + canary_size + size
    canary_ends = canary_begins + canary_size - 1

    ql.mem.write(canary_begins, canary_byte * canary_size)
    ql.hook_mem_write(bo_handler, begin=canary_begins, end=canary_ends)
    ql.hook_mem_read(oob_handler, begin=canary_begins, end=canary_ends)


