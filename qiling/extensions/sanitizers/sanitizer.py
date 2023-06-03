import sys
sys.path.append("..")
from bitarray import bitarray


from qiling import Qiling
from unicorn.unicorn_const import UC_MEM_READ, UC_MEM_WRITE
from .error import AddressSanitizer, MemorySanitizer
from .utils import *


def bo_handler(ql, access, addr, size, value):
    """
    Called when a buffer overflow/underflow is detected.
    """
    ...
    raise AddressSanitizer("buffer overflow/underflow is detected.")


def oob_handler(ql, access, addr, size, value):
    """
    Called when an out-of-bounds element is accessed.
    """
    ...
    raise AddressSanitizer("out-of-bounds element is accessed.")


def uaf_handler(ql, access, addr, size, value):
    """
    Called when a use-after-free is detected.
    """
    raise AddressSanitizer("use-after-free is detected.")


def bad_free_handler(ql: Qiling, addr):
    """
    Called when a bad/double free is detected.
    """
    raise AddressSanitizer("bad/double free is detected.")


class MallocRegion:
    def __init__(self, begin, end) -> None:
        self.begin = begin
        self.end = end
        self.size = end - begin + 1
        self.shadow_mem = self.__init_shadow_mem()

    def __repr__(self) -> str:
        return f"MallocRegion : {self.begin:#x}-{self.end:#x} {self.shadow_mem}"

    def __init_shadow_mem(self):
        shadow_mem = bitarray(self.size)
        shadow_mem.setall(0)
        return shadow_mem

    def read(self, addr, size):
        start = addr - self.begin

        for offset in range(start, start + size):
            if self.shadow_mem[offset] ^ 1:
                raise MemorySanitizer(
                    f"uninitialized memory read.\n{self} - {self.begin+offset:#x}"
                )

    def write(self, begin, size):
        start = begin - self.begin

        for offset in range(start, start + size):
            self.shadow_mem[offset] |= 1


class MallocRegions:
    def __init__(self) -> None:
        self._regions = []

    def __repr__(self) -> str:
        regions = "\n".join(f"  - {repr(region)}" for region in self.regions)
        return f"MallocRegions : \n{regions}"

    @property
    def regions(self):
        return self._regions

    def add(self, malloc_region: MallocRegion):
        # check
        addr = malloc_region.begin
        size = malloc_region.size
        for region in self.regions:
            # has overlapped region
            if (addr >= region.begin and addr <= region.end) or (
                addr + size - 1 >= region.begin and addr + size - 1 <= region.end
            ):
                raise AddressSanitizer("overlapped memory.")
        self.regions.append(malloc_region)

    def remove(self, malloc_region: MallocRegion):
        self.regions.remove(malloc_region)

    def find(self, addr, size):
        for region in self.regions:
            if addr >= region.begin and addr + size - 1 <= region.end:
                # match malloc region
                return region
        return None

    def equal(self, addr):
        for region in self.regions:
            if addr == region.begin:
                # match malloc region
                return region
        return None

    def __iter__(self):
        return iter(self.regions)


malloc_regions: MallocRegions = MallocRegions()


def memsan_mem_write(ql: Qiling, access, addr, size, value):
    assert access == UC_MEM_WRITE
    ql.log.info(f"write : {addr:#x}, {size}, {value}")
    region = malloc_regions.find(addr=addr, size=size)
    if not region:
        raise AddressSanitizer(
            f"possibly out-of-bounds element is accessed.\n {malloc_regions} \n AccessRegion : {addr:#x}, {size}"
        )
    else:
        region.write(addr, size)


def memsan_mem_read(ql: Qiling, access, addr, size, value):
    assert access == UC_MEM_READ
    ql.log.info(f"read : {addr:#x}, {size}, {value}")
    region = malloc_regions.find(addr=addr, size=size)
    if not region:
        raise MemorySanitizer(
            f"possibly out-of-bounds element is accessed.\n {malloc_regions} \n AccessRegion : {addr:#x}, {size}"
        )
    else:
        region.read(addr, size)
        
   
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

    # set memory sanitizer
    mem_begins = canary_ends + 1
    mem_ends = mem_begins + size - 1
    
    ql.hook_mem_write(memsan_mem_write, begin=mem_begins, end=mem_ends)
    ql.hook_mem_read(memsan_mem_read, begin=mem_begins, end=mem_ends)

    malloc_regions.add(MallocRegion(begin=mem_begins, end=mem_ends))
    
    canary_begins = addr + canary_size + size
    canary_ends = canary_begins + canary_size - 1

    ql.mem.write(canary_begins, canary_byte * canary_size)
    ql.hook_mem_write(bo_handler, begin=canary_begins, end=canary_ends)
    ql.hook_mem_read(oob_handler, begin=canary_begins, end=canary_ends)


def asan_free(ql: Qiling) -> bool:
    addr = get_arg_0(ql)
    malloc_region = malloc_regions.find(addr)

    if not malloc_region:
        bad_free_handler(ql, addr)
        return False

    # Install the UAF canary hook.
    ql.mem.write(addr, canary_byte * malloc_region.size)
    ql.hook_mem_valid(uaf_handler, begin=addr, end=addr + malloc_region.size - 1)

    # Make sure the chunk won't be re-used by the underlying heap.
    malloc_regions.remove(malloc_region)

    return True