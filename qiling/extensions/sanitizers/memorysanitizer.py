from bitarray import bitarray
from qiling import Qiling
from qiling.os.const import SIZE_T
from unicorn.unicorn_const import UC_MEM_READ, UC_MEM_WRITE
from .error import AddressSanitizer, MemorySanitizer
from .utils import *


class MallocRegion:
    def __init__(self, begin, end) -> None:
        self.begin = begin
        self.end = end
        self.size = end - begin + 1
        self.shadow_mem = self.__init_shadow_mem()

    def __repr__(self) -> str:
        return f"[MallocRegion] : {self.begin:#x}-{self.end:#x} {self.shadow_mem}"

    def __init_shadow_mem(self):
        shadow_mem = bitarray(self.size)
        shadow_mem.setall(0)
        return shadow_mem

    def read(self, addr, size):
        start = addr - self.begin

        for offset in range(start, start + size):
            if self.shadow_mem[offset] ^ 1:
                raise MemorySanitizer(
                    None,
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
        return f"[MallocRegions] : \n{regions}"

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
                raise AddressSanitizer(None, "overlapped memory.")
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
            ql,
            f"possibly out-of-bounds element is accessed.\n {malloc_regions} \n [AccessRegion] : {addr:#x}, {size}"
        )
    else:
        region.write(addr, size)


def memsan_mem_read(ql: Qiling, access, addr, size, value):
    assert access == UC_MEM_READ
    ql.log.info(f"read : {addr:#x}, {size}, {value}")
    region = malloc_regions.find(addr=addr, size=size)
    if not region:
        raise MemorySanitizer(
            ql,
            f"possibly out-of-bounds element is accessed.\n {malloc_regions} \n AccessRegion : {addr:#x}, {size}"
        )
    else:
        region.read(addr, size)


def memsan_mem_hook(ql: Qiling, begin, end):
    ql.hook_mem_write(memsan_mem_write, begin=begin, end=end)
    ql.hook_mem_read(memsan_mem_read, begin=begin, end=end)

    malloc_regions.add(MallocRegion(begin=begin, end=end))


def memsan_malloc_call(ql: Qiling):
    params = ql.os.resolve_fcall_params({"size": SIZE_T})
    size = params["size"]

    callee_addr = get_ret_addr(ql)
    ql.hook_address(memsan_malloc_ret, callee_addr, user_data=size)


def memsan_malloc_ret(ql: Qiling, user_data):
    addr = get_arg_0(ql)
    size = user_data

    # memory sanitizer
    begin = addr
    end = addr + size - 1
    memsan_mem_hook(ql, begin=begin, end=end)


def memsan_free_call(ql: Qiling):
    params = ql.os.resolve_fcall_params({"addr": SIZE_T})
    addr = params["addr"]

    region = malloc_regions.equal(addr)
    if not region:
        raise AddressSanitizer(ql, "possibly doudle free detected.")
    malloc_regions.remove(region)
