from qiling import Qiling

canary_size = 4
canary_byte = b"\xCD"


def get_arg_0(ql: Qiling):
    return ql.arch.regs.r0


def set_arg_0(ql: Qiling, val):
    ql.arch.regs.write(ql.arch.regs.r0, val)


def get_ret_addr(ql: Qiling):
    return ql.arch.regs.lr - ql.arch.regs.lr % 2  # why ?
