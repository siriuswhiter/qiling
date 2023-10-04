from enum import Enum

from qiling import Qiling


class CanaryType(Enum):
    underflow = 0
    overflow = 1
    uaf = 2


class Sanitizer(Exception):
    def __init__(self, ql: Qiling, msg: str) -> None:
        super().__init__(msg)
        self.ql = ql
        self.context = str(ql.arch.regs) if ql else "None"
        self.msg = msg
    
    def __str__(self):
        return f"{self.msg}: \n  [CONTEXT]: \n{self.context}"

class AddressSanitizer(Sanitizer):
    ...


class MemorySanitizer(Sanitizer):
    ...