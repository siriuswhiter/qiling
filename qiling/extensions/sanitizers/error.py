from enum import Enum


class CanaryType(Enum):
    underflow = 0
    overflow = 1
    uaf = 2


class AddressSanitizer(Exception):
    ...

class MemorySanitizer(Exception):
    ...