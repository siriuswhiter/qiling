#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes
from qiling.hw.peripheral import QlPeripheral


class HT32Afio(QlPeripheral):
    
    class Type(ctypes.Structure):
        _fields_ = [
            ('ESSR' , ctypes.c_uint32 * 8),
            ('GPACFGLR' , ctypes.c_int32),
            ('GPACFGHR' , ctypes.c_int32),
            ('GPBCFGLR' , ctypes.c_int32),
            ('GPBCFGHR' , ctypes.c_int32),
            ('GPCCFGLR' , ctypes.c_int32),
            ('GPCCFGHR' , ctypes.c_int32),
            ('GPFCFGLR' , ctypes.c_int32),
            ('GPFCFGHR' , ctypes.c_int32), 
        ]
         