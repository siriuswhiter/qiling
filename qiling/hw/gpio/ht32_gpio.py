#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes
from qiling.hw.peripheral import QlPeripheral


class HT32Gpio(QlPeripheral):
    
    class Type(ctypes.Structure):
        _fields_ = [
            ('DIRCR' , ctypes.c_uint32),
            ('INER' , ctypes.c_int32),
            ('PUR' , ctypes.c_int32),
            ('PDR' , ctypes.c_int32),
            ('ODR' , ctypes.c_int32),
            ('DRVR' , ctypes.c_int32),
            ('LOCKR' , ctypes.c_int32),
            ('DINR' , ctypes.c_int32),
            ('DOUTR' , ctypes.c_int32), 
            ('SRR' , ctypes.c_int32), 
            ('RR' , ctypes.c_int32), 
            ('SCER' , ctypes.c_int32), 
        ]
    