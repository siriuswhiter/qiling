#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes
from qiling.hw.peripheral import QlPeripheral


class HT32CKCU_RSTCU(QlPeripheral):
    
    class Type(ctypes.Structure):
        _fields_ = [
            ('GCFGR' , ctypes.c_uint32),
            ('GCCR' , ctypes.c_int32),
            ('GCSR'  , ctypes.c_int32),
            ('GCIR', ctypes.c_uint32 * 5),
            ('AHBCFGR', ctypes.c_uint32),
            ('AHBCCR', ctypes.c_uint32),
            ('APBCFGR', ctypes.c_uint32 * 3),
            ('CKST', ctypes.c_uint32),
            ('RESERVED1', ctypes.c_uint8 * 0xC8),
            ('GRSR', ctypes.c_uint32), # 0x100, RSTCU
            ('AHBPRSTR', ctypes.c_uint32 * 3),
            ('RESERVED2', ctypes.c_uint8 * 0x114),
            ('MCUDBGCR', ctypes.c_uint32),
        ]
        
    def __init__(self, ql, label):
        super().__init__(ql, label)

        self.instance = self.struct(
            # CKCU
            GCFGR = 0x00000002,
            GCCR = 0x00000803,
            GCSR = 0x00000028,
            AHBCCR = 0x00000065,
            CKST = 0x01000003,
            # RSTCU
            GRSR = 0x00000008,
        )
        
        self.clock = {
            "HSE" : {
                "enable_bit" : 11, # HSEEN
                "ready_bit": 2, # HSERDY
            },
            "HSI" : {
                "enable_bit" : 11, # HSIEN
                "ready_bit": 3, # HSIRDY
            },
            "LSE" : {
                "ready_bit": 4, # LSERDY
            },
            "LSI" : {
                "ready_bit": 5, # LSIRDY
            }
        }

        
    @QlPeripheral.monitor()    
    def read(self, offset: int, size: int) -> int:
        # self.ql.log.info(f'read : {offset:#x}, {size}')
        return super().read(offset, size)
    
    @QlPeripheral.monitor()
    def write(self, offset: int, size: int, value: int):
        # self.ql.log.info(f'write : {offset:#x}, {size}, {value:#x}')
        if offset == self.Type.GCCR.offset:
            if value & (1 << 10): # HSEEN
                self.instance.GCSR |= 1 << 2
            if value & (1 << 11): # HSIEN
                self.instance.GCSR |= 1 << 3
                
            if value & 0b111:
                self.instance.CKST &= 0xFFFFFFF8 | value
            
        return super().write(offset, size, value)
    