



imxrt1060 = { 
    "SYSTICK": {
        "base": 0xe000e010,
        "struct": "CortexM0PSysTick",
        "type": "core"
    },
    "NVIC": {
        "base": 0xe000e100,
        "struct": "CortexM0PNvic",
        "type": "core"
    },   
    "SCB": {
        "base": 0xe000ed00,
        "struct": "CortexM0PScb",
        "type": "core"
    },
    
    "ITCM": {
        "base": 0x0,
        "size": 0x80000,
        "type": "memory"
    },
    "ROMCP": {
        "base": 0x200000,
        "size": 0x20000,
        "type": "memory"
    },
    "DTCM": {
        "base": 0x20000000,
        "size": 0x80000,
        "type": "memory"
    },
    "OCRAM2": {
        "base": 0x20200000,
        "size": 0x80000,
        "type": "memory"
    },
    "OCRAM2_FLEXRAM": {
        "base": 0x20280000,
        "size": 0x80000,
        "type": "memory"
    },
    "FLEXSPI": {
        "base": 0x60000000,
        "size": 0x10000000,
        "type": "memory"
    },
    "FLEXSPI2": {
        "base": 0x70000000,
        "size": 0xF000000,
        "type": "memory"
    },
    "FLEXSPI2_TX_FIFO": {
        "base": 0x7F000000,
        "size": 0x400000,
        "type": "memory"
    },
    "FLEXSPI2_RX_FIFO": {
        "base": 0x7F400000,
        "size": 0x400000,
        "type": "memory"
    },
    "FLEXSPI_TX_FIFO": {
        "base": 0x7F800000,
        "size": 0x400000,
        "type": "memory"
    },
    "FLEXSPI_RX_FIFO": {
        "base": 0x7FC00000,
        "size": 0x400000,
        "type": "memory"
    },
    "PPB": {
        "base": 0xE0000000,
        "size": 0x100000,
        "type": "mmio"
    },
}