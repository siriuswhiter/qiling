


ht32f50030 = {
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
    # Clock Control Unit && Reset Control Unit
    "CKCU_RSTCU": {
        "base": 0x40088000,
        "struct": "HT32CKCU_RSTCU",
        "type": "core"
    },
    "AFIO": {
        "base": 0x40022000,
        "struct": "HT32Afio",
        "type": "core"
    },
    "GPIOA": {
        "base": 0x400B0000,
        "struct": "HT32Gpio",
        "type": "core"
    },
    "GPIOB": {
        "base": 0x400B2000,
        "struct": "HT32Gpio",
        "type": "core"
    },
    "GPIOC": {
        "base": 0x400B4000,
        "struct": "HT32Gpio",
        "type": "core"
    },
    "GPIOF": {
        "base": 0x400B8000,
        "struct": "HT32Gpio",
        "type": "core"
    },
    "FLASH": {
        "base": 0x0,
        "size": 0x8000,
        "type": "memory"
    },
    "BOOT LOADER": {
        "base": 0x1f000000,
        "size": 0x800,
        "type": "memory"
    },
    "BYTE ALIAS": {
        "base": 0x1ff00000,
        "size": 0x400,
        "type": "memory"
    },
    "SRAM": {
        "base": 0x20000000,
        "size": 0x800,
        "type": "memory"
    },
    "PERIP": {
        "base": 0x40000000,
        "size": 0x100000,
        "type": "mmio"
    },
    "PPB": {
        "base": 0xe0000000,
        "size": 0x100000,
        "type": "mmio"
    },
}