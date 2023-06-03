


#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
sys.path.append("../..")

from qiling.core import Qiling
from qiling.const import QL_VERBOSE
from qiling.extensions.mcu.ht32 import ht32f50030


if __name__ == "__main__":
    ql = Qiling(["./ht32f50030.axf"], archtype="cortex_m", ostype="mcu", env=ht32f50030, verbose=QL_VERBOSE.DEBUG)

    ql.hw.systick.ratio = 0xff

    ql.run()
