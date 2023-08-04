


#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
sys.path.append("../..")

from qiling.core import Qiling
from qiling.const import QL_VERBOSE
from qiling.extensions.mcu.imxrt.imxrt1060 import imxrt1060


if __name__ == "__main__":
    ql = Qiling(["./imxrt1060_http_server.axf"], archtype="cortex_m", ostype="mcu", env=imxrt1060, verbose=QL_VERBOSE.DEBUG)

    # ql.hw.systick.ratio = 0xff

    ql.run()
