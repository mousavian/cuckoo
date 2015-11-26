# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
from lib.common.rand import random_string


ROOT = os.path.join(os.environ["HOME"], "\\", "z" + random_string(6, 10))

PATHS = {"root"   : ROOT,
         "logs"   : os.path.join(ROOT, "logs"),
         "files"  : os.path.join(ROOT, "files"),
         "shots"  : os.path.join(ROOT, "shots")}

PIPE = "\\\\.\\PIPE\\" + random_string(6, 10)
