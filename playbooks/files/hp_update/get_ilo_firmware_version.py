#!/bin/env python
from __future__ import print_function

import re
import subprocess

def get_ilo_version():
  # Firmware Revision = 2.73 Device type = iLO 4 Driver name = hpilo
  
  query_string = "hponcfg -h"
  query = subprocess.Popen(query_string.split(), stdout=subprocess.PIPE)
  (response, std_out) = query.communicate()

  line = [ l for l in response.split('\n') if l.startswith('Firmware Revision')][0]

  version_pattern = "^Firmware Revision = ([^\s]+) "
  version_re = re.compile(version_pattern)
  
  version_match = version_re.match(line)
  return version_match.groups()[0]

if __name__ == "__main__":
  print(get_ilo_version())
