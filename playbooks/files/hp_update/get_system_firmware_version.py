#!/bin/env python
from __future__ import print_function

import subprocess

def get_system_firmware_version():
  # can't use string split because of the space in the third arg
  query_cmd = ['hpasmcli', '-s', 'show server']

  query = subprocess.Popen(query_cmd, stdout=subprocess.PIPE)
  (response_str, stderr_str) = query.communicate()

  rom_line = [ l for l in response_str.split('\n') if l.startswith('ROM')][0]
  
  return rom_line.lstrip("ROM version   :").split()

if __name__ == "__main__":
  print(get_system_firmware_version())
