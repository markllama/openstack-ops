#!/bin/env python
from __future__ import print_function

import subprocess

def get_system_product_name():
  """
  TBD
  """

  command = "/usr/bin/env dmidecode -s system-product-name"
  pipe = subprocess.Popen(command.split(), stdout=subprocess.PIPE)
  return pipe.communicate()[0].strip()

if __name__ == "__main__":
  print("This system is: {}".format(get_system_product_name()))
