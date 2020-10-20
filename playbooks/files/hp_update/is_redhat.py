#!/bin/env python
from __future__ import print_function

import platform

def is_redhat():
  """
  Indicate if the host is running a Red Hat distribution
  """
  return "Red Hat Enterprise Linux Server" == platform.linux_distribution()[0]

if __name__ == "__main__":

  if is_redhat():
    print ("This system is running Red Hat")
  else:
    print("This system is not running Red Hat")
