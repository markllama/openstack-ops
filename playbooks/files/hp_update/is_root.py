#!/bin/env python
from __future__ import print_function

import os

def is_root():
  return os.geteuid() == 0

if __name__ == "__main__":
  print("The user is {}root.".format("" if is_root() else "not "))
