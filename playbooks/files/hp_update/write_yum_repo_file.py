#!/bin/env python
from __future__ import print_function

import re
import os
repo_template = """\
[hp-spp]
name = HP Service Pack for ProliantPackage
baseurl = https://downloads.linux.hpe.com/SDR/repo/spp-{}/rhel/$releasever/$basearch/{}
enabled = 1
gpgcheck = 1
gpgkey = https://downloads.linux.hpe.com/SDR/repo/spp/GPG-KEY-spp"
"""

def write_hp_repo_file(gen, release, repodir="/etc/yum.repos.d", repofile="hp-spp.repo"):
    """
    Write a repo file to pull RPMs from HP for firmware updates.
    """
    hardware_generations = ['gen8', 'gen9', 'gen10']
    release_pattern="^\d{4}\.\d{2}\..+$"

    # TODO - check inputs
    
    repo_text = repo_template.format(gen, release)
    repo_path = os.path.join(repodir, filename)
    
    repo_fd = open(repo_path, "w+")
    repo_fd.write(repo_text)
    repo_fd.close()

if __name__ == "__main__":

    (gen, release) = os.argv[1:2]
    
    
    

    
