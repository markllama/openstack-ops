#!/usr/bin/env python
from __future__ import print_function
#
#
#
import json
import yaml

device_map = {
  'ILO': { 'type': 'ilom', 'name': 'ilom' },
  'SYSTEM': {'type': 'bios', 'name': 'bios'},
  'SYSTEM-MELTDOWN': {'type': 'bios', 'name': 'meltdown'},
  'RAID': {'type': 'raid', 'name': 'raid'},
  'NIC': {'type': 'nic', 'name': 'nic'},
  'INIC': {'type': 'nic', 'name': 'inic'}
}

device_type_map = {
  'ILO': 'ilom',
  'SYSTEM': 'bios',
  'SYSTEM-MELTDOWN': 'bios',
  'RAID': 'raid',
  'NIC': 'nic',
  'INIC': 'inic'
}

def convert_spec(name, data):
  spec = {
    'name': name,
  }

  spec['spp'] = {
    'gen': data['spp-gen'],
    'version': data['spp-version']
  }
    
  spec['devices'] = [convert_device(dname, data[dname]) for dname in device_map.keys()]

  return spec


def convert_device(dtype, dspec):
  spec = {
    'type': device_map[dtype]['type'],
    'name': device_map[dtype]['name'],
    'package': {
      'name': dspec['fwpkg'],
      'md5': dspec['md5']
    }
  }

  if type(dspec['ver']) == str:
    spec['versions'] = [
      {
        'model': None,
        'match_string': dspec['ver']
      }
    ]
    
  elif type(dspec['ver']) == dict:
    spec['versions'] = []
    for model, match_string in dspec['ver'].items():
      spec['versions'] += [{'model': model, 'match_string': match_string}]

    
  return spec

if __name__ == "__main__":
  old_data = json.load(open("../firmware_data.json"))

  #print("There are {} specs".format(len(old_data['firmware_specs'])))


  new_data = {}
  new_data['firmware_cache_url'] = old_data['firmware_cache_url']
  new_data['systems'] = [convert_spec(s[0], s[1]) for s in old_data['firmware_specs'].items()]

  print(yaml.dump(new_data, indent=2))
  
