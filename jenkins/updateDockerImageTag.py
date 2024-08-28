#!/usr/bin/python

import sys
import yaml

fname = "charts/eric-vm-vnfm-migration/eric-product-info.yaml"

stream = open(fname, 'r')
data = yaml.load(stream)

data['images']['mainImage']['tag'] = sys.argv[1]

with open(fname, 'w') as yaml_file:
    yaml_file.write( yaml.dump(data, default_flow_style=False))
