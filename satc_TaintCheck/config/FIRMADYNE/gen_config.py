import os
import sys
import json

for f in os.listdir('../../eval/firmadyne/'):
    config_name = f + '.config'

    info = {"bin": [],
     "pickle_parsers": "",
     "var_ord": [""], "base_addr": "",
     "fw_path": "./eval/firmadyne/" + f,
     "only_string": "False",
     "angr_explode_bins": [], "glob_var": [],
     "eg_source_addr": "", "arch": "", "data_keys": []}

    with open(config_name, 'w') as outfile:
        json.dump(info, outfile)

