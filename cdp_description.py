#!/usr/bin/env python
#
# Copyright (C) 2014 Cisco Systems Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This script add description to interfaces based on "cdp neighbors" information.
#
#  To use:
#
# 		1. Copy script to N7K switch bootflash:scripts/
# 		2. Execute using: source cdp_description.py
#
# This script was tested on N7K using 6.2(5) release.
#
from cisco import cli
import sys
import xml.etree.cElementTree as ET

# Get interface information in XML format
print
print 'Executing CDP description script '
print


cdp_dict = {}

def extract_cdp_info():
    #cli | xml
    raw = cli('show cdp neighbors | xml | exclude "]]>]]>"')

    # Load and parse XML
    tree = ET.ElementTree(ET.fromstring(raw))
    data = tree.getroot()
    
    cdp_info = '{http://www.cisco.com/nxos:6.2.5.:cdpd}'
    for i in data.iter(cdp_info + 'ROW_cdp_neighbor_brief_info'):
        #parse interface, port and platform info from xml output
        intf_id = i.find(cdp_info + 'intf_id').text
        port_id = i.find(cdp_info + 'port_id').text
        platform_id = i.find(cdp_info + 'platform_id').text

        #save the info in a dictionary
        if intf_id not in cdp_dict:
            cdp_dict[intf_id] = {}
        cdp_dict[intf_id]['intf_id'] = intf_id
        cdp_dict[intf_id]['platform_id'] = platform_id
        cdp_dict[intf_id]['port_id'] = port_id

#add description based on the cdp information
def add_description():
    for key, value in cdp_dict.items():
        if 'port_id' in value and 'platform_id' in value and 'intf_id' in value:
            cli("conf t ")
            cli('interface ' + value['intf_id'] + ' ; description ' + value['platform_id'] + ' ' + value['port_id'])


def main():
    #extract cdp neighbors info
    extract_cdp_info()
    #add description to interfacesbased on cdp info.
    add_description()



if __name__=="__main__":
    sys.exit(main())
