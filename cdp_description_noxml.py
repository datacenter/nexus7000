#!/usr/bin/env python
#
# Copyright (C) 2014 Cisco Systems Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

'''
This script parses the output of "show cdp neighbors" and populates the
interface description based on this data

To invoke,

1. Copy the script into bootflash:scripts
2. Invoke from exec using "source <scriptname>"

This can also be integrated with EEM to be executed on any event, for example on
a link status change

'''

import sys
import re
from cisco import cli


# Sample Output of the CLI : 
'''
Capability Codes: R - Router, T - Trans-Bridge, B - Source-Route-Bridge
                  S - Switch, H - Host, I - IGMP, r - Repeater,
                  V - VoIP-Phone, D - Remotely-Managed-Device,
                  s - Supports-STP-Dispute

Device-ID          Local Intrfce  Hldtme Capability  Platform      Port ID
SW-JWALA-ECBU-KK23
                    mgmt0          142    S I       WS-C2950-24   Fas0/6        
Lotos-PE1(JAF1817AMLJ)
                    Eth7/5         154    R S s     N7K-C7009     Eth7/2        
Lotos-PE2(JAF1817AMLJ)
                    Eth7/6         132    R S s     N7K-C7009     Eth7/4        
Lotos-PE3(JAF1817AMLJ)
                    Eth7/7         169    R S s     N7K-C7009     Eth7/9        

Total entries displayed: 4
'''

# Execute the command on the switch
raw_input = cli("show cdp neighbors")

# Split the output into a list containing each line
all_raw_lines = raw_input.split('\n')
#print all_raw_lines



# We need to ignore the first few lines, including the header of the table. This
# code does that

all_device_lines = []
line_no = 0
dev_list = {}
for line in all_raw_lines:
    line_no += 1
    if line_no <= 6:
        pass
    else:
        all_device_lines.append(line)

# Also remove the last three lines, which contain the footer - Total Entries
# displayed

for i in range(3):
    all_device_lines.pop();


#print all_device_lines

# We now have only the table, which has a line containing switch nae followed by
# the cdp details

# We iterate through this to build up our dictionary of local ports connected to
# particular remote port and platform, switch

# We use the local port as the key

for idx, line in enumerate(all_device_lines):
    if (idx % 2 == 0):
        pass
    else: 
        thisline = re.split('\s+',line)
        dev_list[thisline[1]] = {}
        dev_list[thisline[1]]['remote_port'] = thisline[-2]
        dev_list[thisline[1]]['platform'] = thisline[-3]
        dev_list[thisline[1]]['switch_name'] = all_device_lines[idx-1]

# We can now use the data to configure the description on the switch

for key, value in dev_list.items():
    cli ("conf t ")
    cli ('interface ' + key + ' ; description ' + 'to ' + value['switch_name'] + ' (' +  value['platform'] + ') ' + value['remote_port'])


