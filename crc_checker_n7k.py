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
#
#The following python script checks for CRC errors on all interfaces.
#If crc error > threshold(10) on any interface,  then it prints that interface
"""
Here is sample output of this script

n7k# source crc
----------------------------------
Started running CRC checker script
found CRC errors >  10
shutting interface  Eth1/2       
finished running CRC checker script
----------------------------------

Switch # dir bootflash:scripts
Feb 10 14:50:36 2014  crc.py

"""

from cisco import *
import re
import sys
import syslog

threshold = 10


def shut_interface_and_creat_syslog(counter):
   # print "input counter:",counter
    interfaces_list = cli("show int description | grep eth")
    s = interfaces_list.split("\n")
    match = re.search("(.*) eth \s*", s[counter])
    match.group(1)
    #create a syslog
    syslog(1,"Found CRC errrors > threshold on intreface eth", match.group(1));

    #call cli to shut the interface.
    cli("conf t")
    cli("interface " + match.group(1))
    cli("shut")
    print "shutting interface ", match.group(1)

def main():
    counter = 0
    print "----------------------------------"
    print "Started running CRC checker script"
    crc = cli("show int | grep CRC")
    s=crc.split("\n")

    for line in s:
        match = re.search("\s* giants  (.*) CRC/FCS \s*", line)
        if match and match.group(1):
            if int(match.group(1)) > threshold:
                print "found CRC errors > ", threshold
                #shut the interface with crc errors> threshold
                shut_interface(counter)                
        counter +=1
    print "finished running CRC checker script"
    print "----------------------------------"


if __name__ == "__main__":
    sys.exit(main())

