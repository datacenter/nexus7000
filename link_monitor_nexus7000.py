#!/bin/env python
#Copyright (c) 2009-2010 by Cisco Systems, Inc.
#
#PLEASE READ CAREFULLY BEFORE DOWNLOADING OR USING THE SOFTWARE.
#
#BY OPENING THE PACKAGE, DOWNLOADING THE PRODUCT, OR USING THE EQUIPMENT THAT
#CONTAINS THIS PRODUCT, YOU ARE CONSENTING TO BE BOUND BY THIS AGREEMENT. 
#IF YOU DO NOT AGREE TO ALL OF THE TERMS OF THIS AGREEMENT, RETURN THE PRODUCT,
#OR DO NOT DOWNLOAD THE PRODUCT.
#
#Licensee acknowledges and agrees that: (a) the Software has not been 
#commercially released for sale by Cisco; (b) the Software may not be in final
#form or fully functional and it is expected that it may contain errors, design
#flaws or other problems which cannot or will not be corrected by Cisco;q
#(c) the Software and its use may result in unexpected results, loss of data, 
#project delays or other unpredictable damage or loss to Licensee; (d) Cisco is 
#under no obligation to release a commercial version of the Software and any 
#commercial product released may not be backward compatible and or the
#programming interfaces may change; and (e) Cisco has the right to unilaterally
#abandon development of the Software at any time and without any obligation or 
#liability to Licensee or any third Party. Licensee further agrees that
#
#THE SOFTWARE IS BEING SUPPLIED TO LICENSEE ON AN "AS IS" BASIS. ALL EXPRESS OR 
#IMPLIED CONDITIONS, REPRESENTATIONS, AND WARRANTIES INCLUDING, WITHOUT 
#LIMITATION, ANY IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A PARTICULAR 
#PURPOSE, NONINFRINGEMENT OR ARISING FROM A COURSE OF DEALING, USAGE, OR TRADE 
#PRACTICE, ARE HEREBY EXCLUDED TO THE EXTENT ALLOWED BY APPLICABLE LAW. 
#
#Licensee shall make no claim against Cisco for lost data, re-run time, 
#inaccurate output, work delays or lost profits resulting from the use or 
#operation of the Software."

"""
Goal of this script is to monitor a set of interface status and
act upon another set of interface status.

This Script,
    1.Shuts down all the interfaces mentioned in the -a options, when all the 
      interface mentioned in -m option is down
    2.Brings up all the interfaces mentioned in the -a options, when at least 
      one of the interface mentioned in -m option is back up

Script usage: link-monitor.py -m <interfaces> -a <interfaces> -l "$_syslog_msg" 
    Examples:
        link-monitor.py -m "eth1/1-10" -a "eth1/13-20" -l "$command"
        link-monitor.py -m "eth1/1 Eth1/2 Eth1/3" -a "eth1/20" -l "$command"
        link-monitor.py -m "eth1/1-10 Eth1/15-20" -a "eth1/30-32 eth1/37-38" -l "$command"

Script takes the following three arguments, 
    -m <Interfaces to monitor>
    -a <Interface to act on (shutdown/bringup)>
    -l <Syslog that matched the eem event pattern, passed using $command variable>

Script requires an EEM to be configured as below to work,
    event manager applet link_monitor
    event syslog pattern "IF_UP:|IF_.*DOWN:"
    action 1 cli source link_monitor_nexus7000.py -m eth1/2-5 -a eth1/7-8 -l "$_syslog_msg"

To display EEM policy, use
n7k# show event manager policy internal link_monitor
"""

import os
import re
import sys
import syslog
import logging
import logging.handlers
from optparse import OptionParser

#from cisco import CLI, cli, Interface
from cisco import *

MAX_LOG_BYTES = 1024*1024

def setup_logger():
    # Log File name
    log_file = "/bootflash/link-monitor.log"
    log = logging.getLogger('LINK_MONITOR')
    log.setLevel(logging.DEBUG)
    #Create file log handler and set level to debug
    fh = logging.handlers.RotatingFileHandler(log_file, maxBytes=(MAX_LOG_BYTES/2), backupCount=1)
    fh.setLevel(logging.DEBUG)

    #Create formatter
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    #Add formatter to log handlers
    fh.setFormatter(formatter)

    #Add log handlers to logger
    log.addHandler(fh)

    return log

log = setup_logger()

def sys_log(info):
    log.info(info)
    syslog.syslog(9, info)

def args_parser():
    usage = "Usage:\n\t%prog -m <interface|interfaces> -a <interface|interfaces>"
    parser = OptionParser(usage=usage)
    parser.add_option("-m", "--monitor", dest="monitors",
                      help="[interface | interfaces(seperated by space)] to monitor.")
    parser.add_option("-a", "--actor", dest="actors",
                      help="[interface | interfaces(seperated by space)] to act upon.")
    parser.add_option("-l", "--syslog", dest="syslog",
                      help="Syslog any interface state change")

    options, args = parser.parse_args()
    return options


class LinkMonitor(object):
    def __init__(self, mon_links, act_links, syslog):
        self.mon_links = mon_links.split()
        self.act_links = act_links.split()
        self.syslog = syslog
        self. mon_link_status = {}
        self.link_status = {}
#        self.int = None
        self.expanded_mon_links = self.expand(mon_links)
        self.expanded_act_links = self.expand(act_links)

    def normalize(self, interface):
        if ("eth" in interface or "Eth" in interface):
            match = re.search("[a-z A-Z]*([0-9/]*)", interface)
            if match:
                return "Ethernet%s" % match.group(1)

#    def normalize(self, interface):
#        try:
#            return self.int.normalize(interface)
#        except ValueError, err:
#            log.debug(err)
#            sys.exit(1)
        
    def expand(self, links):
        expanded_links = []
        for link in links.split():
           int_range = link.split("-")
           if len(int_range) == 2:
               slot_int = int_range[0].split("/")
               i = int(slot_int[1])
               while i <= int(int_range[1]):
                   expanded_links.append("%s/%s" % (self.normalize(slot_int[0]), i))
                   i += 1
           else:
               expanded_links.append(self.normalize(int_range[0]))
        return expanded_links
        

    def shutdown(self, interface):
        log.debug("shuting down interface %s", interface)
        cli("configure terminal")
        cli("interface %s" % interface)
        cli("shutdown")

    def bringup(self, interface):
        log.debug("Bringing up interface %s", interface)
        cli("configure terminal")
        cli("interface %s" % interface)
        cli("no shutdown")

    def update_interface_status(self):
        #cmd = CLI('show interface brief', False)
        cmd = cli("show interface brief")
        cmd_sp = cmd.split("\n")
        for line in cmd_sp:
            match = re.search("(^Eth[0-9/]+).*(up|down).*", line)
            if match:
                interface = self.normalize(match.group(1)) 
                if interface in self.expanded_mon_links:
                    self.mon_link_status.update({interface: match.group(2)})
                elif interface in self.expanded_act_links:
                    self.link_status.update({interface: match.group(2)})

    def state_change(self):
        match = re.search("IF_.*:\s*\w*\s*([a-zA-Z0-9/]*).*",  self.syslog)
        if match and self.normalize(match.group(1)) in self.expanded_mon_links:
            return True
        return False
    
    def act(self):
#        self.int = Interface('Ethernet1/1')
        if not self.state_change():
            log.debug("No state change in the interfaces under monitering")
            return

        sys_log("Interface state change detected by EEM")
        self.update_interface_status()
        log.debug("Current status of links to monitor: %s", self.mon_link_status)
        log.debug("Current status of links to act upon: %s", self.link_status)

        if ("up" in self.mon_link_status.values() and
            "down" in self.link_status.values()):
            log.debug("All the monitor links are not down")
            sys_log("Bringing up the links")
            for interface in self.act_links:
                self.bringup(interface)
        elif ("up" not in self.mon_link_status.values() and
              "up" in self.link_status.values()):
            log.debug("All the monitor links are down")
            sys_log("Shuting down the links")
            for interface in self.act_links:
                self.shutdown(interface)

def main():
    log.debug("Script link-monitor.py triggered by EEM")
    option = args_parser()
    if (not option.monitors or not option.actors or not option.syslog):
        log.debug("Mandatory arguments not provided.")
        return 1

    LinkMonitor(option.monitors, option.actors, option.syslog).act()

if __name__=="__main__":
    sys.exit(main())
