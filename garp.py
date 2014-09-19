#!/usr/bin/env python
####################################################################
# File:    arp.py
# Name:    Peppe Monterosso
# Description: ARP microflow policer
#
# Copyright (c) 2013 by cisco Systems, Inc.
# All rights reserved.
#
####################################################################


"""
Auto-detect and block malformed ARP requests coming from random sources and excessive ARP/GARP requests

The Python script allows a Nexus 7000 system to automatically detect if malformed ARP packets (length greater than 128 bytes) are hitting the control plane.
Upon detection via deep packet inspection, the script creates a separate ARP access-list with the offending mac addresses. The "quarantine" access-list can be policed separately, allowing control plane protection.
Example:
ARP access list copp-arp-quarantine
10 permit ip any mac host 0000.0700.0700
20 permit ip any mac host 0000.0700.0701
30 permit ip any mac host 0000.0700.0702

The script also checks for excessice ARP/GARP. Upon detection via deep packet inspection, the script creates a separate ARP access-list (throttle) with the offending mac addresses

When the script run for the first time, it checks if there is a standard CoPP configured based on well know system profiles "dense", "lenient", "moderate", "strict".
In case a standard CoPP is configured, a Custom profile will be configured based on the system profile originally configured

After this initial check, the script starts a packet capture, 1000 ARP packets (this can be tuned)
Once the ARP packet capture is completed, the code look for malformed ARP
The script then put the offending MACs into the Quarantine ARP access list
Example:
Malformed ARP detected for MAC 00:00:07:00:07:00
Malformed ARP detected for MAC 00:00:07:00:07:01
Malformed ARP detected for MAC 00:00:07:00:07:02

 --------------
| APPLY Quarantine settings!
 --------------

If no malformed ARP are detected the following message is printed:
 --------------
| NO Malformed ARP detected!
 --------------

In case of excessive ARP/GARP requests the throttle logic will be applied


All the actions are logged into the syslog. Example:

ARP Python Script: Malformed ARP detected for MAC 00:00:07:00:07:00
ARP Python Script: Throttle MAC address 00:00:07:00:07:00, Seen 304 times (27%) during capture
ARP Python Script: Throttle GARP for IP address 10.10.10.2, Seen 202 times (17%) during capture

"""

import cisco
import sys
import argparse
import re
import inspect
from datetime import datetime as dt

# logger severity constants
error = 0
warning = 1
info = 2

g_trace_file_path = "/volatile/arp.log"
g_log_default_sev = info
g_log_max_sev = error
g_trace = False

violation_file = "/volatile/violation.log"

#------------------------------------------------------------------------------
# basic logger
# msg is a message, sev is optional severity which defaults to 'info'

def log(msg,sev=g_log_default_sev, debug = 0):
    log_severity = ["error","warning","info"]
    if debug:
        msg = inspect.stack()[1][3] + "(): " + msg
        print dt.now(),"["+log_severity[sev]+"] "+msg
    elif sev <= g_log_max_sev:
        print "["+log_severity[sev]+"] "+msg
            
        
#------------------------------------------------------------------------------
# get cli output

def get_cli(cmd):
    global g_trace
    
    try:
        op = cisco.cli(cmd)
    except:
        if cmd.find("|")!=-1:
            # this might be benign, because command executed after pipe returned non-zero rc
            sev = info
        else:
            sev = error
        log("exception for: '"+cmd+"'",sev)
        # in iluka we still get the output...
        op = sys.exc_value
    if type(op)==tuple:
        op = op[1]      # for obscure reason cli() on n6k returns tuple (status, output), not string
    elif type(op)==str:
        op = op.split("\n")
    if g_trace:        
        try:
            trace_file = open(g_trace_file_path,"a+")
            trace_file.write("cmd:"+cmd+"\n")
            for line in op:
                trace_file.write(line+"\n")
            trace_file.close()
        except:
            log("exception while saving trace data, disabling tracing",error)
            g_trace = False
    return op

#------------------------------------------------------------------------------    
# scrub data from outputs using regular expressions

class scrubber:
    FLAT = 0
    PER_LINE = 1
    FIRST_MATCH = 2
    def __init__(self):
        self.success = False    # result of last scrub
        self.data = []          # captures from last scrub
    #------------------------------------------------------------------------------    
    # output: list of strings to scrub from  
    # rex: regular expression (what to match and what to capture in parenthesis)
    # mode: how to store results
    #        0 - default, return all captures as 1-dimension list, i.e. [capture]
    #        1 - all matches from single line are grouped in a list, i.e. 2-dimensions: [line][capture]
    #            this is useful when we don't know how many matches given line will produce
    #        2 - 1st match, this is useful when we just care about 1st match
    # debug: print various intermediate data
    def scrub(self, output, rex, mode = 0, debug = 0):   
        matches = []
        # fixup for the case of output being a single string
        if type(output)==str:
            output = [output]
        for line in output:
            line_matches = []
            for match in re.findall(rex,line):
                if debug:
                    print "scrub_line:",line
                    print "scrub_match:",match
                # if there is >1 capture group findall returns a list of tuples (tuple of all groups)
                # else findall returns a list of a single capture group
                if type(match)==tuple:
                    line_matches += list(match)
                else:
                    line_matches += [match]
                if mode == self.FIRST_MATCH:
                    self.data = match
                    self.success = True
                    return 1
            if line_matches:
                if mode==scrubber.FLAT:
                    matches += line_matches
                elif mode==scrubber.PER_LINE:
                    matches += [line_matches]
        if debug:
            print "scrub_total:",len(matches)
        self.data = matches
        self.success = bool(matches)
        return len(matches)
    #------------------------------------------------------------------------------    
    # cli scrub
    #
    def scrub_cli(self, cmd, rex, mode = 0, debug = 0):
        return self.scrub(get_cli(cmd), rex, mode, debug)



#------------------------------------------------------------------------------    
# START of the actual program

mac_quarantine_list = []
mac_throttle_list = []
mac_garp_throttle_list = []
num_packets = 1
num_packets_garp = 1
packet_capture_num = "1000"
violation_threshold = 0
version = "0.7.10"

print "Version " + version + "\n"
device_version = scrubber()
device_version.scrub_cli("show version | i system | i version", r"[0-9]+.[0-9]+",2,0)

def packet_capture():
    cli("ethanalyzer local interface inband decode-internal capture-filter arp display-filter arp limit-captured-frames " + packet_capture_num + " autostop duration 15 write volatile:ARP.pcap")
    return

def count_arp_request():
    return int(cli("ethanalyzer local read volatile:ARP.pcap display-filter arp limit-captured-frames " + packet_capture_num + " | i Who | count"))

def count_arp_gratuitous():
    return int(cli("ethanalyzer local read volatile:ARP.pcap display-filter arp limit-captured-frames " + packet_capture_num + " | i Gratuitous | count"))

class pkt_mac_desc:
    def __init__(self, frequency, mac, vlan):
        self.frequency = frequency
        self.mac = mac
        self.vlan = vlan
    def __repr__(self):
        return repr([self.frequency, self.mac, self.vlan])

class pkt_ip_desc:
    def __init__(self, frequency, ip, vlan):
        self.frequency = frequency
        self.ip = ip
        self.vlan = vlan
    def __repr__(self):
        return repr([self.frequency, self.ip, self.vlan])

def is_violation_occurring():
    sc = scrubber()
    rc = False
    #if file not present, create one
    f = open(violation_file, "a+")
    f.close()
    sc.scrub_cli("show policy-map interface control-plane class custom-copp-arp-allowed | i violated",r"[0-9]+",0,0)
    f = open(violation_file, "r")
    if f.read() == '':  #file is empty
        f = open(violation_file, "w")
        for viol in sc.data:
            f.write(viol + "\n")
    else:
        # Compare old data with new data
        f = open(violation_file, "r")
        for viol in sc.data:
             viol_old = f.readline()
             if  int(viol) > (int(viol_old) + violation_threshold):
                 rc = True
        # Store new data
        f = open(violation_file, "w")
        for viol in sc.data:
            f.write(viol + "\n")
    f.close()
    return rc

def update_violation():
    sc = scrubber()
    sc.scrub_cli("show policy-map interface control-plane class custom-copp-arp-allowed | i violated",r"[0-9]+",0,0)
    # Store new data
    f = open(violation_file, "w")
    for viol in sc.data:
        f.write(viol + "\n")
    f.close()
    return

def is_mts_l2fm_buffer_big():
    sc = scrubber()
    rc = False
    #Get L2fm SAP number
    sc.scrub_cli("show system internal mts sup apps | i L2fm",r"[0-9]+",2,0)
    l2fm_sap = sc.data
    if (sc.scrub_cli("show system internal mts buffers summary | i " + l2fm_sap,r"\S+",0,0) != 0):
        if (int(sc.data[2]) > 4000):
            rc = True
    return rc

def mac_is_not_static(mac_add):
    sc = scrubber()
    if sc.scrub_cli("show mac address-table address " + mac_add + " | i static",r"static",2,0):
        # Found a static entry
        return False
    else:
        # Not Found any static entry
        return True


cli("end")

#------------------------------------------------------------------------------
# Need to Analyse CoPP and create the custom class-map
#------------------------------------------------------------------------------
if ((cli("show policy-map interface control-plane | i quarantine") == '') | (cli("show policy-map interface control-plane | i throttle") == '')):
    policy_name_standard = ["copp-system-p-policy-dense",
                            "copp-system-p-policy-lenient",
                            "copp-system-p-policy-moderate",
                            "copp-system-p-policy-strict"]
    policy_name_profile = ["dense",
                           "lenient",
                           "moderate",
                           "strict"]
    policy_name = scrubber()
    copp_policy_name = []
    # get current service-policy name
    if policy_name.scrub_cli("show copp status | i Policy-map",r"[\S]+", 0, 0):
        cli("config t")
        # if device is using a standard CoPP profile create a custom profile of the same nature
        if (policy_name_standard.count(policy_name.data[5]) != 0):
            i = policy_name_standard.index(policy_name.data[5])
            print("\n\n --------------")
            print("| System CoPP in use. Profile: " + policy_name_profile[i])
            print("| Apply a Custom CoPP profile based on " + policy_name.data[5])
            print(" --------------\n\n")
            # Create the profile with prefix custom
            cli("copp copy profile " + policy_name_profile[i] + " prefix custom")
            copp_policy_name = "custom-copp-policy-" + policy_name_profile[i]
            # Apply the new CoPP
            cli("control-plane")
            cli("service-policy input " + copp_policy_name)
        else:
            copp_policy_name = policy_name.data[5]
            print("\n\n --------------")
            print("| Custom CoPP in use. Name: " + copp_policy_name)
            print("| Update Custom CoPP to support granular ARP classes")
            print(" --------------\n\n")
        #Create ARP access-list. If already created, overwrite
        cli("arp access-list copp-arp-quarantine")
        cli("arp access-list copp-arp-throttle")
        cli("arp access-list copp-garp-throttle")
        cli("arp access-list copp-arp-allowed")
        cli("1000 permit ip any mac any")
        #Create Custom ARP class-map. If already created, overwrite
        cli("class-map type control-plane custom-copp-arp-quarantine")
        cli("match access-group name copp-arp-quarantine")
        cli("class-map type control-plane custom-copp-arp-throttle")
        cli("match access-group name copp-arp-throttle")
        cli("match access-group name copp-garp-throttle")
        cli("class-map type control-plane custom-copp-arp-allowed")
        cli("match access-group name copp-arp-allowed")
        #Apply new class-map. Set logging drop threshold
        cli("policy-map type control-plane " + copp_policy_name)
        cli("class custom-copp-arp-quarantine")
        cli("police 10")
        cli("class custom-copp-arp-throttle")
        cli("police 32 kbps")
        cli("class custom-copp-arp-allowed")
        cli("police 680 kbps")
        #remove match ARP
        if (cli("show class-map type control-plane custom-copp-class-normal | i arp")!=''):
            cli("class-map type control-plane match-any custom-copp-class-normal")
            cli("no match protocol arp")
        cli("end")

#------------------------------------------------------------------------------
# Function to detect Malformed ARP and Excessive ARP
#------------------------------------------------------------------------------
def arp_malformed_storm_detection():
    #------------------------------------------------------------------------------
    # Count packet capture - Assume packet capture has been done
    #------------------------------------------------------------------------------
    num_packets = count_arp_request()
    #
    #
    #------------------------------------------------------------------------------
    # Extract Source MAC, Packet length and VLAN
    #------------------------------------------------------------------------------
    macs = []
    length_num = []
    vlans = []
    tmp_mac = scrubber()
    tmp_length = scrubber()
    tmp_vlans = scrubber()
    request_reply = scrubber()
    tmp_mac.scrub_cli("ethanalyzer local read volatile:ARP.pcap display-filter arp limit-captured-frames " + packet_capture_num + " detail | i Sender | i MAC | no-more",r"[0-9a-f:]{17}",1,0)
    tmp_length.scrub_cli("ethanalyzer local read volatile:ARP.pcap display-filter arp limit-captured-frames " + packet_capture_num + " detail | i Frame | i Length | no-more",r"[0-9]+")
    tmp_vlans.scrub_cli("ethanalyzer local read volatile:ARP.pcap display-filter arp limit-captured-frames " + packet_capture_num + " detail | i VLAN | no-more",r"[0-9]+")
    request_reply.scrub_cli("ethanalyzer local read volatile:ARP.pcap display-filter arp limit-captured-frames " + packet_capture_num + " detail | i Address | i Resolution | i Protocol | no-more",r"request|reply")
    # packets length and VLAN are string - convert to numbers - filter the request only
    if (len(tmp_mac.data) == len(tmp_length.data) == len(tmp_vlans.data) == len(request_reply.data)):
        for i in range(len(tmp_length.data)):
            if (request_reply.data[i] == 'request'):
                macs.append(tmp_mac.data[i][0])
                length_num.append(int(tmp_length.data[i]))
                vlans.append(int(tmp_vlans.data[i]))
    #
    #
    #------------------------------------------------------------------------------
    # Create MAC statistics for top talkers - throttle
    #------------------------------------------------------------------------------
    if ((len(vlans) > 0) & (len(macs) > 0)):
        mac_throttle_list.append(pkt_mac_desc(1, macs[0], vlans[0]))
        for i in range (1, num_packets):
            for j in range (0, len(mac_throttle_list)):
                if (macs[i] == mac_throttle_list[j].mac):
                    mac_throttle_list[j].frequency += 1
                    break
                elif (j == (len(mac_throttle_list) - 1)):
                    mac_throttle_list.append(pkt_mac_desc(1, macs[i], vlans[i]))
        mac_throttle_list.sort(key=lambda pkt_mac_desc : pkt_mac_desc.frequency, reverse=True)
    #
    #
    #------------------------------------------------------------------------------
    # Create MAC ACL Quarantine based on malformed packet length
    #------------------------------------------------------------------------------
    for i in range (num_packets):
        if (length_num[i] > 128):
            # print "Malformed ARP detected: packet length", length_num[i], "offending MAC " + macs[i]
            # First entry created if list empty
            if (mac_quarantine_list == []):
                mac_quarantine_list.append(macs[i])
            else:
                # First time I see the MAC address, append to the list
                if (mac_quarantine_list.count(macs[i]) == 0):
                    mac_quarantine_list.append(macs[i])
    return num_packets


#------------------------------------------------------------------------------
# Function to detect Excessive GARP
#------------------------------------------------------------------------------
def garp_storm_detection():
    #------------------------------------------------------------------------------
    # Count packet capture
    #------------------------------------------------------------------------------
    num_packets_garp = count_arp_gratuitous()
    #
    #
    #------------------------------------------------------------------------------
    # Extract Source MAC addresses for ARP request
    #------------------------------------------------------------------------------
    ip_add = scrubber()
    ip_add.scrub_cli("ethanalyzer local read volatile:ARP.pcap display-filter arp limit-captured-frames " + packet_capture_num + " | i Gratuitous | no-more",r"\d+\.\d+\.\d+\.\d+",1,0)
    #
    #
    #------------------------------------------------------------------------------
    # Create IP statistics for top talkers - throttle
    #------------------------------------------------------------------------------
    if (len(ip_add.data) > 0):
        mac_garp_throttle_list.append(pkt_ip_desc(1, ip_add.data[0][0], 0))
        for i in range (1, num_packets_garp):
            for j in range (0, len(mac_garp_throttle_list)):
                if (ip_add.data[i][0] == mac_garp_throttle_list[j].ip):
                    mac_garp_throttle_list[j].frequency += 1
                    break
                elif (j == (len(mac_garp_throttle_list) - 1)):
                    mac_garp_throttle_list.append(pkt_ip_desc(1, ip_add.data[i][0], 0))
        mac_garp_throttle_list.sort(key=lambda pkt_ip_desc : pkt_ip_desc.frequency, reverse=True)
    return num_packets_garp



#------------------------------------------------------------------------------
# Decide what function to call based on flag
#------------------------------------------------------------------------------
flag = 0
if (is_violation_occurring() == True):
    flag = 1 # Violations are occurring

if (is_mts_l2fm_buffer_big() == True):
    if (flag == 0):
        flag = 2 # GARP only, no violations
    else:
        flag = 3 # Violations and GARP

if (flag == 1):
    packet_capture()
    num_packets = arp_malformed_storm_detection()
elif (flag == 2):
    packet_capture()
    num_packets_garp = garp_storm_detection()
elif (flag == 3):
    packet_capture()
    num_packets = arp_malformed_storm_detection()
    num_packets_garp = garp_storm_detection()


#------------------------------------------------------------------------------
# Apply mac ACL Modifications
#------------------------------------------------------------------------------
perc = 0
arp_access_list_modify = False

if (mac_quarantine_list != []):
    print "\n\n --------------"
    print "| Malformed ARP detected - APPLY Quarantine settings!"
    print " --------------\n\n"
    arp_access_list_modify = True
    cli("config t")
    cli("arp access-list copp-arp-quarantine")
    for mac in mac_quarantine_list:
        print "Malformed ARP detected for MAC", mac
        cli("logit ARP Python Script: Malformed ARP detected for MAC " + mac)
        cli("permit ip any mac host " + mac)
elif (mac_throttle_list != []):
    print "\n\n --------------"
    print "| NO Malformed ARP detected - Look for excessive"
    print " --------------\n\n"
    for i in range(len(mac_throttle_list)):
        if ((mac_throttle_list[i].frequency >= 35) & (mac_is_not_static(mac_throttle_list[i].mac))):
            perc = (mac_throttle_list[i].frequency * 100) / num_packets
            if (perc >= 8):
                if (arp_access_list_modify == False):
                    arp_access_list_modify = True
                    cli("config t")
                    cli("arp access-list copp-arp-throttle")
                print "Throttle MAC address {}, Seen {} timer ({}%) during capture".format(mac_throttle_list[i].mac, mac_throttle_list[i].frequency, perc)
                cli("permit ip any mac host " + mac_throttle_list[i].mac)
                cli("logit ARP Python Script: Throttle MAC address {}, Seen {} times ({}%) during capture".format(mac_throttle_list[i].mac, mac_throttle_list[i].frequency, perc))

if (mac_garp_throttle_list != []):
    print "\n\n --------------"
    print "| GARP detected - Look for excessive"
    print " --------------\n\n"
    for i in range(len(mac_garp_throttle_list)):
        if (mac_garp_throttle_list[i].frequency >= 35 ):
            perc = (mac_garp_throttle_list[i].frequency * 100) / num_packets_garp
            if (perc >= 8):
                if (arp_access_list_modify == False):
                    arp_access_list_modify = True
                    cli("config t")
                    cli("arp access-list copp-garp-throttle")
                print "Throttle GARP for IP address {}, Seen {} timer ({}%) during capture".format(mac_garp_throttle_list[i].ip, mac_garp_throttle_list[i].frequency, perc)
                cli("permit ip host " + mac_garp_throttle_list[i].ip + " mac any")
                cli("logit ARP Python Script: Throttle GARP for IP address {}, Seen {} times ({}%) during capture".format(mac_garp_throttle_list[i].ip, mac_garp_throttle_list[i].frequency, perc))

if (arp_access_list_modify == True):
    cli("end")
    update_violation()

