#!/usr/bin/env python3

import sys
import os
import pyshark
import argparse
import curses
from packet_struct import *
from display import *

parser = argparse.ArgumentParser()

gx = parser.add_argument_group('input options', 'various (mutually exclusive) ways to consume data')
group = gx.add_mutually_exclusive_group(required=True)
group.add_argument('-f', '--file', action='store', metavar='', help="Pcap file")
group.add_argument('-i', '--interface', action='store', help="Wireless interface in monitor mode", metavar='', choices=os.listdir('/sys/class/net/'))

parser.add_argument('-m', '--max', type=int, default=None, metavar='#', help="Max number of packets to read from interface (Default: unlimited)") #TODO: Disallow negative values
args = parser.parse_args()


if args.interface:
    with open(f'/sys/class/net/{args.interface}/type','r') as f:
        value = int(f.read())
        if value != 803:
            raise ValueError(f"{args.interface} is NOT in monitor mode")




def display_all(count_p, curses=None):
    def local_print(string):
        if curses:
            curses.addstr(string)    
        else:
            print(string, end='')

    if curses:
        curses.clear()

    local_print(f"packets analyzed: {count_p}\n")
    local_print("  AP\tBSSID\t\t\t11w\t11k\t11v\t11r\t11s\tMIMO\tESSID\n")
    local_print("-------------------------------------------------------------------------------\n")

    for index, k in enumerate(AP.stations):
        ap = AP.stations[k]
        
        is_w = print_w(ap)
        is_k = print_k(ap)
        is_v = print_v(ap)
        is_r = print_r(ap)
        is_s = print_s(ap)
        is_m = print_mimo(ap)
            
        
        # print(f"802.11k           : {is_k}")

        if any(ap.get_bssid() == a.get_AP() for i, a in AP.client_stations.items()):
            index_p="·-"
        else:
            index_p="  "

        # print(f"{index_p}{index}\t{ap.get_bssid()}\t{is_w}\t{is_k}\t{is_v}\t{is_r}\t{is_s}\t{is_m}\t{ap.get_essid()}")
        local_print(f"{index_p}{index}\t{ap.get_bssid()}\t{is_w}\t{is_k}\t{is_v}\t{is_r}\t{is_s}\t{is_m}\t{ap.get_essid()}\n")
        subi=1
        for f in AP.client_stations:
            cl = AP.client_stations[f]
            if cl.get_AP() == ap.get_bssid():
                is_w = print_w(cl)
                is_k = print_k(cl)
                is_v = print_v(cl)
                is_s = print_s(cl)
                is_m = print_mimo(ap)
                # print(f"·-{index}_{subi}\t{f}\t{is_w}\t{is_k}\t{is_v}\t{is_r}\t{is_s}\t{is_m}")
                local_print(f"·-{index}_{subi}\t{f}\t{is_w}\t{is_k}\t{is_v}\t{is_r}\t{is_s}\t{is_m}\n")

                subi=subi+1
        # print("___________________________")
        # print
    if curses:
        curses.refresh()


if args.file:
    cap = pyshark.FileCapture(args.file)
    screen = None
else:
    capture = pyshark.LiveCapture(interface=args.interface)
    cap = capture.sniff_continuously(packet_count=args.max)
    screen = curses.initscr()
    screen.scrollok(True)




packet_count = 0

for p in cap:
    if 'WLAN' in p: # Only WLAN packets
        try:
            if p.wlan.fc_type == '0': # Managment
                process_management(p)
            elif p.wlan.fc_type == '1': # Control
                process_control(p)
            elif p.wlan.fc_type == '2': # Data
                process_data(p)
            elif p.wlan.fc_type == '3': # Extension
                pass
        except Exception as e:
            if 'MALFORMED' in p.highest_layer:
                continue
            else:
                raise e

    packet_count+=1
    if args.interface and packet_count % 13 == 0:
        display_all(packet_count, curses=screen)


display_all(packet_count)
            

