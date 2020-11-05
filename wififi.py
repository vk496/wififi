#!/usr/bin/env python3

import sys
import pyshark
import argparse
import argparse
from packet_struct import *
from display import *

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-f', '--file', action='store')
group.add_argument('-i', '--interface', action='store')
args = parser.parse_args()


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

    for index, k in enumerate(stations):
        ap = stations[k]
        
        is_w = print_w(ap)
        is_k = print_k(ap)
        is_v = print_v(ap)
        is_r = print_r(ap)
        is_s = print_s(ap)
        is_m = print_mimo(ap)
            
        
        # print(f"802.11k           : {is_k}")

        if any(ap.get_bssid() == a.get_AP() for i, a in ap_clients.items()):
            index_p="·-"
        else:
            index_p="  "

        # print(f"{index_p}{index}\t{ap.get_bssid()}\t{is_w}\t{is_k}\t{is_v}\t{is_r}\t{is_s}\t{is_m}\t{ap.get_essid()}")
        local_print(f"{index_p}{index}\t{ap.get_bssid()}\t{is_w}\t{is_k}\t{is_v}\t{is_r}\t{is_s}\t{is_m}\t{ap.get_essid()}\n")
        subi=1
        for f in ap_clients:
            cl = ap_clients[f]
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

import curses


if args.file:
    cap = pyshark.FileCapture(args.file)
else:
    screen = curses.initscr()
    capture = pyshark.LiveCapture(interface=args.interface)
    cap = capture.sniff_continuously()




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
        if args.interface and packet_count % 10 == 0:
            display_all(packet_count, curses=screen)


    
        # try:
        #     for i, ap in stations.items():
        #         print(ap.get_k())
        # except Exception:
        #     pass

if args.file:
    display_all(packet_count)
else:
    curses.endwin()
            

