#!/usr/bin/env python

import sys
import pyshark
from colorama import init
from colorama import Fore, Back, Style

init()


rfile="wifidump.pcap-01.cap"
rfile="iphone5-80211k.pcap"
rfile="802.11r-01.cap"
rfile="802.11r-air-01.cap"
rfile="iphone5-EAP-FT-over-air-ch40.pcap"
rfile="mesh.pcap"

if len(sys.argv) > 1:
    rfile=sys.argv[1]



### 802.1w protected frames:
# w_protected=(
#     10, # Disassociate
#     12, # Deauthentication
#     24, # Block ACK req
#     25, # Block ACK
# )


def valid_bssid(x):
    return {
        'ff:ff:ff:ff:ff:ff': False,
        '00:00:00:00:00:00': False,
    }.get(x, True)

def get_bap(bss):

    if not valid_bssid(bss):
        return

    try:
        myAp = stations[bss]
    except KeyError:
        myAp = AP(p)
        stations[bss] = myAp
    
    return myAp


def get_cap(client_bssid):
    try:
        c = ap_clients[client_bssid]
    except KeyError:
        c = AP(p, client=client_bssid)
        ap_clients[client_bssid] = c
    
    return c

def process_management(p):
    # process_client(p)
    if p.wlan.fc_type_subtype == '8': # Beacon frames
        bss = p.wlan.bssid # bssid sometimes can report all "0" or "f"
        get_bap(bss).update_beacon(p)
    
    elif p.wlan.fc_type_subtype == '4': # Probe request    
        client_bssid = p.wlan.sa
        get_cap(client_bssid).update_probe_request(p)

    elif p.wlan.fc_type_subtype == '5': # Probe response
        bss = p.wlan.bssid
        client_bssid = p.wlan.da

        get_bap(bss).update_probe_response(p) # Register if not exists

    elif p.wlan.fc_type_subtype == '0': # Association request
        bss = p.wlan.bssid
        client_bssid = p.wlan.ta

        get_bap(bss) # Register if not exists
        get_cap(client_bssid).update_association_request(p)

    elif p.wlan.fc_type_subtype == '1': # Association response
        bss = p.wlan.bssid
        client_bssid = p.wlan.ra

        get_bap(bss) # Register if not exists
        get_cap(client_bssid)

    elif p.wlan.fc_type_subtype == '2': # Reassociation req
        bss = p.wlan.bssid
        ap = get_bap(bss) # Register if not exists

        if p.wlan.ta == bss:
            cli = get_cap(p.wlan.ra)
            sender = ap
        else:
            cli = get_cap(p.wlan.ta)
            sender = cli

        sender.update_reassociation_request(p)

    elif p.wlan.fc_type_subtype == '3': # Reassociation response
        bss = p.wlan.bssid
        ap = get_bap(bss) # Register if not exists

        if p.wlan.ta == bss:
            cli = get_cap(p.wlan.ra)
            sender = ap
        else:
            cli = get_cap(p.wlan.ta)
            sender = cli

        sender.update_reassociation_response(p)

    elif p.wlan.fc_type_subtype == '11': # Authentication
        bss = p.wlan.bssid
        ap = get_bap(bss) # Register if not exists

        if p.wlan.ta == bss:
            cli = get_cap(p.wlan.ra)
            sender = ap
        else:
            cli = get_cap(p.wlan.ta)
            sender = cli

        sender.update_authentication(p)
        

    elif p.wlan.fc_type_subtype == '13': # Action.
        bss = p.wlan.bssid
        ap = get_bap(bss) # Register if not exists
        

        if p.wlan.ta == bss:
            cli = get_cap(p.wlan.ra)
            sender = ap
        else:
            cli = get_cap(p.wlan.ta)
            sender = cli

        cli.update_relationship(bss)
        sender.update_action(p)



    else: # For the case...
        if 'bssid' in p.wlan.field_names:
            bss = p.wlan.bssid
            get_bap(bss).logic_w(p) # Register if not exists and check 802.11w




    
        

def process_control(packet):
    # Verify if possible. Don't register new elements

    # If someone is already registered as AP, verify w
    for bssid_ap, ap in stations.items():
        if 'ra' in packet.wlan.field_names and bssid_ap == packet.wlan.ra:
            ap.logic_w(packet)

        if 'ta' in packet.wlan.field_names and bssid_ap == packet.wlan.ta:
            ap.logic_w(packet)
        
    # The same for clients
    for bssid_cli, cli in ap_clients.items():
        if 'ra' in packet.wlan.field_names and bssid_cli == packet.wlan.ra:
            cli.logic_w(packet)

        if 'ta' in packet.wlan.field_names and bssid_cli == packet.wlan.ta:
            cli.logic_w(packet)

def process_data(p):
    if p.wlan.fc_type_subtype == '40': # QoS Data

        if 'bssid' in p.wlan.field_names:
            bss = p.wlan.bssid
            client_bssid = p.wlan.staa
        else:
            if p.wlan.ta in stations:
                bss = p.wlan.ta
                client_bssid = p.wlan.ra
            elif p.wlan.ta in ap_clients:
                bss = p.wlan.ra
                client_bssid = p.wlan.ta
            else:
                return

        get_bap(bss) # Register if not exists
        get_cap(client_bssid) # Register if not exists

        if p.wlan.ta == bss:
            sender = get_bap(bss)
        else:
            sender = get_cap(client_bssid)

        sender.update_data(p)

        




#########
stations = dict()
ap_clients = dict()
###3

def check_available_r(packet):
    verified = False
    status = None
    if 'wlan.mgt' in packet:
        if 'wlan_mobility_domain_ft_capab_ft_over_ds' in packet['wlan.mgt'].field_names:
            if '1' in packet['wlan.mgt'].wlan_mobility_domain_ft_capab_ft_over_ds:
                status = "DS"
            else:
                status = "Air"
        else:
            status = False

        if 'wlan_ft_snonce' in  packet['wlan.mgt'].field_names:
            verified = True
    
    return status, verified


def check_available_v(packet):
    verified = False
    status = None
    if 'wlan.mgt' in packet:
        #wlan.extcap.b19 == 0
        if 'wlan_extcap_b19' in packet['wlan.mgt'].field_names:
            if packet['wlan.mgt'].wlan_extcap_b19 == '1':
                status = True
            else:
                status = False
        
        # wlan.fixed.action_code == 23
        if 'wlan_fixed_action_code' in packet['wlan.mgt'].field_names:
            if packet['wlan.mgt'].wlan_fixed_action_code == '23' or packet['wlan.mgt'].wlan_fixed_action_code == '24':
                verified = True
            

    return status, verified

def check_available_w(packet):
    verified = False
    status = None
    if 'wlan.mgt' in packet:
        if 'wlan_rsn_capabilities' in packet['wlan.mgt'].field_names:
            if packet['wlan.mgt'].wlan_rsn_capabilities_mfpr == '1':
                status = "Required"
            elif packet['wlan.mgt'].wlan_rsn_capabilities_mfpc == '1':
                status = "Optional"
            else:
                status = False

        if packet.wlan.fc_protected == '1': # If Mgn have protected bit, we are sure is 802.11w
            verified = True

    if packet.wlan.fc_type == '1' and packet.wlan.fc_protected == '1': # The same for control
        verified = True
    
    return status, verified
        

def check_available_k(packet):
    verified = False
    status = None
    if 'wlan.mgt' in packet:
        if p.wlan.fc_type == '0' and (p.wlan.fc_type_subtype == '0' or p.wlan.fc_type_subtype == '8'): # Available just in beacons or assoc req
            status = False
            if 'wlan_rmcap' in packet['wlan.mgt'].field_names:
                if packet['wlan.mgt'].wlan_rmcap_b1 == '1':
                    status = True

        #wlan.tag.number == 52
        if 'wlan_rm_action_code' in packet['wlan.mgt'].field_names:
            if packet['wlan.mgt'].wlan_rm_action_code == '4' or packet['wlan.mgt'].wlan_rm_action_code == '5':
                status = True
                verified = True


    return status, verified

class AP:
    def __init__(self, packet, client=False):
        self._packet = packet

        if not client:
            self.bssid = packet['wlan'].bssid
        else:
            self.bssid = client

        self.ap_connected = None

        self.essid = None

        self.ext_w = None
        self.ext_w_verified = False

        self.ext_k = None
        self.ext_k_verified = False

        self.ext_v = None
        self.ext_v_verified = False

        self.ext_r = None
        self.ext_r_verified = False

    def update_probe_request(self, packet):
        # 802.11v
        self.logic_v(packet)

    def update_authentication(self, packet):
        # 802.11r
        self.logic_r(packet)

    def update_reassociation_request(self, packet):
        # 802.11r
        self.logic_r(packet)

    def update_reassociation_response(self, packet):
        # 802.11r
        self.logic_r(packet)

    def update_action(self, packet):
        self.logic_k(packet)
        self.logic_v(packet)
        self.logic_r(packet)

    def logic_v(self, packet):
        v, vv = check_available_v(packet)

        if v != None:
            self.ext_v = v

        if vv:
            self.ext_v_verified = True
            self.ext_v = True

    def logic_w(self, packet):
        w, wv = check_available_w(packet)

        if w != None:
            self.ext_w = w

        if wv:
            self.ext_w_verified = True
            self.ext_w = True

    def logic_r(self, packet):
        r, rv = check_available_r(packet)

        if r != None:
            self.ext_r = r

        if rv:
            self.ext_r_verified = True
            self.ext_r = True


    def logic_k(self, packet):
        k, kv = check_available_k(packet)

        if k != None:
            self.ext_k = k

        if kv:
            self.ext_k_verified = True
            self.ext_k = True


    def update_probe_response(self, packet):
        # 802.11w
        self.logic_w(packet)

        # 802.11v
        self.logic_v(packet)

        self.logic_r(packet)

        self.essid = packet['wlan.mgt'].wlan_ssid
        

    def update_data(self, packet):
        pass

    def update_association_request(self, packet):
        self.logic_w(packet)
        self.logic_k(packet)
        self.logic_v(packet)


    def update_relationship(self, AP):
        self.ap_connected = AP # string of BSSID

    def get_AP(self):
        return self.ap_connected

    def update_beacon(self, packet):
        self._packet = packet

        self.essid = packet['wlan.mgt'].wlan_ssid

        # 802.11w
        self.logic_w(packet)

        # 802.11k
        self.logic_k(packet)

        # 802.11v
        self.logic_v(packet)

        # 802.11r
        self.logic_r(packet)
        

    def get_bssid(self):
        return self.bssid
    
    def get_essid(self):
        return self.essid

    def get_w(self):
        return self.ext_w, self.ext_w_verified

    def get_r(self):
        return self.ext_r, self.ext_r_verified

    def get_k(self):
        return self.ext_k, self.ext_k_verified

    def get_v(self):
        # TODO: verify if client support it only when AP broadcast its support
        return self.ext_v, self.ext_v_verified

    def __str__(self):
        return f"{self.bssid}\t{self.essid}"

    def __eq__(self, other):
        if not isinstance(other, AP):
            return False
        return self.bssid == other.bssid
        

    def __hash__(self):
        return hash(self.bssid)


cap = pyshark.FileCapture(rfile)

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

    
        # try:
        #     for i, ap in stations.items():
        #         print(ap.get_k())
        # except Exception:
        #     pass
            

            


print(f"  AP\tBSSID\t\t\t11w\t11k\t11v\t11r\tESSID")
print("-------------------------------------------------------------------------------")

print_unknown='?'

def print_w(ap):
    w_status, w_verified=ap.get_w()

    if w_status == None:
        is_w=print_unknown
    elif not w_status:
        is_w=Fore.RED + 'No' + Style.RESET_ALL
    else:
        if w_status == 'Optional':
            is_w=Fore.YELLOW + 'Opt' + Style.RESET_ALL
        else:
            is_w=Fore.GREEN + 'Req' + Style.RESET_ALL

        if not w_verified:
            is_w=is_w + Fore.BLUE + '*' + Style.RESET_ALL

    return is_w

def print_r(ap):
    r_status, r_verified=ap.get_r()

    if r_status == None:
        is_r=print_unknown
    elif not r_status:
        is_r=Fore.RED + 'No' + Style.RESET_ALL
    else:
        is_r=Fore.GREEN + r_status + Style.RESET_ALL

        if not r_verified:
            is_r=is_r + Fore.BLUE + '*' + Style.RESET_ALL

    return is_r

def print_k(ap):
    k_status, k_verified=ap.get_k()
    
    if k_status == None:
        is_k=print_unknown
    elif not k_status:
        is_k=Fore.RED + 'No' + Style.RESET_ALL
    else:
        is_k=Fore.GREEN + 'Yes' + Style.RESET_ALL
        
        if not k_verified:
            is_k=is_k + Fore.BLUE + '*' + Style.RESET_ALL
    
    return is_k


def print_v(ap):
    v_status, v_verified=ap.get_v()
    
    if v_status == None:
        is_v=print_unknown
    elif not v_status:
        is_v=Fore.RED + 'No' + Style.RESET_ALL
    else:
        is_v=Fore.GREEN + 'Yes' + Style.RESET_ALL
        
        if not v_verified:
            is_v=is_v + Fore.BLUE + '*' + Style.RESET_ALL
    
    return is_v

for index, k in enumerate(stations):
    ap = stations[k]
    
    is_w = print_w(ap)
    is_k = print_k(ap)
    is_v = print_v(ap)
    is_r = print_r(ap)
        
    
    # print(f"802.11k           : {is_k}")

    if any(ap.get_bssid() == a.get_AP() for i, a in ap_clients.items()):
        index_p="·-"
    else:
        index_p="  "

    print(f"{index_p}{index}\t{ap.get_bssid()}\t{is_w}\t{is_k}\t{is_v}\t{is_r}\t{ap.get_essid()}")
    
    subi=1
    for f in ap_clients:
        cl = ap_clients[f]
        if cl.get_AP() == ap.get_bssid():
            is_w = print_w(cl)
            is_k = print_k(cl)
            is_v = print_v(cl)
            print(f"·-{index}_{subi}\t{f}\t{is_w}\t{is_k}\t{is_v}\t{is_r}")
            subi=subi+1
    # print("___________________________")
    print