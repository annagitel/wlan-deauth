import sys

import netifaces
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp

device_list = {}
client_list = {}

def iface_list():
    if_list = netifaces.interfaces()
    return if_list


def monitorMode(iface):
    os.system("ifconfig " + iface + " down")
    os.system("iwconfig " + iface + " mode monitor")
    os.system("ifconfig " + iface + " up")


def packet_handler(pkt):
    if pkt.haslayer(Dot11Beacon):
        dot11_layer = pkt[Dot11]
        if dot11_layer.addr2 and (dot11_layer.addr2 not in device_list):
            new_kv = {dot11_layer.addr2: dot11_layer}
            device_list.update(new_kv)


def sniffClients(interface):
    interupted = False
    try:
        sniff(iface=interface, prn=getClients, stop_filter=interupted)
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        interupted = True

    """
    Get the clients for the BSSID
    """


def getClients(pkt):
    bssid = pkt[Dot11].addr3
    if not pkt.haslayer(Dot11Beacon) and not pkt.haslayer(
            Dot11ProbeReq) and not pkt.haslayer(Dot11ProbeResp):
        print(pkt.summary())


if __name__ == '__main__':
    print("available interfaces:")
    if_list = iface_list()
    for i in range(1, len(if_list)):
        print(i, if_list[i])
    user_choice = input("please pick an interface")
    user_iface = if_list[int(user_choice)]

    print('moving interface to monitor mode')
    monitorMode(user_iface)

    print("sniffing for available networks for 60 seconds...")
    sniff(iface=user_iface, prn=packet_handler, timeout=15)
    count = 0
    for k in device_list:
        print(count + 1, device_list[k].info.decode("utf-8"))
        count = count+1

    user_choice = input("please pick a network: ")
    user_network = device_list[int(user_choice)-1]

    print("sniffing clients on network for 60 seconds...")
    sniffClients()
