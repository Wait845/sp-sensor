import utils as utils
from scapy.all import *


def calculate_a(rssi_list: list) -> float:
    rssi_list.sort()
    # remove smallest and biggest values
    rssi_list = rssi_list[1: -1]

    # a mean value
    a = round(sum(rssi_list) / len(rssi_list), 2)

    return abs(a)


def calculate_n(rssi_list: list, a: float) -> float:
    rssi_list.sort()
    # remove smallest and biggest values
    rssi_list = rssi_list[1: -1]
    rssi_mean = round(sum(rssi_list) / len(rssi_list), 2)

    # log(10)2 = 0.3
    n = (abs(rssi_mean) - a) / 0.3
    n /= 10
    n = round(n, 2)

    return abs(n)



def get_pkt_rssi(pkt) -> float:
    """Get rssi from request packet
    """
    print(pkt.getlayer(Dot11).addr2, pkt.haslayer(Dot11ProbeReq))
    if pkt.haslayer(Dot11ProbeReq) and \
            pkt.getlayer(Dot11).addr2 == detect_mac:
        print("got one:", pkt.getlayer(Dot11).addr2)
        rssi = pkt.dBm_AntSignal
        return rssi
    return None


def process_prn(pkt):
    rssi = get_pkt_rssi(pkt)
    if rssi == None:
        return None
    
    if collection_1m == True and len(rssi_list_1m) < 5:
        rssi_list_1m.append(rssi)
    if collection_2m == True and len(rssi_list_2m) < 5:
        rssi_list_2m.append(rssi)

    return None


if __name__ == "__main__":
    # initial
    interface = input("Enter Network Interface Name:")
    detect_mac = input("Enter Mac Address You Want to Detect:").lower()
    rssi_list_1m = []
    rssi_list_2m = []
    collection_1m = True
    collection_2m = False

    channel_table = utils.initial_available_channels([interface])
    utils.switch_channel(channel_table)

    input("Put Your Mobile Phone One Meter Away From the AP, Press Enter to Continue...")
    print("Data Collecting...")
    while len(rssi_list_1m) < 5:
        sniff(iface=interface, prn=process_prn, count=50)

    collection_1m = False
    collection_2m = True
    
    input("Put Your Mobile Phone Two Meter Away From the AP, Press Enter to Continue...")
    print("Data Collecting...")
    while len(rssi_list_2m) < 5:
        sniff(iface=interface, prn=process_prn, count=50)
    
    a = calculate_a(rssi_list_1m)
    n = calculate_n(rssi_list_2m, a)
    print(rssi_list_1m)
    print(rssi_list_2m)
    print(f"Result: a is {a}, n is {n}")

