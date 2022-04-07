import threading
import config
import utils
import manuf
import copy
import time
from scapy.all import *
import json
import requests
import gc
import objgraph


ENVIRONMENT_A = config.ENVIRONMENT_A
ENVIRONMENT_N = config.ENVIRONMENT_N
SERVER_ADDR = config.SERVER_ADDR
INTERFACES = config.INTERFACES
DOT11_TYPE = {
    0: {  # Management
        0: "Association Request",
        1: "Association Response",
        2: "Reassociation Request",
        3: "Reassociation Response",
        4: "Probe Request",
        5: "Probe Response",
        6: "Timing Advertisement",
        8: "Beacon",
        9: "ATIM",
        10: "Disassociation",
        11: "Authentication",
        12: "Deauthentification",
        13: "Action",
        14: "Action No Ack",
    },
    1: {  # Control
        4: "Beamforming Report Poll",
        5: "VHT NDP Announcement",
        6: "Control Frame Extension",
        7: "Control Wrapper",
        8: "Block Ack Request",
        9: "Block Ack",
        10: "PS-Poll",
        11: "RTS",
        12: "CTS",
        13: "Ack",
        14: "CF-End",
        15: "CF-End+CF-Ack",
    },
    2: {  # Data
        0: "Data",
        1: "Data+CF-Ack",
        2: "Data+CF-Poll",
        3: "Data+CF-Ack+CF-Poll",
        4: "Null (no data)",
        5: "CF-Ack (no data)",
        6: "CF-Poll (no data)",
        7: "CF-Ack+CF-Poll (no data)",
        8: "QoS Data",
        9: "QoS Data+CF-Ack",
        10: "QoS Data+CF-Poll",
        11: "QoS Data+CF-Ack+CF-Poll",
        12: "QoS Null (no data)",
        14: "QoS CF-Poll (no data)",
        15: "QoS CF-Ack+CF-Poll (no data)"
    },
    3: {  # Extension
        0: "DMG Beacon"
    }
}


def _update_room_position():
    ROOM_POSITION = config.ROOM_POSITION
    post_data = {"position": json.dumps(ROOM_POSITION)}
    requests.post("http://{}/update_room_position/".format(SERVER_ADDR), data=post_data, timeout=5)
    print(post_data)


def _update_ap_position():
    AP_POSITION = config.INTERFACES
    post_data = {"position": json.dumps(AP_POSITION)}
    requests.post("http://{}/update_ap_position/".format(SERVER_ADDR), data=post_data, timeout=5)
    print(post_data)


def _update_position():
    while True:
        # update position every 30 sec
        _update_room_position()
        _update_ap_position()
        time.sleep(30)


def update_position():
    threading.Thread(target=_update_position).start()


def rssi_to_dis(rssi: float, a: float = ENVIRONMENT_A, n: float = ENVIRONMENT_N) -> float:
    """RSSI cover to distance

    :param rssi: received signal strength indication
    :param a: rssi at 1 meter distance
    :param n: environmental attenuation factor
    """
    # a = 35
    # n = 2.5
    return round(10 ** ((abs(rssi) - abs(a)) / (10 * n)), 2)


def get_queue() -> list:
    global msg_queue
    """Get the messages from the queue

    :return: all message from the queue
    """
    lock.acquire()
    result = copy.deepcopy(msg_queue)
    del msg_queue
    gc.collect()
    msg_queue = []
    lock.release()
    return result


def put_queue(msg: dict) -> bool:
    """Put the message into the message queue

    :param msg: message

    :return: whether put the message into queue successful
    """
    try:
        lock.acquire()
        msg_queue.append(msg)
        lock.release()
        return True
    except:
        return False


def send_msg():
    """Send msg to the server
    """
    global first_time_msg
    while True:
        time.sleep(5)
        msg = get_queue()
        if first_time_msg == True:
            first_time_msg = False
        else:
            post_msg = {"data": json.dumps(msg)}
            # result = requests.post("http://{}/detect_info/".format(server_addr), data=post_msg, timeout=5)
            # print(result.text)
            # print(post_msg)
            print(post_msg, len(msg))
            del msg
            gc.collect()


def parse_pkt(pkt) -> dict:
    """Parse packet to dict form

    :param pkt: packet object

    :return: the dict which includes useful information
    """
    # addr 2 = sender
    # addr 1 = receiver
    sender = pkt.getlayer(Dot11).addr2
    target = pkt.getlayer(Dot11).addr1
    dot_type = pkt.getlayer(Dot11).type
    dot_subtype = pkt.getlayer(Dot11).subtype

    # collect AP
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        if sender not in ap_dict.keys():
            ap_dict[sender] = pkt[Dot11Elt].info.decode()
        return None

    # filter AP package
    if sender in ap_dict.keys() or sender == None:
        return None

    if first_time_msg:
        return None

    interface = str(pkt.sniffed_on)
    frequency = pkt.ChannelFrequency
    channel = channel_table[interface].get(frequency, 0)
    manuf = manuf_parser.get_manuf_long(sender) or "unknown"
    rssi = pkt.dBm_AntSignal
    timestamp = pkt.time
    distance = rssi_to_dis(rssi)
    probe_type = DOT11_TYPE.get(dot_type, {}).get(dot_subtype, 'unknown')
    # probe_type = DOT11_TYPE[dot_type][dot_subtype]


    return {
        "interface": interface,
        "addr": sender,
        "target": target,
        "manuf": manuf,
        "rssi": rssi,
        "frequency": frequency,
        "channel": channel,
        "timestamp": timestamp,
        "probe_type": probe_type,
        "distance": distance
    }


def _process_prn(pkt):
    sniff_thread_dict[str(pkt.sniffed_on)]["count"] += 1
    result = parse_pkt(pkt)
    if result != None:
        put_queue(result)


def scan_dead_sniff():
    while True:
        time.sleep(5)
        for interface in sniff_thread_dict.keys():
            # print(f"{interface} {sniff_thread_dict[interface]['count']}")
            if sniff_thread_dict[interface]["count"] == 0:
                print(f"{interface} IS DEAD")
                # thread dead
                old_sniff = sniff_thread_dict[interface]["thread"]
                new_thread = AsyncSniffer(iface=interface, prn=_process_prn)
                sniff_thread_dict[interface]["thread"] = new_thread
                new_thread.start()
                del old_sniff
                gc.collect()
            else:
                print(f"{interface} IS ACTIVE")
                # set count empty
                sniff_thread_dict[interface]["count"] = 0


if __name__ == "__main__":

    manuf_parser = manuf.MacParser()

    lock = threading.Lock()
    msg_queue = []
    first_time_msg = True

    # start thread to update position info
    update_position()

    # start channel hopping
    channel_table = utils.initial_available_channels(INTERFACES)
    utils.switch_channel(channel_table)

    ap_dict = {}

    print("APs detecting...")

    # start signal catch
    sniff_thread_dict = {}
    for interface in INTERFACES:
        sniff_thread = AsyncSniffer(iface=interface, prn=_process_prn)
        sniff_thread_dict[interface] = {"thread": sniff_thread, "count": 1}
        sniff_thread.start()

    # start thread to send message
    send_msg_thread = threading.Thread(target=send_msg)
    send_msg_thread.daemon = True
    send_msg_thread.start()

    # start thread to detect is sniff alive
    scan_sniff_thread = threading.Thread(target=scan_dead_sniff)
    scan_sniff_thread.start()
    scan_sniff_thread.join()
