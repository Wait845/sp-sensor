from pickle import TRUE
import threading
from configuration import config
import utils
import manuf
import copy
import time
from scapy.all import *
import json
import requests

def _update_room_position():
    ap_position = eval(config.get("general", "room_position"))
    post_data = {"position": json.dumps(ap_position)}
    requests.post("http://{}/update_room_position/".format(server_addr), data=post_data, timeout=5)
    print(post_data)

def _update_ap_position():
    ap_position = eval(config.get("general", "interfaces"))
    post_data = {"position": json.dumps(ap_position)}
    requests.post("http://{}/update_ap_position/".format(server_addr), data=post_data, timeout=5)
    print(post_data)

def _update_position():
    while True:
        # update position every 30 sec
        _update_room_position()
        _update_ap_position()
        time.sleep(30)

def update_position():
    threading.Thread(target=_update_position).start()


def rssi_to_dis(rssi: float, a: float, n: float) -> float:
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


# def update_position(room_position: list, interfaces_position: dict):
#     """Update positions to the server
#     """
#     print(f"room position:{room_position}")
#     print(f"ifaces position:{interfaces_position}")


def send_msg():
    """Send msg to the server
    """
    while True:
        time.sleep(5)
        msg = get_queue()
        post_msg = {"data": json.dumps(msg)}
        # result = requests.post("http://{}/detect_info/".format(server_addr), data=post_msg, timeout=5)
        # print(result.text)
        print(post_msg)


def parse_pkt(pkt) -> dict:
    """Parse packet to dict form

    :param pkt: packet object

    :return: the dict which includes useful information
    """
    addr, target = None, None
    probe_type = ""

    if "74:23:44:eb:30:0c" not in [pkt.getlayer(Dot11).addr1, pkt.getlayer(Dot11).addr2, pkt.getlayer(Dot11).addr3]:
        return None
    print(pkt.getlayer(Dot11).type, pkt.getlayer(Dot11).subtype, pkt.getlayer(Dot11).addr1, pkt.getlayer(Dot11).addr2)
    return None

    if pkt.haslayer(Dot11ProbeReq):
        addr = pkt.getlayer(Dot11).addr2
        target = pkt.getlayer(Dot11ProbeReq).info or ""
        probe_type = "Probe Req"
    if pkt.haslayer(Dot11ProbeResp):
        addr = pkt.getlayer(Dot11).addr1
        target = pkt.getlayer(Dot11ProbeResp).info or ""
        probe_type = "Probe Resp"
    if addr:
        if target != "":
            # print(target)
            target = target.decode()

        interface = str(pkt.sniffed_on)
        manuf = manuf_parser.get_manuf_long(addr) or "unknown"
        rssi = pkt.dBm_AntSignal
        frequency = pkt.ChannelFrequency
        channel = channel_table[interface].get(frequency, 0)
        timestamp = pkt.time
        distance = rssi_to_dis(rssi, environment_a, environment_n)

        return {
            "interface": interface,
            "addr": addr,
            "target": target,
            "manuf": manuf,
            "rssi": rssi,
            "frequency": frequency,
            "channel": channel,
            "timestamp": timestamp,
            "probe_type": probe_type,
            "distance": distance
        }
    else:
        return None


def _process_prn(pkt):
    result = parse_pkt(pkt)
    if result != None:
        put_queue(result)


def start_sniff(interface: str):
    sniff(iface=interface, prn=_process_prn)


if __name__ == "__main__":
    server_addr = config.get("general", "server_addr")
    interfaces_dict = eval(config.get("general", "interfaces"))
    interfaces = [interface for interface in interfaces_dict.keys()]
    # room_position = eval(config.get("general", "room_position"))
    environment_a = float(config.get("general", "environment_a"))
    environment_n = float(config.get("general", "environment_n"))

    manuf_parser = manuf.MacParser()

    lock = threading.Lock()
    msg_queue = []

    update_position()

    channel_table = utils.initial_available_channels(interfaces)
    utils.switch_channel(channel_table)

    # start signal catch
    sniff_thread_list = []
    for interface in interfaces:
        sniff_thread = threading.Thread(target=start_sniff, args=(interface, ))
        sniff_thread.daemon = True
        sniff_thread_list.append(sniff_thread)
        sniff_thread.start()

    send_msg_thread = threading.Thread(target=send_msg)
    send_msg_thread.daemon = True
    send_msg_thread.start()

    for sniff_thread in sniff_thread_list:
        sniff_thread.join()
