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
        # print(post_msg)
        print(post_msg)


def parse_pkt(pkt) -> dict:
    """Parse packet to dict form

    :param pkt: packet object

    :return: the dict which includes useful information
    """
    addr, target = None, None
    probe_type = ""
    # addr 2 = sender
    # addr 1 = receiver

    a1 = "d8:f3:bc:5e:70:17"
    a2 = "54:40:ad:87:0b:96"
    a3 = "4c:4f:ee:10:d9:f0"
    a4 = "42:c8:a9:e9:c6:d9"
    a5 = "ff:ff:ff:ff:ff:ff"
    addr1 = pkt.getlayer(Dot11).addr1
    addr2 = pkt.getlayer(Dot11).addr2
    dot_type = pkt.getlayer(Dot11).type
    dot_subtype = pkt.getlayer(Dot11).subtype
    t = str(dot_type) + "." + str(dot_subtype)
    print(pkt.ChannelFrequency)
    return None
    if pkt.haslayer(Dot11) and (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
        ap_set.add(addr2)
        # print(ap_set)
    # if t == "0.4":
    #     print("0.4")
    # if pkt.haslayer(Dot11ProbeReq):
    #     print("Probe Req")
    # return None
    # Probe Request, Action No Ack, Null (no data)
    if addr2 in ap_set:
        return None
    if addr2 == None and addr1 not in ap_set:
        return None
    if addr2 == "f8:4d:89:7e:4d:a4":
        return None
    print(f"{addr2} ==> {addr1} : {t}")
    return None
    sta_type = ["0.4", "0.14", "2.4"]
    if t in sta_type:
        addr = addr2
        target = addr1
        probe_type = t
        print(f"{addr} ==> {target} : {probe_type}")
        return None

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

    # if t in ["0.4", "2.4", "0.14"]:
    #     print(f"addr1:{pkt.getlayer(Dot11).addr1} addr2:{pkt.getlayer(Dot11).addr2} type:{pkt.getlayer(Dot11).type} {pkt.getlayer(Dot11).subtype} RSSI:{pkt.dBm_AntSignal}")
    # sta = ["e8:fb:e9:1e:5a:2c"]
    # ap = ["74:23:44:EB:30:0C", "5C:02:14:F1:F3:BB".lower()]
    # if addr1 in sta:
    #     type_dict["sta"]["r"].add(t)
    # elif addr1 in ap:
    #     type_dict["ap"]["r"].add(t)
    
    # if addr2 in sta:
    #     type_dict["sta"]["s"].add(t)
    # elif addr2 in ap:
    #     type_dict["ap"]["s"].add(t)

    # if addr1 != "e8:fb:e9:1e:5a:2c" and addr2 != "e8:fb:e9:1e:5a:2c":
    #     return None
    # if abs(pkt.dBm_AntSignal) > 40:
    #     if t not in type_dict["sta"]:
    #         type_dict["sta"].add(t)
    #         print(type_dict)
    # else:
    #     if t not in type_dict["ap"]:
    #         type_dict["ap"].add(t)
    #         print(type_dict)

    # print(f"addr1:{pkt.getlayer(Dot11).addr1} addr2:{pkt.getlayer(Dot11).addr2} type:{pkt.getlayer(Dot11).type} {pkt.getlayer(Dot11).subtype} RSSI:{pkt.dBm_AntSignal}")
    
    return None

    if pkt.getlayer(Dot11).addr2 == None:
        return None

    if pkt.getlayer(Dot11).type == 1 and pkt.getlayer(Dot11).subtype == 14:
        return None
    if pkt.getlayer(Dot11).addr2 == "ff:ff:ff:ff:ff:ff":
        return None
    if pkt.haslayer(Dot11ProbeReq) or pkt.getlayer(Dot11).addr1 == a4 or pkt.getlayer(Dot11).addr2 == a4:
        print(pkt.getlayer(Dot11).type, pkt.getlayer(Dot11).subtype, pkt.getlayer(Dot11).addr2, pkt.getlayer(Dot11).addr1)
        if pkt.getlayer(Dot11).addr1 == a4:
            addr = pkt.getlayer(Dot11).addr2
            target = pkt.getlayer(Dot11).addr1
        elif pkt.getlayer(Dot11).addr2 == a4:
            addr = pkt.getlayer(Dot11).addr1
            target = pkt.getlayer(Dot11).addr2
        elif pkt.getlayer(Dot11).addr1 == "ff:ff:ff:ff:ff:ff":
            target = "ff:ff:ff:ff:ff:ff"
            addr = pkt.getlayer(Dot11).addr2
        probe_type = str(pkt.getlayer(Dot11).type) + "." + str(pkt.getlayer(Dot11).subtype)
    if addr:
        #if target != "":
            #print(target)
	     #   target = target.decode()

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
    sniff_thread_dict[str(pkt.sniffed_on)]["count"] += 1
    result = parse_pkt(pkt)
    if result != None:
        put_queue(result)


def start_sniff(interface: str):
    sniff(iface=interface, prn=_process_prn, count=10000)


def scan_dead_sniff():
    while True:
        time.sleep(30)
        for interface in sniff_thread_dict.keys():
            print(f"{interface} {sniff_thread_dict[interface]['count']}")
            if sniff_thread_dict[interface]["count"] == 0:
                print(f"{interface} is dead")
                # thread dead
                new_thread = AsyncSniffer(iface=interface, prn=_process_prn)
                sniff_thread_dict[interface]["thread"] = new_thread
                new_thread.start()
            else:
                print(f"{interface} is active")
                # set count empty
                sniff_thread_dict[interface]["count"] = 0


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

    ap_set = set()
    # start signal catch
    # sniff_thread_list = []
    sniff_thread_dict = {}
    for interface in interfaces:
        sniff_thread = AsyncSniffer(iface=interface, prn=_process_prn)
        sniff_thread_dict[interface] = {"thread": sniff_thread, "count": 1}
        sniff_thread.start()
        # sniff_thread = threading.Thread(target=start_sniff, args=(interface, ))
        # sniff_thread.daemon = True
        # sniff_thread_list.append(sniff_thread)
        # sniff_thread.start()

    send_msg_thread = threading.Thread(target=send_msg)
    send_msg_thread.daemon = True
    send_msg_thread.start()

    scan_sniff_thread = threading.Thread(target=scan_dead_sniff)
    scan_sniff_thread.start()
    scan_sniff_thread.join()

    # for sniff_thread in sniff_thread_list:
    #     sniff_thread.join()




{
    "STA":[
        2.4, 1.11, 0.14
    ],
    "AP": [
        1.13, 1.9, 1.12, 1.5
    ]
}

{'sta': {'1.9', '2.4', '0.14', '1.8', '1.11', '0.13', '0.4'}, 'ap': {'1.9', '1.13', '1.11', '0.13', '1.5', '1.12'}}
{'sta': {'1.12', '0.14', '1.11', '0.13', '2.4', '1.9', '0.10', '1.13', '0.4'}, 'ap': {'1.12', '1.5', '1.11', '1.9', '1.13'}}

{
    'sta': {
        's': {
            '0.4', '1.9', '0.13', '1.11', '2.4', '0.14'
        },
        'r': {
            '1.8', '1.13', '1.9', '2.8', '1.12', '0.13', '1.5', '1.11'
        }
    },
    'ap': {
        's': {
            '1.8', '0.8', '2.0', '0.5', '1.9', '2.8', '0.13', '1.11', '2.12'
        },
        'r': {
            '2.0', '1.13', '1.9', '2.8', '0.13', '1.12', '1.11', '2.4', '2.12', '0.14'
        }
    }
}

# sta:s = [0.4, 2.4, 0.14] 
# ap:r = [2.0, 2.4, 2.12, 0.14]


{
    'sta': {
        's': {
            '0.14', '2.4', '1.9', '1.11'
        },
        'r': {
            '1.9', '1.11', '1.12', '1.13', '1.5'
        }
    },
    'ap': {
        's': {
            '0.8', '1.9', '2.0', '1.11', '0.13', '2.12', '2.8', '0.5'
        },
        'r': {
            '0.14', '1.9', '1.11', '2.12', '2.8', '2.4', '1.12', '1.13'
        }
    }
}
# sta:s = [0.14, 2.4, 0.4]
# ap:r = [2.12, 2.8, 2.4, ]

{
    'sta': {
        's': {
            '1.11', '0.13', '1.8', '0.4', '1.9', '0.14', '2.8', '2.4'
        },
        'r': {
            '0.13', '1.8', '1.13', '0.5', '1.9', '1.5', '2.8', '1.12'
        }
    },
    'ap': {
        's': {
            '1.11', '0.5', '1.9', '2.8', '2.0', '0.8'
        },
        'r': {
            '1.11', '1.13', '1.9', '0.14', '2.8', '2.12', '1.12', '2.4'
        }
    }
}
# sta:s = [0.13, 1.8, 0.4, 0.14, 2.4]
# ap:r = [1.11, 0.14, 2.12, 2.4]



# sta:s = [0.4, 2.4, 0.14] 
# ap:r = [2.0, 2.4, 2.12, 0.14]

# sta:s = [0.14, 2.4, 0.4]
# ap:r = [2.12, 2.8, 2.4, ]

# sta:s = [0.13, 1.8, 0.4, 0.14, 2.4]
# ap:r = [1.11, 0.14, 2.12, 2.4]

# final
sta_s = [0.4, 2.4, 0.14]
ap_r = [2.0, 2.4, 2.12, 0.14]