import subprocess
import threading
import time


def initial_available_channels(interfaces: list) -> dict:
    """Get all available channels for each interface

    :param interfaces: interface list

    :return: available channels
    """
    channel_table = {}
    for interface in interfaces:
        # initial channel table for the interface
        channel_table[interface] = {}
        # get all available chennels9
        available_channels = subprocess.check_output(["iwlist", interface, "channel"]).decode().split("\n")[1:-3]
        for available_channel in available_channels:
            # map frequency and channel
            available_channel = available_channel.split(":")
            channel, frequency = available_channel
            channel = int(channel.split(" ")[-2])
            frequency = int(float(frequency.split(" ")[1]) * 1000)
            channel_table[interface][frequency] = channel
    return channel_table


# def _set_interface_channel(interface: str, channel_table: dict) -> None:
def _set_interface_channel(interface: str, channel_table: dict) -> None:

    """Set interface channel

    :param interface: interface name
    :param channel_table: all available channels

    :return: none
    """
    while True:
        for channel in channel_table.values():
            for i in interface:
                subprocess.check_output(["iwconfig", i, "channel", str(channel)])
                time.sleep(0.15)


def switch_channel(channel_table: dict) -> bool:
    """Switch channel for each interface

    :param channel_table: available channels, use function 'initial_available_channels' to get

    :return: whether threading starting successful
    """
    try:
        # for interface, channels_dict in channel_table.items()[0]:
            # sc_thread = threading.Thread(target=_set_interface_channel, args=(interface, channels_dict))
        sc_thread = threading.Thread(target=_set_interface_channel, args=(channel_table.keys(), channel_table[list(chanta.keys())[0]]))
        sc_thread.daemon = True
        sc_thread.start()
        return True
    except:
        return False















