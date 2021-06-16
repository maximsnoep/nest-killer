#!/usr/bin/python3

"""Main module for packet analyzation attack."""
from modules.device_analyzer import DeviceAnalyzer
from modules.wireless_traffic_analyzer import WirelessTrafficAnalyzer


def attack(interface, vendor=None):
    analyzer = WirelessTrafficAnalyzer(interface, 2)
    devices = analyzer.get_devices(vendor)
    device = None
    for channel in devices:
        if (len(devices[channel]) > 0):
            device = devices[channel][0]
            break

    aps = analyzer.get_aps(device)
    ap = None
    for channel in aps:
        if (len(aps[channel]) > 0):
            ap = aps[channel][0]
            break

    device_analyzer = DeviceAnalyzer(device, ap, interface)
    channel = device_analyzer.get_channels()

    device_analyzer.visualize_packets(channel)

    return True


if __name__ == '__main__':

    interface = "wlan0"
    vendor = "64:16:66"

    attack(interface, vendor)
