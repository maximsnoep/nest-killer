#!/usr/bin/python3

"""Main module for packet analyzation attack."""
from modules.device_analyzer import DeviceAnalyzer
from modules.wireless_traffic_analyzer import WirelessTrafficAnalyzer
from modules.denial_of_service import DenialOfService


def attack(wlan_interface, bl_interface, vendor=None):

    analyzer = WirelessTrafficAnalyzer(wlan_interface, bl_interface, 10)
    devices = analyzer.get_devices(vendor)

    if len(devices) == 0:
        print(f'[INFO] No devices found !!! Exiting...')
        return
    # We pick the first device
    # when more devices or APs are found, choose wisely!
    device_addr = next(iter(devices))
    device = devices[device_addr]

    device_analyzer = DeviceAnalyzer(device, wlan_interface)
    device_analyzer.visualize_packets()

    return True


if __name__ == '__main__':

    wlan_interface = "wlan0"
    bl_interface = "hci0"
    vendor = "64:16:66"

    attack(wlan_interface, bl_interface, vendor)
