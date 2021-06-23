#!/usr/bin/python3

"""Main module for packet analyzation attack."""
from modules.device_analyzer import DeviceAnalyzer
from modules.wireless_traffic_analyzer import WirelessTrafficAnalyzer
from modules.denial_of_service import DenialOfService


if __name__ == '__main__':
    # Setup
    wlan_interface = "wlan0"
    bl_interface = "hci0"
    vendor = "64:16:66"

    # Get devices from a certain vendor
    analyzer = WirelessTrafficAnalyzer(wlan_interface, bl_interface, 10)
    devices = analyzer.get_devices(vendor)

    # If any device has been found
    if len(devices) != 0:
        # We pick the first device when more devices or APs are found, choose wisely!
        device_addr = next(iter(devices))
        device = devices[device_addr]

        # Analyze (attack) the device
        device_analyzer = DeviceAnalyzer(device, wlan_interface)
        device_analyzer.visualize_packets()
    else: 
        print(f'[INFO] No devices found !!! Exiting...')
