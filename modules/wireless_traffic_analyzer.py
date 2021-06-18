#!/usr/bin/python3

"""This module contains multiple tools to analyze wireless traffic."""
from .interface_manager import InterfaceManager


class WirelessTrafficAnalyzer():
    """Analyze wireless traffic."""

    def __init__(self, interface, timeout=3):
        """Initialize variables."""
        self.timeout = timeout
        self.channels = [1, 6, 11]
        self.devices = {i: [] for i in self.channels}
        self.aps = {i: [] for i in self.channels}
        self.manager = InterfaceManager(interface)

    def get_devices(self, vendor=None):
        """Returns devices in wireless traffic (from a vendor)."""
        print(f'[INFO]',
              f'Analyzing devices...',
              f'[vendor: {vendor}]')
        # set to monitor mode
        self.manager.wlan_mode(InterfaceManager.MONITOR_MODE)
        # for each channel
        for ch in self.channels:
            # set interface to correct channel
            self.manager.wlan_channel(ch)
            # sniff on the interface
            capture = self.manager.capture(timeout=self.timeout)
            # add device if it has vendor subaddress
            self.devices[ch] = list(set([
                p.wlan.ra for p in capture._packets
                if (p.wlan.ra.startsWith(vendor) or vendor is None)
                ]))
            if (len(self.devices[ch]) > 0):
                print(f'[INFO]',
                      f'Channel {ch}: {len(self.devices[ch])} devices',
                      f'{self.devices[ch]}')
        # reset to managed mode
        self.manager.wlan_mode(InterfaceManager.MANAGED_MODE)
        # return the devices
        return self.devices

    def get_aps(self, device=None):
        """Returns APs in wireless traffic (connected to a device)."""
        print(f'[INFO]',
              f'Analyzing APs...',
              f'[device: {device}]')
        # set to monitor mode
        self.manager.wlan_mode(InterfaceManager.MONITOR_MODE)
        # for each channel
        for ch in self.channels:
            # set interface to correct channel
            self.manager.wlan_channel(ch)
            # sniff on the interface
            capture = self.manager.capture(
                bpf_filter=f'wlan addr2 {device} or \
                             wlan addr1 {device}',
                timeout=self.timeout)
            # add device if it has vendor subaddress
            for p in capture._packets:
                try:
                    if p.wlan.bssid not in self.aps[ch]:
                        self.aps[ch].append(p.wlan.bssid)
                except AttributeError as error:
                    print(error)
            if (len(self.aps[ch]) > 0):
                print(f'[INFO]',
                      f'Channel {ch}: {len(self.aps[ch])} APs',
                      f'{self.aps[ch]}')
        # reset to managed mode
        self.manager.wlan_mode(InterfaceManager.MANAGED_MODE)
        # return the devices
        return self.aps
