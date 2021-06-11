#!/usr/bin/python3

"""This module analyzes the devices of a vendor."""
from interface_manager import InterfaceManager


class DeviceAnalyzer():
    """Analyze devices of a vendor."""

    def __init__(self, interface, timeout=3):
        """Initialize variables."""
        self.timeout = timeout
        self.channels = range(1, 14+1)
        self.devices = {i: set() for i in self.channels}
        self.manager = InterfaceManager(interface)
        self.manager.wlan_mode(InterfaceManager.MONITOR_MODE)

    def get_devices(self, vendor=None):
        """Returns devices by counting packets to vendor subaddress."""
        # for each channel
        for ch in self.channels:
            # set interface to correct channel
            self.manager.wlan_channel(ch)
            # sniff on the interface
            capture = self.manager.capture(timeout=self.timeout)
            # add device if it has vendor subaddress
            self.devices[ch] = set([
                p.wlan.ra for p in capture._packets
                if (p.wlan.ra[0:8] == vendor or vendor is None)
                ])
            if (len(self.devices[ch]) > 0):
                print(f'[INFO]',
                      f'Channel {ch}: {len(self.devices[ch])} devices\n',
                      f'{self.devices[ch]}')
        # return the devices
        return self.devices
