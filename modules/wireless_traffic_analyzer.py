#!/usr/bin/python3

"""This module contains multiple tools to analyze wireless traffic."""
from .interface_manager import InterfaceManager
import numpy as np


class WirelessTrafficAnalyzer():
    """Analyze wireless traffic."""

    def __init__(self, wlan_interface, bl_interface, timeout=3):
        """Initialize variables."""
        self.timeout = timeout
        self.channels = [1, 6, 11]
        self.devices = []
        self.wlan_manager = InterfaceManager(wlan_interface)
        self.bl_manager = InterfaceManager(bl_interface)

    def get_devices(self, vendor=None):
        """Returns devices in wireless traffic (from a vendor)."""
        print(f'[INFO]',
              f'Analyzing devices phase 1...',
              f'[finding devices from vendor: {vendor}]')

        # set to monitor mode
        self.wlan_manager.wlan_mode(InterfaceManager.MONITOR_MODE)
        devices = []
        # for each channel
        for ch in self.channels:
            # set interface to correct channel
            self.wlan_manager.wlan_channel(ch)
            # sniff on the interface
            capture = self.wlan_manager.wlan_capture(timeout=self.timeout)
            # add device if it has vendor subaddress
            devices += list(set([
                p.wlan.ra for p in capture._packets
                if (p.wlan.ra[0:8] == vendor or vendor is None)
                ]))
        self.devices = list(set(devices))
        print(f'[INFO]',
              f'Found {len(self.devices)} devices',
              f'{self.devices}')
        self.devices_info = {i: {'address': i,
                                 'name': None,
                                 'APs': [],
                                 'strength': None,
                                 'distance': None,
                                 'channels': {ch: None
                                              for ch in self.channels}}
                             for i in self.devices}

        print(f'[INFO]',
              f'Analyzing devices phase 2...',
              f'[finding more information]')

        for device in self.devices:
            strengths = []
            distances = []
            aps = []
            for ch in self.channels:
                ch_counter = 0
                # set interface to correct channel
                self.wlan_manager.wlan_channel(ch)
                # sniff on the interface
                capture = self.wlan_manager.wlan_capture(
                    bpf_filter=f'wlan addr2 {device} or \
                                 wlan addr1 {device}',
                    timeout=self.timeout)
                # find information in packets
                for p in capture._packets:
                    try:
                        if p.wlan.fc_type == '2':
                            ch_counter += 1
                            aps.append(p.wlan.bssid)
                            if p.wlan.ta == device:
                                strengths.append(
                                    int(p.wlan_radio.signal_dbm))
                                distances.append(
                                    self.dbm_to_meters(
                                        ch, int(p.wlan_radio.signal_dbm)))
                    except AttributeError as error:
                        print(error)
                self.devices_info[device]['channels'][ch] = ch_counter
            strength = np.mean(strengths)
            distance = np.mean(distances)
            self.devices_info[device]['strength'] = strength
            self.devices_info[device]['distance'] = distance
            self.devices_info[device]['APs'] = list(set(aps))

        print(f'[INFO]',
              f'Analyzing devices phase 3...',
              f'[finding device names through bluetooth]')

        self.bl_manager.bl_mode(InterfaceManager.ON_MODE)
        bl_scan = self.bl_manager.bl_capture(self.timeout)

        for device in bl_scan:
            if device['address'] in self.devices:
                self.devices_info[device['address']]['name'] = device['name']

        # reset to managed mode
        self.wlan_manager.wlan_mode(InterfaceManager.MANAGED_MODE)
        # return the devices
        print(self.devices_info)
        return self.devices_info

    @staticmethod
    def dbm_to_meters(channel, dbm):
        # source:
        # https://gist.github.com/cryptolok/516471ce35a9851197b204853c6de080
        mhz = 2407 + 5 * channel
        FSPL = 27.55
        return 10 ** (np.subtract(FSPL, 20 * np.log10(mhz) + dbm) / 20)
