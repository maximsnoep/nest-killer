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
        """Return devices in wireless traffic (from a vendor)."""
        # Phase one, finding devices from a certain vendor
        print(f'[INFO] Analyzing devices phase 1... [finding devices from vendor: {vendor}]')
        # Set to monitor mode
        self.wlan_manager.wlan_mode(InterfaceManager.MONITOR_MODE)
        devices = []
        # For each channel
        for ch in self.channels:
            # Set interface to correct channel
            self.wlan_manager.wlan_channel(ch)
            # Sniff on the interface
            capture = self.wlan_manager.wlan_capture(timeout=self.timeout)
            # Add device if it has vendor subaddress
            devices += list(set([p.wlan.ra for p in capture._packets if (p.wlan.ra[0:8] == vendor or vendor is None)]))
        # Remove duplicates
        self.devices = list(set(devices))
        print(f'[INFO] Found {len(self.devices)} devices {self.devices}')
        # Create entry for additional device info
        self.devices_info = {i: {'address': i,
                                 'name': None,
                                 'APs': [],
                                 'strength': None,
                                 'distance': None,
                                 'channels': {ch: None for ch in self.channels}}
                             for i in self.devices}

        # Phase two, finding additional device info, such as signal strength and APs
        print(f'[INFO] Analyzing devices phase 2... [finding more information]')
        # For each device
        for device in self.devices:
            strengths = []
            distances = []
            aps = []
            # For each channel
            for ch in self.channels:
                ch_counter = 0
                # Set interface to correct channel
                self.wlan_manager.wlan_channel(ch)
                # Sniff on the interface
                capture = self.wlan_manager.wlan_capture(
                    bpf_filter=f'wlan addr2 {device} or wlan addr1 {device}',
                    timeout=self.timeout)
                # For all sniffed packets
                for p in capture._packets:
                    try:
                        # If packet has type 2 (data packet)
                        if p.wlan.fc_type == '2':
                            # Count the packet
                            ch_counter += 1
                            # Add the AP (bssid)
                            aps.append(p.wlan.bssid)
                            # Add signal strength and distance if {device} is transmitter
                            if p.wlan.ta == device:
                                strengths.append(int(p.wlan_radio.signal_dbm))
                                distances.append(self.dbm_to_meters(ch, int(p.wlan_radio.signal_dbm)))
                    # Catch AttributeError on wrong (malformed) packets
                    except AttributeError as error:
                        print(error)
                self.devices_info[device]['channels'][ch] = ch_counter
            strength = np.mean(strengths)
            distance = np.mean(distances)
            self.devices_info[device]['strength'] = strength
            self.devices_info[device]['distance'] = distance
            self.devices_info[device]['APs'] = list(set(aps))
        # Reset (wlan) interface to usable mode
        self.wlan_manager.wlan_mode(InterfaceManager.MANAGED_MODE)

        # Phase three, finding device names through bluetooth
        print(f'[INFO] Analyzing devices phase 3... [finding device names through bluetooth]')
        # Set interface to correct mode
        self.bl_manager.bl_mode(InterfaceManager.ON_MODE)
        # Sniff on the interface
        bl_scan = self.bl_manager.bl_capture(self.timeout)
        # For each device
        for device in bl_scan:
            # If device has address of one of our devices
            if device['address'] in self.devices:
                # If name is an actual name (non empty)
                if device['name'] != '' or device['name'] is not None:
                    # Add its name
                    self.devices_info[device['address']]['name'] = device['name']

        # Return the devices
        return self.devices_info

    @staticmethod
    def dbm_to_meters(channel, dbm):
        """Convert signal strength to distance."""
        mhz = 2407 + 5 * channel
        FSPL = 27.55
        return 10 ** (np.subtract(FSPL, 20 * np.log10(mhz) + dbm) / 20)
