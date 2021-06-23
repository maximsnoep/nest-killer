#!/usr/bin/python3

"""This module manages an interface."""
import pyshark
import pygatt
import os


class InterfaceManager():
    """Manage an interface."""

    MANAGED_MODE = 'managed'
    MONITOR_MODE = 'monitor'
    ON_MODE = 'up'
    OFF_MODE = 'down'

    def __init__(self, interface):
        """Initialize variables."""
        self.interface = interface

    def wlan_mode(self, mode):
        """Set wlan interface to a specified mode."""
        # Disable interface
        os.system(f'ifconfig {self.interface} down')
        # Use airmon-ng to kill networkmanager
        os.system(f'airmon-ng check kill')
        # Set the correct interface mode
        os.system(f'iwconfig {self.interface} mode {mode}')
        # Enable networkmanager again if setting to managed mode
        if mode == InterfaceManager.MANAGED_MODE:
            os.system(f'service NetworkManager start')
        # Enable interface
        os.system(f'ifconfig {self.interface} up')
        print(f'[SYSTEM]',
              f'Successfully set {self.interface} to {mode} mode')

    def wlan_channel(self, channel):
        """Set wlan interface to a specified channel."""
        # Use iwconfig to set the channel of the interface
        os.system(f'iwconfig {self.interface} channel {channel}')
        print(f'[SYSTEM]',
              f'Successfully set {self.interface} to channel {channel}')

    def wlan_capture(self, bpf_filter="", timeout=None):
        """Sniff and return a capture."""
        # Create a pyshark live capture
        capture = pyshark.LiveCapture(
            interface=self.interface,
            bpf_filter=bpf_filter)
        # If timeout is not set, sniff continuously
        if timeout is not None:
            capture.sniff(timeout=timeout)
        else:
            capture.sniff_continuously()
        # Return the capture
        return capture

    def bl_mode(self, mode):
        """Set bl interface to a specified mode."""
        # Set the correct interface mode
        os.system(f'hciconfig {self.interface} {mode}')
        print(f'[SYSTEM]',
              f'Successfully set {self.interface} to {mode} mode')

    def bl_capture(self, timeout=30):
        """Sniff and return a capture."""
        # Create a pygatt backend
        adapter = pygatt.GATTToolBackend(hci_device=self.interface)
        adapter.start()
        # Return the scan (capture)
        return adapter.scan(run_as_root=True, timeout=timeout)
