#!/usr/bin/python3

"""This module manages an interface."""
import pyshark
import os


class InterfaceManager():
    """Manages an interface"""
    MANAGED_MODE = 'managed'
    MONITOR_MODE = 'monitor'

    def __init__(self, interface):
        """Initialize variables."""
        self.interface = interface

    def wlan_mode(self, mode):
        """Sets interface to a specified mode."""
        # disable interface
        os.system(f'ifconfig {self.interface} down')
        # use airmon-ng to kill networkmanager
        os.system(f'airmon-ng check kill')
        # set the interface mode
        os.system(f'iwconfig {self.interface} mode {mode}')
        # enable networkmanager again if managed mode
        if mode == InterfaceManager.MANAGED_MODE:
            os.system(f'service NetworkManager start')
        # enable interface
        os.system(f'ifconfig {self.interface} up')
        print(f'[SYSTEM]',
              f'Successfully set {self.interface} to {mode} mode')

    def wlan_channel(self, channel):
        """Sets interface to a specified channel."""
        # use iwconfig to set the channel of the interface
        os.system(f'iwconfig {self.interface} channel {channel}')
        print(f'[SYSTEM]',
              f'Successfully set {self.interface} to channel {channel}')

    def capture(self, bpf_filter="", timeout=None):
        """Returns a capture."""
        # create a capture
        capture = pyshark.LiveCapture(
            interface=self.interface,
            bpf_filter=bpf_filter)
        # sniff on the capture if timeout is not None
        if timeout is not None:
            capture.sniff(timeout=timeout)
        else:
            capture.sniff_continuously()
        # return the capture
        return capture
