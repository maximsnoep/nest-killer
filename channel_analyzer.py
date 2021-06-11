#!/usr/bin/python3

"""This module analyzes the channels of a target."""
from interface_manager import InterfaceManager


class ChannelAnalyzer():
    """Analyze channels of a target."""

    def __init__(self, target, interface, timeout=3):
        """Initialize variables."""
        self.target = target
        self.timeout = timeout
        self.channels = range(1, 14+1)
        self.counters = {i: 0 for i in self.channels}
        self.manager = InterfaceManager(interface)
        self.manager.wlan_mode(InterfaceManager.MONITOR_MODE)

    def get_most_active_channel(self):
        """Returns most active channels by counting packets from/to target."""
        # for each channel
        for ch in self.channels:
            # set interface to correct channel
            self.manager.wlan_channel(ch)
            # sniff on the interface
            capture = self.manager.capture(
                bpf_filter=f'wlan addr2 {self.target} or \
                             wlan addr1 {self.target}',
                timeout=self.timeout)
            # count the number of packets
            self.counters[ch] = len(capture)
            if (self.counters[ch] > 0):
                print(f'[INFO]',
                      f'Channel {ch}: {self.counters[ch]} packets')
        # return the channel with the most counted packets
        return max(self.counters, key=self.counters.get)
