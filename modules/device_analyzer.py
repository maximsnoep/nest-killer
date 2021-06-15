#!/usr/bin/python3

"""This module contains multiple tools to analyze a device."""
from .interface_manager import InterfaceManager
import numpy as np
import threading
from matplotlib.animation import FuncAnimation
import matplotlib.pyplot as plt


class DeviceAnalyzer():
    """Analyze a device."""

    def __init__(self, device, interface, timeout=3):
        """Initialize variables."""
        self.device = device
        self.interface = interface
        self.timeout = timeout
        self.channels = [1, 6, 11]

        self.manager = InterfaceManager(interface)
        self.manager.wlan_mode(InterfaceManager.MONITOR_MODE)

    def get_channels(self):
        """Returns most active channels by counting packets from/to target."""
        print(f'[INFO]',
              f'Analyzing channels...',
              f'[device: {self.device}, interface: {self.interface}]')
        self.counters = {i: 0 for i in self.channels}
        # for each channel
        for ch in self.channels:
            # set interface to correct channel
            self.manager.wlan_channel(ch)
            # sniff on the interface
            capture = self.manager.capture(
                bpf_filter=f'wlan addr2 {self.device} or \
                             wlan addr1 {self.device}',
                timeout=self.timeout)
            # count the number of packets
            self.counters[ch] = len(capture)
            if (self.counters[ch] > 0):
                print(f'[INFO]',
                      f'Channel {ch}: {self.counters[ch]} packets')
        # return the channel with the most counted packets
        return max(self.counters, key=self.counters.get)

    def visualize_packets(self, channel=6, interval=1, length=60):
        """Visualize packets by counting packets from/to target."""
        print(f'[INFO]',
              f'Visualizing packets...',
              f'[channel {channel}, interval: {interval}, length: {length}]')
        self.manager.wlan_channel(channel)
        self.interval = interval
        self.length = length
        self.counters = {'transmitting': 0, 'receiving': 0, 'average': 0}
        self.x = (np.arange(-self.length/self.interval, 0, dtype=np.float))
        self.y = {i: [0]*int(self.length/self.interval) for i in self.counters}
        self.fig = plt.figure(figsize=(10, 4))
        self.lines = {i: plt.plot([], [], label=f'{i}')[0]
                      for i in self.counters}

        # setup graph
        plt.xlim(self.x[0], self.x[-1])
        plt.xticks(
            np.arange(self.x[0], 1, step=10 / self.interval),
            np.arange(int(self.x[0] * self.interval), 1, step=10))
        plt.xlabel('time [s]')
        plt.ylim(0, 80000 * self.interval)
        plt.ylabel(f'payload [bytes in {self.interval}s]')
        plt.title(f'Device: {self.device}', loc='center')
        plt.legend(loc='upper left')

        # thread animating graph
        animation = FuncAnimation(
            self.fig,
            self._update(),
            interval=int(1000.0 * self.interval)
        )

        # thread capturing packets
        threading.Thread(target=self._capture, daemon=True).start()

        plt.show(block=True)

    def _capture(self):
        capture = self.manager.capture(
                bpf_filter=f'wlan addr2 {self.device} or \
                             wlan addr1 {self.device}')
        for packet in capture:
            try:
                if packet.wlan.ta == self.device and \
                   packet.wlan.fc_type == '2':
                    self.counters['transmitting'] += len(packet)
                if packet.wlan.ra == self.device and \
                   packet.wlan.fc_type == '2':
                    self.counters['receiving'] += len(packet)
            except AttributeError:
                continue

    def _update(self):
        def __(_):
            for i in self.counters:
                if i == 'average':
                    self.y[i].append(np.mean(
                        self.y['transmitting'][-5*int(1/self.interval):]))
                else:
                    self.y[i].append(self.counters[i])
                self.y[i] = self.y[i][-int(self.length/self.interval):]
                self.lines[i].set_data([self.x[-len(self.y[i]):], self.y[i]])
                self.counters[i] = 0
            avg = self.y['average'][-1]
            cur = self.y['transmitting'][-1]
            plt.title(f'[average: {avg:.0f}]', loc='left')
            plt.title(f'[current: {cur:.0f}]', loc='right')
            return self.lines.values()
        return __
