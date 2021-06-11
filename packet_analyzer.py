#!/usr/bin/python3

"""This module analyzes the packets from/to a target."""
import numpy as np
import threading
from interface_manager import InterfaceManager
from matplotlib.animation import FuncAnimation
import matplotlib.pyplot as plt


class PacketAnalyzer():
    """Analyze channels of a target."""

    def __init__(self, target, interface, channel, interval, length):
        """Initialize variables."""
        self.target = target
        self.interval = interval
        self.length = length
        self.target = target
        self.counters = {'transmitting': 0, 'receiving': 0, 'average': 0}

        self.x = (np.arange(-self.length/self.interval, 0, dtype=np.float))
        self.y = {i: [0]*int(self.length/self.interval) for i in self.counters}
        self.fig = plt.figure(figsize=(10, 4))
        self.lines = {i: plt.plot([], [], label=f'{i}')[0]
                      for i in self.counters}

        self.manager = InterfaceManager(interface)
        self.manager.wlan_mode(InterfaceManager.MONITOR_MODE)
        self.manager.wlan_channel(channel)

    def _capture(self):
        capture = self.manager.capture(
                bpf_filter=f'wlan addr2 {self.target} or \
                             wlan addr1 {self.target}')
        for packet in capture:
            try:
                if (packet.wlan.ta == self.target):
                    self.counters['transmitting'] += len(packet)
                if (packet.wlan.ra == self.target):
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
            cur = self.y["transmitting"][-1]
            plt.title(f'Status: {self._get_status(avg)}', loc='left')
            plt.title(f'[avg: {avg:.0f}, cur: {cur:.0f}]', loc='right')
            return self.lines.values()
        return __

    def _get_status(self, value):
        # EVERY 60s big spike -> probably saving something on cloud
        # 80000
        #  = monitoring feed + detecting motion
        # 20000
        #  = monitoring feed
        # 5000
        #  = detecting motion
        # 750
        #  = idle
        # 0
        #  = dead
        if value > 20000 * self.interval:
            status = "monitored + detected"
        elif value > 5000 * self.interval:
            status = "monitored"
        elif value > 750 * self.interval:
            status = "detected"
        elif value > 0:
            status = "idle"
        else:
            status = "offline"
        return status

    def start(self):
        """Visualize packets by counting packets from/to target."""

        # setup graph
        plt.xlim(self.x[0], self.x[-1])
        plt.xticks(
            np.arange(self.x[0], 1, step=10 / self.interval),
            np.arange(int(self.x[0] * self.interval), 1, step=10))
        plt.xlabel('time [s]')
        plt.ylim(0, 80000 * self.interval)
        plt.ylabel(f'payload [bytes in {self.interval}s]')
        plt.title(f'Target: {self.target}', loc='center')
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
