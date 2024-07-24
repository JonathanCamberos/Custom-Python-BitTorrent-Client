import random
import string
import socket
import struct

from math import ceil
from util import *
from datetime import datetime

class Peer:
    def __init__(self, id_number, peer_ip_addr, peer_port, sd):
        self.peer_id = id_number
        self.peer_ip_addr = peer_ip_addr
        self.peer_port = peer_port
        self.sock = sd
        self.pieces_they_have = []
        self.am_choking = 1
        self.am_interested = 0
        self.peer_choking = 1
        self.peer_interested = 0
        self.peer_last_message_time = datetime.now()
        self.peer_last_send_time = -1
        self.peer_download_rate = -1
        self.handshake_complete = 0
        self.current_requested_pieces = []

    def __str__(self):
        return "ID: " + self.peer_id + ", " + self.peer_ip_addr + ":" + str(self.peer_port)

    def __eq__(self, other):
        """Overrides the default implementation"""
        return self.peer_id == other.peer_id and self.peer_ip_addr == other.peer_ip_addr and self.peer_port == other.peer_port

    def __lt__(self, other):  # For sorting lists
        return self.peer_id < other.peer_id
    def set_sock(self, sd):
        self.sock = sd
        
    def send_keep_alive_msg(self):
        msg_len = struct.pack("!I", 0)
        message = b"".join([msg_len])
        # print(message)
        # print("send_keep_alive_msg")
        self.sock.sendall(message)
        
    def send_choke_msg(self):
        msg_len = struct.pack("!I", 1)
        msg_id = b"\x00"
        message = b"".join([msg_len, msg_id])
        # print("send_choke_msg")
        self.sock.sendall(message)
        
    def send_unchoke_msg(self):
        msg_len = struct.pack("!I", 1)
        msg_id = b"\x01"
        message = b"".join([msg_len, msg_id])
        # print("send_unchoke_msg")
        self.sock.sendall(message)

    def send_interested_msg(self):
        # print("Inside Sending Interested Message $$$$$$$$$$$$")

        msg_len = struct.pack("!I", 1)
        msg_id = b"\x02"
        message = b"".join([msg_len, msg_id])
        # print(message)
        #print("send_interested_msg on sock: ", self.sock)
        self.sock.sendall(message)
        #print("After sending Message")
        
    def send_not_interested_msg(self):
        msg_len = struct.pack("!I", 1)
        msg_id = b"\x03"
        message = b"".join([msg_len, msg_id])
        # print("send_not_interested_msg")
        self.sock.sendall(message)
        
    def send_have_msg(self, index):
        msg_len = struct.pack("!I", 5)
        msg_id = b"\x04"
        message = b"".join([msg_len, msg_id, index])
        # print(message)
        # print("send_have_msg")
        self.sock.sendall(message)
        
    def send_bitfield_msg(self, bitfield_lst, num_pieces):

        #print("Inside - Sending bitfield message")
        # print("Inside - Sending bitfield message -- Sender bit List --------> ", bitfield_lst)

        bitfield_to_send = convert_list_to_bitfield(bitfield_lst, num_pieces)

        #print("Unformated bitfield to send: ", bitfield_to_send)
        #print("Type of bitfield -> ", type(bitfield_to_send))

        # print("Calculated bitfield to send: ", end=" ")
        # print("{:b}".format(bitfield_to_send))


        num_bytes = ceil(num_pieces / 8)
        #print("Num_bytes -> ", num_bytes)
        #byte_bitfield = struct.pack(f"!{num_bytes}s", bytes(bitfield_to_send))
        #print("Type of bitfield -> ", type(bitfield_to_send))

        byte_bitfield = bitfield_to_send.to_bytes(num_bytes, byteorder='little')   #BIG CHANGE
        #byte_bitfield = int.to_bytes(bitfield_to_send, "little")

        
        # print("Byte_bitfield after struct.pack ", byte_bitfield)
        # print("Type of Byte_bitfield: ", type(byte_bitfield))

        msg_len = struct.pack("!I", 1 + len(byte_bitfield))
        msg_id = b"\x05"
        message = b"".join([msg_len, msg_id, byte_bitfield])
        # print(message)
        # print("send_bitfield_msg")

        self.sock.sendall(message)

        
        # print("Exiting - Sending bitfield message")
        
    def send_request_msg(self, index, begin, length):
        # print(" ^^^^^^^^^^^^^^^ Inside REQUESTING A PIECE ^^^^^^^^^^^^^^^ ")

        # print("Index: ", index, " Begin: ", begin, " Length: ", length)
        
        msg_len = struct.pack("!I", 13)
        msg_id = b"\x06"
        message = b"".join([msg_len, msg_id, index, begin, length])
        # print(message)
        # print("send_request_msg")
        self.sock.sendall(message)
        
    def send_piece_msg(self, index, begin, block):
        num_bytes_block = len(block)
        msg_len = struct.pack("!I", 9 + num_bytes_block)
        msg_id = b"\x07"
        message = b"".join([msg_len, msg_id, index, begin, block])
        # print(message)
        # print("send_piece_msg")
        self.sock.sendall(message)

def generate_peer_id():
    """
    This function generates a peer id according to Azureus-style convention
    :return: int peer id
    """
    generated_id = "-"
    generated_id += "".join(random.choice(string.ascii_letters) for i in range(2))
    generated_id += "".join(random.choice(string.digits) for i in range(4))
    generated_id += "-"
    generated_id += "".join(random.choice(string.digits) for i in range(12))
    return generated_id
