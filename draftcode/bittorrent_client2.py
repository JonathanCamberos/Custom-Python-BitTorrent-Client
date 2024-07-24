"""
README FIRST!
make sure you do the following steps first, so you'll have all modules:
1. sudo apt update
2. sudo apt install python3-pip
3. pip3 install bencode OR pip3 install bencode.py
"""

import socket
import select
import sys
import os.path
import struct
import datetime

from Peer import Peer, generate_peer_id
from Tracker import Tracker
from constants import *

TTL = 120
MIN_PEERS = 30
client_state_dict = {}
bitfield = 0b0

"""
Periodically sends bittorrent keep-alive messages to peers to maintain connection
"""
def send_keep_alive(sd: socket):
    keep_alive_message = b'\x00\x00\x00\x00'
    try:
        result = sd.sendall(keep_alive_message)
        if (result == None):
            print("Successfully sent a keep alive message. (Verify with Wireshark)")
    except e:
        print(e)

"""
Drop a connection with a peer as a result of lack/infrequent keep-alive messages sent to the client. 
In addition, check if the current number of peers on the client’s peer list is below the threshold of peers. If so, the client will request a new peer list
"""
def drop_from_peers(peer: Peer):
    #Drop a connection by updating the client_state_dict and peers list
    del client_state_dict[peer]
    peers.remove(peer)

    #If the number of peers is below the threshold, refresh the peer list
    num_peers = len(client_state_dict)
    if num_peers < MIN_PEERS:
        print("TO-DO when Saar is done: call get_list_of_peers() or get_list_of_peers_compact()")

def send_recv_handshake(sd: socket, peer_id: str, tracker: Tracker):
    """
    Sends and receives bittorrent handshake needed to initiate a connection
    with a client
    """
    pstrlen = b"\x13"
    pstr = b"BitTorrent protocol"
    reserved = b"\x00\x00\x00\x00\x00\x00\x00\x00"
    info_hash = tracker.info_hash
    peer_id = peer_id.encode("utf-8")
    
    handshake_message = b"".join([pstrlen, pstr, reserved, info_hash, peer_id])
    print("SEND RECV: "+str(type(sd)))
    sd.sendall(handshake_message)
        
    response_handshake = sd.recv(68)
    pstrlen, pstr, reserved, info_hash, response_peer_id = struct.unpack("!c19s8s20s20s", response_handshake)
    pstrlen = int.from_bytes(pstrlen, "big")
    pstr = pstr.decode("utf-8")
    response_peer_id = response_peer_id.decode("utf-8")
    print(pstrlen)
    print(pstr)
    print(reserved)
    print(info_hash)
    # TODO: validate response peer id
    print("Received Peer ID:", response_peer_id)
    print("My Peer ID:", peer_id)

def is_valid_port(sd: socket, port: int):
    try:
        sd.bind((socket.gethostname(), port))
        return True
    except socket.error as e:
        return False

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python3 bittorrent_client.py path_to_.torrent_file")
        exit(1)
    if not os.path.exists(sys.argv[1]) or not os.path.isfile(sys.argv[1]) \
            or not sys.argv[1].endswith('.torrent'):
        print("Please enter a valid .torrent file")
        exit(1)
    # 0. Generate a unique id for myself
    peer_id = generate_peer_id()
    # 1. Parse the tracker file and extract all fields from it
    tracker = Tracker(sys.argv[1])

    # 2. Connect a socket to the announce_url to get the peer list using a http get request
    port = min_port
    peers = tracker.get_list_of_peers(port, peer_id)
    if len(peers) == 0:
        exit(1)

    print("Got the following peers:")
    for p in peers:
        print(p)

    # 3. Connect to the peers using TCP to download the file
    num_pieces = tracker.get_num_pieces()
    for n in range(num_pieces - 1):
        bitfield = bitfield << 1
    print("{:b}".format(bitfield))
    
    # Create empty file descriptors lists needed for select call below
    rlist, wlist, xlist = [], [], []
    socket_error = False
    
    for p in peers:
        if p.peer_ip_addr == "128.8.126.63" and p.peer_port == 51413:
            sd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sd.connect((p.peer_ip_addr, p.peer_port))
                send_recv_handshake(sd, peer_id, tracker)
                p.set_sock(sd)
                client_state_dict[p] = {"am_choking": 1,
                                        "am_interested": 0,
                                        "peer_choking": 1,
                                        "peer_interested": 0,
                                        "connection_start": datetime.time()
                                        }
                
                #Start timer for periodic keep-alive messages
                p.connection_start = datetime.time()
                rlist.append(sd)
            except socket.error as e:
                print(e)
                socket_error = True
    
    #4. Reading data from peers
    while True:
        #Handle Periodic Keep-Alive Messages
        for key in client_state_dict.keys():
            #Check if the client maintains the connection
            print(datetime.now()) 
            last_keep_alive_sent = datetime.time().timestamp() - key.connection_start
            print("Time Diff: "+str(last_keep_alive_sent))
            print("Keep Alive - Current Peer "+str(key))
            print("TTL: "+str(TTL)) 
            
            if last_keep_alive_sent >= TTL:
                send_keep_alive(key.sock)
                key.connection_start = datetime.time()
            
            #Check if the current peer maintains the connection
            last_keep_alive_recv = datetime.time() - client_state_dict[key]["connection_start"] 
            if last_keep_alive_recv >= TTL:
                drop_from_peers(key)
                print("Dropped the connection with the peer {key.peer_id} for not maintaining the connection")

        rfds, wfds, xfds = select.select(rlist, wlist, xlist)
        for r in rfds:
            if (r.fileno == -1):
                    continue
            
            current_peer = None
            for k in client_state_dict.keys():
                if k.sock == r:
                    current_peer = k

            #Handle a Handshake Message:
            if client_state_dict[current_peer]["am_interested"] == 1 and client_state_dict[current_peer]["am_choking"] == 0:
                #Extract Message Fields:
                handshake = sd.recv(68)
                pstrlen, pstr, reserved, info_hash, response_peer_id = struct.unpack("!c19s8s20s20s", handshake)
                pstrlen = int.from_bytes(pstrlen, "big")
                pstr = pstr.decode("utf-8")
                response_peer_id = response_peer_id.decode("utf-8")
                print("Recieved a handshake message from peer {current_peer.peer_id}")
                print(pstrlen)
                print(pstr)
                print(reserved)
                print(info_hash)

                #Data Validation:
                if pstrlen != 19:
                    print("Invalid Handshake Recieved: pstr_len should be 19 but is {pstr_len}")
                    continue

                if pstr != "BitTorrent protocol":
                    print("Invalid Handshake Recieved: pstr should be \"BitTorrent protocol\" but is {pstr}")
                    continue

                if tracker.info_hash != info_hash:
                    print("Invalid Handshake Recieved: infohash should be {tracker.info_hash} but is {info_hash}")
                    drop_from_peers(current_peer)
                    continue

                send_recv_handshake(r,current_peer.peer_ip,tracker)
                
            #Handle a Peer Message
            else:
                id = -1
                message = r.recv(4)
                if len(message) == 0:
                    print("Invalid Recv")
                else: 
                    #Extract message fields
                    mlen = struct.unpack("!I", message)
                    mlen = mlen[0]
                    
                    print("Length translated: ", end=" ")
                    print(mlen)
                    if mlen != 0:
                        message2 = r.recv(1)
                        print("ID Recieved: ", end=" ")
                        print(message2)

                        id = struct.unpack("!c", message2)
                        id = id[0]
                        id = int.from_bytes(id, "big") 
                        
                        print("ID Translated: ", end=" ")
                        print(id)
                    else:
                        client_state_dict[r] = datetime.time()
            
                #TODO: Instead of assuming socket corresponds to a peer, use host, port = sd.getpeername() instead
                if id == 0:
                    client_state_dict[current_peer]["peer_choking"] = 1
                if id == 1:
                    client_state_dict[current_peer]["peer_choking"] = 0
                elif id == 2:
                    client_state_dict[current_peer]["peer_interested"] = 1
                elif id == 3:
                    client_state_dict[current_peer]["peer_interested"] = 0
                elif id == 4:
                    k = 7 #Placeholder to ensure if statement doesn't have an empty clause
                elif id == 5:
                    peer_bitfield = r.recv(mlen - 1)
                    peer_bitfield = int.from_bytes(peer_bitfield, "big")
                    print("{:b}".format(peer_bitfield))
                elif id == 6:
                    k = 7
                elif id == 7:
                    k = 7
                elif id == 8:
                    k = 7
                elif id == 9:
                    k = 7

                for k in client_state_dict.keys():
                    if k.sock == r and not client_state_dict[k]["am_interested"]:
                        k.send_interested_msg()
                        client_state_dict[k]["am_interested"] = 1   
    
        #TODO: Handle Periodic Keep-Alive Messages: