"""
README FIRST!
make sure you do the following steps first, so you'll have all modules:
1. sudo apt update
2. sudo apt install python3-pip
3. pip3 install bencode
"""

# TODO: check that all these packages are ok with TA's!
import socket
import sys
import bencode
import re
import urllib.parse

from Peer import Peer, generate_peer_id
from Tracker import Tracker

# the '*' means to import all from constant file :)
# It is just a file which contains all the name of the fields according to the protocol
from constants import *

def is_valid_port(sd: socket, port: int):
    try:
        sd.bind((socket.gethostname(), port))
        return True
    except socket.error as e:
        return False

def get_list_of_peers_from_tracker(tracker: Tracker, port: int):
    sd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    res = re.findall("http://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)/announce", tracker.announce_url)
    tracker_ip_addr, tracker_port = res[0][0], int(res[0][1])
    print(f"BitTorrent client is connecting to a tracker in {tracker_ip_addr}:{tracker_port}")
    try:
        sd.connect((tracker_ip_addr, tracker_port))
    except socket.error as e:
        print("error")

    # TODO: handle compact, no_peer_id
    http_get_req = f"GET /announce?info_hash={urllib.parse.quote(tracker.info_hash)}" \
                   f"&peer_id={urllib.parse.quote(peer_id)}&port={str(port)}" \
                   f"&uploaded=0&downloaded=0&left={str(tracker.len)}" \
                   f"&compact=0&event=started " \
                   f"HTTP/1.1\r\nHost: {tracker_ip_addr}:{str(tracker_port)}\r\n\r\n"
    print("** Sending a HTTP request (GET) to tracker")
    sd.sendall(bytes(http_get_req, 'utf-8'))

    # TODO: check if got bad response
    # TODO: change to recv_all
    response = sd.recv(4096)
    print("** Received a HTTP response from tracker")
    idx = response.index(b"Content-Length")
    actual_response = response[idx:]
    idx = actual_response.index(b"d")  # finding the start of the dictionary encoding
    actual_response = actual_response[idx:]
    response_dict = bencode.decode(actual_response)
    interval = response_dict[interval_keyword]
    tracker_id = response_dict[tracker_id_keyword] if tracker_id_keyword in response_dict.keys() else ""
    num_seeders = response_dict[complete_keyword]
    num_leechers = response_dict[incomplete_keyword]
    peers_list = [Peer(p[peer_id_keyword], p[peer_ip_keyword], p[peer_port_keyword]) for p in response_dict[peers_keyword]]
    if len(peers_list) != num_seeders + num_leechers:
        print("Error: expected different number of peer list!")
    sd.close()
    return peers_list

if __name__ == '__main__':
    # TODO: validation of command line arguments

    # Communicate with the tracker
    peer_id = generate_peer_id()
    # 1. Parse the tracker file and extract all fields from it
    tracker = Tracker(sys.argv[1])

    # 2. Connect a socket to the announce_url to get the peer list using a http get request
    port = min_port
    peers = get_list_of_peers_from_tracker(tracker, port)
    print("Got the following peers:")
    for p in peers:
        print(p)

    #Download a file (Leacher to Seeder Process): 
    #NOTE: This doesn't include Piece Selection Policies/Choking Alg. (extra-credit features)
    
    #Torrent Data Transfer Process: 
        #a. Periodic Updates: Listen for peers to announce what pieces they have
            #Check: If the number of peers in the peer set falls bellow the threshold, contact the tracker for a 
            #new peer list  
        
        #b. Set up Pipelining: Piece requests must be queued up in order 
            #1) Piece Selection: Clients may choose to download pieces in random order.
        #d. Send Piece Request: Every time a new subpiece is recieved, a new request is sent out from the pipeline

        #e. Handle Response:
            #If we don't recieve the piece from the peer, do... (?)
                # Check if the peer is still alive?
            #Else we recieve the piece, do the processing to the filesystem (Merkel Tree)
                #Test the data integrity by hashing the piece with SHA-1 
                #If the integrity test is successful: Write the piece to the filesystem and update the pipeline
                #Else if the integrity test is unsuccessful: Ignore the sender peer (?) and resend the request to another peer

       #g. Update the Tracker:
        #If disconnecting from the torrent, update the tracker
        #Any other conditions? 
        #Periodic Updates: Report state to tracker about peers what pieces now owned

        #g.Completed Torrent: If we have completed the torrent by gathering all pieces...
            #1) Update status from leacher to seeder 
            # What else (?)


    #(NOT DONE) Download a file (Leacher to Seeder Process): This includes the Choking Algorithim/Extra Credit Features...
    
    #2. Begin Data Transfer Process: 
        #a. Periodic Updates: Listen for peers to announce what pieces they have
            #Check: If the number of peers in the peer set falls bellow the threshold, contact the tracker for a 
            #new peer list  
        
        #b. Choking Algorithim: Decide which peers to choke/unchoke
                #i) Default Unchokes: 
                    # Periodic Update: Select the 4 peers to unchoke. This is based on fastest download rates.
                    # Periodic Updates: Recalculate download rates based on rolling 20 second average and are recalculated every 10 seconds by the client.

                #ii) Optimistic Unchoking Policy:
                    # Periodic Update: Randomly select an additional peer to unchoke every 30 seconds

                #iii) Anti-Snubbing Policy: 
                    #If a peer has not recieved any pieces in 60 seconds it has been "snubbed"
                    #Choke the peers that it has not recieved anything from with the exception of the optimistic unchoke

                #iv)Upload Only Policy:
                    #When a download is completed, unchoke peers with the highest upload rate 

        #b. Set up Pipelining: Piece requests must be queued up in order to get good TCP performance
            #1) Piece Selection: Run the Piece Selection Algorithm to find the best piece
                #i) Rarest First Policy: Prioritize getting the rarest piece in the network (Extra Credit)
                #ii) Strict Priority Policy: This one is the first we should implement NOTE
                #iii) Endgame Policy

        #c. Send Piece Request: Every time a new subpiece is recieved, a new request is sent out from the pipeline
            #Check: Client must be in an interested state, Peer must be in a Non-Choking State (Choking Algorithim)

        #d. (NOT DONE) Handle Response:
        #If we don't recieve the piece from the peer, do processing (Choking Algorithim)
        #Else we recieve the piece, do the processing

        #e. (NOT DONE)
        #Update our pipelining
        #Report to peers what pieces we now own

        #f. (NOT DONE) Check if we have all the pieces. What now?

 