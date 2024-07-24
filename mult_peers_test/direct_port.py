"""
README FIRST!
make sure you do the following steps first, so you'll have all modules:
1. sudo apt update
2. sudo apt install python3-pip
3. pip3 install bencode OR pip3 install bencode.py
"""

import socket
import time

import select
import sys
import os
import os.path
import struct
import codecs
import bencode
import hashlib
import argparse
import random
import os.path

from datetime import datetime
from collections import Counter

from Peer import Peer, generate_peer_id
from Tracker import Tracker
from constants import *
from util import *
from math import ceil


num_unchokes = 0
optimistic_unchoke_time = 30
client_state_list = []
my_bitfield_lst = []
my_bitfield = 0b0
piece_dictionary = {}
file = "holder"
down_path = ""
args = []
last_piece_size = "holder"
last_piece_size_requested = 0
num_pieces_global = 0
num_of_peers_threshold = 30
top_four = []
uploader_uninterested_we_unchoked = []
is_in_endgame_mode = False
blocks_threshold_endgame = 3
current_requested_pieces_overall = []
piece_len_per_request = -1


def calc_remain_blocks(total_pieces, piece_size):
    count = 0
    for i in range(0, total_pieces):
        if len(piece_dictionary["piece" + str(i)]) < piece_size:
            count += 1
    return count


def request_last_pieces_endgame(total_pieces, piece_size):
    for i in range(0, total_pieces):
        if len(piece_dictionary["piece" + str(i)]) < piece_size:
            for peer in peers:
                if peer.sock != -1:
                    compare_bitfield_and_request_piece(peer, 0)

def send_recv_handshake(sd: socket, peer_id: str, tracker: Tracker):
    """
    Sends and receives bittorrent handshake needed to initiate a connection
    with a client
    """
    print("send_recv_handshake")
    pstrlen = b"\x13"
    pstr = b"BitTorrent protocol"
    reserved = b"\x00\x00\x00\x00\x00\x00\x00\x00"
    info_hash = tracker.info_hash
    peer_id = peer_id.encode("utf-8")

    handshake_message = b"".join([pstrlen, pstr, reserved, info_hash, peer_id])
    sd.sendall(handshake_message)

    response_handshake = sd.recv(68)
    if len(response_handshake) == 0:
        # print("Couldn't complete the handshake")
        return False
    # print("Bytes recieved from response to our initial handshake --->", len(response_handshake))
    pstrlen, pstr, reserved, info_hash, response_peer_id = struct.unpack("!c19s8s20s20s", response_handshake)
    pstrlen = int.from_bytes(pstrlen, "big")
    pstr = pstr.decode("utf-8")
    # response_peer_id = response_peer_id.decode("utf-8")
    # print(pstrlen)
    # print(pstr)
    # print(reserved)
    # print(info_hash)
    # TODO: validate response peer id
    # print("Received Peer ID:", response_peer_id)
    # print("My Peer ID:", peer_id)
    return True

#Need to Delete This One Later
def compare_bitfield_and_request_piece(peer, piece_length):
    my_bitfield_lst = convert_bitfield_to_list(my_bitfield)
    bitfield_diff = list(set(peer.pieces_they_have) - set(my_bitfield_lst))

    if bitfield_diff != []:
        peer.send_interested_msg()
        index = struct.pack("!I", bitfield_diff[0])
        begin = struct.pack("!I", 0)
        length = struct.pack("!I", 16384)
        peer.send_request_msg(index, begin, length)

def is_valid_port(sd: socket, port: int):
    """ Checks whether port can be binded too and is valid
    """
    try:
        sd.bind(("0.0.0.0", port))
        # sd.bind((socket.gethostname(), port))
        return True
    except socket.error as e:
        return False

def validate_peer_list():
    global client_state_list
    new_clientlist = []
    for c in client_state_list:
        curr_time = datetime.now()
        #Check that client has sent a message in the past two minutes and that
        #it has not closed the socket
        if (curr_time - c.peer_last_message_time).total_seconds() <= 120 and (c.sock.fileno != -1):
            new_clientlist.append(c)

    # If client list is less than threshold, repopulate it by calling the tracker
    if len(client_state_list) > num_of_peers_threshold > len(new_clientlist):
        client_state_list = new_clientlist
        print("! Trying to get new peers due to threshold")
        new_peers = tracker.get_peers_list(peer_id, port)
        # if sorted(new_peers) != sorted(client_state_list):
        if sorted(new_peers) != sorted(peers):
            print("len(new_peers):", len(new_peers))
            print("len(client_state_list):", len(client_state_list))
            print("client_state_list:\n", client_state_list)
            print("new_peers:\n", new_peers)
            initialize_client_state_list()


#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# Start of untested methods ---> Things we couldn't test bc the peers stopped sending an unchoke message

#while we are listening on a socket, if someone sends us a handshake message, we add them to the peer list, and send back a handshake response, and also send our bit field
def recv_handshake_from_initiator(my_socket, my_peerid):

    #accept
    peer_sock, address = my_socket.accept()
    peer_ipaddr, peer_socket = address

    #create new peer (we do not know there peer 'id')
    new_peer = Peer("Unknown", peer_ipaddr, peer_socket, peer_sock)

    #read and parse request
    response_handshake = peer_sock.recv(68)
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
    new_peer.peer_id = response_peer_id
    print("My Peer ID:", my_peerid)

    #create a handshake response and send
    pstrlen = b"\x13"
    pstr = b"BitTorrent protocol"
    reserved = b"\x00\x00\x00\x00\x00\x00\x00\x00"

    #TODO: Validate whether info hash is valid
    info_hash = tracker.info_hash
    peer_id = my_peerid.encode("utf-8")

    #send_test edit
    client_state_list.append(new_peer)

    #join handshake message and send
    handshake_message = b"".join([pstrlen, pstr, reserved, info_hash, peer_id])
    peer_sock.sendall(handshake_message)

    #after handshake message immediatly send our bitfield message
    new_peer.send_bitfield_msg(my_bitfield_lst, num_pieces_global)


#reading a section of the file
def send_from_file(client_we_are_serving, piece_name, piece_index, inner_offset, size_of_block, tracker):

    global file
    global piece_dictionary

    #file = open(down_path, "rb")

    #calc offset for curr piece
    piece_starting_offset = piece_index * tracker.piece_length

    #moving file pointer to offset of current block we are sending (piece_offset + offset_of_block)
    file.seek(piece_starting_offset + inner_offset)

    #getting bytes from file
    block_bytes = file.read(size_of_block)

    print("We read ", len(block_bytes))

    #packaging
    index = struct.pack("!I", piece_index)
    begin = struct.pack("!I", inner_offset)
    client_we_are_serving.send_piece_msg(index, begin, block_bytes)

    #file.close()



#handing peer sending us a request
def handle_request_piece(client_we_are_serving, index, begin, length, tracker):

    #check if piece exists
    piece_name = check_exists_piece_name(index)

    if(piece_name == -1):
        print("Invalid Index Requested --")

    else:
        #send block from file
        send_from_file(client_we_are_serving, piece_name, index, begin, length, tracker)


# end of untested methods
#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@


##########################################################################################################################################
# start of file stuff bc we are lazy :) and global variables are dumb   (we couldnt figure out how to import global variables so we stored everything here for now, we will fix later)

#initializing dicitonary and file
def start_dictionary_and_file(total_pieces):

    global piece_dictionary
    global file

    # print(piece_dictionary)


    for i in range(0, total_pieces):
        piece_dictionary["piece" + str(i)] = bytearray(0)

    # print(piece_dictionary)

    # file = open("./testing/test_write_file", "r+b")
    file = open(down_path, "r+b")
    #file.seek(0)
    #file.truncate(0) #resets file for current session


def write_to_file(piece_name, piece_index, total_piece_size):

    print("Inside write write write write write write write write write")

    #TODO ignore repeat file,

    global file
    global piece_dictionary
    global my_bitfield
    global my_bitfield_lst

    #file = open(down_path, "w+b")

    #calc offset for curr piece
    offset = piece_index * total_piece_size

    print(f"! write_to_file: piece_index = {piece_index}, offset = {offset}")
    time.sleep(1)

    file.seek(0)

    current_pointer_position = file.tell()
    print("Current Pointer Position: ", current_pointer_position)

    #move file pointer to offset
    file.seek(offset)

    current_pointer_position = file.tell()
    print("Current Pointer Position: ", current_pointer_position)

    #get list of bytes from piece_dictionary
    bytes_Array = piece_dictionary[piece_name]
    final_bytes_object = bytes(bytes_Array)

    print(f"! bytes_Array = {bytes_Array}")

    #write list of bytes to file (TODO make this more efficient)
    file.write(final_bytes_object)

    #send to all clients a 'have' message, for current piece we just wrote to file
    for c in client_state_list:
        index = struct.pack("!I", piece_index)
        c.send_have_msg(index)

    #update our bitfield
    my_bitfield_lst.append(piece_index)
    my_bitfield = convert_list_to_bitfield(my_bitfield_lst, num_pieces_global)
    print(my_bitfield)
    print("{:b}".format(my_bitfield))

    #print("wow this is so quirky")

    #file.close()


#everytime we add to dictionary, we check if curr piece hsa reached the total_piece_size ex: 2^14, if so we check the has
def add_bytes_to_dictionary(bytes, piece_index, total_piece_size, offset, client_we_are_serving, total_num_pieces, tracker):

    global last_piece_size_requested
    global piece_dictionary

    #print("Inside RECV - Add Bytes To Dictionary ---- ")

    #returns if valid piece_index was provided
    piece_name = check_exists_piece_name(piece_index)

    if(piece_name == -1):
        print("Piece Name --- Does not exist")

    else:

        #appending bytes recieved to piece byteArray
        piece_dictionary[piece_name].extend(bytes)

    #compare curr list size to expected total_piece_size
    size_res = check_size(piece_index, total_piece_size,  total_num_pieces)

    if(size_res == 1):
        #all blocks recieved! compare recieved piece to expected hash
        check_hash(piece_name, piece_index, total_piece_size, client_we_are_serving, total_num_pieces, tracker)


    elif(size_res == 2):
        #waiting on more blocks...

        #if we have recieved a block pertaining to the last piece
        if (piece_index == total_num_pieces - 1):

            print("GARDENIA")

            #last_piece_size_requested starts at 0    ---> last_piece_size - last_piece_size_requested(what we have recieved) = size of block we still need
            if (last_piece_size - last_piece_size_requested) >= piece_len_per_request:   #if size of block we need, is larger than max request size, request max size
                #formatting to send
                index = struct.pack("!I",piece_index)
                begin = struct.pack("!I", 0)
                length = struct.pack("!I", piece_len_per_request)
                print("TRIGGERED IN IF")
                print("Index:", index)
                print("Begin", begin)
                print("Length:", length)
                client_we_are_serving.send_request_msg(index, begin, length)
                last_piece_size_requested += piece_len_per_request #update how much we have requested

            #else if size of block we need, is less than max request size (ex: this is the last 10 bytes of the files)
            else:
                #formatting to send
                index = struct.pack("!I", piece_index)
                begin = struct.pack("!I", last_piece_size_requested)
                length = struct.pack("!I", (last_piece_size - last_piece_size_requested))  #how much bytes are left for last piece (total_size - what we have recieved)
                print("TRIGGERED IN ELSE")
                print("Index:", index)
                print("Begin", begin)
                print("Length:", length)
                client_we_are_serving.send_request_msg(index, begin, length)

                last_piece_size_requested = 0 #reset how much we have requested, for the next file

        #if we have recieved block NOT from the last piece
        else:
            #trigger request based on offset

            #Starting offset of block we just recieved + len(block) = starting offset of next block

            #formatting to send
            index = struct.pack("!I", piece_index) #current piece
            begin = struct.pack("!I", offset+len(bytes)) #next block offsezt
            next_piece_len = min(total_piece_size-len(piece_dictionary[piece_name]), piece_len_per_request)
            length = struct.pack("!I", next_piece_len) #size of next block request = total_piece_size - currList(what we have recieved)
            # length = struct.pack("!I", total_piece_size-len(piece_dictionary[piece_name])) #size of next block request = total_piece_size - currList(what we have recieved)

            print("ADDING BYTES TO DICITONARYY **************")

            print("offset - ", offset)
            print("We are adding ", len(bytes), end=" ")
            print("New offset/begin: ", offset+len(bytes))
            print("To the dicationary")

            print("Missing: ",  total_piece_size-len(piece_dictionary[piece_name]))
            print("Requesting next_piece_len: ", next_piece_len)

            print("offset+len(bytes) requesting at index --", offset+len(bytes))
            print("Index:", index)
            print("Begin:", begin)
            print("Length:", length)

            client_we_are_serving.send_request_msg(index, begin, length)


    else:
        #too many blocks, reset!
        reset_piece(piece_index)


def generate_hash_from_bytes(bytes):

    #print("Bytes passed to hash ---> ", bytes, " Of type --> ", type(bytes))

    
    #bencoded_bytes = bencode.encode(bytes)
    #print("bencoded bytes : ", end=" ")
    #print(bencoded_bytes)

    hashed_bytes = hashlib.sha1(bytes)
    #print("sha1 on previous: ", end=" ")
    #print(hashed_bytes)

    digested_bytes = hashed_bytes.digest()
    #print(".digest() on previous: ", end=" ")
    #print(digested_bytes)
    


    #hash = hashlib.sha1(bytes)
    hash = digested_bytes
    return hash



    #for index in range(0, 21):
    #    print("Printing index 0-", end="")
    #    print(str(index-1) + ": ", end=" ")
    #    print(digested_bytes[0: index])


    #print(type(digested_bytes))

    return digested_bytes

def check_hash(piece_name, piece_index, total_piece_size, client_we_are_serving, num_pieces, tracker):
    global last_piece_size_requested
    global piece_dictionary

    correct_hash = tracker.get_piece_hash_by_idx(piece_index)

    bytes_recved = bytes(piece_dictionary[piece_name])
    test_hash = generate_hash_from_bytes(bytes_recved)

    print("Correct hash ---> ", correct_hash)
    print("Test hash ---> ", test_hash)

    if(correct_hash == test_hash):

        print("################## HASH CORRECT FOR PIECE: ", piece_index, "#################")

        #hash is correct!! we can write current piece to file

        write_to_file(piece_name, piece_index, total_piece_size)

        print("We have written to file successfully tis a great day now to do the rest:) (request the next piece from peer)  ")

        if piece_index in current_requested_pieces_overall:
            current_requested_pieces_overall.remove(piece_index)
        if piece_index in client_we_are_serving.current_requested_pieces:
            client_we_are_serving.current_requested_pieces.remove(piece_index)

        #piece_index += 1 #next piece to request
        #print("Next Piece we are attempting to request - ", piece_index)
        #print("Index of last Piece - ", num_pieces - 1)


        #Requesting the last piece
        # if (piece_index == num_pieces-1):

        #     print("ROSE")
        #     if (last_piece_size - last_piece_size_requested) >= 16384:
        #         index = struct.pack("!I",piece_index)
        #         begin = struct.pack("!I", 0)
        #         length = struct.pack("!I", 16384)
        #         print("TRIGGERED IN IF")
        #         print("Index:", index)
        #         print("Begin", begin)
        #         print("Length:", length)
        #         client_we_are_serving.send_request_msg(index, begin, length)
        #         last_piece_size_requested += 16384
        #     else:
        #         index = struct.pack("!I", piece_index)
        #         begin = struct.pack("!I", last_piece_size_requested)
        #         length = struct.pack("!I", (last_piece_size - last_piece_size_requested))
        #         print("TRIGGERED IN ELSE")
        #         print("Index:", index)
        #         print("Begin", begin)
        #         print("Length:", length)
        #         client_we_are_serving.send_request_msg(index, begin, length)
        #         last_piece_size_requested = 0

        # #requesting anything other than last piece
        # elif (piece_index + 1 < num_pieces):
        #     print("FLOWER")
        #     index = struct.pack("!I", piece_index)
        #     begin = struct.pack("!I", 0)
        #     length = struct.pack("!I", 16384)
        #     client_we_are_serving.send_request_msg(index, begin, length)

        # else:
        #     print("We have recieved all the pieces!!!! :))")

    #hash was incorrect --> reset dictionary piece
    else:

        print(" ^@^@^@^@^@^@^@ HASH BAD FOR PIECE: ", piece_index, " ^@^@^@^@^@^@^@ ")
        reset_piece(piece_index)
        if piece_index in current_requested_pieces_overall:
            current_requested_pieces_overall.remove(piece_index)
        if piece_index in client_we_are_serving.current_requested_pieces:
            client_we_are_serving.current_requested_pieces.remove(piece_index)

#checks if index exists in global dictionary
def check_exists_piece_name(piece_index):
    global piece_dictionary

    piece_name = "piece" + str(piece_index)

    if piece_name in piece_dictionary.keys():
        return piece_name
    else:
        return -1

#resets certain index in global dictionary
def reset_piece(piece_index):
    global piece_dictionary

    piece_name = check_exists_piece_name(piece_index)

    if(piece_name == -1):
        print("Piece does not exist!!")

    else:
        piece_dictionary[piece_name] = bytearray(0)


#for all pieces except the last one, checks if current list in global dictionary has reached the expected total_piece_size
def check_size(piece_index, piece_size, total_pieces):
    global piece_dictionary

    piece_name = check_exists_piece_name(piece_index)

    if(piece_index == total_pieces-1):

        if(len(piece_dictionary[piece_name]) ==  last_piece_size):
            return 1

    if(piece_name == -1):
        print("Does not exist")

    else:
        if(len(piece_dictionary[piece_name]) == piece_size):
            print("All blocks Recieved!!")
            return 1

        elif(len(piece_dictionary[piece_name]) > piece_size):

            print("Too many blocks recieved!! ---> Reseting...")
            return -1
        else:
            print("Missing some blocks, waiting...")
            return 2


#end of file stuff
##########################################################################################################################################


def initialize_client_state_list():
    global p, socket_error
    hostname = socket.gethostname()
    IPAddr = socket.gethostbyname(hostname)
    if IPAddr == "172.17.0.2":
        IPAddr = "127.0.0.1"

    print(f"IPAddr: {IPAddr}, port: {port}")
    for p in peers:
        print("p.peer_ip_addr: ", p.peer_ip_addr )
        print("p.peer_port: ", p.peer_port )
        # TODO: Get rid of the if statement below later, after testing
        if p.peer_ip_addr == IPAddr and p.peer_port == port:
            continue
        elif args.ip_addr is None or args.ip_port is None:
            sd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        elif p.peer_ip_addr == args.ip_addr and p.peer_port == args.ip_port:
            sd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            # print(f"Could not initialize peer {p.peer_id}")
            continue

        # while port <= max_port and (not is_valid_port(port)):
        #     port += 1
        # print("BitTorrent client bound to port " + str(args.ip_port))
        try:
            print(f"Trying to connect to {p.peer_ip_addr}:{p.peer_port}")
            sd = socket.create_connection((p.peer_ip_addr, p.peer_port), timeout=1)
            sd.settimeout(None)
            if send_recv_handshake(sd, peer_id, tracker):
                print(f"! Connected to {p.peer_ip_addr}:{p.peer_port}")
                p.set_sock(sd)
                client_state_list.append(p)
                rlist.append(sd)
                print("    HANDSHAKE SUUCCESSS")
        except socket.error as e:
            # print("could not connect: ", e)
            socket_error = True


def request_last_piece(piece_index, p: Peer):
    global last_piece_size_requested
    
    if last_piece_size >= piece_len_per_request:
        index = struct.pack("!I",piece_index)
        begin = struct.pack("!I", 0)
        length = struct.pack("!I", piece_len_per_request)
        print("TRIGGERED IN IF")
        print("Index:", index)
        print("Begin", begin)
        print("Length:", length)
        p.send_request_msg(index, begin, length)
        last_piece_size_requested += piece_len_per_request
    else:
        index = struct.pack("!I", piece_index)
        begin = struct.pack("!I", last_piece_size_requested)
        length = struct.pack("!I", last_piece_size)
        print("TRIGGERED IN ELSE")
        print("Index:", index)
        print("Begin", begin)
        print("Length:", length)
        p.send_request_msg(index, begin, length)
        last_piece_size_requested = 0

def request_piece_random():
    for c in client_state_list:
        my_bitfield_lst = convert_bitfield_to_list(my_bitfield)
        bitfield_diff = list(set(c.pieces_they_have) - set(my_bitfield_lst))
        # print("my_bitfield_lst: ", my_bitfield_lst)
        # print("c.pieces_they_have: ", c.pieces_they_have)
        # print("type of c.pieces_they_have: ", type(c.pieces_they_have))
        # print("bitfield_diff: ", bitfield_diff)
        if (bitfield_diff != []) and c.current_requested_pieces == []:
            for b in bitfield_diff:
                if (b not in current_requested_pieces_overall) and (c.current_requested_pieces == []):
                    if c.am_interested == 0 and c.peer_choking == 1:
                        c.send_interested_msg()
                        c.am_interested = 1
                    elif c.am_interested == 1 and c.peer_choking == 0:
                        if b == (num_pieces_global - 1):
                            request_last_piece(b, c)
                            c.current_requested_pieces.append(b)
                            current_requested_pieces_overall.append(b)
                        else:
                            print("Req Random: Index - ", b)
                            print("Req Random: Begin - ", 0)

                            index = struct.pack("!I", b)
                            begin = struct.pack("!I", 0)
                            print("! piece_len_per_request ", piece_len_per_request)
                            length = struct.pack("!I", piece_len_per_request)
                            c.send_request_msg(index, begin, length)
                            c.current_requested_pieces.append(b)
                            current_requested_pieces_overall.append(b)

def request_piece_rarest_first():
    top_3_rarest_pieces = []
    all_elements = []
    for c in client_state_list:
        my_bitfield_lst = convert_bitfield_to_list(my_bitfield)
        bitfield_diff = list(set(c.pieces_they_have) - set(my_bitfield_lst))
        all_elements += bitfield_diff
    
    least_common_pieces = Counter(all_elements).most_common().reverse()
    for i in range(0, 3):
        p, _ = least_common_pieces[i]
        top_3_rarest_pieces.append(p)
        
    rarest_piece_to_request = random.choice(top_3_rarest_pieces)
        
    for c in client_state_list:
        my_bitfield_lst = convert_bitfield_to_list(my_bitfield)
        bitfield_diff = list(set(c.pieces_they_have) - set(my_bitfield_lst))
        if (bitfield_diff != []) and (rarest_piece_to_request in bitfield_diff) and c.current_requested_pieces == []:
            if (rarest_piece_to_request not in current_requested_pieces_overall) and (rarest_piece_to_request not in my_bitfield_lst):
                if c.am_interested != 1 and c.peer_choking == 1:
                    c.send_interested_msg()
                    c.am_interested = 1
                else:
                    if rarest_piece_to_request == (num_pieces_global - 1):
                        request_last_piece(c)
                    else:
                        index = struct.pack("!I", rarest_piece_to_request)
                        begin = struct.pack("!I", 0)
                        length = struct.pack("!I", piece_len_per_request)
                        c.send_request_msg(index, begin, length)
                        c.current_requested_pieces.append(rarest_piece_to_request)
                        current_requested_pieces_overall.append(rarest_piece_to_request)

if __name__ == '__main__':

    if len(sys.argv) < 3:
        print("Usage: python3 bittorrent_client.py --torrent TORRENT [--down_path DOWN_PATH] [--ip_addr IP_ADDR] [--ip_port IP_PORT] [--piece_selection_strategy STRATEGY_1 STRATEGY_2 ... STRATEGY_N] [--choking_strategy TRATEGY_1 STRATEGY_2 ... STRATEGY_N]")
        exit(1)
    else:

        parser = argparse.ArgumentParser()
        parser.add_argument('--torrent',type=str,required=True, help='The path to the desired torrent file')
        parser.add_argument('--down_path',type=str,required=False,help='The path to save the downloaded file. Default value is filenamae from tracker')
        parser.add_argument('--ip_addr',type=str,required=False,help='The ip address that the BitTorrent Client connects to')
        parser.add_argument('--ip_port',type=int,required=False,help='The port that the BitTorrent clienct connects to')
        parser.add_argument('--piece_selection_strategy',nargs="*",type=str,required=False,default="strict_priority",help='The piece selection strategies to use',choices=["rarest_first","strict_priority"])
        parser.add_argument('--choking_strategy', nargs="*",type=str, required=False,default="top_4",help = "The choking strategies to use",choices=["top_4","optimistic_unchoke"])

        args = parser.parse_args()

        #Should this be here?
        if args.down_path is not None:
            down_path = args.down_path

        print(f'Running BitTorrent client with arguments: {args.torrent} {args.down_path} {args.ip_addr} {args.ip_port} {args.choking_strategy} {args.piece_selection_strategy}')

    #0.0 Create a Socket and Bind to It
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if args.ip_addr is not None and args.ip_port is not None:
        my_socket.bind((args.ip_addr, args.ip_port))
    else:
        port = 6882
        while port <= max_port and (not is_valid_port(my_socket, port)):
            port += 1
        print(f"! bounded to {port}")
        # time.sleep(3)
    # else:
    #     my_socket.bind(("0.0.0.0", 6861))
    my_socket.listen()


    hostname=socket.gethostname()
    IPAddr=socket.gethostbyname(hostname)
    print("Your Computer Name is:"+hostname)
    print("Your Computer IP Address is:"+IPAddr)

    # 0. Generate a unique id for myself
    peer_id = generate_peer_id()
    # 1. parse the tracker file and extract all fields from it
    tracker = Tracker(args.torrent)
    if down_path == "":
        down_path = tracker.name

    # 2. connect a socket to the announce_url to get the peer list using a http get request
    peers = tracker.get_peers_list(peer_id, port)
    if len(peers) == 0:
        print("No peers found! Exiting...")
        exit(1)

    print("Got the following peers:")
    for p in peers:
        print(p)

    ########printing stuff
    print("Testing info --------------")

    print("Tracker Piece Length", tracker.piece_length)


    ########printing stuff

    # 3. Connect to the peers using TCP to download the file

    # Set bitfield for client to all zeroes
    num_pieces = tracker.get_num_pieces()
    shift_bits = (ceil(num_pieces / 8) * 8)
    my_bitfield = my_bitfield << shift_bits

    print("Tracker Length --- ", tracker.len)

    last_piece_size = tracker.len-((tracker.get_num_pieces()-1)*tracker.piece_length)
    
    if tracker.piece_length > 16384:
        piece_len_per_request = 16384
    else:
        piece_len_per_request = tracker.piece_length

    # Create File
    start_dictionary_and_file(tracker.get_num_pieces())

    #Initialize Num Pieces
    num_pieces_global = tracker.get_num_pieces()

    # Create empty file descriptors lists needed for select call below
    rlist, wlist, xlist = [], [], []
    socket_error = False

    initialize_client_state_list()

    is_finished = False

    while True:
        # print("my_bitfield_lst: ", set(my_bitfield_lst))
        # print("set(range(num_pieces)): ", set(range(num_pieces)))
        if (not is_finished) and set(my_bitfield_lst) == set(range(num_pieces)):
            is_finished = True
            print(f"! Finished downloading the file! It is in {down_path}")

            #file.close()  #initially opened with  file = open(down_path, "w+b")
            #print("Opened file with just read")
            #file = open(down_path, "r")  



            #for c in client_state_list:
            #    c.send_not_interested_msg()
            #exit out of loop

        #(Annie) Top-4 Choking Policy: Initialize our top-four list and setup our candidates for periodic updates
        top_four = list(filter(lambda peer: peer.peer_interested == 1,client_state_list))
        # print("Peers that are interested in us:")
        # print(top_four)
        if "top_4" in args.choking_strategy and len(top_four) >= 4:
            #Create our top-4 downloaders list from peers that have the best download rate AND are interested
            top_four.sort(key=lambda peer: peer.peer_download_rate)
            top_four = top_four[0:3]

            #Create our candidate list for top-4: Peers which have a better download rate (as compared to the downloaders)
            # but aren't interested get unchoked. 
            for c in client_state_list:
                slower_peers = list(filter(lambda peer: c.peer_download_rate < peer.peer_download_rate,top_four))
                if (c.peer_choking == 0) and (c.peer_interested == 0) and len(slower_peers) > 1:
                    c.send_unchoke_msg()
                    uploader_uninterested_we_unchoked.append(c)

        if "top_4" in args.choking_strategy:
            for c in top_four:
                if c.am_choking == 1:
                    c.send_unchoke_msg()
                    c.am_choking = 0

        #Requesting Pieces
        if not is_finished:
            if "strict_priority" in args.piece_selection_strategy:
                request_piece_random()
            elif "rarest_first" in args.piece_selection_strategy:
                request_piece_rarest_first()
        
        rfds = []
        rlist = []
        validate_peer_list()
        for c in client_state_list:
            rlist.append(c.sock)
        rlist.append(my_socket)
        time_before_select = datetime.now()
        rfds, wfds, xfds = select.select(rlist, wlist, xlist, 5)

        if rfds != []:
            for r in rfds:
                if (r.fileno == -1):
                    continue

                if (r == my_socket):
                    print("recv handshake")
                    recv_handshake_from_initiator(my_socket, peer_id)
                    continue

                message = r.recv(4)
                # print(message)
                if len(message) == 0:  # end of the file
                    continue
                message_length = struct.unpack("!I", message)[0]
                print("Length:", message_length)

                if (message_length == 0): #Keep Alive Message
                    serving_peer_host, serving_peer_port = r.getpeername()
                    for k in client_state_list:
                        if k.peer_ip_addr == serving_peer_host and k.peer_port == serving_peer_port:
                            k.peer_last_message_time = datetime.now()

                else:
                    serving_peer_host, serving_peer_port = r.getpeername()
                    for k in client_state_list:
                        if k.peer_ip_addr == serving_peer_host and k.peer_port == serving_peer_port:
                            client_we_are_serving = k

                    client_we_are_serving.peer_last_message_time = datetime.now()
                    id_message = r.recv(1)
                    id_num = struct.unpack("!c", id_message)[0]
                    id_num = int.from_bytes(id_num, "big")
                    print("ID:", id_num)

                    serving_peer_host, serving_peer_port = r.getpeername()

                    if id_num == 0: #Choke Message
                        client_we_are_serving.peer_choking = 1
                        num_unchokes -= 1
                    if id_num == 1: #Unchoke Message
                        client_we_are_serving.peer_choking = 0
                    elif id_num == 2: #Interested Message
                        client_we_are_serving.peer_interested = 1
                        print("Before Unchoking")
                        
                        #(Annie): Run through different use cases
                        if "top_4" in args.choking_strategy and client_we_are_serving in top_four:
                            print("! HERE, unchoking")
                            # time.sleep(3)
                            client_we_are_serving.send_unchoke_msg()
                            client_we_are_serving.am_choking = 0
                            #compare_bitfield_and_request_piece(client_we_are_serving, tracker.piece_length)
                        else:
                            print(f"We cannot unchoke peer {client_we_are_serving.peer_id} based on client choking strategy")

                        # #Annie: Sanity Check to display any changes
                        # print("All Peers that have been un-choked:")
                        # for k in client_state_list:
                        #     if k.peer_choking == 0:
                        #         print(k)
                    elif id_num == 3: #Not Interested Message
                        client_we_are_serving.peer_interested = 0
                    elif id_num == 4: #Have Message
                        piece_index = r.recv(message_length - 1)
                        piece_index = struct.unpack("!I", piece_index)[0]
                        client_we_are_serving.pieces_they_have.append(piece_index)  #update their bitifled

                        my_bitfield_lst = convert_bitfield_to_list(my_bitfield)
                        bitfield_diff = list(set(client_we_are_serving.pieces_they_have) - set(my_bitfield_lst))

                        if bitfield_diff != []:
                            client_we_are_serving.send_interested_msg()
                            client_we_are_serving.am_interested = 1
                        



                    elif id_num == 5: #Bitfield Message
                        print("! Getting the bitfield")
                        peer_bitfield = r.recv(message_length - 1)
                        peer_bitfield = int.from_bytes(peer_bitfield, "big")
                        # print("{:b}".format(peer_bitfield))

                        #if handshake hasnt been completed yet, send back a bitfield response
                        if(client_we_are_serving.handshake_complete == 0):
                            print("Completing handshake with socket: ", client_we_are_serving.sock)

                            client_we_are_serving.handshake_complete = 1
                            
                            client_we_are_serving.pieces_they_have = convert_bitfield_to_list(peer_bitfield)
                            client_we_are_serving.send_bitfield_msg(convert_bitfield_to_list(my_bitfield), tracker.get_num_pieces())
                            #client_we_are_serving.send_interested_msg() #for testing purposes

                            my_bitfield_lst = convert_bitfield_to_list(my_bitfield)
                            bitfield_diff = list(set(client_we_are_serving.pieces_they_have) - set(my_bitfield_lst))

                            if bitfield_diff != []:
                                client_we_are_serving.send_interested_msg()

                        else:
                            hold = 4

                    elif id_num == 6: #Request Message
                        request_message = r.recv(message_length - 1)
                        index, begin, length = struct.unpack(f"!III", request_message)

                        if(client_we_are_serving.am_choking == 0):
                            handle_request_piece(client_we_are_serving, index, begin, length, tracker)
                        else:
                            print("we are choking!")

                    elif id_num == 7: #Receive Piece Message
                        receive_time = datetime.now()
                        if client_we_are_serving.peer_last_send_time  == -1:
                            client_we_are_serving.peer_last_send_time  = receive_time
                        else:
                            client_we_are_serving.peer_download_rate = (receive_time - client_we_are_serving.peer_last_send_time).microseconds
                            client_we_are_serving.peer_last_send_time  = receive_time

                        block_length = message_length - 9
                        print("Block Length", block_length)  #block length ex: 2^14 = 16384
                        sum_block_length = 0
                        piece_message = b""

                        #Continuously receive until we receive the entire block
                        while (sum_block_length < block_length + 8):
                            if sum_block_length + 1024 > block_length + 8:
                                temp_message = r.recv(block_length + 8 - sum_block_length)
                            else:
                                temp_message = r.recv(1024)
                            piece_message = b"".join([piece_message, temp_message])
                            sum_block_length += len(temp_message)

                        print("Length of Piece Message", len(piece_message))
                        index, begin, block = struct.unpack(f"!II{block_length}s", piece_message)

                        #write recieved bytes to the global dictionary, based on piece index

                        #format of dicitonary:
                        #{
                        #   "piece0": []    <--- list of individual bytes (we will change this format later)
                        #   "piece1": []    <--- we append bytes as we go, until we hit the expected "piece_size"
                        #
                        #}
                        print("len(block): ", len(block))
                        print("Recieved block for index: ", index)
                        add_bytes_to_dictionary(block, index, tracker.piece_length, begin, client_we_are_serving, tracker.get_num_pieces(), tracker)

                        # print(piece_dictionary)

                        # if not is_in_endgame_mode and \
                        #         calc_remain_blocks(tracker.get_num_pieces(), tracker.piece_length) \
                        #         <= blocks_threshold_endgame:
                        #     print("! EndGame activated!")
                        #     is_in_endgame_mode = True
                        #     request_last_pieces_endgame(tracker.get_num_pieces(), tracker.piece_length)

                    elif id_num == 8: #Cancel Message
                        k = 7
                    elif id_num == 9: #Port Message
                        k = 7

                time_after_select = datetime.now()
                if (time_after_select - time_before_select).total_seconds() > 5:
                    for k in client_state_list:
                        k.send_keep_alive_msg()

                #(Annie) Top-4 Choking Policy: Update the top-4
                if  "top_4" in args.choking_strategy and (time_after_select - time_before_select).total_seconds() >= 10:
                    #Candidate List: If a peer becomes interested, the downloader with the worst upload rate gets choked.
                    for c in uploader_uninterested_we_unchoked:
                        if c.peer_interested == 1:
                            top_four[3].am_choking == 1
                            top_four[3].send_choke_msg()
                            top_four = top_four[0:2]
                            top_four[3] = c
                            top_four.sort(key=lambda peer: peer.peer_download_rate)

                        #Does the download rate get updated between when top-4 is initialized and being updated? We might have to check again if so

                #(Annie) Optimistic Unchoking Policy
                if "optimistic_unchoking" in args.choking_strategy and (time_after_select - time_before_select).total_seconds() >= 30:
                    #Unchoke a single peer regardless of its upload rate
                    unchoke_random = False
                    while unchoke_random == False:
                        peer_idx = random.randint(0, len(client_state_list)-1)
                        random_peer = client_state_list[peer_idx]
                        if random_peer.am_choking == 1:
                            continue
                        else:
                            random_peer.am_choking = 0
                            random_peer.send_unchoke_msg()
                            unchoke_random = True
                            if random_peer.peer_interested == 1 and "top_4" in args.choking_strategy:
                                top_four[3].am_choking == 1
                                top_four = top_four[0:2]
                                top_four[3] = random_peer
                                top_four = top_four.sort(key=lambda peer: peer.peer_download_rate)

                    #Sanity Check to display any changes
                    print("All Peers that have been un-choked:")
                    for k in client_state_list:
                        if k.peer_choking == 0:
                            print(k)

        else:
            for k in client_state_list:
                k.send_keep_alive_msg()


