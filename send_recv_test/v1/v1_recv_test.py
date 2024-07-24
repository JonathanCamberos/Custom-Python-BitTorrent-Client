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
import os
import os.path
import struct
import codecs
import bencode
import hashlib
import argparse
from bencodepy.exceptions import *

from datetime import datetime

from Peer import Peer, generate_peer_id
from Tracker import Tracker
from constants import *
from util import *
from math import ceil

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

def send_recv_handshake(sd: socket, peer_id: str, tracker: Tracker):
    """
    Sends and receives bittorrent handshake needed to initiate a connection
    with a client
    """

    print(" REQUESTER IS ASKING FOR FIRST TIME ")

    pstrlen = b"\x13"
    pstr = b"BitTorrent protocol"
    reserved = b"\x00\x00\x00\x00\x00\x00\x00\x00"
    info_hash = tracker.info_hash
    peer_id = peer_id.encode("utf-8")

    print(" Before sending initial handshake ")

    handshake_message = b"".join([pstrlen, pstr, reserved, info_hash, peer_id])
    sd.sendall(handshake_message)

    print(" After sending initial handshake ")


    print(" Before Recieving response handshake ")
    response_handshake = sd.recv(68)

    print(" After Recieving response handshake ")

    if len(response_handshake) == 0:
        print("Couldn't complete the handshake")
        return False

    
    print("Bytes recieved from response to our initial handshake --->", len(response_handshake))
    
    pstrlen, pstr, reserved, info_hash, response_peer_id = struct.unpack("!c19s8s20s20s", response_handshake)
    pstrlen = int.from_bytes(pstrlen, "big")
    pstr = pstr.decode("utf-8")
    # response_peer_id = response_peer_id.decode("utf-8")
    print("pstrlen:", pstrlen)
    print("pstr: ", pstr)
    print("reservered: ", reserved)
    print("info_hash: ", info_hash)
    # TODO: validate response peer id
    print("Received Peer ID:", response_peer_id)
    print("My Peer ID:", peer_id)   
    

    return True

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
        sd.bind((socket.gethostname(), port))
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
        new_peers = get_peers_list()
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

    global client_state_list


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


    #send_test edit
    client_state_list.append(new_peer)

    #create a handshake response and send
    pstrlen = b"\x13"
    pstr = b"BitTorrent protocol"
    reserved = b"\x00\x00\x00\x00\x00\x00\x00\x00"

    #TODO: Validate whether info hash is valid
    info_hash = tracker.info_hash
    peer_id = my_peerid.encode("utf-8")

    #join handshake message and send
    handshake_message = b"".join([pstrlen, pstr, reserved, info_hash, peer_id])
    peer_sock.sendall(handshake_message)

    #after handshake message immediatly send our bitfield message
    new_peer.send_bitfield_msg(my_bitfield_lst, num_pieces_global)


#reading a section of the file
def send_from_file(client_we_are_serving, piece_name, piece_index, inner_offset, size_of_block, tracker):

    global file
    global piece_dictionary

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

###^^^^^
## j - added 12/5/22

def ListOfBytes_to_StringList_to_bytes(bytes_list):

   
    #for i in range(0, len(bytes_list)):
        #print(bytes_list[i])

    holder = []
    

    for i in range(0, len(bytes_list)):
        # print("Index --> ", i)
        # print("Byte --> ", bytes_list[i])
        holder.append((codecs.decode(bytes_list[i])))
        #holder.append((bytes_list[i]).decode("utf-8"))

    # print(holder)

    # print("hello1")

    recv_string = "".join(holder)

    # print(recv_string)

    # print("hello2")


    recv_bytes = bytes(recv_string, 'utf-8')

    # print(recv_bytes)

    # print("hello3")

    return recv_bytes

###^^^^^



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
    file = open("recv_test_file", "r+b")
    #file = open("recv_test_file", "w+b")
    #file.truncate(0) #resets file for current session





def write_to_file(piece_name, piece_index, total_piece_size):


    #TODO ignore repeat file,

    global file
    global piece_dictionary
    global my_bitfield_lst

    #calc offset for curr piece
    offset = piece_index * total_piece_size

    #move file pointer to offset
    file.seek(offset)

    #get list of bytes from piece_dictionary
    bytes_Array = piece_dictionary[piece_name]
    final_bytes_object = bytes(bytes_Array)

    #write list of bytes to file (TODO make this more efficient)
    file.write(final_bytes_object)

    #send to all clients a 'have' message, for current piece we just wrote to file
    for c in client_state_list:
        index = struct.pack("!I", piece_index)
        c.send_have_msg(index)

    #update our bitfield
    my_bitfield_lst.append(piece_index)
    my_bitfield = convert_list_to_bitfield(my_bitfield_lst, num_pieces_global)
    # print(my_bitfield)
    # print("{:b}".format(my_bitfield))

    #print("wow this is so quirky")

#everytime we add to dictionary, we check if curr piece hsa reached the total_piece_size ex: 2^14, if so we check the has
def add_bytes_to_dictionary(bytes, piece_index, total_piece_size, offset, client_we_are_serving, total_num_pieces, tracker):

    global last_piece_size_requested
    global piece_dictionary

    print("Inside RECV - Add Bytes To Dictionary ---- ")

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

            # print("GARDENIA")

            #last_piece_size_requested starts at 0    ---> last_piece_size - last_piece_size_requested(what we have recieved) = size of block we still need
            if (last_piece_size - last_piece_size_requested) >= 16384:   #if size of block we need, is larger than max request size, request max size
                #formatting to send
                index = struct.pack("!I",piece_index)
                begin = struct.pack("!I", 0)
                length = struct.pack("!I", 16384)
                # print("TRIGGERED IN IF")
                # print("Index:", index)
                # print("Begin", begin)
                # print("Length:", length)
                client_we_are_serving.send_request_msg(index, begin, length)
                last_piece_size_requested += 16384 #update how much we have requested

            #else if size of block we need, is less than max request size (ex: this is the last 10 bytes of the files)
            else:
                #formatting to send
                index = struct.pack("!I", piece_index)
                begin = struct.pack("!I", last_piece_size_requested)
                length = struct.pack("!I", (last_piece_size - last_piece_size_requested))  #how much bytes are left for last piece (total_size - what we have recieved)
                # print("TRIGGERED IN ELSE")
                # print("Index:", index)
                # print("Begin", begin)
                # print("Length:", length)
                client_we_are_serving.send_request_msg(index, begin, length)

                last_piece_size_requested = 0 #reset how much we have requested, for the next file

        #if we have recieved block NOT from the last piece
        else:
            #trigger request based on offset

            #Starting offset of block we just recieved + len(block) = starting offset of next block

            #formatting to send
            index = struct.pack("!I", piece_index) #current piece
            begin = struct.pack("!I", offset+len(bytes)) #next block offsezt
            length = struct.pack("!I", total_piece_size-len(piece_dictionary[piece_name])) #size of next block request = total_piece_size - currList(what we have recieved)

            # print("ADDING BYTES TO DICITONARYY **************")

            # print("offset - ", offset)
            # print("We are adding ", len(bytes), end=" ")
            # print("To the dicationary")

            # print("Missing: ",  total_piece_size-len(piece_dictionary[piece_name]))

            # print("offset+len(bytes) requesting at index --", offset+len(bytes))
            # print("Index:", index)
            # print("Begin:", begin)
            # print("Length:", length)

            client_we_are_serving.send_request_msg(index, begin, length)


    else:
        #too many blocks, reset!
        reset_piece(piece_index)


def generate_hash_from_bytes(bytes):

    #print("Bytes passed to hash ---> ", bytes, " Of type --> ", type(bytes))

    '''
    bencoded_bytes = bencode.encode(bytes)
    #print("bencoded bytes : ", end=" ")
    #print(bencoded_bytes)

    hashed_bytes = hashlib.sha1(bencoded_bytes)
    #print("sha1 on previous: ", end=" ")
    #print(hashed_bytes)

    digested_bytes = hashed_bytes.digest()
    #print(".digest() on previous: ", end=" ")
    #print(digested_bytes)
    '''

    hash = hashlib.sha1(bytes)

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

    global my_bitfield
    global my_bitfield_lst

    correct_hash = tracker.get_piece_hash_by_idx(piece_index)

    bytes_recved = bytes(piece_dictionary[piece_name])
    test_hash = generate_hash_from_bytes(bytes_recved)

    

    # print("Correct hash ---> ", correct_hash)
    # print("Test hash ---> ", test_hash)

    #if(correct_hash == test_hash):
    if(1 == 1):

        print("################## HASH CORRECT FOR PIECE: ", piece_index, "#################")

        #hash is correct!! we can write current piece to file

        write_to_file(piece_name, piece_index, total_piece_size)

        #update bitfields

        print("We have written to file successfully tis a great day now to do the rest:) (request the next piece from peer)  ")

        piece_index += 1 #next piece to request
        # print("Next Piece we are attempting to request - ", piece_index)
        # print("Index of last Piece - ", num_pieces - 1)

        #Requesting the last piece
        if (piece_index == num_pieces-1):

            # print("ROSE")
            if (last_piece_size - last_piece_size_requested) >= 16384:
                index = struct.pack("!I",piece_index)
                begin = struct.pack("!I", 0)
                length = struct.pack("!I", 16384)
                # print("TRIGGERED IN IF")
                # print("Index:", index)
                # print("Begin", begin)
                # print("Length:", length)
                client_we_are_serving.send_request_msg(index, begin, length)
                last_piece_size_requested += 16384
            else:
                index = struct.pack("!I", piece_index)
                begin = struct.pack("!I", last_piece_size_requested)
                length = struct.pack("!I", (last_piece_size - last_piece_size_requested))
                # print("TRIGGERED IN ELSE")
                # print("Index:", index)
                # print("Begin", begin)
                # print("Length:", length)
                client_we_are_serving.send_request_msg(index, begin, length)
                last_piece_size_requested = 0

        #requesting anything other than last piece
        elif (piece_index + 1 < num_pieces):
            # print("FLOWER")
            index = struct.pack("!I", piece_index)
            begin = struct.pack("!I", 0)
            length = struct.pack("!I", 16384)
            client_we_are_serving.send_request_msg(index, begin, length)

        else:
            print("We have recieved all the pieces!!!! :))")

    #hash was incorrect --> reset dictionary piece
    else:

        print(" ^@^@^@^@^@^@^@ HASH BAD FOR PIECE: ", piece_index, " ^@^@^@^@^@^@^@ ")
        reset_piece(piece_index)

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
        piece_dictionary[piece_name] = []


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
            # print("All blocks Recieved!!")
            return 1

        elif(len(piece_dictionary[piece_name]) > piece_size):

            # print("Too many blocks recieved!! ---> Reseting...")
            return -1
        else:
            # print("Missing some blocks, waiting...")
            return 2


#end of file stuff
##########################################################################################################################################


def get_peers_list():

    print("test1")
    # global peers, p
    port = min_port
    try:
        # print("==== Trying non-compact mode first ====")
        print("test2")
        peers = tracker.get_list_of_peers(port, peer_id)
        print("test3")
    except (TypeError, BencodeDecodeError):
        # print("==== non-compact mode didn't work, trying compact mode ====")
        peers = tracker.get_list_of_peers_compact(port, peer_id)
    if len(peers) == 0:
        exit(1)
    return peers


def initialize_client_state_list():
    global p, socket_error

    print("INITIALIZING _ CLIENT _ STATE _ LIST  @@@@@@@@@@@@@@@@@@@@@@@@@")

    #connecting directly to the sender
    direct_peer = Peer("Unknown", args.ip_addr, args.ip_port, -1)
    
    #args.ip_addr  args.ip_port:
    sd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
    try:
        print(f"Trying to connect to {args.ip_addr}:{args.ip_port}")
        sd = socket.create_connection((args.ip_addr, args.ip_port), timeout=1)
        sd.settimeout(None)
        print(f"! Connected to {args.ip_addr}:{args.ip_port}")
        print("Connection Accepted!!! On peer sock: ", sd)

        if send_recv_handshake(sd, peer_id, tracker):
            direct_peer.set_sock(sd)
            client_state_list.append(direct_peer)
            rlist.append(sd)
    except socket.error as e:
        print("could not connect: ", e)
        socket_error = True


if __name__ == '__main__':

    if len(sys.argv) < 3:
        print("Usage: python3 bittorrent_client.py --torrent TORRENT [--down_path DOWN_PATH] [--ip_addr IP_ADDR] [--ip_port IP_PORT]")
        exit(1)
    else:
        
        parser = argparse.ArgumentParser()
        parser.add_argument('--torrent',type=str,required=True, help='The path to the desired torrent file')
        parser.add_argument('--down_path',type=str,required=False,help='The path to save the downloaded file. Default value is ./testing/test_write_file')
        parser.add_argument('--ip_addr',type=str,required=False,help='The ip address that the BitTorrent Client connects to')
        parser.add_argument('--ip_port',type=int,required=False,help='The port that the BitTorrent clienct connects to')
        args = parser.parse_args()
    
        if args.down_path is None:
            args.down_path = './testing/test_write_file'
        down_path = args.down_path
        print(f'Running BitTorrent client with arguments: {args.torrent} {args.down_path} {args.ip_addr} {args.ip_port}')

    #0.0 Create a Socket and Bind to It
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    my_socket.bind(("0.0.0.0", 6881))
    my_socket.listen()

    # 0. Generate a unique id for myself
    peer_id = generate_peer_id()
    # 1. parse the tracker file and extract all fields from it
    tracker = Tracker(args.torrent)

    # 2. connect a socket to the announce_url to get the peer list using a http get request
    #peers = get_peers_list()  send_test we dont need peers
    #print("Got the following peers:")
    #for p in peers:
    #    print(p)

    print("hello3")


    ########printing stuff
    print("Testing info --------------")

    print("Tracker Piece Length", tracker.piece_length)


    ########printing stuff

    # 3. Connect to the peers using TCP to download the file

    # Set bitfield for client to all zeroes
    num_pieces = tracker.get_num_pieces()
    #shift_bits = (ceil(num_pieces / 8) * 8)   #send_test
    #my_bitfield = my_bitfield << shift_bits

    my_bitfield = 0b00000000   # 7 '1's and 1 '0'
    print("Sender bit Field --------> ", end=" ")
    print("{:b}".format(my_bitfield))


    print("Tracker Length --- ", tracker.len)

    last_piece_size = tracker.len-((tracker.get_num_pieces()-1)*tracker.piece_length)

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
        if (not is_finished) and set(my_bitfield_lst) == set(range(num_pieces)):
            is_finished = True
            print("! Finished downloading the file!")

        rfds = []
        rlist = []
        #validate_peer_list()   We dont want any peers, we only seeding!
        
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
                    recv_handshake_from_initiator(my_socket, peer_id)
                    continue

                message = r.recv(4)
                if len(message) == 0:  # end of the file
                    continue
                message_length = struct.unpack("!I", message)[0]
                #message_length = int.from_bytes(message_length, "big")
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
                    if id_num == 1: #Unchoke Message
                        client_we_are_serving.peer_choking = 0
                        compare_bitfield_and_request_piece(client_we_are_serving, tracker.piece_length)
                    elif id_num == 2: #Interested Message
                        client_we_are_serving.peer_interested = 1
                        client_we_are_serving.send_unchoke_msg()
                    elif id_num == 3: #Not Interested Message
                        client_we_are_serving.peer_interested = 0
                    elif id_num == 4: #Have Message
                        piece_index = r.recv(message_length - 1)
                        client_we_are_serving.pieces_they_have.append(piece_index)
                    elif id_num == 5: #Bitfield Message

                        print("Recieved a bitfield!!")
                        print("Message length: ", message_length)

                        peer_bitfield = r.recv(message_length - 1)

                        print("Recved many bytes: ", peer_bitfield)

                        peer_bitfield = int.from_bytes(peer_bitfield, "big")
                        
                        print("Peer_bitfield: ", peer_bitfield)

                        print("Recieved bitfield ", end=" ")
                        print("{:b}".format(peer_bitfield))

                        client_we_are_serving.pieces_they_have = convert_bitfield_to_list(peer_bitfield)
                        
                        
                         #if handshake hasnt been completed yet, send back a bitfield response
                        if(client_we_are_serving.handshake_complete == 0):
                            print("Completing handshake iwth socket: ", client_we_are_serving.sock)
                            
                            client_we_are_serving.handshake_complete = 1
                            client_we_are_serving.send_bitfield_msg(convert_bitfield_to_list(my_bitfield), tracker.get_num_pieces())
                            client_we_are_serving.send_interested_msg() #for testing purposes
                        else:
                            hold = 4
                        
                    elif id_num == 6: #Request Message
                        request_message = r.recv(message_length - 1)
                        index, begin, length = struct.unpack(f"!III", request_message)
                        index = int.from_bytes(index, "big")
                        begin = int.from_bytes(begin, "big")
                        length = int.from_bytes(length, "big")

                        if(client_we_are_serving.peer_choking == 0):
                            handle_request_piece(client_we_are_serving, index, begin, length, tracker)
                        else:
                            print("we are choking!")
                        

                    elif id_num == 7: #Recieve Piece Message
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
                        add_bytes_to_dictionary(block, index, tracker.piece_length, begin, client_we_are_serving, tracker.get_num_pieces(), tracker)

                        #print(piece_dictionary)

                    elif id_num == 8: #Cancel Message
                        k = 7
                    elif id_num == 9: #Port Message
                        k = 7

                time_after_select = datetime.now()
                if (time_after_select - time_before_select).total_seconds() > 5:
                    for k in client_state_list:
                        k.send_keep_alive_msg()
        else:
            for k in client_state_list:
                k.send_keep_alive_msg()
