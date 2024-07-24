import socket
import select
import sys
import os.path
import struct
import hashlib
import bencode
import codecs

#from Peer import Peer, generate_peer_id
#from Tracker import Tracker
#from constants import *

test_global_piece_dictionary = {}
test_global_file = "holder"

EXTENDS_piece_dictionary = {}
EXTENDS_file = "holder"

def find_chunks_of_8(find):

    start = 0b11111111
    chunk = 1

    while(start < find):

        start << 8
        chunk+= 1

    return chunk

def make_missing_list(peer_bit_field, my_bit_field):

    print("Peer: ", end=" ")
    print("{:b}".format(peer_bit_field))

    print("Client: ", end=" ")
    print("{:b}".format(my_bit_field))

    #only leaves '1's in bits where peer has chunk and we do not have that chunk
    bits_mismatched = peer_bit_field ^ my_bit_field

    print("mismatched field of: ", end=" ")
    print("{:b}".format(bits_mismatched))

    curr = bits_mismatched
    
    chunks8 = find_chunks_of_8(bits_mismatched)
    maxNum = 2**(8 * chunks8)
    currNum = int(maxNum/2)
    indexCount = 0

    print("maxNum of: ", end=" ")
    print("{:b}".format(maxNum))

    print("curNum of: ", end=" ")
    print("{:b}".format(currNum))


    peer_has_bits_we_need = []

    while(currNum > 0):

        print("curNum is at: ", end=" ")
        print("{:b}".format(currNum))

        #print("bits_mismatched is at: ", end=" ")
        #print("{:b}".format(bits_mismatched))


        if(bits_mismatched&currNum == currNum):
            
            

            if(peer_bit_field&currNum == currNum):

                #check who has the bit
                print("bit set at index: ", end=" ")
                print(indexCount)

                peer_has_bits_we_need.append(indexCount)

                #return indexCount

            
            

        currNum = currNum >> 1

        indexCount+= 1

    return peer_has_bits_we_need


def test_udpdate_need_bit_indexs(case: int):
    
    if(case == 1):

        # 10000000 = 128
        # 11110000 = 240

        bits1 = 128
        bits2 = 240
    

        res = make_missing_list(bits1, bits2)

        print("Peer has bits we need: ")
        print(res)

    elif(case == 2):
        # 10000010 = 130
        # 11110000 = 240

        bits1 = 130
        bits2 = 240
    
        res = make_missing_list(bits1, bits2)

        print("Peer has bits we need: ")
        print(res)

    elif(case == 3):
        # 10000011 = 131
        # 11110000 = 240

        bits1 = 131
        bits2 = 240
    
        res = make_missing_list(bits1, bits2)

        print("Peer has bits we need: ")
        print(res)
    

    if(res == []):
        print("Peer has nothing we need!!")

    else:
        print("Peer has something valuable!!")


def test_write_to_file():
    print("Called function")

    file = open("test_write", "w")
    file.close() #creates new file if doesnt exists already

    file = open("test_write", "r+b")

    file_pointer = file.tell()
    print(file_pointer)

    bits = b'\x21\x21\x21\x21'


    file.write(bits)
    file_pointer = file.tell()
    print(file_pointer)


    file_pointer = file.seek(5, 1)

    print(file_pointer)

    file.write(bits)
    file_pointer = file.tell()
    print(file_pointer)


def test_dictionary():
    print("Inside Test Dictionary")

    dictionary = {}
    print(type(dictionary))
    print(dictionary)

    for i in range(10):
        dictionary["piece" + str(i)] = [] 

    print(dictionary)


def listTest():

    test = [2, 5, 7, 3, 5, 6]
    print(test)
    print(test[1])


def test_bytes_to_StringList_to_bytes():

    recved = b'\x32\x32\x32\x32\x32'

    for i in range(0, 6):
        print(recved[0:i])

    dict_test = {}

    dict_test["piece1"] = []
    dict_test["piece2"] = []

    for i in range(0,6):
        dict_test["piece1"].append(recved[i:i+1])

    print(dict_test)

    for i in range(0,6):
        dict_test["piece2"].append((recved[i:i+1]).decode("utf-8"))

    print(dict_test)


    recv_string = "".join(dict_test["piece2"])

    print(recv_string)

    recv_bytes = bytes(recv_string, 'utf-8')

    print(recv_bytes)


def test_ListOfBytes_to_StringList_to_bytes():

    print("test ListOfBytes to StringList To Bytes ")

    recved = [b'\x32', b'\x32', b'\x32', b'\x32', b'\x32']

    for i in range(0, 5):
        print(recved[i])

    dict_test = {}

    dict_test["piece1"] = []
    dict_test["piece2"] = []


    for i in range(0,5):
        dict_test["piece2"].append((recved[i]).decode("utf-8"))

    print(dict_test)

    print("hello1")

    recv_string = "".join(dict_test["piece2"])

    print(recv_string)

    print("hello2")


    recv_bytes = bytes(recv_string, 'utf-8')

    print(recv_bytes)

    print("hello3")




def test_bytes_to_StringList_to_bytes():

    recved = b'\x32\x32\x32\x32\x32'

    for i in range(0, 6):
        print(recved[0:i])

    dict_test = {}

    dict_test["piece1"] = []
    dict_test["piece2"] = []

    for i in range(0,6):
        dict_test["piece1"].append(recved[i:i+1])

    print(dict_test)

    for i in range(0,6):
        dict_test["piece2"].append((recved[i:i+1]).decode("utf-8"))

    print(dict_test)


    recv_string = "".join(dict_test["piece2"])

    print(recv_string)

    recv_bytes = bytes(recv_string, 'utf-8')

    print(recv_bytes)



def make_tracker():
    if len(sys.argv) != 2:
        print("Usage: python3 bittorrent_client.py path_to_.torrent_file")
        exit(1)
    if not os.path.exists(sys.argv[1]) or not os.path.isfile(sys.argv[1]) \
            or not sys.argv[1].endswith('.torrent'):
        print("Please enter a valid .torrent file")
        exit(1)

    # 0. Generate a unique id for myself
    peer_id = generate_peer_id()
    # print(peer_id)
    # 1. parse the tracker file and extract all fields from it
    tracker = Tracker(sys.argv[1])

    return tracker


def test_analyze_pieces(tracker):

    print("Inside test analyze pieces w tracker")

    print(tracker.info)

    info_hash = tracker.info_hash
    print("Tracker info hash: ", end=" ")
    print(info_hash)


    num_pieces = tracker.get_num_pieces()

    print("Num of pieces: ", end=" ")
    print(num_pieces)

    print("Tracker .info[pieces] ---> ", end=" ")
    print(type(tracker.info[pieces_keyword]))
    print(tracker.info[pieces_keyword])

    '''
    print("Printing index 0: ", end=" ")
    print(tracker.pieces[0:1])

    print("Printing index 0-1: ", end=" ")
    print(tracker.pieces[0:2])

    print("Printing index 0-2: ", end=" ")
    print(tracker.pieces[0:3])

    print("Printing index 0-3: ", end=" ")
    print(tracker.pieces[0:4])
    '''

    #for index in range(0, 21):
    #    print("Printing index 0-", end="")
    #    print(str(index-1) + ": ", end=" ")
    #    print(tracker.pieces[0: index])


    for index in range(0, num_pieces):
        print("For piece " + str(index) + " ------ ")
        
        curr_piece_len = tracker.piece_length
        curr_piece_hash = tracker.get_piece_hash_by_idx(index)

        print("Length: ", end=" ")
        print(str(curr_piece_len))
        print("Hash bytes: ", end=" ")
        print(curr_piece_hash)

        print(type(curr_piece_hash))

        #curr_piece_hash = curr_piece_hash.digest()
        #print("Hash Digest: ", end=" ")
        #print(curr_piece_hash)

        #hash_string = curr_piece_hash.decode("utf-8")
        #print("Hash String: ", end=" ")
        #print(hash_string)
    


def test_sha1():

    bytes = b'HelloWorld'

    print("bytes: ", end=" ")
    print(bytes)

    hash_obj = hashlib.sha1(bytes)

    print("hash obj: ", end=" ")
    print(hash_obj)

    print("hexdigest(): ", end=" ")
    hexa_value = hash_obj.hexdigest()
    print(hexa_value)
    #length = len(pbHash.decode("hex"))
    #print(length)


    other = bencode.encode(bytes)
    print("bencode to encode 'HelloWorld': ", end=" ")
    print(other)

    other = hashlib.sha1(other)
    print("sha1 on previous: ", end=" ")
    print(other)

    other = other.digest()
    print(".digest() on previous: ", end=" ")
    print(other)

    #for index in range(0, 21):
    #    print("Printing index 0-", end="")
    #    print(str(index-1) + ": ", end=" ")
    #    print(other[0: index])

    # second to compare
    test = bencode.encode(bytes)
    print("bencode to encode 'HelloWorld': ", end=" ")
    print(test)

    test = hashlib.sha1(test)
    print("sha1 on previous: ", end=" ")
    print(test)

    test = test.digest()
    print(".digest() on previous: ", end=" ")
    print(test)

    #compare

    if(other == test):
        print("SUCCESS!!!")
    else:
        print("No chance sirrr")




def generate_hash_from_bytes(bytes):

    print("Inside Generate_Hash_from_bytes object")

    print(bytes)

    bencoded_bytes = bencode.encode(bytes)
    print("bencoded --> 'HelloWorld': ", end=" ")
    print(bencoded_bytes)

    hashed_bytes = hashlib.sha1(bencoded_bytes)
    print("sha1 on previous: ", end=" ")
    print(hashed_bytes)

    digested_bytes = hashed_bytes.digest()
    print(".digest() on previous: ", end=" ")
    print(digested_bytes)


    #for index in range(0, 21):
    #    print("Printing index 0-", end="")
    #    print(str(index-1) + ": ", end=" ")
    #    print(digested_bytes[0: index])


    print(type(digested_bytes))

    return digested_bytes


#used to turn a List of Bytes ---> List of Strings ---> Single String ---> Single Bytes Obj
def get_bytes_from_listOfBytes(listOfBytes):
    

    holder = []

    #current list of bytes
    print("Curr List of Bytes: ", end=" ")
    print(listOfBytes)


    #creating list of sintrgs
    for i in range(0,len(listOfBytes)):
        print("Test ---- > type: ", end=" ")
        print(type(listOfBytes[i]))

        print(listOfBytes[i])
        holder.append((codecs.decode(listOfBytes[i])))
        #holder.append((listOfBytes[i]).decode("utf-8"))

    print("Holder: ", end=" ")
    print(holder)

    #single strings (all blocks for a single piece)
    recv_string = "".join(holder)

    print(recv_string)

    #a single bytes obj for a certain list of bytes obj
    recv_bytes = bytes(recv_string, 'utf-8')

    print(recv_bytes)

    #return single bytes obj
    return recv_bytes



#pretending the global dictionary steps are occuring
def recieve_dictionary():

    print("Inside Test Dictionary   --------------------")


    #create dicationary
    global_dictionary = {}
    print(type(global_dictionary))
    print(global_dictionary)


    #add 10 pieces ---> 10 separate empty lists
    for i in range(10):
        global_dictionary["piece" + str(i)] = [] 

    print(global_dictionary)

    #create a list of separate bytes objects
    for i in range (10):
        global_dictionary["piece3"].append(b'\x32')

    print(global_dictionary)


    #We recieve all blocks for piece3
    if(len(global_dictionary["piece3"]) == 10):

        print("Recieved all blocks for piece 3")

        print("Dictionary ['piece3'] a list (after all blocks arrive!) -----> ", end=" ")
        print(type(global_dictionary["piece3"]))

        print(global_dictionary["piece3"])

        return global_dictionary["piece3"]

    else:
        print("This is so sad, alexa play descpaicto")



def fill_In_Dictionary(dictionary, num_pieces):
    for i in range(0, num_pieces):
        dictionary["piece" + str(i)] = []

    return dictionary

def start_hash_test():

    #we will be building a dictionary, that will slowly add on bytes
    #until the size of the array for a certain piece, will reach a length,
    #at which point we will compute the hash and compare with the expected results

    # 10 * \x32
    #correct answer for this test!
    correct_hash = generate_hash_from_bytes(b'\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32')

    #printing correct hash
    print("Correct hash is: ", end=" ")
    print(correct_hash)


    #pretending we are reciving bytes in the global dictionary
    complete_byte_list_for_piece = recieve_dictionary()

    single_bytes_obj_for_complete_piece = get_bytes_from_listOfBytes(complete_byte_list_for_piece)
   
    hash_from_recv = generate_hash_from_bytes(single_bytes_obj_for_complete_piece)

    print("Attempt Hash is: ", end=" ")
    print(hash_from_recv)


    if(correct_hash == hash_from_recv): 
        print("Correct!!!")

        
    else:
        print("Ur wrong!!")




#############################################################################
#test cases

def case_adding_to_many_bytes():
    final_test_add_bytes_to_dictionary(b'\x32\x32\x32\x32', 2, total_piece_size, 0)
    print(test_global_piece_dictionary)
 
    final_test_add_bytes_to_dictionary(b'\x32\x32\x32\x32', 2, total_piece_size, 0)
    print(test_global_piece_dictionary)

    final_test_add_bytes_to_dictionary(b'\x32\x32\x32\x32\x32\x32', 2, total_piece_size, 0)
    print(test_global_piece_dictionary)


def case_correct_blocks_then_write_and_delete():
    final_test_add_bytes_to_dictionary(b'\x32\x32\x32\x32', 2, total_piece_size, 0)
    print(test_global_piece_dictionary)
 
    final_test_add_bytes_to_dictionary(b'\x32\x32\x32\x32', 2, total_piece_size, 0)
    print(test_global_piece_dictionary)

    final_test_add_bytes_to_dictionary(b'\x32\x32', 2, total_piece_size, 0)
    print(test_global_piece_dictionary)



def case_sending_to_client():

    piece_index_to_send = 2


##############################################################################
    

def final_test_start_dictionary_and_file(total_pieces):

    global test_global_piece_dictionary
    global test_global_file

    print(test_global_piece_dictionary)

    for i in range(0, total_pieces):
        test_global_piece_dictionary["piece" + str(i)] = []

    print(test_global_piece_dictionary) 

    test_global_file = file = open("./testing_hash_write", "r+b")
    test_global_file.truncate(0) #resets file for current session
    bits = b'\x32\x32\x32\x32\x32'
    test_global_file.write(bits)




def final_check_exists_piece_name(piece_index):
    global test_global_piece_dictionary
    
    piece_name = "piece" + str(piece_index)

    if piece_name in test_global_piece_dictionary.keys():
        return piece_name
    else:
        return -1


def final_test_ListOfBytes_to_StringList_to_bytes(bytes_list):

   
    for i in range(0, len(bytes_list)):
        print(bytes_list[i])

    holder = []
    concat = bytearray(0)
    print("*********************************")

    for i in range(0, len(bytes_list)):
        #holder.append((codecs.decode(bytes_list[i])))
        concat.append(bytes_list[i])
        #holder.append((listOfBytes[i]).decode("utf-8"))
        #holder.append((bytes_list[i]).decode("utf-8"))

    print(holder)
    print(concat)

    print("hello1")

    recv_string = "".join(holder)

    print(recv_string)

    print("hello2")


    recv_bytes = bytes(recv_string, 'utf-8')

    print(recv_bytes)

    print("hello3")

    return recv_bytes



def final_test_write_to_file(piece_name, piece_index, total_piece_size):

    global test_global_file
    global test_global_piece_dictionary

    #piece Index's start from 0
    offset = piece_index * total_piece_size

    test_global_file.seek(offset)

    bytes_list = test_global_piece_dictionary[piece_name]

    print("Bytes List we will write to file: ", end=" ")

    final_bytes = final_test_ListOfBytes_to_StringList_to_bytes(bytes_list)
   
    print("Bytes Object we will wrtie to file: ", end=" ")
    print(final_bytes)

    
    test_global_file.write(final_bytes)


def final_test_check_hash(piece_name, piece_index, total_piece_size):

    correct_hash = generate_hash_from_bytes(b'\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32')

    single_bytes = final_test_ListOfBytes_to_StringList_to_bytes(test_global_piece_dictionary[piece_name])
    single_hash = generate_hash_from_bytes(single_bytes)


    #TODO check from torrent if hash is correct

    if(correct_hash == single_hash):
        #hash is correct!!
        print("############################## SUCCESS!!!! ######################")

        final_test_write_to_file(piece_name, piece_index, total_piece_size)

    else:
        final_test_reset_piece(piece_index)

def final_test_add_bytes_to_dictionary(bytes, piece_index, total_piece_size, offset):

    global test_global_piece_dictionary

    print("Inside FINAL - Add Bytes To Dictionary ---- ")

    piece_name = final_check_exists_piece_name(piece_index)

    if(piece_name == -1):
        print("Piece Name --- Does not exist")
    
    else:
        
        print("piece name based on index: exists!!")

        print("Adding", end=" ")
        print(len(bytes), end=" ")
        print("Number of Bytes")

        for i in range(0, len(bytes)):
            print("Index: " + str(i) + ": ", end=" ")
            print(bytes[i:i+1])

        for i in range(0, len(bytes)):
            test_global_piece_dictionary[piece_name].append(bytes[i:i+1])

    size_res = final_test_check_size(2, total_piece_size)

    if(size_res == 1):
        #all pieces recieved!
        final_test_check_hash(piece_name, piece_index, total_piece_size)

    elif(size_res == 2):
        hold = 4
        #missing blocks, waiting...

    else:
        final_test_reset_piece(piece_index)
        #too many blocks, reset!


def final_test_reset_piece(piece_index):
    global test_global_piece_dictionary

    piece_name = final_check_exists_piece_name(piece_index)

    if(piece_name == -1):
        print("Piece does not exist!!")

    else:
        test_global_piece_dictionary[piece_name] = []


def final_test_check_size(piece_index, piece_size):
    global test_global_piece_dictionary

    piece_name = final_check_exists_piece_name(piece_index)

    if(piece_name == -1):
        print("Does not exist")
    
    else:

        if(len(test_global_piece_dictionary[piece_name]) == piece_size):
            print("All blocks Recieved!!")
            return 1

        elif(len(test_global_piece_dictionary[piece_name]) > piece_size):

            print("Too many blocks recieved!! ---> Reseting...")
            return -1

        else:
            print("Missing some blocks, waiting...")
            return 2   




# ^^^^^^^^^^^^
#bytearray testing  ---> EXTENDS exists im an idiot ! I was not aware of this thanks python very cool kys

def first_bytearry():

    test = bytearray(b''    )

    print("hello0")
    print(test)

    test.extend(b'\x23')

    print("hello1")
    print(test)

    test.extend(b'\x23')

    print("hello2")
    print(test)

    test.extend(b'\x23\x23')

    print("hello3")
    print(test)

    


    

# ^^^^^^^^^^





#####@@@@@@@@@@@@@@@@
#changing the global strcutures / methods to work with a dicitonary of bytes, we will use 'extend' to add to them


### %%%%%%%%%%%%%
#simple 
def EXTENDS_test_hash_theory(case):

    print("EXTENDS_Test_hash_Theory")
    correct_hash = EXTENDS_generate_hash_from_bytes(b'\x23\x23\x23')

    if(case == 1):
        correct_hash = EXTENDS_generate_hash_from_bytes(b'\x23\x23\x23')

        test = bytearray(0)
        test.extend(b'\x23')
        test.extend(b'\x23\x23')

    elif(case == 2):
        test = bytearray(0)
        test.extend(b'\x23')
        test.extend(b'\x23\x23')
        test.extend(b'\x23\x23')
        

    print(test)
    form_bytes = bytes(test)

    print("ByteArray ---> bytes: ", form_bytes)

    test_hash = EXTENDS_generate_hash_from_bytes(form_bytes)

    print("Correct --> ", correct_hash)
    print("Test ---> ", test_hash)


    if(correct_hash == test_hash):
        print("^^^^^^^^^^^^^^ CORRECT!! ^^^^^^^^^^^")
    else:
        print("Nope ")

#simple 
### %%%%%%%%%%%%%


def EXTENDS_write_to_file(piece_name, piece_index, total_piece_size):

    global EXTENDS_file
    global EXTENDS_piece_dictionary

    #piece Index's start from 0
    offset = piece_index * total_piece_size

    EXTENDS_file.seek(offset)

    bytes_Array = EXTENDS_piece_dictionary[piece_name]

    final_bytes = bytes(bytes_Array)
   
    print("Bytes Object we will wrtie to file: ", end=" ")
    print(final_bytes)

    
    EXTENDS_file.write(final_bytes)


def EXTENDS_reset_piece(piece_index):
    global EXTENDS_piece_dictionary

    piece_name = EXTENDS_check_exists_piece_name(piece_index)

    if(piece_name == -1):
        print("Piece does not exist!!")

    else:
        EXTENDS_piece_dictionary[piece_name] = []


def EXTENDS_check_hash(piece_name, piece_index, total_piece_size):

    correct_hash = generate_hash_from_bytes(b'\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32')

    bytes_recved = bytes(EXTENDS_piece_dictionary[piece_name])
    test_hash = generate_hash_from_bytes(bytes_recved)

    #TODO check from torrent if hash is correct

    if(correct_hash == test_hash):
        #hash is correct!!
        print("############################## SUCCESS!!!! ######################")

        EXTENDS_write_to_file(piece_name, piece_index, total_piece_size)

    else:
        EXTENDS_reset_piece(piece_index)

def EXTENDS_generate_hash_from_bytes(bytes):

    print("Bytes passed to hash ---> ", bytes, " Of type --> ", type(bytes))

    bencoded_bytes = bencode.encode(bytes)
    print("bencoded bytes : ", end=" ")
    #print(bencoded_bytes)

    hashed_bytes = hashlib.sha1(bencoded_bytes)
    print("sha1 on previous: ", end=" ")
    #print(hashed_bytes)

    digested_bytes = hashed_bytes.digest()
    print(".digest() on previous: ", end=" ")
    #print(digested_bytes)


    #for index in range(0, 21):
    #    print("Printing index 0-", end="")
    #    print(str(index-1) + ": ", end=" ")
    #    print(digested_bytes[0: index])


    #print(type(digested_bytes))

    return digested_bytes



def EXTENDS_check_size(piece_index, piece_size):
    global EXTENDS_piece_dictionary

    piece_name = EXTENDS_check_exists_piece_name(piece_index)


    if(piece_name == -1):
        print("Does not exist")
    
    else:

        if(len(EXTENDS_piece_dictionary[piece_name]) == piece_size):
            print("All blocks Recieved!!")
            return 1

        elif(len(EXTENDS_piece_dictionary[piece_name]) > piece_size):

            print("Too many blocks recieved!! ---> Reseting...")
            return -1

        else:
            print("Missing some blocks, waiting...")
            return 2   

def EXTENDS_check_exists_piece_name(piece_index):
    global EXTENDS_piece_dictionary
    
    piece_name = "piece" + str(piece_index)

    print("Curr Piece name: ", piece_name)

    if piece_name in EXTENDS_piece_dictionary.keys():
        return piece_name
    else:
        return -1


def EXTENDS_add_bytes_to_dictionary(bytes, piece_index, total_piece_size, offset):

    global EXTENDS_piece_dictionary

    print("Inside EXTENDS - Add Bytes To Dictionary ---- ")

    piece_name = EXTENDS_check_exists_piece_name(piece_index)

    if(piece_name == -1):

        print("Piece Name --- Does not exist")
    
    else:
        
        print("piece name based on index: exists!!")

        print("Adding", len(bytes), " Number of Bytes")

        EXTENDS_piece_dictionary[piece_name].extend(bytes)
        print(EXTENDS_piece_dictionary[piece_name])

    size_res = EXTENDS_check_size(2, total_piece_size)

    if(size_res == 1):
        #all pieces recieved!
        EXTENDS_check_hash(piece_name, piece_index, total_piece_size)

    elif(size_res == 2):
        hold = 4
        #missing blocks, waiting...

    else:
        EXTENDS_reset_piece(piece_index)
        #too many blocks, reset!

def EXTENDS_test_start_dictionary_and_file(total_pieces):

    global EXTENDS_piece_dictionary
    global EXTENDS_file

    print("Dictionary: ---> ", end=" ")
    print(EXTENDS_piece_dictionary)

    for i in range(0, total_pieces):
        EXTENDS_piece_dictionary["piece" + str(i)] = bytearray(0)

    print("Dictionary: ---> ", end=" ")
    print(EXTENDS_piece_dictionary) 

    EXTENDS_file = file = open("./testing_hash_write", "r+b")
    EXTENDS_file.truncate(0) #resets file for current session
    bits = b'\x32\x32\x32\x32\x32'
    EXTENDS_file.write(bits)


def EXTENDS_case_correct_blocks_then_write_and_delete():

    global EXTENDS_piece_dictionary

    total_piece_size = 10

    EXTENDS_test_start_dictionary_and_file(5)

    EXTENDS_add_bytes_to_dictionary(b'\x32\x32\x32\x32', 2, total_piece_size, 0)
    print(EXTENDS_piece_dictionary)
 
    EXTENDS_add_bytes_to_dictionary(b'\x32\x32\x32\x32', 2, total_piece_size, 0)
    print(EXTENDS_piece_dictionary)

    EXTENDS_add_bytes_to_dictionary(b'\x32\x32', 2, total_piece_size, 0)
    print(EXTENDS_piece_dictionary)




#####@@@@@@@@@@@@@@@




if __name__ == '__main__':

    
    #correct_hash = generate_hash_from_bytes(b'\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32')


    '''
    #creates global dictionary with 5 pieces
    final_test_start_dictionary_and_file(5)

    print("In Main - - ")

    #adding correct blocks, write to file, then delete piece from dictionary to save space
    case_correct_blocks_then_write_and_delete()
    '''

    #works!!
    #EXTENDS_test_hash_theory(2)
    
    
    EXTENDS_case_correct_blocks_then_write_and_delete()

    
