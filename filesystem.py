def start_dictionary_and_file(total_pieces):

    global test_global_piece_dictionary
    global test_global_file

    print(test_global_piece_dictionary)

    for i in range(0, total_pieces):
        test_global_piece_dictionary["piece" + str(i)] = []

    print(test_global_piece_dictionary) 

    test_global_file = file = open("test_write_file", "r+b")
    bits = b'\x32\x32\x32\x32\x32'
    test_global_file.write(bits)


def check_exists_piece_name(piece_index):
    global test_global_piece_dictionary
    
    piece_name = "piece" + str(piece_index)

    if piece_name in test_global_piece_dictionary.keys():
        return piece_name
    else:
        return -1

def listOfBytes_to_StringList_to_bytes(bytes_list):
    for i in range(0, len(bytes_list)):
        print(bytes_list[i])

    holder = []

    for i in range(0, len(bytes_list)):
        holder.append((bytes_list[i]).decode("utf-8"))

    print(holder)

    print("hello1")

    recv_string = "".join(holder)

    print(recv_string)

    print("hello2")


    recv_bytes = bytes(recv_string, 'utf-8')

    print(recv_bytes)

    print("hello3")

    return recv_bytes



def write_to_file(piece_name, piece_index, total_piece_size):

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




def check_hash(piece_name, piece_index, total_piece_size):

    #TODO check from torrent if hash is correct

    if(1 == 1):
        #hash is correct!!

        final_test_write_to_file(piece_name, piece_index, total_piece_size)

    else:
        final_test_reset_piece(piece_index)




def add_bytes_to_dictionary(bytes, piece_index, total_piece_size, offset):

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



def reset_piece(piece_index):
    global test_global_piece_dictionary

    piece_name = final_check_exists_piece_name(piece_index)

    if(piece_name == -1):
        print("Piece does not exist!!")

    else:
        test_global_piece_dictionary[piece_name] = []



def check_size(piece_index, piece_size):
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
