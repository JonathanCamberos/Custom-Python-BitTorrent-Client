from math import ceil

def test_find_chunks_of_8(find):
    start = 0b11111111
    chunk = 1

    while(start < find):
        
        start << 8
        chunk+= 1

    return chunk

def test_convert_bitfield_to_list(bitfield):
    chunks8 = find_chunks_of_8(bitfield)
    maxNum = 2**(8 * chunks8)
    currNum = int(maxNum/2)
    indexCount = 0

    bit_lst = []

    while currNum > 0:
        if (bitfield & currNum) == currNum:
            bit_lst.append(indexCount)
                
        currNum = currNum >> 1
        indexCount+= 1

    return bit_lst

def test_convert_list_to_bitfield(lst, num_pieces):
    # This one may have a bug
    bitfield = 0b0

    shift_bits = (ceil(num_pieces / 8) * 8)
    bitfield = bitfield << shift_bits-1

    for n in lst:
        bitfield = bitfield | (1 << (shift_bits - n))
        
    return bitfield



def testing_find_chunks_of_8(find):
    start = 0b11111111
    chunk = 1

    while(start < find):
        start << 8
        chunk+= 1

    return chunk


def final_find_chunks_of_8(bytes):

    bit_length = bytes.bit_length()
    chunks_of_8 = ceil(bit_length/8)
    return chunks_of_8


def case_find_chunks():

    bit_field1 = 0b11111110  #<--- 8 bits, 1 byte , 1 chunk of 8

    res1 = test_find_chunks_of_8(bit_field1)
    print("For: ", end=" ")
    print("{:b}".format(bit_field1))
    print(" ---> chunks: ", res1)


    #this case leads to an infinite loop inside the find_chunks_of_8 function
    bit_field2 = 0b1000000000000110    #<--- 16 bits, 2 bytes,  2 chunks of 8
    res2 = test_find_chunks_of_8(bit_field2)
    print("For: ", end=" ")
    print("{:b}".format(bit_field2))
    print(" ---> chunks: ", res2)

def testing_bytes():

    bit_field1 = 0b11111110  #<--- 8 bits, 1 byte , 1 chunk of 8
    bit_field2 = 0b1000000000000110    #<--- 16 bits, 2 bytes,  2 chunks of 8


    chunks_8_1 = final_find_chunks_of_8(bit_field1)
    print("{:b}".format(bit_field1))
    print(bit_field1.bit_length())
    print("This many bytes: ", chunks_8_1)
    
    chunks_8_2 = final_find_chunks_of_8(bit_field2)
    print("{:b}".format(bit_field2))
    print(bit_field2.bit_length())
    print("This many bytes: ", chunks_8_2)


    bit_field3 = 0b0000100000000110    #<--- 16 bits, 2 bytes,  2 chunks of 8

    chunks_8_3 = final_find_chunks_of_8(bit_field3)
    print("{:b}".format(bit_field3))
    print(bit_field3.bit_length())
    print("This many bytes: ", chunks_8_3)

#def testing_bytes2()

#   bit_field1 = 0b0


##########################################################################

#Tested funcitons

def final_find_chunks_of_8(bytesObject):
    bit_length = bytesObject.bit_length()
    chunks_of_8 = ceil(bit_length/8)
    return chunks_of_8

def final_convert_bitfield_to_list(bitfield):

    print("Inside convert bitfield --> list")
    print("curr --> ", end=" ")
    print("{:b}".format(bitfield))


    chunks8 = final_find_chunks_of_8(bitfield)
    print("Curr Chunks8/Bytes: ", chunks8)

    maxNum = 2**(8 * chunks8)
    currNum = int(maxNum/2)
    indexCount = 0

    bit_lst = []

    while currNum > 0:
        if (bitfield & currNum) == currNum:
            bit_lst.append(indexCount)
                
        currNum = currNum >> 1
        indexCount+= 1

    return bit_lst

def final_convert_list_to_bitfield(lst, num_pieces):
    # This one may have a bug
    
    print("final convert list --> bitfield")
    
    bitfield = 0b0

    #in case 7 pieces, rounds up shift_bits to 8, or in case of 13 pieces rounds up to 16
    shift_bits = (ceil(num_pieces / 8) * 8) - 1   #added -1

    print("Shift bits: ", shift_bits)

    bitfield = bitfield << shift_bits-1

    print("Bitfield: ", end=" ")
    print("{:b}".format(bitfield))


    for n in lst:
        print("Before Bitfield: ", end=" ")
        print("{:b}".format(bitfield))
        bitfield = bitfield | (1 << (shift_bits - n))
        print("After Bitfield: ", end=" ")
        print("{:b}".format(bitfield))
        
    return bitfield

def test_final_convert_list_to_bitfield(lst, num_pieces):
    print("In TEST FINAL convert list --> bitfield")
    print("List ---> ", lst)
    bitfield = 0b0

    #in case 7 pieces, rounds up shift_bits to 8, or in case of 13 pieces rounds up to 16
    shift_bits = (ceil(num_pieces / 8) * 8)  -1  #added -1

    print("Shift bits: ", shift_bits)

    bitfield = bitfield << shift_bits-1

    print("Bitfield: ", end=" ")
    print("{:b}".format(bitfield))


    for n in lst:
        print("for loop ----------")
        
        print("Before Bitfield: ", end=" ")
        print("{:b}".format(bitfield))

        print("Shift_bits: ", shift_bits)
        print("N: ", n)

        currShift = shift_bits - n
        print("Curr Shift: ", currShift)

        newBit = (1 << currShift)
        print("New Bit: ", end=" ")
        print("{:b}".format(newBit))

        #bitfield, or new bitfield with a 1 set at where the item is in list
        bitfield = bitfield | newBit
        print("After Bitfield: ", end=" ")
        print("{:b}".format(bitfield))
        
    return bitfield





############################################################################

#@@@@@@@@
#cases

def test_case_bits_1():

    bit_field1 = 0b11111110  #<--- 8 bits, 1 byte , 1 chunk of 8
    bit_list = final_convert_bitfield_to_list(bit_field1)

    print(bit_list)

    #should this be 7 or 8 yk? Like theres only 7 pieces, but theres 8 bits in the byte
    #edit --> no need to worry, convert_list_to_bitfield takes care of this
    num_pieces = final_find_chunks_of_8(bit_field1)

    bit_revert = final_convert_list_to_bitfield(bit_list, num_pieces)
    print("{:b}".format(bit_revert))


def test_case_bits_2():
    bit_field1 = 0b1000000000000110    #<--- 16 bits, 2 bytes,  2 chunks of 8
    bit_list = final_convert_bitfield_to_list(bit_field1)

    print(bit_list)

    #should this be 7 or 8 yk? Like theres only 7 pieces, but theres 8 bits in the byte
    #edit --> no need to worry, convert_list_to_bitfield takes care of this
    num_pieces = (final_find_chunks_of_8(bit_field1) * 8)

    print("Here  *************** Num_Pieces: ", num_pieces)

    bit_revert = test_final_convert_list_to_bitfield(bit_list, num_pieces)
    print("{:b}".format(bit_revert))


def test_case_bits_3():
    bit_field1 = 0b001000001000000000000110    #<--- 16 bits, 2 bytes,  2 chunks of 8
    bit_list = final_convert_bitfield_to_list(bit_field1)

    print(bit_list)

    #should this be 7 or 8 yk? Like theres only 7 pieces, but theres 8 bits in the byte
    #edit --> no need to worry, convert_list_to_bitfield takes care of this
    num_pieces = (final_find_chunks_of_8(bit_field1) * 8)

    print("Here  *************** Num_Pieces: ", num_pieces)

    bit_revert = test_final_convert_list_to_bitfield(bit_list, num_pieces)
    print("{:b}".format(bit_revert))


#@@@@@@@


if __name__ == '__main__':

    #finding the bug/fixing
    #found infinit loop in find_chunks_of_8  -- fixed with final_find_chunks_of_8
    #case_find_chunks()clare
    #testing_bytes()
    #testing_bytes2()

    #testing rest of functions
    #test_case_bits_1()
    #test_case_bits_2()
    test_case_bits_3()