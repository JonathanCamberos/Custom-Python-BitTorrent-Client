from math import ceil

def find_chunks_of_8(bytesObject):

    #print("Inside Find Chunks of 8 #############")
    #print("Given bytes object: ", end=" ")
    #print("{:b}".format(bytesObject))

    bit_length = bytesObject.bit_length()

    if(bit_length == 0):
        bit_length = 1

    #print("Bit Length: ", bit_length)

    chunks_of_8 = ceil(bit_length/8)

    #print("Chunks of 8: ", chunks_of_8)
    return chunks_of_8
    
    '''
    start = 0b11111111
    chunk = 1

    while(start < find):
        start = start << 8
        chunk += 1

    return chunk
    '''

def convert_bitfield_to_list(bitfield):

    #print("Inside Convert Bitfield to List  *****************")
    #print("Given bitfield: ", end=" ")
    #print("{:b}".format(bitfield))

    chunks8 = find_chunks_of_8(bitfield)

    #print("Chunks of 8: ", chunks8)

    maxNum = 2**(8 * chunks8)
    #print("MaxNum: ", maxNum)

    # currNum = int(maxNum/2)

    currNum = 2**(8 * chunks8 - 1)
    #print("CurrNum: ", currNum)

    indexCount = 0

    bit_lst = []

    while currNum > 0:
        currNum = int(currNum)
        if (bitfield & currNum) == currNum:
            bit_lst.append(indexCount)
                
        currNum = currNum >> 1
        indexCount+= 1

    return bit_lst


'''
def convert_bitfield_to_list(bitfield):

    #print("Inside")

    chunks8 = find_chunks_of_8(bitfield)
    maxNum = 2**(8 * chunks8)
    # currNum = int(maxNum/2)
    currNum = 2**(8 * chunks8 - 1)
    indexCount = 0

    bit_lst = []

    while currNum > 0:
        currNum = int(currNum)
        if (bitfield & currNum) == currNum:
            bit_lst.append(indexCount)
                
        currNum = currNum >> 1
        indexCount+= 1

    return bit_lst
'''

def convert_list_to_bitfield(lst, num_pieces):
    bitfield = 0b0

    shift_bits = (ceil(num_pieces / 8) * 8)  - 1  #added '- 1'
    bitfield = bitfield << shift_bits-1

    for n in lst:
        bitfield = bitfield | (1 << (shift_bits - n))
        
    return bitfield
    '''
    # This one may have a bug
    bitfield = 0b0

    shift_bits = (ceil(num_pieces / 8) * 8)  
    bitfield = bitfield << shift_bits-1

    for n in lst:
        bitfield = bitfield | (1 << (shift_bits - n))
        
    return bitfield
    '''
