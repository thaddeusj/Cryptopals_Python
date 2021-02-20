def bytearray_XOR(barr1,barr2):
    return bytearray([x for x in map(lambda a,b: a^b,barr1,barr2)])



def repeating_XOR(key,plaintext):
    key_array = key

    if(len(key) < len(plaintext)):
        while(len(key_array)<len(plaintext) - len(key)):
            key_array.extend(key)
        
        currentlength = len(key_array)   #Just to be safe and avoid dependence on a changing variable

        for x in range(0,len(plaintext) - currentlength):
            key_array.append(key[x])
    
    return bytearray_XOR(key_array,plaintext)
