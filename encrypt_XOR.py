import text_conversion

def bytearray_XOR(barr1,barr2):
    return bytearray([x for x in map(lambda a,b: a^b,barr1,barr2)])

def fixed_XOR(array1,array2):
    
    

    if(len(array1)!= len(array2)): raise Exception("Different sized buffers")
    
    XOR = []

    for x in range(0,len(array1)):

        XOR.append((array1[x])^(array2[x]))
        

    return XOR

# def hexstring_XOR(s1,s2):

#     i1 = text_conversion.hexstring_to_intarray(s1)
#     i2 = text_conversion.hexstring_to_intarray(s2)

#     iXOR = fixed_XOR(i1,i2)

#     return text_conversion.intarray_to_hexstring(iXOR)


def singlechar_key_XOR(key,plaintext):
    key_array = []
    
    for y in range(0,len(plaintext)):
            key_array.append(key)

    return fixed_XOR(key_array,plaintext)


def repeating_XOR(key,plaintext):
    key_array = key

    if(len(key) < len(plaintext)):
        while(len(key_array)<len(plaintext) - len(key)):
            key_array.extend(key)
        
        currentlength = len(key_array)   #Just to be safe and avoid dependence on a changing variable

        for x in range(0,len(plaintext) - currentlength):
            key_array.append(key[x])
    
    return bytearray_XOR(key_array,plaintext)
