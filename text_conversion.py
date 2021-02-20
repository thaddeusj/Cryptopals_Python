def hexstring_to_intarray(s):
    ibytes = []

    if (len(s)%2 ==1):  raise Exception("This is not a hex string.")

    for x in range(0,int(len(s)/2)):
        ibytes.append( hexchar_to_int(s[2*x])*16 + hexchar_to_int(s[2*x+1]))

    return ibytes


def intarray_to_hexstring(array):

    output_string = ""

    for x in range(0,len(array)):
        h1 = array[x]>>4
        h2 = array[x]%16

        output_string += int_to_hexchar(h1)
        output_string += int_to_hexchar(h2)
    
    return output_string

def int_to_hexchar(i):
    return{
        0: '0',
        1: '1',
        2: '2',
        3: '3',
        4: '4',
        5: '5',
        6: '6',
        7: '7',
        8: '8',
        9: '9',
        10: 'a',
        11: 'b',
        12: 'c',
        13: 'd',
        14: 'e',
        15: 'f'
    }[i]

    
def hexchar_to_int(c):
    return{
        '0': 0,
        '1': 1,
        '2': 2,
        '3': 3,
        '4': 4,
        '5': 5,
        '6': 6,
        '7': 7,
        '8': 8,
        '9': 9,
        'a': 10,
        'A': 10,
        'b': 11,
        'B': 11,
        'c': 12,
        'C': 12,
        'd': 13,
        'D': 13,
        'e': 14,
        'E': 14,
        'f': 15,
        'F': 15
    }[c]

def intarray_to_base64string(array):
    output_string = ""

    for x in range(0,int(len(array)/3)):
        b1 = array[3*x]>>2
        b2 = (array[3*x]%4)*16 + (array[3*x+1]>>4)   #order of operations matters: bit shifting has lower precedence than addition
        b3 = (array[3*x+1]%16)*4 + (array[3*x+2]>>6)
        b4 = array[3*x+2]%64

        output_string += int_to_base64(b1)
        output_string += int_to_base64(b2)
        output_string += int_to_base64(b3)
        output_string += int_to_base64(b4)

    if (len(array)%3 != 0):
        
        b1 = 0
        b2 = 0
        b3 = 0

        if(len(array)%3 ==1):
            b1 = array[3*len(array)-3]>>2
            b2 = (array[3*len(array)-3]%4)*16

            output_string += int_to_base64(b1)
            output_string += int_to_base64(b2)
            output_string += "="
            output_string += "="

        if(len(array)%3 ==2):
            b1 = array[3*len(array)-3]>>2
            b2 = (array[3*len(array)-3]%4)*16 + array[3*len(array)-2]>>4
            b3 = (array[3*len(array)-2]%16)*4

            output_string += int_to_base64(b1)
            output_string += int_to_base64(b2)
            output_string += int_to_base64(b3)
            output_string += "="
    
    return output_string

        


def int_to_base64(i):
    return{
        0:'A',
        1: 'B',
        2: 'C',
        3: 'D',
        4: 'E',
        5: 'F',
        6: 'G',
        7: 'H',
        8: 'I',
        9: 'J',
        10: 'K',
        11: 'L',
        12: 'M',
        13: 'N',
        14: 'O',
        15: 'P',
        16: 'Q',
        17: 'R',
        18: 'S',
        19: 'T',
        20: 'U',
        21: 'V',
        22: 'W',
        23: 'X',
        24: 'Y',
        25: 'Z',
        26: 'a',
        27: 'b',
        28: 'c',
        29: 'd',
        30: 'e',
        31: 'f',
        32: 'g',
        33: 'h',
        34: 'i',
        35: 'j',
        36: 'k',
        37: 'l',
        38: 'm',
        39: 'n',
        40: 'o',
        41: 'p',
        42: 'q',
        43: 'r',
        44: 's',
        45: 't',
        46: 'u',
        47: 'v',
        48: 'w',
        49: 'x',
        50: 'y',
        51: 'z',
        52: '0',
        53: '1',
        54: '2',
        55: '3',
        56: '4',
        57: '5',
        58: '6',
        59: '7',
        60: '8',
        61: '9',
        62: '+',
        63: '/',
    }[i]

def base64char_to_int(c):
    return{
        'A': 0,
        'B': 1,
        'C': 2,
        'D': 3,
        'E': 4,
        'F': 5,
        'G': 6,
        'H': 7,
        'I': 8,
        'J': 9,
        'K': 10,
        'L': 11,
        'M': 12,
        'N': 13,
        'O': 14,
        'P': 15,
        'Q': 16,
        'R': 17,
        'S': 18,
        'T': 19,
        'U': 20,
        'V': 21,
        'W': 22,
        'X': 23,
        'Y': 24,
        'Z': 25,
        'a': 26,
        'b': 27,
        'c': 28,
        'd': 29,
        'e': 30,
        'f': 31,
        'g': 32,
        'h': 33,
        'i': 34,
        'j': 35,
        'k': 36,
        'l': 37,
        'm': 38,
        'n': 39,
        'o': 40,
        'p': 41,
        'q': 42,
        'r': 43,
        's': 44,
        't': 45,
        'u': 46,
        'v': 47,
        'w': 48,
        'x': 49,
        'y': 50,
        'z': 51,
        '0': 52,
        '1': 53,
        '2': 54,
        '3': 55,
        '4': 56,
        '5': 57,
        '6': 58,
        '7': 59,
        '8': 60,
        '9': 61,
        '+': 62,
        '/': 63
    }[c]


def base64string_to_intarray(s):

    array = []

    
    for x in range(0, int(len(s)/4)):
        c1 = base64char_to_int(s[4*x])
        
        if (s[4*x+1]!='='):
            c2 = base64char_to_int(s[4*x+1])

            array.append(c1*4 + (c2>>4))
            
            if (s[4*x+2]!='='):
                c3 = base64char_to_int(s[4*x+2])
            
                array.append((c2%16)*16 +(c3>>2))

                if (s[4*x+3]!='='):
                    c4 = base64char_to_int(s[4*x+3])

                    array.append((c3%4)*64 + c4)
                else:
                    c4 = 100
                    array.append((c3%4)*64)

            else:
                c3 = 100
                array.append((c2%16)*16)
        
        else:
            c2 = 100
            array.append(c1*4)
        
        
    return array



def intarray_to_string(i):
    output_string = ""

    for x in range(0,len(i)):
        output_string += chr(i[x])

    return output_string

def string_to_intarray(s):
    array = []

    for x in range(0,len(s)):
        array.append(ord(s[x]))
    
    return array

