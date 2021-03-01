import XOR_tools
from operator import itemgetter

def break_single_char_XOR(cipher_text):

    min_score = 100000*len(cipher_text)
    min_score_key = 0
    
    for x in range(0,256):
        
        text = XOR_tools.bytearray_XOR(bytearray([x for y in range(0,len(cipher_text))]),cipher_text)

        s = score_text(text)

        if (s < min_score):
            min_score = s
            min_score_key = x

        #print("The score with key " + str(x) + " is " + str(s))

    min_key_array = bytearray([min_score_key for x in range(0,len(cipher_text))])
        
    return [min_score,min_score_key,XOR_tools.bytearray_XOR(cipher_text,min_key_array)]


def break_repeating_key_XOR(cipher_text): #we'll handle i/o processing separately for this one. This will break a repeating XOR cipher on a byte array.

    #For reasoning behind the Hamming distance trick to find key size, see: https://crypto.stackexchange.com/questions/8115/repeating-key-xor-and-hamming-distance

    #First, we will test reasonably sized keys to find the most reasonable key size

    key_sizes = find_key_sizes(cipher_text,1)  #We can look for the top n most likely key sizes. We'll stick with 1 for now.

    
    return break_repeating_with_keysize(cipher_text,key_sizes[0])

    

    

def find_key_sizes(cipher_text,n): #Return the n most likely keysizes
    
    h_dists = []

    for key_size in range(2,min(51,int(len(cipher_text)/2))):
        
        temp_dist = 0

        x = 0
        while(x + 2*key_size < len(cipher_text)):
            temp_dist += hamming_distance(cipher_text[x:x+key_size],cipher_text[x+key_size:x+2*key_size])

            x+= 2*key_size


        h_dists.append([key_size,temp_dist])

        #print("For the key size " + str(key_size) + " the normalized Hamming distance is " + str(h_dists[key_size-2][1]))

        
    best_sorted_key_sizes=[item[0] for item in sorted(h_dists,key=itemgetter(1))[0:n]]

    return best_sorted_key_sizes

def break_repeating_with_keysize(cipher_text, key_size):
    
    transposed_blocks = transpose_blocks(cipher_text,key_size)

    #Now break each block separately

    solved_blocks = []

    for block_num in range(0,len(cipher_text)):
        solved_blocks.append(bytearray(0))        


    for block_num in range(0,key_size):
        #print("Solving block: " +str(block_num))
        
        this_solve = break_single_char_XOR(transposed_blocks[block_num])
        
        solved_blocks[block_num].extend(this_solve[2])

        #print("Block " + str(block_num) + " was broken with key " + str(this_solve[1]))

        
    #Put it all back together
    
    total_solve = bytearray(0)
    
    curr_spot = 0

    while (curr_spot*key_size < len(cipher_text)):
        for block_num in range(0,key_size):
            if(curr_spot*key_size + block_num < len(cipher_text)):
                total_solve.append(solved_blocks[block_num][curr_spot])
        
        curr_spot +=1


    return total_solve

def transpose_blocks(barray, k):

    transposed_blocks = []

    for block_num in range(0,k):
        transposed_blocks.append([])

        curr_spot = 0

        while(curr_spot*k + block_num < len(barray)):
            transposed_blocks[block_num].append(barray[curr_spot*k + block_num])
            curr_spot +=1

    return transposed_blocks


def detect_single_XOR(file_string):  #detects a single 1char XOR encrypted line from a file of candidates
    
    min_key = 0
    min_score_text = ""
    min_score_line = 0
    
    
    with open(file_string) as file:
        hlines = file.read().splitlines()

        lines=[bytearray.fromhex(line) for line in hlines]
        
        min_score= 100000*len(lines[1])
        min_key = 0
        min_score_text = ""


        for x in range(0,len(lines)):
            decode = break_single_char_XOR(lines[x])

            if (decode[0] < min_score):
                min_score = decode[0]
                min_key = decode[1]
                min_score_text = decode[2]
                min_score_line = x
    
    print("The encoded line is " + str(min_score_line) + " which was encoded with the key " + str(min_key) + ".")
    print("The encrypted text was: " + min_score_text.decode())





def score_text(intarray):

    score = 0

    frequencies = {
            'a': 0,
            'b': 0,
            'c': 0,
            'd': 0,
            'e': 0,
            'f': 0,
            'g': 0,
            'h': 0,
            'i': 0,
            'j': 0,
            'k': 0,
            'l': 0,
            'm': 0,
            'n': 0,
            'o': 0,
            'p': 0,
            'q': 0,
            'r': 0,
            's': 0,
            't': 0,
            'u': 0,
            'v': 0,
            'w': 0,
            'x': 0,
            'y': 0,
            'z': 0
        }

    for x in range(0,len(intarray)):
        if((intarray[x]> 64 and intarray[x]<91) or (intarray[x]>96 and intarray[x] < 123)): 
            frequencies[int_to_letter(intarray[x])]+=1
        elif (intarray[x] == 0): score +=1000
        elif (intarray[x] == 9 or intarray[x] == 10 or intarray[x] == 13): score += 10
        elif (intarray[x] == 32): score += 1
        elif (intarray[x] > 32 and intarray[x] < 65): score += 100
        elif (intarray[x] > 90 and intarray[x] < 97): score += 100
        elif (intarray[x] > 122 and intarray[x] < 128): score += 100
        else: score += 10000

    for x in range(65,91):
        score += (frequencies[int_to_letter(x)] - len(intarray)*letter_frequencies(int_to_letter(x)))**2/(len(intarray)*letter_frequencies(int_to_letter(x)))

    return score



def int_to_letter(i):
    return{
        32: ' ',
        65: 'a',
        66: 'b',
        67: 'c',
        68: 'd',
        69: 'e',
        70: 'f',
        71: 'g',
        72: 'h',
        73: 'i',
        74: 'j',
        75: 'k',
        76: 'l',
        77: 'm',
        78: 'n',
        79: 'o',
        80: 'p',
        81: 'q',
        82: 'r',
        83: 's',
        84: 't',
        85: 'u',
        86: 'v',
        87: 'w',
        88: 'x',
        89: 'y',
        90: 'z',
        97: 'a',
        98: 'b',
        99: 'c',
        100: 'd',
        101: 'e',
        102: 'f',
        103: 'g',
        104: 'h',
        105: 'i',
        106: 'j',
        107: 'k',
        108: 'l',
        109: 'm',
        110: 'n',
        111: 'o',
        112: 'p',
        113: 'q',
        114: 'r',
        115: 's',
        116: 't',
        117: 'u',
        118: 'v',
        119: 'w',
        120: 'x',
        121: 'y',
        122: 'z'
    }[i]

def letter_frequencies(l):
    return{
        'a': 0.08167,
        'b': 0.01492,
        'c': 0.02782,
        'd': 0.04253,
        'e': 0.12702,
        'f': 0.02228,
        'g': 0.02015,
        'h': 0.06094,
        'i': 0.06696,
        'j': 0.00153,
        'k': 0.00772,
        'l': 0.04025,
        'm': 0.02406,
        'n': 0.06749,
        'o': 0.07507,
        'p': 0.01929,
        'q': 0.00095,
        'r': 0.05987,
        's': 0.06327,
        't': 0.09056,
        'u': 0.02758,
        'v': 0.00978,
        'w': 0.02360,
        'x': 0.00150,
        'y': 0.01974,
        'z': 0.00074,
        ' ': 0.15
    }[l]

def hamming_distance(iarray1,iarray2):   #computes the Hamming distance between two byte arrays of EQUAL length

    dist = 0

    for x in range(0,len(iarray1)):
        for y in range(0,8):
            xor = iarray1[x]^iarray2[x]
            dist += (xor >> y)%2

    return dist

