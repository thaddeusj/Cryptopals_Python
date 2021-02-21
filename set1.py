import XOR_tools
import vigenere

import cryptography
import modes

import base64
from itertools import chain

def challenge1():
    print(base64.b64encode(bytearray.fromhex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")))

def challenge2():
    b1 = bytearray.fromhex('1c0111001f010100061a024b53535009181c')
    b2 = bytearray.fromhex('686974207468652062756c6c277320657965')

    print(bytearray.hex(XOR_tools.bytearray_XOR(b1,b2)))

    print("This matches the target output: " + str(bytearray.hex(XOR_tools.bytearray_XOR(b1,b2)) == '746865206b696420646f6e277420706c6179'))

def challenge3():
    cipher_text = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'

    decrypted = vigenere.break_single_char_XOR(bytearray.fromhex(cipher_text))

    print("The cipher text decrypts to:\n\t" + decrypted[2].decode())
    print("The key was: " + str(decrypted[1]))


def challenge4(file_name):
    vigenere.detect_single_XOR(file_name)

def challenge5(key="ICE",text ="Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"):
    key_bytes = bytearray(key,'utf-8')
    text_bytes = bytearray(text,'utf-8')

    cipher_text = XOR_tools.repeating_XOR(key_bytes,text_bytes)

    print(str(bytearray.hex(cipher_text)))
    print("This matches the expected output: " + str(str(bytearray.hex(cipher_text))== "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"))
    

def challenge6(file_string):

    cipher_text = bytearray()

    with open(file_string) as file:
        lines = file.read().splitlines()

        cipher_text.extend(chain.from_iterable([bytearray(base64.b64decode(line)) for line in lines]))

    #print(text_conversion.intarray_to_hexstring(cipher_text))

    #print(cipher_text)

    plaintext = vigenere.break_repeating_key_XOR(cipher_text)

    print(plaintext.decode())

    #Success!!! It plays that funky music.

def challenge7(file_string):

    b64string = ""

    cipher_text = bytearray(0)

    with open(file_string) as file:
        lines = file.read().splitlines()

        cipher_text.extend(chain.from_iterable([bytearray(base64.b64decode(line)) for line in lines]))

    print(modes.my_ECB.AES_ECB_decrypt(cipher_text,b"YELLOW SUBMARINE").decode())

def challenge8(file_string):

    cipher_texts = []

    with open(file_string) as file:
        lines = file.read().splitlines()

        for line in lines:
            cipher_texts.append(bytearray.fromhex(line))
    
    detected_line = modes.my_ECB.detect_ECB_mode(cipher_texts,16)

    print("The ECB encoded string is string " + str(detected_line[0]+1) + " out of " + str(len(lines)) + ".")  #+1 to account for 0 indexing.
    print("The detected line was " + str(bytearray.hex(detected_line[1])) + ".")
