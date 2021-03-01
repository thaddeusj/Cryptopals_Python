import os
import random
import base64
import time
from itertools import chain

import modes
import padding
import CTR_mode
import PRNG
import set1
import XOR_tools

def challenge25():
    key = os.urandom(16)
    CTR = CTR_mode.my_CTR(key,os.urandom(8))

    plaintext = set1.challenge7("25.txt")

    cipher_text = CTR.CTR_transform(plaintext)


    #Okay, now we've got our plaintext. We'll proceed with the attack.

    attack_message = bytearray(len(cipher_text))

    key = CTR.edit(cipher_text,0,attack_message)

    guessed_plaintext = XOR_tools.bytearray_XOR(key,cipher_text)

    print(guessed_plaintext == plaintext)

def challenge26():
    key = os.urandom(16)
    CTR = CTR_mode.my_CTR(key,os.urandom(8))

    attack_string = "aaaaaaaaaaa"

    cookie = CTR.encrypt_cookie(attack_string)

    bitflip = CTR_mode.CTR_bitflip(attack_string)


    editted_cookie = bitflip.ATTACK(cookie)

    print(CTR.CTR_transform(editted_cookie).decode())


def challenge27():
    key = bytearray(os.urandom(16))

    CBC = modes.my_CBC(key,key)

    plaintext = bytearray("ring around the rosie, pocket full of posie, ashes ashes we all fall down",'utf-8')

    cipher = CBC.encrypt(plaintext)

    new_cipher = cipher[0:16]
    new_cipher.extend(bytearray(16))
    new_cipher.extend(cipher)

    modified_plaintext = bytearray(0)

    try:
        CBC.verified_decrypt(new_cipher)
    except Exception as e:  
        modified_plaintext = e.args[0]

    if len(modified_plaintext) == 0:
        raise Exception("We got unlucky.")

    p_1 = modified_plaintext[0:16]
    p_3 = modified_plaintext[32:48]

    guessed_key = XOR_tools.bytearray_XOR(p_1,p_3)

    print("Our attack produced the key: " + str(guessed_key))
    print("The actual key was: " + str(CBC.key))
    print("We found it: " + str(CBC.key == guessed_key))







    

