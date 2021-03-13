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
from Hashes import SHA1, MD4

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



def challenge29():

    kl = random.randint(1,32)
    key = bytearray(os.urandom(kl))

    message = bytearray("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon",'utf-8')

    MAC = SHA1.secret_prefix_MAC(key,message)


    #Now we want to forge this with ;admin = true; tacked on.
    #Original message is 77 bytes long.

    a = int.from_bytes(MAC[0:4],"big")
    b = int.from_bytes(MAC[4:8],"big")
    c = int.from_bytes(MAC[8:12],"big")
    d = int.from_bytes(MAC[12:16],"big")
    e = int.from_bytes(MAC[16:20],"big")

    #while we already know the key length is 16 bytes, that's not realistic. We could try 16 and 32 first, since those are probably the most common options.
    #Instead, I'm opting to just do a search for the right key length.

    for key_length in range(1,33):

        ml = (key_length + 77)*8

        padding_length = int(((440 - ml)%512)/8)
        glue_padding = bytearray(b'\x80')
        glue_padding.extend(bytearray(padding_length))
        glue_padding.extend(bytearray((ml).to_bytes(8,"big")))


        attack_string =bytearray(";admin=true;",'utf-8')

        forged_MAC = SHA1.sha1(attack_string,a,b,c,d,e,ml + len(glue_padding)*8 + len(attack_string)*8)

        #Now, we check if we've successfully forged this.

        fullstring = bytearray(message)
        fullstring.extend(glue_padding)
        fullstring.extend(attack_string)

        correct_MAC = SHA1.secret_prefix_MAC(key,fullstring)
            
        if forged_MAC == correct_MAC:
            print("Success!")

            print(forged_MAC.hex())

            break


def challenge30():

    kl = random.randint(1,32)
    key = bytearray(os.urandom(kl))

    message = bytearray("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon",'utf-8')

    MAC = MD4.secret_prefix_MAC(key,message)

    A = int.from_bytes(MAC[0:4],"little")
    B = int.from_bytes(MAC[4:8],"little")
    C = int.from_bytes(MAC[8:12],"little")
    D = int.from_bytes(MAC[12:16],"little")

    for key_length in range(1,33):

        ml = (key_length + 77)*8

        padding_length = int(((440 - ml)%512)/8)
        glue_padding = bytearray(b'\x80')
        glue_padding.extend(bytearray(padding_length))
        glue_padding.extend(bytearray((ml).to_bytes(8,"little")))


        attack_string =bytearray(";admin=true;",'utf-8')

        forged_MAC = MD4.MD4(attack_string,A,B,C,D,ml + len(glue_padding)*8 + len(attack_string)*8)

        fullstring = bytearray(message)
        fullstring.extend(glue_padding)
        fullstring.extend(attack_string)

        correct_MAC = MD4.secret_prefix_MAC(key,fullstring)
            
        if forged_MAC == correct_MAC:
            print("Success!")

            print(forged_MAC.hex())

            break

    

