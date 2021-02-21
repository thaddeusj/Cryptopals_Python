import padding
import modes


import os
import random

from itertools import chain

import base64

def challenge9(text,block_size): #Text here is a string

    text_bytes = bytearray(text, 'utf-8')

    padded_text_bytes = padding.pkcs7_padding(text_bytes,block_size)

    print(str(padded_text_bytes))

def challenge10(file_string):

    cipher_text = bytearray(0)

    with open(file_string) as file:
        lines = file.read().splitlines()

        cipher_text.extend(chain.from_iterable([bytearray(base64.b64decode(line)) for line in lines]))

    iv = bytearray(16)

    CBC = modes.my_CBC(iv,bytearray("YELLOW SUBMARINE",'utf-8'))  #IV given in the challenge.

    print(CBC.decrypt(cipher_text).decode())


def challenge11(m,choice):   #We want an ECB/CBC Oracle
                            #I am assuming that the plaintext is long and has some repetition. If the plaintext never repeats, 
                            #   you can't use the statelessness of ECB to say anything.

                            #From playing around, it looks like you need a very long plaintext for this to be reliable.
                            #I had trouble with a piece of plaintext that I know had repetitions but was only 2000 or so bytes.
                            #I am assuming we can't just choose the plaintext arbitrarily. If you can, this becomes much easier:
                            #   choose a plaintext of the form "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" for a long enough string of "a"s.

    message = bytearray(0)  #I'm going to use one source of a large amount of text that I have: one of the previous challenge texts!

    if choice == 0:
        message = bytearray(m,'utf-8')

    if choice == 1:
        with open("11.txt") as file:
            lines = file.read().splitlines()

            message.extend(chain.from_iterable([bytearray(line,'utf-8') for line in lines]))

    key = os.urandom(16)

    

    plaintext = message
    cipher_text = bytearray(0)

    #Append and prepend random bytes, then pad to correct length

    prep_num = random.randint(5,10)
    app_num = random.randint(5,10)

    app = bytearray(os.urandom(app_num))
    plaintext.extend(app)
    
    prepped_plaintext = bytearray(os.urandom(prep_num))
    prepped_plaintext.extend(plaintext)


    ECB_or_CBC = random.randint(0,1)

    if ECB_or_CBC == 1:
        padded_plaintext = padding.pkcs7_padding(prepped_plaintext,16)

        cipher_text = modes.my_ECB.AES_ECB_encrypt(padded_plaintext,key)
    else:
        iv = os.urandom(16)
        CBC = modes.my_CBC(iv,key)

        cipher_text = CBC.encrypt(prepped_plaintext)

    guess = modes.ECB_CBC_oracle.detect(cipher_text,16)

    print("Did I guess correctly?")

    if guess == ECB_or_CBC:
        print("Yes.")
    else:
        print("No.")

    if ECB_or_CBC == 0:
        print("The correct mode was CBC.")
    else:
        print("The correct mode was ECB.")


def challenge12():      #Now I do get to choose what I feed into the plaintext.
                        #Parameters:
                        #   - There is a fixed secret.
                        #   - I can inject arbitrary text before the secret. 
                        #   - I will be assuming that there is fixed size offsets at the beginning (and end, but that doesn't matter) if the plaintext.
                        #This last assumption isn't a part of the challenge, but it does look like it resembles real world conditions for this attack.

                        #Our steps will be:
                        #   1) Discover the block size. (We know it, but we might not know it in the field.)
                        #   2) Check that it's ECB. Now that I have the ability to inject arbitrary text,
                        #       I can choose a string of a's that's guaranteed to have lots of collisions.
                        #   3) Determine the offset.
                        #   4) Break the secret, as described in the challenge.

    b64_cipher_text = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"


    offset = random.randint(0,16)
    key = os.urandom(16)



    #We need to find the block length first.
    #The idea here is to increase the size of our input string until the cipher_text length jumps twice.
    #The block length will be the difference of the two sizes we got: ex. if it jumped at us feeding 5 and 21 characters, then
    #   the length will be 21-5 = 16. This works because padding will force everyhing from 5 to 20 to have the same length, and
    #   then when we hit 21, we've filled up our current block and the padding pushes it back. (If we're doing pkcs#7)

    ECB_hook = modes.ECB_to_attack(offset,key,bytearray(base64.b64decode(b64_cipher_text)))

    attack = modes.ECB_injection_attack(ECB_hook)

    attack.find_block_length()
    attack.break_ECB()
    attack.find_offset(attack.block_length)

    print(attack.offset)
    print(attack.ECB_hook.offset)


