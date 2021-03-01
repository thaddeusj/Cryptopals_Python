import os
import random
import base64
import time

import modes
import padding
import CTR_mode
import PRNG

def challenge17():

    padding_attack = modes.CBC_padding_oracle_attack(os.urandom(16))

    plaintext = padding_attack.ATTACK()

    print((padding.pkcs7_unpad(plaintext)).decode())
    
def challenge18():
    key = bytearray("YELLOW SUBMARINE",'utf-8')
    nonce = b'\x00\x00\x00\x00\x00\x00\x00\x00'

    stream = bytearray(base64.b64decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="))

    CTR = CTR_mode.my_CTR(nonce,key)

    print(CTR.CTR_transform(stream).decode())


def challenge21(seed):
    rand = PRNG.MT19937(seed)

    n = int(input("How many random numbers would you like?"))

    for x in range(0,n):
        print(rand.rand())

def challenge22():
    seed = int(time.time())
    rand = PRNG.MT19937(seed)

    time.sleep(random.randint(40,100))

    output = rand.rand()


    found = False
    guess = int(time.time())

    print("The chase is on!")

    while not found:
        guess_rand = PRNG.MT19937(guess)
        if guess_rand.rand() == output:
            found = True
            break
        
        guess -=1

    print(str(guess == seed))




def challenge23():

    MT = PRNG.MT19937(int.from_bytes(os.urandom(4), "big"))

    values = []

    for x in range(0,624):
        rand = MT.rand()

        values.append(PRNG.MT19937_copy.untemper(rand))

    

    MT_copy = PRNG.MT19937_copy(values)


    

    for x in range(0,624):
        prediction = MT_copy.rand()
        actual = MT.rand()

        print("--------------------")
        print("Our prediction for value " + str(x) + " is " + str(prediction) + ".")
        print("The actual output for value " + str(x) + " is " + str(actual) + ".")


        if actual != prediction:
                
            
            raise Exception("Did not copy!")


def challenge24():

    key = int.from_bytes(os.urandom(2),"big")
    cipher = PRNG.PRNG_stream_cipher(PRNG.MT19937,key)

    postfix = bytearray("AAAAAAAAAAAAAA",'utf-8')
    
    prefix_length = int.from_bytes(os.urandom(20),"big") % 101
    prefix = bytearray(os.urandom(prefix_length))

    message = prefix
    message.extend(postfix)

    cipher_text = cipher.transform(message)

    #Alright, now let's find that key. We know the keyspace, so we'll just brute force it.

    known_plaintext = "AAAAAAAAAAAAAA"
    known_plaintext_length = len(known_plaintext)
    guessed_key = -1

    print(key)
    input("Start.")

    for x in range(0,2**16):

        print("Trying " + str(x))
        found = True

        attack_rng = PRNG.MT19937(x)

        for y in range(0,len(cipher_text) - known_plaintext_length):
            attack_rng.rand()

        for y in range(0,known_plaintext_length):
            attack_byte = attack_rng.rand() %(2**8)
            cipher_text_byte = cipher_text[len(cipher_text) - known_plaintext_length + y]

            if attack_byte^cipher_text_byte != 65:
                found = False

        if found == True:
            guessed_key = x
            break

    if guessed_key == -1:
        raise Exception("You dun goofed.")

    print(key == guessed_key)





        






    