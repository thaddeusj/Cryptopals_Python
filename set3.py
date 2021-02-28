import os
import random
import base64

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


    