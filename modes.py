import cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import padding


#class ECB_CBC_oracle:   #For later
    


class my_CBC:   #For now, we're tying this explicitly to AES. Later on, if necessary, I'll refactor to allow for different encryption primitives.
    def __init__(self, iv, key):
        self.iv = iv
        self.key = key

    
    def encrypt(self, plaintext):
        padded_plaintext = padding.pkcd7_padding(plaintext,len(self.key))

        blocks = [padded_plaintext[i:i+len(self.key)] for i in range(0,len(padded_plaintext),len(self.key))]

        cipher_text = []

        cipher_text.append(my_ECB.AES_ECB_encrypt(blocks[0]^self.iv,self.key))

        for x in range(len(self.key), len(padded_plaintext), len(self.key)):
            cipher_text.append(my_ECB.AES_ECB_encrypt(blocks[int(x/len(self.key))]^cipher_text[int(x/len(self.key))-1],self.key))

        return cipher_text



class my_ECB:  #For now, we're tying this explicitly to AES. Later on, if necessary, I'll refactor to allow for different encryption primitives.


    @staticmethod
    def AES_ECB_encrypt(plaintext,key): #We're going to assume that the plaintext has already been padded.
        cipher_text=[]

        cipher = Cipher(algorithms.AES(key),modes.ECB)

        encryptor = cipher.encryptor()

        for x in range(0,len(plaintext)/len(key)):
            cipher_text.extend(encryptor(plaintext[x*len(key):(x+1)*len(key)]))

        return cipher_text


    @staticmethod
    def AES_ECB_decrypt(cipher_text,key):   # The python crypto packages require an encryption mode to be specified. So, we're going to specify ECB and then use it block by block.
                                            # Not ideal, but it has the same effect as if I had just the AES primitive. AES in ECB mode on one block is just the AES primitive really.

        cipher = Cipher(algorithms.AES(key),modes.ECB())

        decryptor = cipher.decryptor()

        plaintext = bytearray(0)

        for x in range(0,int(len(cipher_text)/len(key))):
            plaintext.extend(decryptor.update(bytearray(cipher_text[x*len(key):(x+1)*len(key)])))

        return plaintext.decode()


    @staticmethod
    def detect_ECB_mode(cipher_texts, key_len):  #Idea: break cipher texts into blocks, check for collisions.
                                                #Highest incidence number will be the ECB encoded text.

                                                #Assumptions: that the plaintext contains repeated fragments of text.


        line_num = 0
        max_coincidences = 0

        for line in range(0,len(cipher_texts)):
            line_blocks = block_decompse(cipher_texts[line], key_len)

            temp_coincidences = 0

            for block1 in range(0,len(line_blocks)):
                for block2 in range(block1,len(line_blocks)):
                    if (line_blocks[block1] == line_blocks[block2]):
                        temp_coincidences +=1

            if (temp_coincidences > max_coincidences):
                max_coincidences = temp_coincidences
                line_num = line

        return [line_num,cipher_texts[line_num]]







def block_decompse(iarray, block_len):
    blocks = []

    for x in range(0, int(len(iarray)/block_len)):
        blocks.append(iarray[x*block_len:(x+1)*block_len])

    return blocks
