import modes
import XOR_tools

from cryptography.hazmat.primitives.ciphers import algorithms,modes,Cipher

class my_CTR():


    def __init__(self, key, nonce = b'\x00\x00\x00\x00\x00\x00\x00\x00', counter_endian =0):        #We'll set it to work with little or big endianness. 0 for little as the default for the counter block..
        self.nonce = nonce
        self.endianness = counter_endian

        self.cipher = Cipher(algorithms.AES(key),modes.ECB())


    def format_counter(self,count):

        
        formatted_counter = bytearray(0)

        counter = count

        for x in range(0,8):
            formatted_counter.append(counter % 256)
            counter = counter >> 8
        
        if self.endianness == 1:
            formatted_counter.reverse()

        full_block = bytearray(self.nonce)  
        full_block.extend(formatted_counter)

        return full_block

    def CTR_transform(self,stream):

        pre_keystream = bytearray(0)

        count = 0

        while len(pre_keystream) < len(stream):
            pre_keystream.extend(self.format_counter(count))

            count += 1

        enc = self.cipher.encryptor()
        keystream = enc.update(pre_keystream) + enc.finalize()



        final_key_stream = keystream[0:len(stream)]

        



        return XOR_tools.bytearray_XOR(stream,final_key_stream)
            

        


