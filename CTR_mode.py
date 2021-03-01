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


    def edit(self,cipher_text,offset,new_text):     #We'll assume the offset is 0 indexed. We'll also write this so that it overwrites more than just one character of the original plaintext.

        if new_text is str:                         #Not that I plan on using this situation, but it's worth having.
            new_text = bytearray(new_text,'utf-8')            

        new_cipher_text = bytearray(0)

        plaintext = self.CTR_transform(cipher_text)

        new_plaintext = plaintext[0:offset]
        new_plaintext.extend(new_text)
        
        if len(new_plaintext) < len(plaintext):
            new_plaintext.extend(plaintext[(len(new_plaintext) + 1) : len(plaintext)])

        new_cipher_text = self.CTR_transform(new_plaintext)
            
        return new_cipher_text

    def encrypt_cookie(self,cookie):
        no_equals = cookie.replace("=","\x22=\x22")
        no_semicolon = no_equals.replace(";","\x22;\x22")

        cookie = "comment1=cooking%20MCs;userdata=" + no_semicolon + ";comment2=%20like%20a%20pound%20of%20bacon"

        cookie_bytes = bytearray(cookie,'utf-8')

        return self.CTR_transform(cookie_bytes)

class CTR_bitflip:
    
    def __init__(self, attack_text):
        self.attack_text = attack_text


    def ATTACK(self,cipher_text):
        original_text = bytearray(self.attack_text,'utf-8') 
        injection_text = bytearray(";admin=true",'utf-8')

        prefix = bytearray(32)
        postfix = bytearray(42)

        replacement_text = prefix
        replacement_text.extend(XOR_tools.bytearray_XOR(original_text,injection_text))
        replacement_text.extend(postfix)

        return XOR_tools.bytearray_XOR(cipher_text,replacement_text)

        


