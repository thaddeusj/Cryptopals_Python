import XOR_tools

import hashlib
import os

class SHA1:

    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    @staticmethod
    def left_rotate(n,m,x): #Left rotates an m/8 byte bytearray x by n
        i = int.from_bytes(x,byteorder = "big")
        
        i = ((i<<n)|(i >> (m-n)))%2**m

        return (i).to_bytes(int(m/8),"big")

    
    @staticmethod
    def sha1(message, h0 =  0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0):
        '''message should be a bytearray
        
        This code should NEVER EVER EVER be used in practice. This has not been auditted for security or accuracy. Etc.'''

        ml = len(message)*8

        #Pre-processing

        m = bytearray(message)

        m.extend(bytearray(b'\x80'))
        extension_length = int(((440 - ml)%512)/8)
        extension = bytearray(extension_length)
        m.extend( extension )
        m.extend(bytearray((ml).to_bytes(8,"big")))
        
        chunks = [m[x:x+64]  for x in range(0,len(m),64)]

        
        for chunk in chunks:
            w = [chunk[x:x+4] for x in range(0,len(chunk),4)]

            for x in range(16,80):

                w_xor = XOR_tools.bytearray_XOR(XOR_tools.bytearray_XOR(w[x-3],w[x-8]), XOR_tools.bytearray_XOR(w[x-14],w[x-16]))

                w.append(SHA1.left_rotate(1,32,w_xor))


            a = h0
            b = h1
            c = h2
            d = h3
            e = h4
        
            for x in range(0,80):
                f = 0
                k = 0

                if x in range(0,20):
                    f = (b&c)|((~b)&d)
                    k = 0x5A827999
                elif x in range(20,40):
                    f = b^c^d
                    k = 0x6ED9EBA1
                elif x in range(40,60):
                    f = (b & c) | (b & d) | (c & d) 
                    k = 0x8F1BBCDC
                elif x in range(60,80):
                    f = b ^ c ^ d
                    k = 0xCA62C1D6

                a = a%(2**32)
                b = b%(2**32)
                c = c%(2**32)
                d = d%(2**32)
                e = e%(2**32)
                

                temp = (int.from_bytes(SHA1.left_rotate(5,32,(a).to_bytes(4,"big")),"big") + f + e + k + int.from_bytes(w[x],"big"))%2**32
                e = d
                d = c
                c = int.from_bytes(SHA1.left_rotate(30,32,(b).to_bytes(4,"big")),"big")
                b = a
                a = temp
            
            h0 = (h0 + a)%2**32
            h1 = (h1 + b)%2**32
            h2 = (h2 + c)%2**32
            h3 = (h3 + d)%2**32
            h4 = (h4 + e)%2**32
        

        hh = bytearray(h0.to_bytes(4,"big"))
        hh.extend(bytearray(h1.to_bytes(4,"big")))
        hh.extend(bytearray(h2.to_bytes(4,"big")))
        hh.extend(bytearray(h3.to_bytes(4,"big")))
        hh.extend(bytearray(h4.to_bytes(4,"big")))

        return hh

    @staticmethod
    def hash_test():

        for x in range(0,100):
            print("Doing hash: " +str(x+1))

            length = int.from_bytes(os.urandom(2),"big")

            r = os.urandom(length)

            m = hashlib.sha1()
            m.update(r)
            
            correct = m.digest()
            ours = SHA1.sha1(r)

            assert ours == correct

        print("all good boss")

    @staticmethod
    def secret_prefix_MAC(key,message):
        m = key
        m.extend(message)

        return SHA1.sha1(m)
