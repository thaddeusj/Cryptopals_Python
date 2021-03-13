import XOR_tools

import hashlib
import os

class SHA1:
    
    @staticmethod
    def left_rotate(n,m,x): #Left rotates an m/8 byte bytearray x by n
        i = int.from_bytes(x,byteorder = "big")
        
        i = ((i<<n)|(i >> (m-n)))%2**m

        return (i).to_bytes(int(m/8),"big")

    
    @staticmethod
    def sha1(message, h0 =  0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0, ml = 0):
        '''message should be a bytearray
        
        This code should NEVER EVER EVER be used in practice. This has not been auditted for security or accuracy. Etc.'''
        if ml == 0:
            ml = len(message)*8
        
        #Pre-processing

        m = bytearray(message)

        m.extend(bytearray(b'\x80'))
        extension_length = int(((448 - len(m)*8)%512)/8)
        extension = bytearray(extension_length)
        m.extend(extension)
        m.extend(bytearray((ml).to_bytes(8,"big")))

       
        chunks = [m[x:x+64]  for x in range(0,len(m),64)]

        #Hash

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

        m = bytearray(key)
        m.extend(message)


        return SHA1.sha1(m)


class MD4:
    @staticmethod
    def MD4(message, ml = 0):

        '''message should be a bytearray
        
        This code should NEVER EVER EVER be used in practice. Especially since it's nearly 30 years old and totally obselete.
        '''
        if ml == 0:
            ml = len(message)*8
        
        #Pre-processing

        m = bytearray(message)

        m.extend(bytearray(b'\x80'))
        extension_length = int(((448 - len(m)*8)%512)/8)
        extension = bytearray(extension_length)
        m.extend(extension)

        length_padding = bytearray((ml).to_bytes(8,"little"))


        m.extend(length_padding)  #This might be a problem. We'll revist this.
        

        A = 0x67452301
        B = 0xefcdab89
        C = 0x98badcfe
        D = 0x10325476

        chunks = [m[x:x+64] for x in range(0,len(m),64)]

        for chunk in chunks:

            AA = A
            BB = B
            CC = C
            DD = D

            X = [int.from_bytes(chunk[x:x+4],"little") for x in range(0,len(chunk),4)]

            #Round 1

            A = MD4.round1_op(X,A,B,C,D,0,3)
            D = MD4.round1_op(X,D,A,B,C,1,7)
            C = MD4.round1_op(X,C,D,A,B,2,11)
            B = MD4.round1_op(X,B,C,D,A,3,19)

            A = MD4.round1_op(X,A,B,C,D,4,3)
            D = MD4.round1_op(X,D,A,B,C,5,7)
            C = MD4.round1_op(X,C,D,A,B,6,11)
            B = MD4.round1_op(X,B,C,D,A,7,19)

            A = MD4.round1_op(X,A,B,C,D,8,3)
            D = MD4.round1_op(X,D,A,B,C,9,7)
            C = MD4.round1_op(X,C,D,A,B,10,11)
            B = MD4.round1_op(X,B,C,D,A,11,19)

            A = MD4.round1_op(X,A,B,C,D,12,3)
            D = MD4.round1_op(X,D,A,B,C,13,7)
            C = MD4.round1_op(X,C,D,A,B,14,11)
            B = MD4.round1_op(X,B,C,D,A,15,19)

            #Round 2

            A = MD4.round2_op(X,A,B,C,D,0,3)
            D = MD4.round2_op(X,D,A,B,C,4,5)
            C = MD4.round2_op(X,C,D,A,B,8,9)
            B = MD4.round2_op(X,B,C,D,A,12,13)

            A = MD4.round2_op(X,A,B,C,D,1,3)
            D = MD4.round2_op(X,D,A,B,C,5,5)
            C = MD4.round2_op(X,C,D,A,B,9,9)
            B = MD4.round2_op(X,B,C,D,A,13,13)

            A = MD4.round2_op(X,A,B,C,D,2,3)
            D = MD4.round2_op(X,D,A,B,C,6,5)
            C = MD4.round2_op(X,C,D,A,B,10,9)
            B = MD4.round2_op(X,B,C,D,A,14,13)

            A = MD4.round2_op(X,A,B,C,D,3,3)
            D = MD4.round2_op(X,D,A,B,C,7,5)
            C = MD4.round2_op(X,C,D,A,B,11,9)
            B = MD4.round2_op(X,B,C,D,A,15,13)

            #Round 3

            A = MD4.round3_op(X,A,B,C,D,0,3)
            D = MD4.round3_op(X,D,A,B,C,8,9)
            C = MD4.round3_op(X,C,D,A,B,4,11)
            B = MD4.round3_op(X,B,C,D,A,12,15)

            A = MD4.round3_op(X,A,B,C,D,2,3)
            D = MD4.round3_op(X,D,A,B,C,10,9)
            C = MD4.round3_op(X,C,D,A,B,6,11)
            B = MD4.round3_op(X,B,C,D,A,14,15)

            A = MD4.round3_op(X,A,B,C,D,1,3)
            D = MD4.round3_op(X,D,A,B,C,9,9)
            C = MD4.round3_op(X,C,D,A,B,5,11)
            B = MD4.round3_op(X,B,C,D,A,13,15)

            A = MD4.round3_op(X,A,B,C,D,3,3)
            D = MD4.round3_op(X,D,A,B,C,11,9)
            C = MD4.round3_op(X,C,D,A,B,7,11)
            B = MD4.round3_op(X,B,C,D,A,15,15)

            #Update registers

            A = (A + AA)%(2**32)
            B = (B + BB)%(2**32)
            C = (C + CC)%(2**32)
            D = (D + DD)%(2**32)

        digest = bytearray(A.to_bytes(4,"little"))
        digest.extend(bytearray(B.to_bytes(4,"little")))
        digest.extend(bytearray(C.to_bytes(4,"little")))
        digest.extend(bytearray(D.to_bytes(4,"little")))

        return digest

    #Helper functions as defined in RFC1320
    #These operate on 32 bit integers.

    @staticmethod
    def F(X,Y,Z):
        return (X&Y)|((~X)&Z)

    @staticmethod
    def G(X,Y,Z):
        
        return (X&Y)|(X&Z)|(Y&Z)

    @staticmethod
    def H(X,Y,Z):
        return X^Y^Z

    @staticmethod
    def left_rotate(x,s):
        return ((x<<s)|(x >> (32-s)))


    @staticmethod
    def round1_op(X,A,B,C,D,k,s):
        return MD4.left_rotate((A + MD4.F(B,C,D) + X[k])%(2**32),s)

    @staticmethod
    def round2_op(X,A,B,C,D,k,s):
        return MD4.left_rotate((A + MD4.G(B,C,D) + X[k] + 0x5A827999)%(2**32),s)

    @staticmethod
    def round3_op(X,A,B,C,D,k,s):
        return MD4.left_rotate((A + MD4.H(B,C,D) + X[k] + 0x6ED9EBA1)%(2**32),s)


    @staticmethod
    def hash_test(runs=100):


        for x in range(0,runs):
            print("Doing hash: " +str(x+1))

            length = int.from_bytes(os.urandom(2),"big")

            r = os.urandom(length)

            hasher = hashlib.new("md4", r)

            assert MD4.MD4(r).hex() == hasher.hexdigest()

        print("A-OK")

