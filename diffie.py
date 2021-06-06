class DH:


    
    def __init__(self, p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff,
        g = 2):
        import random

        self.p = p
        self.g = g

        self.a = random.randrange(0,self.p)


    def get_param(self):
        self.param = DH.modexp(self.g,self.a,self.p)
        return self.param

    def generate_secret(self,b):
        s = DH.modexp(b,self.a,self.p)

        import hashlib

        return hashlib.md5(s.to_bytes(200,"big")).digest()


    @staticmethod
    def modexp(a,b,n):
        #returns a^b mod n

        #Idea: we'll calculate a^2, a^4, etc, each mod n. 
        #Then, write b in binary, for each 1 in b we multiply in a^{2^k} where k is the place of that 1

        power = 1

        cur_pow = a

        while b > 0:
            if b % 2 == 1:
                power = (power*cur_pow) %n
            
            b = b>>1
            
            cur_pow = (cur_pow*cur_pow)%n

            #import pdb; pdb.set_trace()

        return power


        