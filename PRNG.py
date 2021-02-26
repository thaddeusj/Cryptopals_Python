

class MT19936:

    def __init__(self, seed,
        w = 32, 
        n = 624, 
        m = 397,
        r = 31, 
        a = b'\x99\x08\xB0\xDF',            
        b = b'\x9D\x2C\x56\x80', 
        c = b'\xEF\xC6\x00\x00', 
        s = 7, 
        t = 15, 
        u = 11, 
        d = b'\xFF\xFF\xFF\xFF', 
        l = 18, 
        f = 1812433253):

        # These constants are as described in the algorithm on wikipedia: https://en.wikipedia.org/wiki/Mersenne_Twister



        self.w = w
        self.n = n
        self.m = m
        self.r = r
        self.a = int.from_bytes(a,"big")
        self.b = int.from_bytes(b,"big")
        self.c = int.from_bytes(c,"big")
        self.s = s
        self.t = t
        self.u = u
        self.d = int.from_bytes(d,"big")
        self.l = l
        self.seed = seed
        self.f = f

        self.index = self.n + 1

        
        self.state = []

        #Initialize the state array.

        self.state.append(seed)

        for x in range(1,self.n):
            self.state.append((f*(self.state[x-1]^(self.state[x-1]>>(w-2))) + x)%(2**self.w))

    def twist(self):

        for i in range(0,self.n):

            upper = (self.state[0]>>self.r)<<self.r
            lower = (self.state[1]) % (2**self.r)
            twister = (upper + lower) >> 1

            if (upper + lower) % 2 != 0:
                twister = twister^self.a

            self.state.append(self.state[self.m]^twister)
            self.state = self.state[-self.n:]
        
        self.index = 0
            

        
    def temper(self,x):
        y = x^((x >> self.u) & self.d)
        y = y^((y << self.s) & self.b)
        y = y^((y << self.t) & self.c)

        return y^(y >> self.l)

    def rand(self):


        if self.index > self.n:
            self.twist()
        
        self.index += 1

        return self.temper(self.state[self.index -1])



        


    