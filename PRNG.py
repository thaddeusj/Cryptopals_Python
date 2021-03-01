

class MT19937:

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

        self.index = self.n

        
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
        
        self.index = 1
            

        
    def temper(self,x):
        
        y = x^((x >> self.u) & self.d)
        
        y = y^((y << self.s) & self.b)
        
        y = y^((y << self.t) & self.c)
        
        z = y^(y >> self.l)
    

        return z

    def rand(self):

        self.index += 1

        if self.index > self.n:
            self.twist()

        return self.temper(self.state[self.index -1])



class MT19937_copy:        #Copy MT19937 state array, with default parameters.

    w = 32
    n = 624
    m = 397
    r = 31 
    a = b'\x99\x08\xB0\xDF'            
    b = b'\x9D\x2C\x56\x80' 
    c = b'\xEF\xC6\x00\x00' 
    s = 7 
    t = 15 
    u = 11 
    d = b'\xFF\xFF\xFF\xFF' 
    l = 18 
    f = 1812433253

    def __init__(self, state,
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
        self.state = state
        self.f = f

        self.index = self.n + 1

    def twist(self):

        for i in range(0,self.n):

            upper = (self.state[0]>>self.r)<<self.r
            lower = (self.state[1]) % (2**self.r)
            twister = (upper + lower) >> 1

            if (upper + lower) % 2 != 0:
                twister = twister^self.a

            self.state.append(self.state[self.m]^twister)
            self.state = self.state[-self.n:]
        
        self.index = 1
            
    def temper(self,x):
        
        y = x^((x >> self.u) & self.d)
        
        y = y^((y << self.s) & self.b)
        
        y = y^((y << self.t) & self.c)
        
        z = y^(y >> self.l)
    
        return z

    def rand(self):

        self.index += 1

        if self.index > self.n:
            self.twist()

        return self.temper(self.state[self.index -1])


    @staticmethod
    def untemper(z):

        #Undo the last operation: z = y^(y>>l)

        temp = z >>MT19937_copy.l
        
        y_3 = z

        while temp != 0:
            y_3 = y_3^temp
            temp = temp >> MT19937_copy.l

        #Undo operation y = y^((y<<t)&c)
        #Key fact: this operation does not affect the last 17 bits of y: y_15 ... y_31
        #In particular, the (y>> t)&c term looks like y_15...y_29 0...0. except the first part is missing y_18, y_25, y_26, y_27

        y_2 = y_3^((((y_3 % (2**17))<<15)% (2**MT19937_copy.w)) & (0xEFC60000))

        #Undoing the next operation y = y^((y<<s)&b) is much harder.
        #Here, we only have access to the last 7 bits of y, so this is going to take 5 steps tor recover all of y.

        step_1 = y_2 % 2**7
        
        step_2 = ((y_2 >> 7)^(step_1 & (0x2D)))%2**7
        step_3 = ((y_2 >> 14)^(step_2 & (0x31)))%2**7
        step_4 = ((y_2 >> 21)^(step_3 & (0x69)))%2**7
        step_5 = ((y_2 >> 28)^(step_4 & (0x9)))%2**7

        y_1 = (step_5 * (2**28)) + (step_4 * (2**21)) + (step_3 * (2**14)) + (step_2 * (2**7)) + step_1

        # #Undoing the last operation is the same as the first, since the &d operation doesn't do anything for 32 bit MT19937.
        
        temp_x = y_1 >> MT19937_copy.u
        x = y_1

        while temp_x != 0:
            x = x^temp_x
            temp_x = temp_x >> MT19937_copy.u

        return x

        
class PRNG_stream_cipher():

    def __init__(self,PRNG,seed):
        self.PRNG = PRNG
        self.seed = seed


    def transform(self,text):
        PRNG = self.PRNG(self.seed)

        key = bytearray(0)
        output = bytearray(0)

        for x in range(0,len(text)):
            key.append(PRNG.rand()%(2**8))
            
            output.append(key[x]^text[x])

        return output


        


    