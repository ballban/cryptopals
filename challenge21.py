class MT19937:
    ### init
    w, n = 32, 624
    f = 1812433253

    ### Twist Function ###
    # m be an offset where 1 <= m < n
    m = 397
    # r be the number of bits of the lower bitmask where 0 <= r<= w-1;
    r = 31
    # a be the coefficients of the rational normal form twist matrix
    a = 0x9908B0DF
    # A be the twist transformation in the rational normal form
    # ???

    #######################
    ### Temper Function ###
    #######################
    # y be a temporary intermediate value
    # x be the next value from the series
    # z be the value returned from the algorithm
    # a, b, b be TGFSR(R) tempering bitmasks
    d, b, c = 0xFFFFFFFF, 0x9D2C5680, 0xEFC60000

    # u, s, t, l be TGFSR(R) tempering bit shifts
    u, s, t, l = 11, 7, 15, 18

    def __init__(self, seed) -> None:
        self.X = [0] * MT19937.n
        self.cnt = 0

        self.X[0] = seed
        for i in range(1, MT19937.n):
            self.X[i] = self.cut_bit(MT19937.f * (self.X[i - 1] ^ (self.X[i - 1] >> (MT19937.w - 2))) + i)


    def twist(self):
        lower_mask = (1 << MT19937.r) - 1
        upper_mask = (~lower_mask) & ((1 << MT19937.w) - 1)
        for i in range(MT19937.n):
            tmp = (self.X[i] & upper_mask) + (self.X[(i + 1) % MT19937.n] & lower_mask)
            tmpA = tmp >> 1
            tmpA = tmpA ^ MT19937.a if tmp % 2 else tmpA
            self.X[i] = self.X[(i + MT19937.m) % MT19937.n] ^ tmpA
        self.cnt = 0


    def rand(self):
        if self.cnt == MT19937.n:
            self.twist()
        y = self.X[self.cnt]
        y = y ^ ((y >> MT19937.u) & MT19937.d)
        y = y ^ ((y << MT19937.s) & MT19937.b)
        y = y ^ ((y << MT19937.t) & MT19937.c)
        z = y ^ (y >> MT19937.l)
        self.cnt += 1
        return self.cut_bit(z)
    

    def cut_bit(self, num):
        return num & ((1 << MT19937.w) - 1)