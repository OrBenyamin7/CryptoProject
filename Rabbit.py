# import that used for hashing
import hashlib
# import that used for converting binary data to ASCII
# encoded hexadecimal strings
import binascii


def enc_long(n):
    '''Encodes arbitrarily large number n to a sequence of bytes.
    Big endian byte order is used.'''
    # A big-endian system stores the most significant byte of a word at the smallest memory address 
    # and the least significant byte at the largest
    
    s = "" # empty string which will store the encoded bytes
    while n > 0:
        # isolating the least significant byte of n
        # and converting it to its ASCII character
        s = chr(n & 0xFF) + s

        # right shift by n-bits => removing the least significant byte
        n >>= 8
    return s

# represent the maximum value of a 32 bit unsigned integer
WORDSIZE = 0x100000000

# lambada function for rotating bites left by 8 and 16 positions respectively
# shifting x left 8 positions performing with the result bitwise AND with 0xFFFFFFFF
# then performing with the result bitwise OR with shifting x to the right 24 positions
rot08 = lambda x: ((x <<  8) & 0xFFFFFFFF) | (x >> 24)
rot16 = lambda x: ((x << 16) & 0xFFFFFFFF) | (x >> 16)

def _nsf(u, v):
    '''Internal non-linear state transition'''
    # calculate the sum s+v modulus WORDSIZE
    s = (u + v) % WORDSIZE
    s = s * s
    # bitwise XOR between s and right-shifted s 32 bits
    return (s ^ (s >> 32)) % WORDSIZE

class Rabbit:

    # sets up the internal state variables
    def __init__(self, key, iv = None):
        '''Initialize Rabbit cipher using a 128 bit integer/string'''
        
        # in case the key is a string
        if isinstance(key, str):
            # interpret key string in big endian byte order
            if len(key) < 16:
                key = '\x00' * (16 - len(key)) + key
            # if len(key) > 16 bytes only the first 16 will be considered
            k = [ord(key[i + 1]) | (ord(key[i]) << 8)
                 for i in range(14, -1, -2)]
        
        # key is integer
        # It splits the 128-bit integer into eight 
        # 16-bit values and stores them in the list 'k'
        else:
            # k[0] = least significant 16 bits
            # k[7] = most significant 16 bits
            k = [(key >> i) & 0xFFFF for i in range(0, 128, 16)]
            
        # State and counter initialization with values from 'k'
        x = [(k[(j + 5) % 8] << 16) | k[(j + 4) % 8] if j & 1 else
             (k[(j + 1) % 8] << 16) | k[j] for j in range(8)]
        c = [(k[j] << 16) | k[(j + 1) % 8] if j & 1 else
             (k[(j + 4) % 8] << 16) | k[(j + 5) % 8] for j in range(8)]
        
        self.x = x
        self.c = c
        self.b = 0
        self._buf = 0           # output buffer
        self._buf_bytes = 0     # fill level of buffer
        
        # advance the internal state of the cipher
        next(self)
        next(self)
        next(self)
        next(self)

        for j in range(8):
            c[j] ^= x[(j + 4) % 8]
        
        self.start_x = self.x[:]    # backup initial key for IV/reset
        self.start_c = self.c[:]
        self.start_b = self.b

        if iv != None:
            self.set_iv(iv)

    def reset(self, iv = None):
        '''Reset the cipher and optionally set a new IV (int64 / string).'''
        
        # restore the cipher states that stored in the backup variables
        self.c = self.start_c[:]
        self.x = self.start_x[:]
        self.b = self.start_b
        self._buf = 0
        self._buf_bytes = 0
        if iv != None:
            self.set_iv(iv)

    def set_iv(self, iv):
        '''Set a new IV (64 bit integer / bytestring).'''

        # checking if the iv provided is string
        # ensuring iv is a 64-bit integer
        if isinstance(iv, str):
            i = 0
            # shifting the existing bits to the left by 8 positions
            # and OR-ing the ASCII value of the current character
            for c in iv:
                i = (i << 8) | ord(c)
            iv = i

        c = self.c

        # split the 64-bit iv into 4 16-bit components
        # i0 and i2 are the lower 32 bits and higher 32 bits of the 64-bit iv
        i0 = iv & 0xFFFFFFFF
        i2 = iv >> 32
        i1 = ((i0 >> 16) | (i2 & 0xFFFF0000)) % WORDSIZE
        i3 = ((i2 << 16) | (i0 & 0x0000FFFF)) % WORDSIZE
        
        c[0] ^= i0
        c[1] ^= i1
        c[2] ^= i2
        c[3] ^= i3
        c[4] ^= i0
        c[5] ^= i1
        c[6] ^= i2
        c[7] ^= i3

        next(self)
        next(self)
        next(self)
        next(self)
        

    def __next__(self):
        '''Proceed to the next internal state'''
        
        # counter array
        c = self.c
        # state array
        x = self.x
        # buffer variable
        b = self.b

        t = c[0] + 0x4D34D34D + b
        c[0] = t % WORDSIZE
        t = c[1] + 0xD34D34D3 + t // WORDSIZE
        c[1] = t % WORDSIZE
        t = c[2] + 0x34D34D34 + t // WORDSIZE
        c[2] = t % WORDSIZE
        t = c[3] + 0x4D34D34D + t // WORDSIZE
        c[3] = t % WORDSIZE
        t = c[4] + 0xD34D34D3 + t // WORDSIZE
        c[4] = t % WORDSIZE
        t = c[5] + 0x34D34D34 + t // WORDSIZE
        c[5] = t % WORDSIZE
        t = c[6] + 0x4D34D34D + t // WORDSIZE
        c[6] = t % WORDSIZE
        t = c[7] + 0xD34D34D3 + t // WORDSIZE
        c[7] = t % WORDSIZE
        b = t // WORDSIZE
        
        g = [_nsf(x[j], c[j]) for j in range(8)]
        
        x[0] = (g[0] + rot16(g[7]) + rot16(g[6])) % WORDSIZE
        x[1] = (g[1] + rot08(g[0]) + g[7]) % WORDSIZE
        x[2] = (g[2] + rot16(g[1]) + rot16(g[0])) % WORDSIZE
        x[3] = (g[3] + rot08(g[2]) + g[1]) % WORDSIZE
        x[4] = (g[4] + rot16(g[3]) + rot16(g[2])) % WORDSIZE
        x[5] = (g[5] + rot08(g[4]) + g[3]) % WORDSIZE
        x[6] = (g[6] + rot16(g[5]) + rot16(g[4])) % WORDSIZE
        x[7] = (g[7] + rot08(g[6]) + g[5]) % WORDSIZE
        
        self.b = b
        return self

    def derive(self):
        '''Derive a 128 bit integer from the internal state'''
        
        x = self.x
        return ((x[0] & 0xFFFF) ^ (x[5] >> 16)) | \
               (((x[0] >> 16) ^ (x[3] & 0xFFFF)) << 16)| \
               (((x[2] & 0xFFFF) ^ (x[7] >> 16)) << 32)| \
               (((x[2] >> 16) ^ (x[5] & 0xFFFF)) << 48)| \
               (((x[4] & 0xFFFF) ^ (x[1] >> 16)) << 64)| \
               (((x[4] >> 16) ^ (x[7] & 0xFFFF)) << 80)| \
               (((x[6] & 0xFFFF) ^ (x[3] >> 16)) << 96)| \
               (((x[6] >> 16) ^ (x[1] & 0xFFFF)) << 112)

    
    def keystream(self, n):
        '''Generate a keystream of n bytes'''
        
        res = "" # empty string to store the generated keystream
        
        # the buffer and the number of bytes in the buffer
        b = self._buf
        j = self._buf_bytes

        # advance the internal state and derive a 128-bit integer
        # from the internal state
        next = self.__next__
        derive = self.derive
        
        for i in range(n):
            if not j:
                j = 16
                next()
                b = derive()
            # appending the least significant byte of b to the res
            res += chr(b & 0xFF)
            j -= 1
            b >>= 1

        self._buf = b
        self._buf_bytes = j
        return res

    def encrypt(self, data):
        '''Encrypt/Decrypt data of arbitrary length.'''
        
        res = "" # empty string to store encrypted result
        keystream = self.keystream(len(data))  # Generate keystream of the same length as data

        # XOR operation between each character of data and the corresponding character of keystream
        for i in range(len(data)):
            res += chr(ord(data[i]) ^ ord(keystream[i]))

        return res
        
    '''
        res = "" # empty string to store encrypted or decrypted result
        b = self._buf
        j = self._buf_bytes
        next = self.__next__
        derive = self.derive

        # Encryption & Decryption loop
        for c in data:
            if not j:   # empty buffer => fetch next 128 bits
                j = 16
                next()
                b = derive()
            res += chr(ord(c) ^ (b & 0xFF))
            j -= 1
            b >>= 1
        self._buf = b
        self._buf_bytes = j
        return res
    '''

    decrypt = encrypt

#message="Hello"
#key="qwerty"
#iv=0
    
#message = input("Enter you message here: ")
#key = input("Enter you key here: ")
#iv = input("Enter your iv here: ")

#key1 = hashlib.md5('0f01dbd6d2ea452fb64730c544269f44'.encode()).hexdigest()

#print("Message:\t\t",message)
#print("IV:\t",iv)
#print("Encryption password:\t",'0f01dbd6d2ea452fb64730c544269f44')
#print("Encryption key:\t\t",key1)
#print("\n======Rabbit encryption========")

#iv=0

#msg=Rabbit(key1,iv).encrypt(message)
#print("Encrypted:\t",binascii.hexlify(msg.encode()))

#text=Rabbit(key1,iv).decrypt(msg)

#print("Decrypted:\t",text)


