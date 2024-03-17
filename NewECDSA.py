import hashlib
import random

class ECDSA:
    def __init__(self, curve):
        self.curve = curve
        self.n = curve.order
        self.G = curve.generator() # G(Gx,Gy)

    def generate_key_pair(self):
        private_key = random.randint(1, self.n - 1) 
        public_key = self.curve.multiply(self.G, private_key)
        return private_key, public_key

    def sign(self, private_key, message):
        z = self._hash_message(message) # hash the message
        k = self._generate_random_k()  # generate a random k
        r, _ = self.curve.multiply(self.G, k) # r = k(the random number) * G(the G'x and G'y where G is generator of the curve)
        # s = k^-1 * (H(M) + r * private_key)
        # first find the inverse of k
        # z = H(M)
        s = self.curve.mod_inverse(k, self.n) * (z + r * private_key) % self.n
        return r, s # signature = (r,s)

    def verify(self, public_key, message, signature):
        z = self._hash_message(message) # hash the message
        r, s = signature # saving the signature components in r and s
        w = self.curve.mod_inverse(s, self.n) # calculating the opposite of s and saving it in w
        u1 = (z * w) % self.n # computing u1 = (z * w) mod n
        u2 = (r * w) % self.n # computing u2 = (r * w) mod n

        # x is the random point which serves in the sign process
        x, _ = self.curve.add(self.curve.multiply(self.G, u1), self.curve.multiply(public_key, u2))
        if (r % self.n) == (x % self.n): # checking if r equals to x
            return True # signature is valid
        return False # signature is not valid

    def _hash_message(self, message):
        hash_obj = hashlib.sha256(message.encode())
        hash_digest = int.from_bytes(hash_obj.digest(), 'big')
        return hash_digest % self.n

    def _generate_random_k(self):
        while True:
            k = random.randint(1, self.n - 1)
            if self.curve.mod_inverse(k, self.n) != 0:
                return k

class EllipticCurve:
    def __init__(self):
        # y^2 = x^3 + 3
        # secp192k1 curve
        self.p = 0xfffffffffffffffffffffffffffffffffffffffeffffee37
        self.a = 0x000000000000000000000000000000000000000000000000 # a = a = 0
        self.b = 0x000000000000000000000000000000000000000000000003 # b = b = 3
        self.Gx = 0xdb4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d # x of G on curve
        self.Gy = 0x9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d # y of G on curve
        # order is the order of the generator of point G
        self.order = 0xfffffffffffffffffffffffe26f2fc170f69466a74defd8d # number of points on the curve = prime number

    def generator(self):
        return self.Gx, self.Gy

    def add(self, P, Q):
        if P is None:
            return Q
        if Q is None:
            return P
        Px, Py = P
        Qx, Qy = Q
        if P == Q:
            # m (lam) = (3x1^2 + a) / (2y1)    : Case 3 x1 = x2 and y1 = y2
            lam = (3 * Px * Px + self.a) * self.mod_inverse(2 * Py, self.p)
        else:
            # m (lam) = (y2 - y1) / (x2 - x1)    : Case 1 x1 != x2
            lam = (Qy - Py) * self.mod_inverse(Qx - Px, self.p)
        Rx = (lam * lam - Px - Qx) % self.p # x3 = m^2 - x1 - x2
        Ry = (lam * (Px - Rx) - Py) % self.p # y3 = m(x1 - x3) - y1
        return Rx, Ry # coordinates of new point (Rx,Ry)

    def multiply(self, P, scalar):
        if scalar == 0:
            return None
        Q = None
        for i in range(scalar.bit_length()):
            if (scalar >> i) & 1:
                Q = self.add(Q, P)
            P = self.add(P, P)
        return Q

    def mod_inverse(self, a, m):
        if a < 0 or m <= a:
            a = a % m # ensuring that a is in the range of 0 to n-1
        c, d = a, m
        uc, vc, ud, vd = 1, 0, 0, 1
        while c != 0:
            q, c, d = divmod(d, c) + (c,)
            uc, vc, ud, vd = ud - q * uc, vd - q * vc, uc, vc
        if ud > 0:
            return ud
        else:
            return ud + m


# Define elliptic curve parameters

#y^2 = x^3 + ax + b mod p
# p is prime very big = n (modn)
'''
p = 6277101735386680763835789423207666416083908700390324961279
a = -3 # a = a
b = 2455155546008943817740293915197451784769108058161191238065 # b = b
Gx = 602046282375688656758213480587526111916698976636884684818 # x of G on curve
Gy = 174050332293622031404857552280219410364023488927386650641 # y of G on curve
order = 6277101735386680763835789423176059013767194773182842284081 # number of points on the curve = prime number
'''
'''
# y^2 = x^3 + 3
p = 0xfffffffffffffffffffffffffffffffffffffffeffffee37
a = 0x000000000000000000000000000000000000000000000000 # a = a
b = 0x000000000000000000000000000000000000000000000003 # b = b
Gx = 0xdb4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d # x of G on curve
Gy = 0x9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d # y of G on curve
# order is the order of the generator of point G
order = 0xfffffffffffffffffffffffe26f2fc170f69466a74defd8d # number of points on the curve = prime number

curve = EllipticCurve()

# Initialize ECDSA
ecdsa = ECDSA(curve)

# Generate key pair
private_key, public_key = ecdsa.generate_key_pair()

# Sign message
message = "Hello, world!"
signature = ecdsa.sign(private_key, message)

# Verify signature
valid = ecdsa.verify(public_key, message, signature)

print("Message:", message)
print("Private Key:", private_key)
print("Public Key:", public_key)
print("Signature:", signature)
print("Signature is Valid:", valid)
'''
