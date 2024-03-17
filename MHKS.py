import random
import math

class MerkleHellmanKnapsack:
    def __init__(self):
        self.private_key, self.public_key, self.q, self.r = self.generate_keypair()

    def generate_superincreasing_sequence(self, length): #generaete superincreasing_sequence that will be my private key 
        sequence = [random.randint(1, 1000)]
        for _ in range(1, length):
            sequence.append(random.randint(sum(sequence) + 1, 2 * sum(sequence))) #by the order of the seq we every time add next number that bigger than the sum of everyone before
        return sequence

    def generate_keypair(self):
        private_key = self.generate_superincreasing_sequence(128) #key size 128
        #now we select 2 random numbers q(m) and r(n)
        q = sum(private_key) + random.randint(1, 1000)  # q should be grather from sum all seq of the private key
        r = random.randint(2, q - 1)  # r sould gcd(r,q)=1
        while math.gcd(r, q) != 1:  # do it until we find
            r = random.randint(2, q - 1)  # Choose a new value for r
        public_key = [(r * element) % q for element in private_key] #calc public key
        #every number in the private key *r mod q
        return private_key, public_key, q, r

    def encrypt(self, plaintext, public_key): #we encrypt blocks of 128
        binary_plaintext = bin(plaintext)[2:].zfill(128) #if the block smaller than 128 add 0 to the left
        #multiple puclic key with plaintext and sum
        encrypted = sum([int(bit) * element for bit, element in zip(binary_plaintext, public_key)])
        return encrypted

    def decrypt(self, ciphertext, private_key):
        decrypted = []
        #pow(self.r, -1, self.q) this is the inverse of r and we * with cipher text modolo q
        s = (ciphertext * pow(self.r, -1, self.q)) % self.q
        #all the point of knapsack we run on our private_key that issuperincreasing seq so wen the element is smaller the s it must be him
        for element in reversed(private_key):
            if element <= s:
                decrypted.insert(0, 1)
                s -= element
            else:
                decrypted.insert(0, 0)
        decrypted_value = int(''.join(str(bit) for bit in decrypted), 2)#convert to decimal
        return decrypted_value
    
    def returnKeys(self):
        return self.private_key, self.public_key, self.q, self.r

