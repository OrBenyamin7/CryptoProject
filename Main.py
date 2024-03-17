from NewECDSA import ECDSA,EllipticCurve
from MHKS import MerkleHellmanKnapsack
from Rabbit import Rabbit

# import that used for converting binary data to ASCII
# encoded hexadecimal strings
import binascii

# Rabbit key
Rabbit_key = '0f01dbd6d2ea452fb64730c544269f44'

class Person:
    def __init__(self):
        self.isMessageWaiting = False
        self.messageWaiting = None
        self.signedMessageWaiting = None

    def GenerateMHKSKeys(self):
        self.mhks = MerkleHellmanKnapsack()
        self.privateMHKSKey, self.publicMHKSKey, self.q, self.r = self.mhks.returnKeys()

    def GenerateSignatureKeys(self,curve,ecdsa):
        #self.ecdsa = ECDSA()
        self.curve = curve
        self.ecdsa = ecdsa
        self.privateSignatureKey, self.publicSignatureKey = self.ecdsa.generate_key_pair()

    def signOn(self, message):
        signedMessage = self.ecdsa.sign(self.privateSignatureKey,message)
        return signedMessage

    def encryptRabbitKey(self, keyToEncrypt ,key):
        return self.mhks.encrypt(keyToEncrypt, key)
    
    def decryptRabbitKey(self, keyToDecrypt ,key):
        return self.mhks.decrypt(keyToDecrypt, key)

def main():
    alice = Person()
    bob = Person()

    bob.GenerateMHKSKeys()
        
    curve = EllipticCurve()
    ecdsa = ECDSA(curve)
    alice.GenerateSignatureKeys(curve,ecdsa)

    mhks = MerkleHellmanKnapsack()

    file_path = 'file.txt'  # Assuming the file is in the same directory as your Python script

    with open(file_path, 'r') as file:
        messageToSend = file.read()
    
    print("=========================================================================================")
    alice.rabbitKey = int(Rabbit_key, 16)
    print("Rabbit key before encryption is :",alice.rabbitKey)

    print("\nAlice now encrypt the message using the Rabbit algorithm")
    encryptedMessage = Rabbit(alice.rabbitKey,0).encrypt(messageToSend)
    print("\nEncrypted message  :",encryptedMessage) #message to send for bob
    encodedMessage = binascii.hexlify(encryptedMessage.encode()) 
    print("\nEncrypted message with regular signs :",encodedMessage)

    # Alice encrypt Rabbit key using Bob's public key with MHKS algorithm
    print("\nAlice now encrypt the Rabbit's key using the MHKS algorithm\n")
    encryptedRabbitKey = mhks.encrypt(alice.rabbitKey, bob.publicMHKSKey)
    print("Rabbit key after encryption is : ", encryptedRabbitKey)
   
    # Alice sign the message using her private key using ECDSA algorithm
    print("\nAlice now sign the message using the ECDSA algorithm")
    signMessage = alice.signOn(messageToSend)

    print("=========================================================================================")
    print("Bob now decrypts the Rabbit's key using the MHKS algorithm\n")
    # Bob decrypt the rabbit key using his private key and MHKS algorithm
    decryptedRabbitKey = bob.decryptRabbitKey(encryptedRabbitKey, bob.privateMHKSKey)
    print("Rabbit key after decryption is : ", decryptedRabbitKey)
    
    # Bob decrypt the message using Rabbit algorithm
    print("\nBob now decrypts the message using the Rabbit algorithm\n")
    text = Rabbit(decryptedRabbitKey,0).decrypt(encryptedMessage)
    print("Decrypted :",text)

    # Bob doing verification on message using Alice public key from ECDSA
    print("Bob now verify alice's signature using the ECDSA algorithm\n")
    result = ecdsa.verify(alice.publicSignatureKey, text, signMessage)
    if(result):
        print("----Verification complete----\n")
    if(not result):
        print("----Verification failed----\n")

    # Open the file in write mode and write the string
    with open("output.txt", 'w') as file:
        file.write(text)


if __name__ == "__main__":
    main()