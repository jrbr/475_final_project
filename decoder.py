from hashlib import md5
from base64 import b64decode
from base64 import b64encode
from Crypto import Random
from Crypto.Cipher import AES
import hmac
import time


# Padding for the input string --not
# related to encryption itself.
BLOCK_SIZE = 16  # Bytes
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


class AESCipher:
    """
    Usage:
        c = AESCipher('password').encrypt('message')
        m = AESCipher('password').decrypt(c)
    Tested under Python 3 and PyCrypto 2.6.1.
    """

    def __init__(self, key):
        self.key = md5(key.encode('utf8')).hexdigest()

    def paddingError(ciphertext_string):
        x = ciphertext_string[-1]
        y = len(ciphertext_string)
        while y > len(ciphertext_string) - x:
            if(ciphertext_string[y] == x):
                y = y - 1
            else:
                return True
        return False

    def encrypt(self, raw):
        raw = pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        cipherHMAC = hmac.new(self.key, raw, digestmod = md5)
        raw2 = raw + cipherHMAC.digest()
        return iv + cipher.encrypt(raw2)

    def decrypt(self, enc):
        start = time.time()
        iv = enc[:16]
        dummy = enc[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)

        #decrypt the ciphertext
        d = cipher.decrypt(dummy)
        #check if a padding error occured, and print an error message if so.
        if paddingError(d):
            print("ERROR: PADDING ERROR OCCURED")
            end = time.time()
            print("Padding error time: " + end-start)
            return -2
        #unpad the the decrypted ciphertext
        unpadded = unpad(d)
        #grab the HMAC appended to the end of it.
        HMAC1 = unpadded[-32:]
        #find the length of the plaintext and separate the plaintex from the HMAC
        length = len(unpadded)-32
        plaintext = unpadded[:length]
        HMAC2 = hmac.new(self.key, plaintext, digestmod = md5)
        #Compare HMACS
        if hmac.compare_digest(HMAC1, HMAC2):
            print("HMACS ARE UNTAMPERED")
            return plaintext
        else:
            print("HMACS ARE COMPROMISED")
            end = time.time()
            print("HMAC error time: " + end-start)
            return -1


##
# MAIN
# Just a test.
msg = input('Message...: ')
pwd = input('Password..: ')

print('Ciphertext:', AESCipher(pwd).encrypt(msg))