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

    def __init__(self, enc_key, mac_key):
        self.enc_key = md5(enc_key.encode('utf8')).hexdigest()
        self.mac_key = md5(mac_key.encode('utf8')).digest()


    def paddingError(self, ciphertext_string):
        x = ciphertext_string[-1]
        #print("pad: {}".format(x))
        if x == 0:
            return True

        y = len(ciphertext_string) - 1
        while y >= len(ciphertext_string) - x:
            if(ciphertext_string[y] == x):
                y = y - 1
            else:
                return True
        return False

    def encrypt(self, raw):
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.enc_key, AES.MODE_CBC, iv)
        cipherHMAC = hmac.new(self.mac_key, raw.encode('utf-8'), digestmod = md5)
        raw2 = raw + cipherHMAC.hexdigest()
        print("plaintext with HMAC and Padding: {}".format(pad(raw2)))
        return iv + cipher.encrypt(pad(raw2))

    def decrypt(self, enc):
        start = time.time()
        iv = enc[:16]
        dummy = enc[16:]
        cipher = AES.new(self.enc_key, AES.MODE_CBC, iv)



        #decrypt the ciphertext
        d = cipher.decrypt(dummy)

        #print(d)
        #check if a padding error occured, and print an error message if so.
        if self.paddingError(d) == True:
            #print("ERROR: PADDING ERROR OCCURED")
            end = time.time()
            #print("Padding error time: {}".format(end-start))
            return -2
        #unpad the the decrypted ciphertext
        
        #print('here')
        unpadded = unpad(d)
        #print(d)
        #print(unpadded)
        #grab the HMAC appended to the end of it.
        HMAC1 = unpadded[-32:]
        #find the length of the plaintext and separate the plaintext from the HMAC
        length = len(unpadded)-32
        plaintext = unpadded[:length]
        HMAC2 = hmac.new(self.mac_key, plaintext, digestmod = md5).hexdigest().encode('utf-8')
        #print("hmac1: {}".format(HMAC1))
        #print("hmac2: {}".format(HMAC2))
        #Compare HMACS
        if hmac.compare_digest(HMAC1, HMAC2):
            #print("HMACS ARE UNTAMPERED")
            return plaintext.decode('utf-8')
        else:
            #print("HMACS ARE COMPROMISED")
            end = time.time()
            #print("HMAC error time: {}".format( end-start))
            return -1


##
# MAIN
# Just a test.
if __name__ == "__main__":
    msg = "rew" #input('Message...: ')
    pwd = "rew" #input('Password..: ')

    ciphertext = AESCipher(pwd, "klde").encrypt(msg)
    print('Ciphertext:', ciphertext)
    print('Ciphertext:', AESCipher(pwd, "klde").decrypt(ciphertext))