'''
This implementation is a modifed version of the one found at
https://gist.github.com/forkd/168c9d74b988391e702aac5f4aa69e41
'''

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

    def __init__(self, enc_key, mac_key, hide_errors=False):
        self.enc_key = md5(enc_key.encode('utf8')).hexdigest()
        self.mac_key = md5(mac_key.encode('utf8')).digest()
        self.PaddingError = -2
        self.MACError = -1
        self.GenError = -3
        self.hide_errors = hide_errors


    def paddingError(self, ciphertext_string):
        x = ciphertext_string[-1]
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
        iv = enc[:16]
        dummy = enc[16:]
        cipher = AES.new(self.enc_key, AES.MODE_CBC, iv)



        #decrypt the ciphertext
        d = cipher.decrypt(dummy)

        #check if a padding error occured, and print an error message if so.
        if self.paddingError(d) == True:
            #print("ERROR: PADDING ERROR OCCURED")
            end = time.time()
            #print("Padding error time: {}".format(end-start))
            if self.hide_errors:
                return self.GenError
            return self.PaddingError
        #unpad the the decrypted ciphertext
        
        unpadded = unpad(d)

        #grab the HMAC appended to the end of it.
        HMAC1 = unpadded[-32:]
        #find the length of the plaintext and separate the plaintext from the HMAC
        length = len(unpadded)-32
        plaintext = unpadded[:length]
        HMAC2 = hmac.new(self.mac_key, plaintext, digestmod = md5).hexdigest().encode('utf-8')

        #Compare HMACS
        if hmac.compare_digest(HMAC1, HMAC2):
            #print("HMACS ARE UNTAMPERED")
            return plaintext.decode('utf-8')
        else:
            #print("HMACS ARE COMPROMISED")
            if self.hide_errors:
                return self.GenError
            return self.MACError


##
# MAIN
# Just a test.
if __name__ == "__main__":
    msg = "rew" #input('Message...: ')
    pwd = "rew" #input('Password..: ')

    ciphertext = AESCipher(pwd, "klde").encrypt(msg)
    print('Ciphertext:', ciphertext)
    print('Ciphertext:', AESCipher(pwd, "klde").decrypt(ciphertext))