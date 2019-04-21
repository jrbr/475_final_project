import decoder
import binascii
import time

from base64 import b64decode
from base64 import b64encode

BLOCK_SIZE = 16  # Bytes

cipher = decoder.AESCipher("enc_key", "mac_key")

class Oracle:
    def __init__(self, use_timing=False):
        self.use_timing = use_timing
        self.time_threshold = .000016
        if use_timing:
            global cipher 
            cipher = decoder.AESCipher("enc_key", "mac_key", hide_errors=True)

    #oracle returns true on padding error
    def query(self, ciphertext_string):
        if self.use_timing:
            return self.timer_query(ciphertext_string)
        decrypted = cipher.decrypt(ciphertext_string)
        return decrypted == cipher.PaddingError

    def timer_query(self, ciphertext_string):
        sum_time = 0
        num_iterations = 20
        for i in range(0, num_iterations):
            start = time.time()
            decrypted = cipher.decrypt(ciphertext_string)
            end = time.time()
            sum_time += end-start
        print (sum_time/num_iterations)
        return sum_time/num_iterations < self.time_threshold

#returns the length of padding in the provided ciphertext
#requirements: block size must be in bytes, ciphertext must be a string
#inputs: ciphertext, block size
def paddingLength(ciphertext_string, L, oracle):
    ciphertext_bytearray =  getBytearray(ciphertext_string)#convert ciphertext to an array of bytes
    num_bytes = len(ciphertext_bytearray)
    for i in range(0, L): #loop through c_(l-1), byte by byte (will be up to l times)

        ciphertext_bytearray[num_bytes - 2*L + i] = 0 #modify ciphertext
        if oracle.query(bytes(ciphertext_bytearray)): #if oracle outputs "padding error" for modified ciphertext
            return (L - i ) #return padding length


#converts the ciphertext to decoded plaintext
#requirements: block size must be in bytes, ciphertext must be a string
#inputs: ciphertext, block size, padding length         
def paddingOracleAttack(ciphertext_string, L, oracle):
    b = paddingLength(ciphertext_string, L, oracle)
    print("padding length: {}".format(b))

    ciphertext_bytearray =  getBytearray(ciphertext_string)
    num_bytes = len(ciphertext_bytearray)

    # buffer to hold deciphered message
    message_bytearray = getBytearray(' '*(num_bytes - b))

    while len(ciphertext_bytearray) > L: #loop through ciphertext_bytearray until it's empty -> ciphertext deciphered
        original_padding_length = b

        #base xor block, used to create block (00...0t'b'b'b'')
        xor_block = getBytearray('0'*(L)) 
        for byte in range(0, b):
            xor_block[-byte - 1] = b 

        while b < L: #iterate through block c_(l-1) to decode c_l 
            modified_cipher_bytearray = bytearray(ciphertext_bytearray)
            mod_xor_block = bytearray(xor_block)

            #update modified_cipher Bytearray so
            #c_(l-1) = c_(l-1) XOR (00...0t'b'b'b'')
            #or c_(l-1) = c_(l-1) XOR (00...0t_(L-b)'b'b'b'') on further iterations
            for byte in range(0, L):
                if mod_xor_block[byte] != 0:
                    mod_xor_block[byte] ^= (b+1)
                modified_cipher_bytearray[-2*L + byte] ^= mod_xor_block[byte]
            
            xor_block[-b -1 ] = modifyByte(modified_cipher_bytearray, num_bytes - L - b - 1, oracle) ^ciphertext_bytearray[- L - b - 1] ^ (b + 1)#see modifyByte function
            message_bytearray[num_bytes - b - 1] = xor_block[-b-1]
            b += 1
            print(message_bytearray)
        b = 0
        ciphertext_bytearray = ciphertext_bytearray[:-L]
        num_bytes = len(ciphertext_bytearray)   

    return message_bytearray.decode('utf-8').strip()


#returns a bytearray representation of various data types
def getBytearray(ciphertext):
    byteArray = None
    if isinstance(ciphertext, bytes): 
        byteArray = bytearray(ciphertext)
    elif isinstance(ciphertext, str): 
        byteArray = bytearray(ciphertext, 'utf-8')
    else:
        print("invalid type")
    return byteArray

#modify the ciphertext block until it returns a padding error
#requirements: index must be < num_bytes, ciphertext must be a bytearray
#inputs: ciphertext as bytearray, ciphertext block  
def modifyByte(ciphertext_bytearray, index, oracle):
    print("modifying byte")
    for i in range(0, 256):
        ciphertext_bytearray[index] = i
        #print(ciphertext_bytearray)
        #print (ciphertext_bytearray[index])
        if not oracle.query(bytes(ciphertext_bytearray)):
            return ciphertext_bytearray[index]
    print("no byte found")




if __name__ ==  "__main__":
    plaintext = "This seems to be working"
    ciphertext = cipher.encrypt(plaintext)

    #c = b'roX+Bm0JNAQO9/W7jlNPrquLPwGB451mmEMFb8Gq7Nax4UPT2WUD9H/EJbqotxhy60M/kbuuEfW3yahL9GCqOFNi0dQxouLfV+1sRgw4yw4-'

    #print
    print("plaintext: {} \nciphertext: {}".format(plaintext, ciphertext))


    #oracle(c)
    #print("decrypted: {}".format(cipher.decrypt(ciphertext)))
    oracle = Oracle(use_timing=True)

    poa_result = paddingOracleAttack(ciphertext, 16, oracle)[:-32]
    print("decoded result: {}".format(poa_result))

    print("Successful decoding: {}".format(plaintext == poa_result))