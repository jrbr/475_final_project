import decoder
import binascii
import time
import statistics

from base64 import b64decode
from base64 import b64encode

BLOCK_SIZE = 16  # Bytes

cipher = decoder.AESCipher("enc_key", "mac_key")

class Oracle:
    def __init__(self, use_timing=False):
        self.use_timing = use_timing
        self.time_threshold = .000024
        if use_timing:
            global cipher 
            cipher = decoder.AESCipher("enc_key", "mac_key", hide_errors=True)

    def set_threshold(self, pad_time_mean, pad_time_stdev, mac_time_mean, mac_time_stdev):
        print("padding error mean time: {}".format(pad_time_mean))
        print("padding std dev: {}".format(pad_time_stdev))
        print("mac error mean time: {}".format(mac_time_mean))
        print("mac error std dev: {}".format(mac_time_stdev))
        self.time_threshold = (mac_time_mean - 2 * mac_time_stdev + pad_time_mean + 2 * pad_time_stdev) / 2
        print(self.time_threshold)
        print("{} stdev above padding error mean".format((self.time_threshold - pad_time_mean) / pad_time_stdev)) 
        print("{} stdev below MAC error mean".format((mac_time_mean - self.time_threshold) / mac_time_stdev)) 

    #oracle returns true on padding error
    def query(self, ciphertext_string):
        if self.use_timing:
            return self.timer_query(ciphertext_string)
        decrypted = cipher.decrypt(ciphertext_string)
        return decrypted == cipher.PaddingError

    def timer_query(self, ciphertext_string):
        sum_time = 0
        num_iterations = 500
        sample =[]
        for i in range(0, num_iterations):

            start = time.time()
            decrypted = cipher.decrypt(ciphertext_string)
            end = time.time()
            sample.append(end - start)

        #print (statistics.mean(sample))
        return statistics.mean(sample) < self.time_threshold

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
    #exit()
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
            byteFound = False
            while not byteFound:

                try:
                    xor_block[-b -1 ] = modifyByte(modified_cipher_bytearray, num_bytes - L - b - 1, oracle) ^ciphertext_bytearray[- L - b - 1] ^ (b + 1)#see modifyByte function
                    byteFound = True
                except TypeError:# try it again
                    pass
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
    #print("modifying byte")
    for i in range(0, 256):
        ciphertext_bytearray[index] = i
        #print(ciphertext_bytearray)
        #print (ciphertext_bytearray[index])
        if not oracle.query(bytes(ciphertext_bytearray)):
            if not oracle.query(bytes(ciphertext_bytearray)):
                print(ciphertext_bytearray[index])
                return ciphertext_bytearray[index]
    print("no byte found")




if __name__ ==  "__main__":
    plaintext = "this is a much longer message. what are the chances that it doesn't mess up at all in this whole message?"
    ciphertext = cipher.encrypt(plaintext)

    #c = b'roX+Bm0JNAQO9/W7jlNPrquLPwGB451mmEMFb8Gq7Nax4UPT2WUD9H/EJbqotxhy60M/kbuuEfW3yahL9GCqOFNi0dQxouLfV+1sRgw4yw4-'

    #print
    print("plaintext: {} \nciphertext: {}".format(plaintext, ciphertext))

    oracle = Oracle(use_timing=True)


    
    ciphertext_bytearray =  getBytearray(ciphertext)#convert ciphertext to an array of bytes
    num_bytes = len(ciphertext_bytearray)

    #ciphertext_bytearray[num_bytes - 16 -1 ] = 0 #modify ciphertext


    mac_times = []
    iters = 1000
    for i in range(0, iters):
        start = time.time()
        decrypted = cipher.decrypt(bytes(ciphertext_bytearray))
        end = time.time()
        mac_times.append(end - start)

    ciphertext_bytearray[num_bytes - 16 -1 ] = 0 #modify ciphertext


    pad_times = []
    iters = 1000
    for i in range(0, iters):
        start = time.time()
        decrypted = cipher.decrypt(bytes(ciphertext_bytearray))
        end = time.time()
        pad_times.append(end - start)

    print("sample size: {}".format(len(pad_times)))
    

    oracle.set_threshold(statistics.mean(pad_times), statistics.stdev(pad_times),
                    statistics.mean(mac_times), statistics.stdev(mac_times))
    
    poa_result = paddingOracleAttack(ciphertext, 16, oracle)[:-32]
    print("decoded result: {}".format(poa_result))

    print("Successful decoding: {}".format(plaintext == poa_result))