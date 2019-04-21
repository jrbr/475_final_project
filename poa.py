import decoder
import binascii

from base64 import b64decode
from base64 import b64encode

BLOCK_SIZE = 16  # Bytes

cipher = decoder.AESCipher("enc_key", "mac_key")

#returns the length of padding in the provided ciphertext
#requirements: block size must be in bytes, ciphertext must be a string
#inputs: ciphertext, block size
def paddingLength(ciphertext_string, L):
	#print (type(ciphertext_string))
	ciphertext_bytearray =  getBytearray(ciphertext_string)#convert ciphertext to an array of bytes
	num_bytes = len(ciphertext_bytearray)
	for i in range(0, L): #loop through c_(l-1), byte by byte (will be up to l times)
		#print (i)
		ciphertext_bytearray[num_bytes - 2*L + i] = 0 #modify ciphertext
		#print("calling oracle")
		if oracle(bytes(ciphertext_bytearray)): #if oracle outputs "padding error" for modified ciphertext
			return (L - i ) #return padding length


#converts the ciphertext to decoded plaintext
#requirements: block size must be in bytes, ciphertext must be a string
#inputs: ciphertext, block size, padding length			
def paddingOracleAttack(ciphertext_string, L):
	b = paddingLength(ciphertext_string, L)
	print("padding length: {}".format(b))

	ciphertext_bytearray =  getBytearray(ciphertext_string)
	num_bytes = len(ciphertext_bytearray)
	message_bytearray = getBytearray(' '*(num_bytes - b))
	#print(message_bytearray)
	while len(ciphertext_bytearray) > L: #loop through ciphertext_bytearray until it's empty -> ciphertext deciphered
		original_padding_length = b
		xor_block = getBytearray('0'*(L))#base xor block, used create instances for each test
		for byte in range(0, b):
			xor_block[-byte - 1] = b 
		#print(xor_block)
		while b < L: #iterate through b bytes and change each to b + 1
			modified_cipher_bytearray = bytearray(ciphertext_bytearray)
			mod_xor_block = bytearray(xor_block)
			#print(mod_xor_block)
			
			for byte in range(0, L):
				if mod_xor_block[byte] != 0:
					mod_xor_block[byte] ^= (b+1)
				modified_cipher_bytearray[-2*L + byte] ^= mod_xor_block[byte]
			
			#print(mod_xor_block)
			xor_block[-b -1 ] = modifyByte(modified_cipher_bytearray, num_bytes - L - b - 1) ^ciphertext_bytearray[- L - b - 1] ^ (b + 1)#see modifyByte function
			message_bytearray[num_bytes - b - 1] = xor_block[-b-1]
			b += 1
			#print(message_bytearray)
		b = 0
		ciphertext_bytearray = ciphertext_bytearray[:-L]
		num_bytes = len(ciphertext_bytearray)	

	return message_bytearray.decode('utf-8')



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
def modifyByte(ciphertext_bytearray, index):
	for i in range(0, 256):
		ciphertext_bytearray[index] = i
		#print(ciphertext_bytearray)
		#print (ciphertext_bytearray[index])
		if not oracle(bytes(ciphertext_bytearray)):
			return ciphertext_bytearray[index]


#oracle returns true on padding error
def oracle(ciphertext_string):
	#print("in oracle")
	decrypted =	cipher.decrypt(ciphertext_string)
	return decrypted == -2

if __name__ ==  "__main__":
	plaintext = "This seems to be working"
	ciphertext = cipher.encrypt(plaintext)

	#c = b'roX+Bm0JNAQO9/W7jlNPrquLPwGB451mmEMFb8Gq7Nax4UPT2WUD9H/EJbqotxhy60M/kbuuEfW3yahL9GCqOFNi0dQxouLfV+1sRgw4yw4-'

	#print
	print("plaintext: {} \nciphertext: {}".format(plaintext, ciphertext))


	#oracle(c)
	#print("decrypted: {}".format(cipher.decrypt(ciphertext)))

	poa_result = paddingOracleAttack(ciphertext, 16)[:-32]
	print(poa_result)