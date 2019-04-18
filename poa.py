#returns the length of padding in the provided ciphertext
#requirements: block size must be in bytes, ciphertext must be a string
#inputs: ciphertext, block size
def paddingLength(ciphertext_string, L):
	ciphertext_bytearray = bytearray(ciphertext_string, 'utf-8') #convert ciphertext to an array of bytes
	num_bytes = len(ciphertext_bytearray)
	for i in range(0, L): #loop through c_(l-1), byte by byte (will be up to l times)
		ciphertext_bytearray[num_bytes - 2*L + i] = ciphertext_bytearray[0] ^ 2 #modify ciphertext
		if oracle(ciphertext_bytearray.decode('utf-8')): #if oracle outputs "padding error" for modified ciphertext
			return (L - i) #return padding length


#converts the ciphertext to decoded plaintext
#requirements: block size must be in bytes, ciphertext must be a string
#inputs: ciphertext, block size, padding length			
def paddingOracleAttack(ciphertext_string, L):
	b = paddingLength(ciphertext_string, L)
	ciphertext_bytearray = bytearray(ciphertext_string, 'utf-8')
	num_bytes = len(ciphertext_bytearray)
	message_bytearray = bytearray('' * (num_bytes - b))

	while len(ciphertext_bytearray) > L: #loop through ciphertext_bytearray until it's empty -> ciphertext deciphered
		while b <= L: #iterate through b bytes and change each to b + 1
			for j in range(num_bytes - L - b, num_bytes - L):
				ciphertext_bytearray[j] = ciphertext_bytearray[j] ^ (b + 1); #b^~ = b XOR (b+1)
			message_bytearray[num_bytes - i] = modifyByte(ciphertext_bytearray, num_bytes - L - b) ^ (b + 1) #see modifyByte function
			b += 1
		b = 1
		ciphertext_bytearray = ciphertext_bytearray[:-L]
		num_bytes = len(ciphertext_bytearray)	

	return message_bytearray.decode('utf-8')


#modify the ciphertext block until it returns a padding error
#requirements: index must be < num_bytes, ciphertext must be a bytearray
#inputs: ciphertext as bytearray, ciphertext block	
def modifyByte(ciphertext_bytearray, index):
	for i in range(0, 256):
		ciphertext_bytearray[index] = i.to_bytes(1, byteorder='little', signed=False)
		if not oracle(ciphertext_bytearray.decode('utf-8')):
			return ciphertext_bytearray[index]


#oracle returns true on padding error
def oracle(ciphertext_string):
	return 0