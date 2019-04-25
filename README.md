# 475_final_project
EECS 475 final project by Joe Brenner, Rishi Devangam, Johnathan Foy, and Andrew Kennedy

In this repository there are two python scripts.

1. decoder.py
	This file contains our encryption/decryption scheme. It runs a Mac-then-encrypt CBC scheme on a given plaintext,
	and decrypts then authentices a given ciphertext. 

	The decryption function has two modes:
	1. standard: distinct messages are provided for padding error and MAC authentication errors
	2. hidden_errors: The same generic message is returned for both padding and MAC errors

2. poa.py
	This is where our attack algorithm is implemented. To run the attack, simply call "python3 poa.py" (we have not tested in python 2.7). 

	You can affect the behavior of our attack in 2 ways
	1. Change the plaintext by assigning a different string to the "plaintext" variable at the beginning of main
	2. Change from a standard padding oracle attack to a timing augmented attack by changing the boolean value passed into the "oracle(use_timing=true)" call, which is also found at the top of main.

	As the attack progresses, it will print out the reconstructed portion of the plaintext whenever it finds a new byte, so you can easily track the algorithms progress.

	Please note that while the plaintext message is defined in the code, it is only used for the initial encryption and final correctness check. It would be fairly straightforward to modify this script to take in an arbitrary ciphertext as a command line function for decryption, but we decided that for this demonstration that ability was unnessecary.
