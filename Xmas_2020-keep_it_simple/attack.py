from cipher import *
import random

def generate_pairs(nb,key):
	pairs = []
	cipher = FEAL(4, key)
	for i in range(nb):
		plaintext = [random.randint(0,255) for x in range(8)]
		ciphertext = cipher.encrypt(plaintext)
		pairs.append([plaintext,ciphertext])
	return pairs

def bit_array(array):
	bit = []
	for byte in array:
		for i in range(7,-1,-1):
			bit.append((byte >> i) & 1)
	return bit


def from_bit_array(bit):
	byte = []
	for i in range(0,len(bit),8):
		number = 0
		for j in range(8):
			number += bit[i+j] << (7-j)
		byte.append(number)
	return byte


def crack_key0(pairs):
	L0s = []
	R0s = []
	L4s = []
	R4s = []

	for i in range(len(pairs)):
		L0s.append(bit_array(pairs[i][0][:4]))
		R0s.append(bit_array(pairs[i][0][4:]))
		L4s.append(bit_array(pairs[i][1][:4]))
		R4s.append(bit_array(pairs[i][1][4:]))
	
	candidates = []
	for k1 in range(2 ** 6):
		for k2 in range(2 ** 6):
			key_trial = [0,k1,k2,0]
	 		dico = {0:0,1:0}
			for i in range(len(pairs)):
				L0 = L0s[i]
				R0 = R0s[i]
				L4 = L4s[i]
				R4 = R4s[i]
				end = round_function(from_bit_array(xor(L0,R0)),key_trial)
				constant = xor(xor(L0,R0),L4)[5] ^ xor(xor(L0,R0),L4)[13] ^ xor(xor(L0,R0),L4)[21] ^ xor(xor(L0,L4),R4)[15] ^ bit_array(end)[15]
				dico[constant] += 1
				if dico[0] != 0 and dico[1] != 0:
					break
			if dico[0] == nb or dico[1] == nb:
				candidates.append(key_trial)

	candidates2 = []
	for candidate in candidates:
		for k0 in range(2 ** 6):
			for k1_high in range(4):
				k1 = candidate[1] + (k1_high << 6)
				for k2_high in range(4):
					k2 = candidate[2] + (k2_high << 6)
					key_trial = [k0,k1,k2,0]
			 		dico = {0:0,1:0}
					for i in range(nb):
						L0 = L0s[i]
						R0 = R0s[i]
						L4 = L4s[i]
						R4 = R4s[i]
						end = round_function(from_bit_array(xor(L0,R0)),key_trial)
						constant = xor(xor(L0,R0),L4)[5] ^ xor(xor(L0,R0),L4)[15] ^ xor(xor(L0,L4),R4)[7] ^ bit_array(end)[7]
						dico[constant] += 1
						if dico[0] != 0 and dico[1] != 0:
							break
					if dico[0] == nb or dico[1] == nb:
						candidates2.append(key_trial)

	candidates3 = []
	for candidate in candidates2:
		for k3 in range(2 ** 6):
			key_trial = [candidate[0],candidate[1],candidate[2],k3]
	 		dico = {0:0,1:0}
			for i in range(nb):
				L0 = L0s[i]
				R0 = R0s[i]
				L4 = L4s[i]
				R4 = R4s[i]
				end = round_function(from_bit_array(xor(L0,R0)),key_trial)
				constant = xor(xor(L0,R0),L4)[15] ^ xor(xor(L0,R0),L4)[21] ^ xor(xor(L0,L4),R4)[23] ^ xor(xor(L0,L4),R4)[31] ^ bit_array(end)[23] ^ bit_array(end)[31]	
				dico[constant] += 1
				if dico[0] != 0 and dico[1] != 0:
					break
			if dico[0] == nb or dico[1] == nb:
				candidates3.append(key_trial)


	candidates4 = []
	for candidate in candidates3:
		for k0_high in range(4):
			k0 = candidate[0] + (k0_high << 6)
			for k3_high in range(4):
				k3 = candidate[3] + (k3_high << 6)
				candidates4.append([k0,candidate[1],candidate[2],k3])

	return candidates4


def crack_key1(pairs,K0_candidates):
	L0s = []
	R0s = []
	L4s = []
	R4s = []

	for i in range(len(pairs)):
		L0s.append(bit_array(pairs[i][0][:4]))
		R0s.append(bit_array(pairs[i][0][4:]))
		L4s.append(bit_array(pairs[i][1][:4]))
		R4s.append(bit_array(pairs[i][1][4:]))
	
	candidates = []
	for key0 in K0_candidates: 
		K0 = bit_array(key0)
		for k1 in range(2 ** 6):
			for k2 in range(2 ** 6):
				key_trial = [0,k1,k2,0]
		 		dico = {0:0,1:0}
				for i in range(len(pairs)):
					L0 = L0s[i]
					R0 = R0s[i]
					L4 = L4s[i]
					R4 = R4s[i]
					Y0 = bit_array(round_function(from_bit_array(xor(L0,R0)),key0))
					end = round_function(from_bit_array(xor(L0,Y0)),key_trial)
					constant = xor(xor(R0,R4),Y0)[5] ^ xor(xor(R0,R4),Y0)[13] ^ xor(xor(R0,R4),Y0)[21] ^ xor(xor(xor(Y0,R0),R4),L4)[15] ^ bit_array(end)[15]
					dico[constant] += 1
					if dico[0] != 0 and dico[1] != 0:
						break
				if dico[0] == nb or dico[1] == nb:
					candidates.append([key0,key_trial])

	candidates2 = []
	for key0,candidate in candidates:
		for k0 in range(2 ** 6):
			for k1_high in range(4):
				k1 = candidate[1] + (k1_high << 6)
				for k2_high in range(4):
					k2 = candidate[2] + (k2_high << 6)
					key_trial = [k0,k1,k2,0]
			 		dico = {0:0,1:0}
					for i in range(nb):
						L0 = L0s[i]
						R0 = R0s[i]
						L4 = L4s[i]
						R4 = R4s[i]
						Y0 = bit_array(round_function(from_bit_array(xor(L0,R0)),key0))
						end = round_function(from_bit_array(xor(L0,Y0)),key_trial)
						constant = xor(xor(R0,R4),Y0)[5] ^ xor(xor(R0,R4),Y0)[15] ^ xor(xor(xor(Y0,R0),R4),L4)[7] ^ bit_array(end)[7]
						dico[constant] += 1
						if dico[0] != 0 and dico[1] != 0:
							break
					if dico[0] == nb or dico[1] == nb:
						candidates2.append([key0,key_trial])

	candidates3 = []
	for key0,candidate in candidates2:
		for k3 in range(2 ** 6):
			key_trial = [candidate[0],candidate[1],candidate[2],k3]
	 		dico = {0:0,1:0}
			for i in range(nb):
				L0 = L0s[i]
				R0 = R0s[i]
				L4 = L4s[i]
				R4 = R4s[i]
				Y0 = bit_array(round_function(from_bit_array(xor(L0,R0)),key0))
				end = round_function(from_bit_array(xor(L0,Y0)),key_trial)
				constant = xor(xor(R0,R4),Y0)[15] ^ xor(xor(R0,R4),Y0)[21] ^ xor(xor(xor(Y0,R0),R4),L4)[23] ^ xor(xor(xor(Y0,R0),R4),L4)[31] ^ bit_array(end)[23] ^ bit_array(end)[31]		
				dico[constant] += 1
				if dico[0] != 0 and dico[1] != 0:
					break
			if dico[0] == nb or dico[1] == nb:
				candidates3.append([key0,key_trial])


	candidates4 = []
	for key0,candidate in candidates3:
		for k0_high in range(4):
			k0 = candidate[0] + (k0_high << 6)
			for k3_high in range(4):
				k3 = candidate[3] + (k3_high << 6)
				candidates4.append([key0,[k0,candidate[1],candidate[2],k3]])

	return candidates4


def reverse_G(x,out,b):
	t = ((out >> 2) & (2**8-1)) | (out & 3) << (8-2) 
	return (t - b - x) % 256


def Fk(A,B):
	a0,a1,a2,a3 = A
	b0,b1,b2,b3 = B
	o1 = G(1,a0 ^ a1,b0^a2^a3)
	o0 = G(0,a0,o1^b2)
	o2 = G(0,a2^a3,b1^o1)
	o3 = G(1,a3,b3^o2)
	return [o0,o1,o2,o3]

def reverse_Fk(out,A):
	o0,o1,o2,o3 = out
	a0,a1,a2,a3 = A
	b3 = reverse_G(1,o3,a3) ^ o2
	b2 = reverse_G(0,o0,a0) ^ o1
	b1 = reverse_G(0,o2,a2 ^ a3) ^ o1
	b0 = reverse_G(1,o1,a0 ^ a1) ^ a2 ^ a3
	return [b0,b1,b2,b3]

def extract_key(k0, k1, k2):
    b0 = xor(reverse_Fk(k2, k0), k1)
    a0 = xor(reverse_Fk(k1, b0), k0)
    key = a0 + b0
    return key

def check(k0, k1, k2, k3):
    k3_exp = Fk(k1, xor(k0, k2))
    if k3 == k3_exp:
    	return True
    else:
    	return False


def convert(array):
	return ''.join([chr(x) for x in array]).encode("hex")


def fromhex(string):
	result = []
	for i in range(0,len(string),2):
		result.append(int(string[i:i+2],16))
	return result


nb = 16


pairs = eval(open("pairs_server.txt","r").read())

#get k0,k1

key0_candidates = crack_key0(pairs)
key0_1_candidates = crack_key1(pairs,key0_candidates)

#get k3,k2

reversed_pairs = [[x[1],x[0]] for x in pairs]

key3_candidates = crack_key0(reversed_pairs)
key3_2_candidates = crack_key1(reversed_pairs,key3_candidates)


#Meet-in-the-Middle

LR_start = {}

pt = pairs[0][0]
ct = pairs[0][1]
L0 = pt[:4]
R0 = pt[4:]
L4 = ct[:4]
R4 = ct[4:]


full_key_candidates = []

for i in range(len(key0_1_candidates)):
	key0 = key0_1_candidates[i][0]
	key1 = key0_1_candidates[i][1]
	R = xor(L0, R0)
	L = L0[:]
	t = round_function(R, key0)
	L, R = R, xor(L, t)
	t = round_function(R, key1)
	L, R = R, xor(L, t)
	LR_start[convert(R + L)] = i


for i in range(len(key3_2_candidates)):
	key3 = key3_2_candidates[i][0]
	key2 = key3_2_candidates[i][1]
	R = xor(L4, R4)
	L = L4[:]
	t = round_function(R, key3)
	L, R = R, xor(L, t)
	t = round_function(R, key2)
	L, R = R, xor(L, t)
	if convert(L+R) in LR_start:
		full_key_candidates.append(key0_1_candidates[LR_start[convert(L+R)]] + [key2,key3])


#First filter based on the cipher giving the right ciphertexts from the plaintexts (not bringing much here tbh)

full_key_candidates_filtered = []

for candidate in full_key_candidates:
	correct = 0
	cipher = FEAL(4,candidate)
	for i in range(nb):
		if cipher.encrypt(pairs[i][0]) == pairs[i][1]:
			correct += 1
	if correct == 16:
		full_key_candidates_filtered.append(candidate)



#Second filter based on key_schedule + final key


for k0,k1,k2,k3 in full_key_candidates_filtered:
	if check(k0,k1,k2,k3):

		print "key: " + convert(extract_key(k0,k1,k2))

