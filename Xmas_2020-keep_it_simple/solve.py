from pwn import *
import random
import subprocess



def convert(array):
	return ''.join([chr(x) for x in array]).encode("hex")


def fromhex(string):
	result = []
	for i in range(0,len(string),2):
		result.append(int(string[i:i+2],16))
	return result

context.log_level = "debug"

#p = remote("challs.xmas.htsp.ro",1005)

p = process("./server")


pts = []
pairs = []

for i in range(16):
		pts.append([random.randint(0,255) for x in range(8)])

for i in range(16):
	p.recvuntil("plaintext: ")
	p.sendline(convert(pts[i]))
	p.recvuntil("ciphertext: ")
	pairs.append([pts[i],fromhex(p.recvline().strip())])

with open("pairs_server.txt","w") as output_file:
	output_file.write(str(pairs))


p.recvuntil("guess: ")


cmd = ["/home/suchro/pypy2.7-v7.3.3-linux64/bin/pypy","/home/suchro/NOPS/CTF/Xmas_2020/crypto/keep_it_simple/writeup/scripts/attack.py"]

output = subprocess.check_output(cmd)

print output

key = output.replace("\n","").replace("key: ","")


p.sendline(key)
print p.recvall()


p.close()