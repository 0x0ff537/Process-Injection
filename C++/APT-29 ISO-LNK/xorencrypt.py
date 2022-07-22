import sys

KEY = "jikoewarfkmzsdlhfnuiwaejrpaw"

def xor(data, key):
	
	key = str(key)
	l = len(key)
	output_str = ""

	for i in range(len(data)):
		current = data[i]
		current_key = key[i % len(key)]
		output_str += chr(current ^ ord(current_key))
	
	return output_str

def printCiphertext(ciphertext):
	print('{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' };')



try:
    plaintext = open(sys.argv[1], "rb").read()
except:
    print("\n[-] Usage: %s <raw payload file>" % sys.argv[0])
    sys.exit()


ciphertext = xor(plaintext, KEY)

with open('out.h', 'w') as f:
    f.write(f'CHAR key[] = {{\"{KEY}\"}};\n')
    f.write('unsigned char payload[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' };\n')
    f.close()
    print("[+] File written to out.h\n")

#print('{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' };')

""" chunk = 120
split_file = [ciphertext[i:i+chunk] for i in range(0, len(ciphertext), chunk)]
i = 0
while i < len(split_file):
	print('CHAR payload' + str(i) + '[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in split_file[i]) + ' };')
	i += 1 """

