import sys

KEY = "jikoewarfkmzsdlhfnuiwaejrpaw"

def xor(data, key):
	
	key = str(key)
	output = bytearray(len(data))

	for i in range(len(data)):
		current = data[i]
		current_key = key[i % len(key)]
		output[i] = current ^ ord(current_key)
	
	return output

try:
    plaintext = open(sys.argv[1], "rb").read()
except:
    print("\n[-] Usage: %s <raw payload file>" % sys.argv[0])
    sys.exit()


ciphertext = xor(plaintext, KEY)

with open('OneDrive.Update', 'wb') as f:
    f.write(ciphertext)
    f.close()
    print("\n[+] File written to OneDrive.Update\n")