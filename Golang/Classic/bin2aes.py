import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import hashlib

key = get_random_bytes(16)
iv = 16 * b'\x00'
cipher = AES.new(hashlib.sha256(key).digest(), AES.MODE_CBC, iv)

try:
    plaintext = open(sys.argv[1], "rb").read()
except:
    print("\n[-] Something went wrong!")
    print(f"[?] Example: python3 {sys.argv[0]} <path to raw shellcode>")
    sys.exit()

ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

print('[+] Shellcode: []byte{0x' + ', 0x'.join(hex(x)[2:] for x in ciphertext) + '}')
print('[+] Key: []byte{0x' + ', 0x'.join(hex(x)[2:] for x in key) + '}')