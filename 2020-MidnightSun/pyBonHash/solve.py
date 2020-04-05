from Crypto.Cipher import AES
from itertools import product


hexdigest = b'0123456789abcedf'
FIBOFFSET = 4919


def fibseq(n):
    out = [0, 1]
    for i in range(2, n):
        out += [out[(i - 1)] + out[(i - 2)]]

    return out


with open('hash.txt', 'r') as f:
    hashdata = f.read().strip()

len_key = 42
key = bytearray(42)

FIB = fibseq(FIBOFFSET + len_key + len(hashdata) // 32)

for i in range(0, len(hashdata) // 32, 2):
    enc = bytes.fromhex(hashdata[32*i:32*i+64])

    for key1, key2 in product(range(256), repeat=2):
        thiskey = bytes([key1, key2]) * 16
        cipher = AES.new(thiskey, AES.MODE_ECB)
        dec = cipher.decrypt(enc)
        if all(b in hexdigest for b in dec):
            break
    else:
        raise Exception

    key[(FIB[FIBOFFSET + i] + i) % len_key] = key1
    key[(FIB[FIBOFFSET + i + 1] + i + 1) % len_key] = key2

key = bytes(key).decode()
print(key)
