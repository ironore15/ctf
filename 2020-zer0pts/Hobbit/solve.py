import pwn


def crypt(data, key):
    """RC4 algorithm"""
    x = 0
    box = list(range(256))
    for i in range(256):
        x = (x + int(box[i]) + int(key[i % len(key)])) % 256
        box[i], box[x] = box[x], box[i]
    x = y = 0
    out = []
    for char in data:
        x = (x + 1) % 256
        y = (y + box[x]) % 256
        box[x], box[y] = box[y], box[x]
        out.append(char ^ box[(box[x] + box[y]) % 256])

    return bytes(out)


with open('./chall.hbt', 'rb') as f:
    hbt = f.read()

key1 = hbt[0x8:0x18]
key2 = hbt[0x18:0x28]

data = crypt(hbt[0x40:0x80], key1)

code = pwn.disasm(crypt(hbt[0x80:], key2))
pwn.log.info(code)

flag = bytearray(data[0x19:0x19 + 0x27])

for i in range(len(flag)):
    flag[i] ^= (0x27 - i)

flag = bytes(flag).decode()
pwn.log.info(flag)
