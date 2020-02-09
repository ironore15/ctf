from ocb import Block, BLOCKSIZE
from string import hexdigits
import pwn


def getData(text):
    p.recvuntil('{:s} = '.format(text))
    data = p.recvline().strip().decode()
    if all(c in hexdigits for c in data):
        return Block(bytes.fromhex(data))
    return data


def sendData(text, data):
    p.recvuntil('{:s} = '.format(text))
    if isinstance(data, Block):
        p.sendline(data.hex())
    else:
        p.sendline(data)


def menu(i):
    p.recvuntil('4) Exit\n')
    p.sendline(str(i))


def encrypt(nonce, plain):
    menu(1)
    sendData('nonce', nonce)
    sendData('plain', plain)

    cipher = getData('cipher')
    tag = getData('tag')
    return cipher, tag


def decrypt(nonce, cipher, tag, exploit=False):
    menu(3 if exploit else 2)
    sendData('nonce', nonce)
    sendData('cipher', cipher)
    sendData('tag', tag)

    auth = getData('auth') == "True"
    plain = getData('plain') if auth and not exploit else None
    return auth, plain


pwn.context.log_level = 'debug'
p = pwn.remote('34.82.101.212', 20000)

target = b'giveme flag.txt'

N1 = Block.random(BLOCKSIZE)
M1 = Block.len(len(target))
M1 |= Block.len(BLOCKSIZE)
M1 |= Block.random(BLOCKSIZE)

C1, T1 = encrypt(N1, M1)

C2 = C1[0]
C2 |= M1[0] ^ C1[1] ^ Block.len(BLOCKSIZE)
T2 = M1[2] ^ C1[2]

auth, M2 = decrypt(N1, C2, T2)

L = M1[0] ^ M2[1] ^ Block.len(BLOCKSIZE)
L = L.half().half()

X = M1[1] ^ L.double().double()
Y = C1[1] ^ L.double().double()

N3 = X

M3 = Block(target) | (C1[0] ^ L.double()).lsb(1)
M3 ^= Y.double()
M3 ^= L.double().double() ^ L.double()

M3 |= Block.random(BLOCKSIZE)

C3, T3 = encrypt(N3, M3)

C = C1[0] ^ L.double() ^ Block(target.ljust(16, b'\x00'))
C = C.msb(len(target))
T = C3[0] ^ Y.double()

decrypt(N1, C, T, exploit=True)

flag = p.recvline().strip().decode()
p.close()

pwn.log.info(flag)

# BAMBOOFOX{IThOUgHtitWAspRoVaBles3cuRE}
