from ast import literal_eval
from base64 import b64encode
from hashlib import sha1
from itertools import product
from string import printable
import pwn

import schnorr3


printable = printable.strip()

DEBUG = False
if DEBUG:
    p = pwn.remote("localhost", 20014)
else:
    p = pwn.remote("tcp.realworldctf.com", 20014)
pwn.context.log_level = "debug"


def PoW(proof, length):
    assert len(proof) < length
    for work in product(printable, repeat=5):
        work = proof + "".join(work).encode()
        h = sha1(work).hexdigest()
        if h.endswith("0000"):
            break
    return work


def menu(pubkey, choice):
    p.recvuntil("Please tell us your public key:")
    p.sendline(b64encode("{},{}".format(pubkey[0], pubkey[1]).encode()))
    p.recvuntil("our first priority!\n")
    p.sendline(b64encode(str(choice).encode()))


p.recvuntil("starting with ")
proof = p.recvline().strip()
work = PoW(proof, len(proof) + 5)
p.send(work)

privKey, pubKey = schnorr3.generate_keys()

menu(pubKey, 3)
p.recvuntil("himself as one of us: ")
serverPubKey = literal_eval(p.recvline().strip().decode().replace("L", ""))

sign = schnorr3.schnorr_sign(b"DEPOSIT", privKey)

menu(pubKey, 1)
p.recvuntil("Please send us your signature")
p.sendline(b64encode(sign))

fakePubKey = schnorr3.point_mul(serverPubKey, schnorr3.n - 1)
fakePubKey = schnorr3.point_add(pubKey, fakePubKey)
fakeSign = schnorr3.schnorr_sign(b"WITHDRAW", privKey)

menu(fakePubKey, 2)
p.recvuntil("Please send us your signature")
p.sendline(b64encode(fakeSign))

pwn.context.log_level = "info"
p.interactive()
