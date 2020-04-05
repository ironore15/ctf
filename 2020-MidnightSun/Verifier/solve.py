import hashlib
import pwn
import re


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m


def sign(message):
    p.sendlineafter('\n> ', '1')
    p.sendlineafter('message> ', message)
    p.recvuntil('Signature: ')
    return p.recvline().decode().strip()


def verify(message, sign):
    p.sendlineafter('\n> ', '2')
    p.sendlineafter('message> ', message)
    p.sendlineafter('signature> ', sign)
    result = p.recvline().decode().strip()

    return result == 'Signature valid'


def get_flag(sign):
    p.sendlineafter('\n> ', '3')
    p.sendlineafter('signature> ', sign)
    return p.recvline().decode().strip()


p = pwn.remote('verifier2-01.play.midnightsunctf.se', 31337)

pwn.context.log_level = 'DEBUG'

while True:
    sign1 = sign('ironore15')
    sign2 = sign('ironore16')
    r1, s1 = int(sign1[:48], 16), int(sign1[48:], 16)
    r2, s2 = int(sign2[:48], 16), int(sign2[48:], 16)

    if r1 == r2:
        break

n = 6277101735386680763835789423176059013767194773182842284081
z1 = int(hashlib.sha1(b'ironore15').hexdigest()[:48], 16)
z2 = int(hashlib.sha1(b'ironore16').hexdigest()[:48], 16)
z3 = int(hashlib.sha1(b'please_give_me_the_flag').hexdigest()[:48], 16)

k = (((z1 - z2) % n) * modinv((s1 - s2) % n, n)) % n

s3 = modinv(k, n) * (k * s1 - z1 + z3) % n

sign3 = '{:048x}{:048x}'.format(r1, s3)
assert verify('please_give_me_the_flag', sign3)

flag = get_flag(sign3)
m = re.search('midnight{\w*}', flag)
flag = m.group()

pwn.context.log_level = 'INFO'
p.close()

pwn.log.info(flag)

# midnight{number_used_once_or_twice_or_more_e8595d72819c03bf07e534a9adf71e8a}
