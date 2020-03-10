import pwn


def prime_factorization(n):
    '''returns the prime factorization of a number; author: Wazim Karim'''
    factors = []
    i = 2
    while n >= i:
        if n % i == 0:
            factors.append(i)
            n = n // i
            i = 2
        else:
            i = i + 1
    return factors


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


elf = pwn.ELF('./wysinwyg')

data = elf.read(0x202020, 0x130)

enc_flag = []
for i in range(0, 0x130, 8):
    enc_flag.append(pwn.u64(data[i:i + 8]))

e, n = 23531, 2343464867
factors = prime_factorization(n)

phi_n = 1
for p in factors:
    phi_n *= p - 1

d = modinv(e, phi_n)

flag = bytes(map(lambda x: pow(x, d, n), enc_flag)).decode().strip()
pwn.log.info(flag)
