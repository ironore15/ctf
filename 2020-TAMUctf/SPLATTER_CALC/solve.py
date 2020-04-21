import pwn


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


def ModInv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m


def Step(s1, s2):
    if s2 & 7 == 0:
        ret = s1
    elif s2 & 7 == 1:
        ret = s1 + s2
    elif s2 & 7 == 2:
        ret = s1 - s2
    elif s2 & 7 == 3:
        ret = s1 * s2
    elif s2 & 7 == 4:
        ret = s1 * s1
    elif s2 & 7 == 5:
        ret = s1 << (s2 & 0xFF)
    elif s2 & 7 == 6:
        ret = s1 >> (s2 & 0xFF)
    elif s2 & 7 == 7:
        ret = s1 ^ s2
    return ret & ((1 << 64) - 1)


def StepInv(ret, s2):
    if s2 & 7 == 0:
        s1 = ret
    elif s2 & 7 == 1:
        s1 = ret - s2
    elif s2 & 7 == 2:
        s1 = ret + s2
    elif s2 & 7 == 3:
        pwn.log.error('Inverse Multiplication')
        exit(1)
    elif s2 & 7 == 4:
        pwn.log.error('Inverse Square')
        exit(1)
    elif s2 & 7 == 5:
        s1 = ret >> (s2 & 0xFF)
    elif s2 & 7 == 6:
        s1 = ret << (s2 & 0xFF)
    elif s2 & 7 == 7:
        s1 = ret ^ s2
    return s1 & ((1 << 64) - 1)


value = 0xACDEE2ED87A5D886
seed = 0x471DE8678AE30BA1

for i in range(8):
    seed -= 0x24A452F8E
    seed *= ModInv(0x83F66D0E3, 1 << 64)
    seed &= (1 << 64) - 1
    value = StepInv(value, seed)

p = pwn.remote('challenges.tamuctf.com', 60032)
pwn.context.log_level = 'DEBUG'

p.sendlineafter('Please enter an initial rng: ', str(seed))
flag = p.recvline().decode().strip()

pwn.context.log_level = 'INFO'
p.close()

pwn.log.info(flag)

# gigem{00ps_ch3ck_y0ur_7upl35}
