#!/usr/bin/python3
from Crypto.Util.number import long_to_bytes
import pwn


def menu(i):
    p.recvuntil('3) Exit\n')
    p.sendline(str(i))


def oracle(c):
    menu(2)
    p.recvuntil('c = ')
    p.sendline(str(c))
    p.recvuntil('m = ')
    return int(p.recvline().strip())


# pwn.context.log_level = 'debug'
p = pwn.remote('34.82.101.212', 20001)

menu(1)
p.recvuntil('c = ')
c = int(p.recvline().strip())
p.recvuntil('n = ')
n = int(p.recvline().strip())

low = 0
high = n - 1
count = 1

# To optimize server query
# Estimated flag length == 23
# log(2 ** (1024 - 8 * 23), 3) == 530
for i in range(530):
    high = high // 3
    count += 1

while low < high:
    if low != 0:
        pwn.log.info(long_to_bytes(low))
    mid1, mid2 = (2 * low + high) // 3, (low + 2 * high) // 3

    r = oracle((c * pow(3, 65537 * count, n)) % n)
    count += 1

    if r == 0:
        low, high = low, mid1
    elif r == 3 - n % 3:
        low, high = mid1, mid2
    elif r == n % 3:
        low, high = mid2, high

p.close()

flag = long_to_bytes(low).decode()
flag = flag[:-1] + '}'  # To match flag format
pwn.log.info(flag)

# BAMBOOFOX{SimPlE0RACl3}
