#!/usr/bin/python3
import pwn


p = pwn.remote('stegasaurus.pwni.ng', 1337)
pwn.context.log_level = 'DEBUG'

with open('solve.lua', 'r') as f:
    lua = f.read()

hashcash = pwn.process(['hashcash', '-b', '25', '-m', '-r', 'stegasaurus'])
hashcash.recvuntil('hashcash token: ')
token = hashcash.recvline(keepends=False)
hashcash.close()

p.recvuntil('> ')
p.sendline(token)

p.recvuntil('send your file\n')
p.send(lua)

p.shutdown('send')

p.recvline()
p.recvline()
flag = p.recvline(keepends=False).decode()

pwn.context.log_level = 'INFO'
p.close()

pwn.log.info(flag)

# PCTF{c4rd_b4s3d_crypt0_1s_4_r33l_fi31d}
