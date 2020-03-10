import pwn


elf = pwn.ELF('./chall')

fake = b'zer0pts{********CENSORED********}'
fake += b'\x00' * (8 - len(fake) % 8)

data = elf.read(0x201060, len(fake))

flag = b''

for i in range(0, len(fake), 8):
    flag += pwn.p64(pwn.u64(fake[i:i+8]) + pwn.u64(data[i:i+8]))

flag = flag.strip(b'\x00').decode()

pwn.log.info(flag)
