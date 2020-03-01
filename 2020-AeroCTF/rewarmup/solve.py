import pwn


elf = pwn.ELF('./rewarmup')

raw_data = elf.read(0xDCF28, 70 * 4)
data = []

for i in range(70):
    data.append(pwn.u32(raw_data[4 * i:4 * i + 4]))

flag = bytearray(70)

for seed in range(0xFF * 70):
    for i in range(70):
        seed = (0x1282 * seed + 0x1634) & 0xFFFFFFFF
        seed %= 0xFEFEFEFE
        flag[i] = (seed & 0xFF) ^ data[i]

    if flag.startswith(b'Aero'):
        break

pwn.log.info(flag.decode())
