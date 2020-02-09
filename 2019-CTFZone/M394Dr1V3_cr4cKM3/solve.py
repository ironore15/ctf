#!/usr/bin/python3
import z3


flag = [z3.BitVec('flag[{}]'.format(i), 8) for i in range(16)]

s = z3.Solver()

for i in range(16):
    s.add(flag[i] >= 0x30)
    s.add(flag[i] <= 0x5A)

s.add(0x4F * flag[0] + 0x28 * flag[1] + 0x04 * flag[2] + 0x1C * flag[3] == 0xF7)
s.add(0x25 * flag[0] + 0x3F * flag[1] + 0x05 * flag[2] + 0x3C * flag[3] == 0x2F)
s.add(0x60 * flag[0] + 0x40 * flag[1] + 0x5E * flag[2] + 0x08 * flag[3] == 0x02)
s.add(0x3B * flag[0] + 0x01 * flag[1] + 0x4E * flag[2] + 0x10 * flag[3] == 0xB6)

s.add(0x4F * flag[4] + 0x28 * flag[5] + 0x04 * flag[6] + 0x1C * flag[7] == 0xB8)
s.add(0x25 * flag[4] + 0x3F * flag[5] + 0x05 * flag[6] + 0x3C * flag[7] == 0xFD)
s.add(0x60 * flag[4] + 0x40 * flag[5] + 0x5E * flag[6] + 0x08 * flag[7] == 0x18)
s.add(0x3B * flag[4] + 0x01 * flag[5] + 0x4E * flag[6] + 0x10 * flag[7] == 0x8F)

s.add(0x4F * flag[8] + 0x28 * flag[9] + 0x04 * flag[10] + 0x1C * flag[11] == 0x3E)
s.add(0x25 * flag[8] + 0x3F * flag[9] + 0x05 * flag[10] + 0x3C * flag[11] == 0xB8)
s.add(0x60 * flag[8] + 0x40 * flag[9] + 0x5E * flag[10] + 0x08 * flag[11] == 0x90)
s.add(0x3B * flag[8] + 0x01 * flag[9] + 0x4E * flag[10] + 0x10 * flag[11] == 0xE0)

s.add(0x4F * flag[12] + 0x28 * flag[13] + 0x04 * flag[14] + 0x1C * flag[15] == 0xCF)
s.add(0x25 * flag[12] + 0x3F * flag[13] + 0x05 * flag[14] + 0x3C * flag[15] == 0x85)
s.add(0x60 * flag[12] + 0x40 * flag[13] + 0x5E * flag[14] + 0x08 * flag[15] == 0xCC)
s.add(0x3B * flag[12] + 0x01 * flag[13] + 0x4E * flag[14] + 0x10 * flag[15] == 0x41)

s.check()
m = s.model()

key = ''
for i in range(16):
    key += chr(m[flag[i]].as_long())

print(key)

# ctfzone{0mg_it$fu11_0f_f1ags_lo1!}
