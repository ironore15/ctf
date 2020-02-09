#!/usr/bin/python3
import pwn
import z3


class ROP(object):
    def __init__(self, payload, stack_size=7):
        self.payload = payload
        for i in range(stack_size):
            self.pop()

    def pop(self):
        data = pwn.u64(self.payload[:8])
        self.payload = self.payload[8:]
        return data

    def rop(self):
        while len(self.payload) != 0:
            ret_addr = self.pop()

            if ret_addr == 0x40119A:
                self.rdi = self.pop()
            elif ret_addr == 0x40119C:
                self.rsi = self.pop()
            elif ret_addr == 0x40119E:
                self.rdx = self.pop()
            elif ret_addr == 0x4011A0:
                self.rcx = self.pop()
            elif ret_addr == 0x4011A2:
                self.rax = self.pop()
            elif ret_addr == 0x4011A4:
                self.rax += self.rdi
            elif ret_addr == 0x4011A8:
                self.rax += self.rsi
            elif ret_addr == 0x4011AC:
                self.rax += self.rdx
            elif ret_addr == 0x4011B0:
                self.rax += self.rcx
            elif ret_addr == 0x4011B4:
                self.rax += self.rax
            elif ret_addr == 0x4011B8:
                self.rax += 1
            elif ret_addr == 0x4011BD:
                self.rax ^= self.rax
            elif ret_addr == 0x4011C1:
                self.rax -= self.rdi
            elif ret_addr == 0x4011C5:
                self.rax -= self.rsi
            elif ret_addr == 0x4011C9:
                self.rax -= self.rdx
            elif ret_addr == 0x4011CD:
                self.rax -= self.rcx
            elif ret_addr == 0x4011D1:
                self.rax -= 1
            elif ret_addr == 0x4011D6:
                assert 0x4040A0 <= self.rdi < 0x4040A0 + 0x1F
                self.rdi = flag[self.rdi - 0x4040A0]
            elif ret_addr == 0x4011DB:
                assert 0x4040A0 <= self.rsi < 0x4040A0 + 0x1F
                self.rsi = flag[self.rsi - 0x4040A0]
            elif ret_addr == 0x4011E0:
                assert 0x4040A0 <= self.rdx < 0x4040A0 + 0x1F
                self.rdx = flag[self.rdx - 0x4040A0]
            elif ret_addr == 0x4011E5:
                assert 0x4040A0 <= self.rcx < 0x4040A0 + 0x1F
                self.rcx = flag[self.rcx - 0x4040A0]
            elif ret_addr == 0x4011EA:
                self.rdi = self.rax
            elif ret_addr == 0x4011EE:
                self.rsi = self.rax
            elif ret_addr == 0x4011F2:
                self.rdx = self.rax
            elif ret_addr == 0x4011F6:
                self.rcx = self.rax
            elif ret_addr == 0x4011FF:
                return self.rdi


flag = [z3.Int('flag[{}]'.format(i)) for i in range(0x1F)]


o = [296, 272, 272, 272, 296, 360, 272, 424, 272, 208, 120, 120, 120, 96, 120, 120, 120, 120, 120, 120, 120, 208, 120, 120, 208, 208, 208, 208, 208, 272, 120, 208, 208]
r = [208, 225, 237, 20, 214, 183, 79, 105, 207, 217, 125, 66, 123, 104, 97, 99, 107 , 105, 109, 50, 48, 202, 111, 111, 29, 63, 223, 36, 0, 124, 100, 219, 32]

rets = []

with open('blob', 'rb') as f:
    for offset in o:
        data = f.read(offset)
        rets.append(ROP(data).rop())

s = z3.Solver()

for i in range(len(r)):
    s.add(rets[i] == r[i])

pwn.log.info(s.check())
m = s.model()

flag_str = ''

for ch in flag:
    flag_str += chr(m[ch].as_long())
pwn.log.info(flag_str)
