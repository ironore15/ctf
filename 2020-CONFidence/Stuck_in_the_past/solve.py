import pwn
import re
import sys


with open('./stuck_in_the_past.exe', 'rb') as f:
    binary = f.read()

code = binary[0x7DE:0x3EC8]
code = pwn.disasm(code, byte=False, offset=False)

instr_dict = {
    'nop': '',
    'xchg   ax, ax': '',
    'push   0x1\npush   0x0\nmov    eax, 0x4010f6\njmp    eax': '>',
    'push   0x1\npush   0x21\nmov    eax, 0x4010f6\njmp    eax': '<',
    'push   0x1\npush   0x42\nmov    eax, 0x4010f6\njmp    eax': 'v',
    'push   0x1\npush   0x63\nmov    eax, 0x4010f6\njmp    eax': '^',
    'push   0x1\npush   0x70\nmov    eax, 0x4010f6\njmp    eax': '#',
    'push   0x2\npush   0x70\nmov    eax, 0x4010f6\njmp    eax': '#',
    'push   0x0\nmov    eax, 0x401124\njmp    eax': '+',
    'push   0x4\nmov    eax, 0x401124\njmp    eax': '-',
    'push   0x8\nmov    eax, 0x401124\njmp    eax': '*',
    'push   0xc\nmov    eax, 0x401124\njmp    eax': '/',
    'push   0x15\nmov    eax, 0x401124\njmp    eax': '%',
    'mov    eax, 0x4010fe\njmp    eax': '_',
    'mov    eax, 0x401111\njmp    eax': '|',
    'mov    eax, 0x401153\njmp    eax': '!',
    'mov    eax, 0x40115f\njmp    eax': ':',
    'mov    eax, 0x401167\njmp    eax': '\\',
    'mov    eax, 0x401170\njmp    eax': '$',
    'mov    eax, 0x401176\njmp    eax': '?',
    'mov    eax, 0x40119d\njmp    eax': '@',
    'mov    eax, 0x4011a4\njmp    eax': '~',
    'mov    eax, 0x4011cd\njmp    eax': '.',
    'mov    eax, 0x401218\njmp    eax': ',',
    'mov    eax, 0x40123c\njmp    eax': 'p',
    'mov    eax, 0x4013a6\njmp    eax': 'g',
    'mov    eax, 0x4013b0\njmp    eax': '"',
}

s = r'\b(' + '|'.join(instr_dict.keys()) + r')\b'
pattern = re.compile(s)
code = pattern.sub(lambda x: instr_dict[x.group()], code)

s = r'\b(push   0x(?P<int>[0-9]{1})\nmov    eax, 0x401027\njmp    eax)\b'
pattern = re.compile(s)
code = pattern.sub(lambda x: x.group('int'), code)

s = r'\b(push   0x(?P<char>[0-9a-f]{1,8})\nmov    eax, 0x401027\njmp    eax)\b'
pattern = re.compile(s)
code = pattern.sub(lambda x: chr(int(x.group('char'), 16) & 0xFF), code)

s = r'\b(mov    eax, 0x401027\njmp    eax)\b'
pattern = re.compile(s)
code = pattern.sub(lambda x: ' ', code)

code = code.replace('\n', '').encode()
befunge = []

for i in range(1, len(code), 0x47):
    befunge.append(code[i:i + 0x47])
    sys.stdout.buffer.write(befunge[-1] + b'\n')
print()

enc_flag = befunge[5][2:30]
flag = b''

for ch in enc_flag:
    if ch == 0x5F or ch == 0x61:
        flag += bytes([ch])
        continue
    a = (ch + 1) % 2
    b = (ch // 2 // 0x20 + 1) % 2 * 2 * 0x20
    c = ch // 2 % 0x20 * 2
    flag += bytes([a + b + c])

flag = flag[::-1].decode()

print(flag)
