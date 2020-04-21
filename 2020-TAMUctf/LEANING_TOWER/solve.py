#!/usr/bin/python3
from hashlib import sha1


data = [
    'da39a3ee5e6b4b0d3255bfef95601890afd80709',
    '9033bacfd0636139084ea80aa654113f3240f7fc',
    '97f0f871be356f464bca862487e365d92fc507bb',
    '11071c464490c8baaa979bf83e098f3318b36003',
    '45fa0b57640f797ad28709cf7f3b495d61514418',
    '2540407ace41adaaa279c9a9f8d900bd87a8aa5d',
    'f4c50cd4475f6a1833180506817b4bbd45dc17f7',
    'f0e8c88568fcb989f60f09f52b1aad1b7d2454b5',
    '744dde01735bc3d2b047d7d9fbc5662b97628f01',
    '2cab6da567fa23426f81d54326ca537e5bd89d7e',
    '7f0bc15fb2695af18fd1e6c8df386f824cf67af9',
    '2326181b6f80ba790e6f164190dfdda8106a31ff',
    '59a7b725369a7d6af671b7ae79e2129e0517b289',
    'b070a87bd15350073f989853d4f5aa234c563d11',
    '72c77719d0ae83311c01914cdedcff2ebf06667b',
    '5b8e4855bdc9d3bea82500fea95d4306d304dccb'
]

data = list(map(lambda x: bytes.fromhex(x), data))
flag = ''

for i in range(15):
    target = bytes(a ^ b for a, b in zip(data[i], data[i+1]))

    for ch in range(0x100):
        if sha1(bytes([ch])).digest() == target:
            flag += chr(ch)
            break

print(flag)
