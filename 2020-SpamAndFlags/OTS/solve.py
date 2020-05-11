#!/usr/bin/env python3
import hashlib
import hmac
import pwn
import re
import secrets


class OTS:
    def __init__(self):
        self.key_len = 128
        self.priv_key = secrets.token_bytes(16*self.key_len)
        self.pub_key = b''.join([self.hash_iter(self.priv_key[16*i:16*(i+1)], 255) for i in range(self.key_len)]).hex()

    def hash_iter(self, msg, n):
        assert len(msg) == 16
        for i in range(n):
            msg = hashlib.md5(msg).digest()
        return msg

    def wrap(self, msg):
        raw = msg.encode('utf-8')
        assert len(raw) <= self.key_len - 16
        raw = raw + b'\x00'*(self.key_len - 16 - len(raw))
        raw = raw + hashlib.md5(raw).digest()
        return raw

    def sign(self, msg):
        raw = self.wrap(msg)
        signature = b''.join([self.hash_iter(self.priv_key[16*i:16*(i+1)], 255-raw[i]) for i in range(len(raw))]).hex()
        self.verify(msg, signature)
        return signature

    def verify(self, msg, signature):
        raw = self.wrap(msg)
        signature = bytes.fromhex(signature)
        assert len(signature) == self.key_len * 16
        calc_pub_key = b''.join([self.hash_iter(signature[16*i:16*(i+1)], raw[i]) for i in range(len(raw))]).hex()
        assert hmac.compare_digest(self.pub_key, calc_pub_key)


while True:
    p = pwn.remote('34.89.64.81', 1337)

    p.recvuntil('\npub_key = ')
    pub_key = p.recvline(keepends=False)

    sign = p.recvline(keepends=False)
    m = re.match(b'sign\(\"(?P<msg>.+)\"\) = (?P<sign>\w+)', sign)
    msg, sign = m.group('msg'), m.group('sign')
    wrapped_msg = msg.ljust(128 - 16, b'\x00')
    msg_hash = hashlib.md5(wrapped_msg).digest()
    wrapped_msg += msg_hash

    for i in range(len(msg) - 3):
        if all(a >= b for a, b in zip(msg[i:i+4], b'flag')):
            forged_msg = msg[:i] + b'flag' + msg[i+4:]
            forged_msg = forged_msg.ljust(112, b'\x00')
            forged_hash = hashlib.md5(forged_msg).digest()
            if all(a >= b for a, b in zip(msg_hash, forged_hash)):
                forged_msg += forged_hash
                forged_sign = ''

                for j, (a, b) in enumerate(zip(wrapped_msg, forged_msg)):
                    hash_sign = bytes.fromhex(sign[32*j:32*(j+1)].decode())
                    for k in range(a - b):
                        hash_sign = hashlib.md5(hash_sign).digest()
                    forged_sign += hash_sign.hex()

                pwn.log.info(forged_sign)
                break
    else:
        p.close()
        continue

    p.recvline()
    p.recvline()
    p.sendline(forged_msg[:-16].strip(b'\x00'))
    p.recvline()
    p.sendline(forged_sign)

    pwn.context.log_level = 'INFO'
    p.interactive()
    break

# SaF{better_stick_with_WOTS+}
