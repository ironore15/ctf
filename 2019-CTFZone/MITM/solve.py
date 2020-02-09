#!/usr/bin/python3
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.number import long_to_bytes
import pwn
import re


HOST = 'crypto-mitm.ctfz.one'

client = pwn.remote(HOST, 3338)
server = pwn.remote(HOST, 3339)

length = pwn.u16(client.recvn(2))
client.recvn(length)

server.send(pwn.p16(37))
server.send('ClientHello:SHA_AES_CTR_RSA_DHE_2048\n')

length = pwn.u16(server.recvn(2))
data = server.recvn(length)

s = pwn.process('./solve')
private_key = int(s.recvline().strip(), 16)

regex = 'ServerHello:'
regex += 'p=(?P<p>[0-9a-f]+)\|'
regex += 'g=(?P<g>[0-9a-f]+)\|'
regex += 'A=(?P<A>[0-9a-f]+)\|'
regex += 's=(?P<s>[0-9a-f]+)\|'

regex = re.compile(regex)
m = regex.match(data.decode())
p = int(m.group('p'), 16)
g = int(m.group('g'), 16)
A = int(m.group('A'), 16)
s = int(m.group('s'), 16)

pwn.log.info('p: {}'.format(p))
pwn.log.info('g: {}'.format(g))
pwn.log.info('A: {}'.format(A))
pwn.log.info('s: {}'.format(s))

assert pow(g, private_key, p) == A

pwn.log.info('a: {}'.format(private_key))

client.send(pwn.p16(length))
client.send(data)

length = pwn.u16(client.recvn(2))
data = client.recvn(length)
client.close()

regex = 'OK:'
regex += 'B=(?P<B>[0-9a-f]+)\|'
regex += 'nonce=(?P<nonce>[0-9a-f]+)\|'

regex = re.compile(regex)
m = regex.match(data.decode())
B = int(m.group('B'), 16)
counter = int(m.group('nonce'), 16)

pwn.log.info('B: {}'.format(B))
pwn.log.info('counter: {}'.format(counter))

server.send(pwn.p16(length))
server.send(data)

key = pow(B, private_key, p)
secret_key = SHA256.new('{:x}'.format(key).encode()).digest()

length = pwn.u16(server.recvn(2))
enc_flag = bytes.fromhex(server.recvn(length).decode())

server.close()


def AES_CTR_decrypt(key, ctr, ciphertext):
    plaintext = b''
    for i in range((len(ciphertext) + 15) // 16):
        nonce = long_to_bytes(ctr + i)
        block = ciphertext[16 * i:16 * i + 16]
        aes = AES.new(secret_key, AES.MODE_ECB)
        block = [b1 ^ b2 for b1, b2 in zip(aes.encrypt(nonce), block)]
        plaintext += bytes(block)
    return plaintext


flag = AES_CTR_decrypt(secret_key, counter, enc_flag).decode()
pwn.log.info(flag)

# ctfzone{Remember_hacking_is_more_than_just_a_crime_It_is_a_survival_trait}
