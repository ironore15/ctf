#!/usr/bin/python3
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from base64 import b64decode, b64encode
from string import printable
import copy
import json
import pwn


HOST, PORT = 'crypto1.ctf.nullcon.net', 5001


def sign_message(message):
    eccpubkey = ECC.import_key(message['eccpubkey'])
    h = SHA256.new(message['aeskey'] + message['nonce'] + message['message'])
    signer = DSS.new(eccpubkey, 'fips-186-3')

    return signer.sign(h)


printable = printable.strip()

with open('./message.txt', 'r') as f:
    message = f.read()

message = json.loads(message)

message['nonce'] = b64decode(message['nonce'])
message['message'] = b64decode(message['message'])
message['aeskey'] = b64decode(message['aeskey'])
message['signature'] = b64decode(message['signature'])
message['eccpubkey'] = b64decode(message['eccpubkey'])

eccpubkey = ECC.import_key(message['eccpubkey'])
eccprivkey = ECC.generate(curve=eccpubkey.curve)

flag = b''

pwn.context.log_level = 'debug'

for i in range(len(message['message'])):
    query = copy.deepcopy(message)

    query['eccpubkey'] = eccprivkey.export_key(format='PEM').encode()
    query['message'] = message['message'][:i+1]
    query['signature'] = sign_message(query)

    query['nonce'] = b64encode(query['nonce']).decode()
    query['message'] = b64encode(query['message']).decode()
    query['aeskey'] = b64encode(query['aeskey']).decode()
    query['signature'] = b64encode(query['signature']).decode()
    query['eccpubkey'] = b64encode(query['eccpubkey']).decode()

    p = pwn.remote(HOST, PORT)

    p.recvuntil('Enter message in json format: ')
    p.sendline(json.dumps(query))

    p.recvuntil('Here is your read receipt:\n')
    hm = p.recvline(keepends=False).decode()

    p.close()

    for ch in printable:
        ch = ch.encode()
        if hm == SHA256.new(flag + ch).hexdigest():
            flag += ch
            continue

flag = flag.decode()

pwn.log.info(flag)

# hackim20{digital_singatures_does_not_always_imply_authenticitaaayyy}
