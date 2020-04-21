import random
from math import sqrt
from requests import post


URL = 'https://cryptoqkd.web.ctfcompetition.com/qkd/qubits'


def compare_bases_and_generate_key(tx_bases, rx_bases, measure):
    """Compares TX and RX bases and return the selected bits."""
    if not (len(tx_bases) == len(rx_bases) == len(measure)):
        raise ValueError
    ret = ''
    for bit, tx_base, rx_base in zip(measure, tx_bases, rx_bases):
        if tx_base == rx_base:
            ret += str(bit)
    return ret


random_bits = [random.randint(0, 1) for _ in range(512)]
basis = [random.choice('+x') for _ in range(512)]

qubits = []

for bit, base in zip(random_bits, basis):
    if bit == 0 and base == '+':
        qubits.append({'real': 1, 'imag': 0})
    elif bit == 0 and base == 'x':
        qubits.append({'real': sqrt(0.5), 'imag': sqrt(0.5)})
    elif bit == 1 and base == '+':
        qubits.append({'real': 0, 'imag': 1})
    elif bit == 1 and base == 'x':
        qubits.append({'real': -sqrt(0.5), 'imag': sqrt(0.5)})
    else:
        raise ValueError

data = {'basis': basis, 'qubits': qubits}

res = post(URL, json=data)
res = res.json()
binary_key = compare_bases_and_generate_key(basis, res['basis'], random_bits)

shared_key = '{:032x}'.format(int(binary_key[:128], 2))

enc_key = '{:032x}'.format(int(shared_key, 16) ^ int(res['announcement'], 16))
enc_key = bytes.fromhex(enc_key)

with open('enc.key', 'wb') as f:
    f.write(enc_key)
