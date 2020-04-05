from itertools import product
import re


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m


n = int('7ef80c5df74e6fecf7031e1f00fbbb74c16dfebe9f6ecd29091d51cac41e30465777f5e3f1f291ea82256a72276db682b539e463a6d9111cf6e2f61e50a9280ca506a0803d2a911914a385ac6079b7c6ec58d6c19248c894e67faddf96a8b88b365f16e7cc4bc6e2b4389fa7555706ab4119199ec20e9928f75393c5dc386c65', 16)
ct = int('3ea5b2827eaabaec8e6e1d62c6bb3338f537e36d5fd94e5258577e3a729e071aa745195c9c3e88cb8b46d29614cb83414ac7bf59574e55c280276ba1645fdcabb7839cdac4d352c5d2637d3a46b5ee3c0dec7d0402404aa13525719292f65a451452328ccbd8a0b3412ab738191c1f3118206b36692b980abe092486edc38488', 16)

max_idx = 1

pq_list = [(1, 5), (3, 7), (9, 13), (11, 15)]

for idx in range(1, 256):
    mod = 16 ** (idx + 1)
    new_pq_list = []

    for p, q in pq_list:
        for i, j in product(range(16), repeat=2):
            np = i * 16 ** idx + p
            nq = j * 16 ** idx + q

            if (np * nq) % mod != n % mod:
                continue

            rp_min = int('{:x}'.format(np)[::-1].ljust(128, '0'), 16)
            rq_min = int('{:x}'.format(nq)[::-1].ljust(128, '0'), 16)
            rp_max = int('{:x}'.format(np)[::-1].ljust(128, 'f'), 16)
            rq_max = int('{:x}'.format(nq)[::-1].ljust(128, 'f'), 16)

            if n < rp_min * rq_min or rp_max * rq_max < n:
                continue

            new_pq_list.append((np, nq))

    pq_list = new_pq_list

assert len(pq_list) == 1

p, q = pq_list[0]

# p = 10940426841622676366921134263606230797852377049845508023073731851498778062165943872403574214831422325352658084111135335937429027508321743816310547640134073
# q = 8149647373983803351750886568540598477647671089400013740300059155182763355863916783703939054112148224308893530604866892896459967322672335047042674959531533

d = modinv(0x10001, (p - 1) * (q - 1))
pt = pow(ct, d, n)
pt = bytes.fromhex('{:X}'.format(pt))

m = re.search(b'midnight{\w*}', pt)
flag = m.group().decode()

print(flag)

# midnight{d1vid3_and_c0nqu3r}
