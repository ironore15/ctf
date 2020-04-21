from Crypto.Cipher import AES
from itertools import product
import ast
import hashlib
import pwn
import string


e2 = 0xD8
e3 = 0x89
p = (2^e2)*(3^e3)-1
K.<ii> = GF(p^2, modulus=x^2+1)
E = EllipticCurve(K, [0,6,0,1,0])
xP20 = 0x00003CCFC5E1F050030363E6920A0F7A4C6C71E63DE63A0E6475AF621995705F7C84500CB2BB61E950E19EAB8661D25C4A50ED279646CB48
xP21 = 0x0001AD1C1CAE7840EDDA6D8A924520F60E573D3B9DFAC6D189941CB22326D284A8816CC4249410FE80D68047D823C97D705246F869E3EA50
yP20 = 0x0001AB066B84949582E3F66688452B9255E72A017C45B148D719D9A63CDB7BE6F48C812E33B68161D5AB3A0A36906F04A6A6957E6F4FB2E0
yP21 = 0x0000FD87F67EA576CE97FF65BF9F4F7688C4C752DCE9F8BD2B36AD66E04249AAF8337C01E6E4E1A844267BA1A1887B433729E1DD90C7DD2F
xQ20 = 0x0000C7461738340EFCF09CE388F666EB38F7F3AFD42DC0B664D9F461F31AA2EDC6B4AB71BD42F4D7C058E13F64B237EF7DDD2ABC0DEB0C6C
xQ21 = 0x000025DE37157F50D75D320DD0682AB4A67E471586FBC2D31AA32E6957FA2B2614C4CD40A1E27283EAAF4272AE517847197432E2D61C85F5
yQ20 = 0x0001D407B70B01E4AEE172EDF491F4EF32144F03F5E054CEF9FDE5A35EFA3642A11817905ED0D4F193F31124264924A5F64EFE14B6EC97E5
yQ21 = 0x0000E7DEC8C32F50A4E735A839DCDB89FE0763A184C525F7B7D0EBC0E84E9D83E9AC53A572A25D19E1464B509D97272AE761657B4765B3D6
xP30 = 0x00008664865EA7D816F03B31E223C26D406A2C6CD0C3D667466056AAE85895EC37368BFC009DFAFCB3D97E639F65E9E45F46573B0637B7A9
xP31 = 0x00000000
yP30 = 0x00006AE515593E73976091978DFBD70BDA0DD6BCAEEBFDD4FB1E748DDD9ED3FDCF679726C67A3B2CC12B39805B32B612E058A4280764443B
yP31 = 0x00000000
xQ30 = 0x00012E84D7652558E694BF84C1FBDAAF99B83B4266C32EC65B10457BCAF94C63EB063681E8B1E7398C0B241C19B9665FDB9E1406DA3D3846
xQ31 = 0x00000000
yQ30 = 0x00000000
yQ31 = 0x0000EBAAA6C731271673BEECE467FD5ED9CC29AB564BDED7BDEAA86DD1E0FDDF399EDCC9B49C829EF53C7D7A35C3A0745D73C424FB4A5FD2
P2 = E(xP20+ii*xP21, yP20+ii*yP21)
Q2 = E(xQ20+ii*xQ21, yQ20+ii*yQ21)
P3 = E(xP30+ii*xP31, yP30+ii*yP31)
Q3 = E(xQ30+ii*xQ31, yQ30+ii*yQ31)


def elem_to_coefficients(x):
    l = x.polynomial().list()
    l += [0] * (2 - len(l))
    return l


def elem_to_bytes(x):
    n = ceil(log(p, 2) / 8)
    x0, x1 = elem_to_coefficients(x)  # x == x0 + ii * x1
    x0 = ZZ(x0).digits(256, padto=n)
    x1 = ZZ(x1).digits(256, padto=n)
    return bytes(x0 + x1)


def isogen2(sk2):
    Ei = E
    P = P3
    Q = Q3
    S = P2 + sk2 * Q2
    for i in range(e2):
        phi = Ei.isogeny((2^(e2 - i - 1)) * S)
        Ei = phi.codomain()
        S = phi(S)
        P = phi(P)
        Q = phi(Q)
    return (Ei, P, Q)


def isogen3(sk3):
    Ei = E
    P = P2
    Q = Q2
    S = P3 + sk3 * Q3
    for i in range(e3):
        phi = Ei.isogeny((3^(e3 - i - 1)) * S)
        Ei = phi.codomain()
        S = phi(S)
        P = phi(P)
        Q = phi(Q)
    return (Ei, P, Q)


def isoex2(sk2, pk3):
    Ei, P, Q = pk3
    S = P + sk2 * Q
    for i in range(e2):
        R = (2^(e2 - i - 1)) * S
        phi = Ei.isogeny(R)
        Ei = phi.codomain()
        S = phi(S)
    return Ei.j_invariant()


def recv_K_elem(prompt):
    t.recvuntil(prompt)

    a = t.recvline(keepends=False).decode()
    k = ast.literal_eval(a)
    return K(k[0] + ii*k[1])


def send_K_elem(k, prompt=None):
    if prompt:
        t.recvuntil(prompt)
    t.recvline()

    k = vector(k)
    t.recvuntil('  re: ')
    t.sendline(str(k[0]))
    t.recvuntil('  im: ')
    t.sendline(str(k[1]))


supersingular_cache = set()
def is_supersingular(Ei):
    a = Ei.a_invariants()
    if a in supersingular_cache:
        return True
    result = Ei.is_supersingular(proof=False)
    if result:
        supersingular_cache.add(a)
    return result


def recv_pk3():
    t.recvuntil('public key:\n')
    a1 = recv_K_elem('a1: ')
    a2 = recv_K_elem('a2: ')
    a3 = recv_K_elem('a3: ')
    a4 = recv_K_elem('a4: ')
    a6 = recv_K_elem('a6: ')
    Ei = EllipticCurve(K, [a1, a2, a3, a4, a6])
    assert is_supersingular(Ei)

    Px = recv_K_elem('Px: ')
    Py = recv_K_elem('Py: ')
    P = Ei(Px, Py)

    Qx = recv_K_elem('Qx: ')
    Qy = recv_K_elem('Qy: ')
    Q = Ei(Qx, Qy)

    assert P * (2^e2) == Ei(0) and P * (2^(e2 - 1)) != Ei(0)
    assert Q * (2^e2) == Ei(0) and Q * (2^(e2 - 1)) != Ei(0)
    assert P.weil_pairing(Q, 2^e2) == (P2.weil_pairing(Q2, 2^e2))^(3^e3)

    return (Ei, P, Q)


def send_pk2(pk2):
    Ei, P, Q = pk2
    t.recvuntil('input your public key:\n')

    send_K_elem(Ei.a1(), prompt='a1: ')
    send_K_elem(Ei.a2(), prompt='a2: ')
    send_K_elem(Ei.a3(), prompt='a3: ')
    send_K_elem(Ei.a4(), prompt='a4: ')
    send_K_elem(Ei.a6(), prompt='a6: ')

    send_K_elem(P[0], prompt='Px: ')
    send_K_elem(P[1], prompt='Py: ')
    send_K_elem(Q[0], prompt='Qx: ')
    send_K_elem(Q[1], prompt='Qy: ')
    return


def proof_of_work():
    t.recvuntil('Give me a string starting with ')
    prefix = t.recvn(10)
    t.recvuntil('fffffff.\n')

    for postfix in product(string.ascii_letters + string.digits, repeat=8):
        target = prefix + ''.join(postfix).encode()
        if hashlib.sha256(target).hexdigest().endswith('fffffff'):
            break

    t.sendline(target)
    return


DEBUG = False

if DEBUG:
    t = pwn.process(['sage', 'server.sage'])
else:
    t = pwn.remote('149.28.9.162', 31337)

if not DEBUG:
    proof_of_work()

pk3 = recv_pk3()

secretkey = 2
sk2 = randint(1, 2^e2 - 1)
pk2 = isogen2(sk2)

shared = isoex2(sk2, pk3)
key = hashlib.sha256(elem_to_bytes(shared)).digest()
cipher = AES.new(key, AES.MODE_ECB)
ciphertext = cipher.encrypt(b'Hello world.'.ljust(16, b'\x00'))

Ei, P, Q = pk2

FF = IntegerModRing(3^e3)

for i in range(e3 - 1):
    theta = Integer(FF((1 + 3^(e3 - i - 1))^-1).sqrt())

    for j in range(2):
        Pprime = theta * (P - (3^(e3 - i - 1) * secretkey) * Q)
        Qprime = theta * (1 + 3^(e3 - i - 1)) * Q

        pk2prime = Ei, Pprime, Qprime

        send_pk2(pk2prime)

        t.recvuntil('ciphertext: ')
        t.sendline(ciphertext.hex())

        response = t.recvline(keepends=False).decode()
        pwn.log.info(response)

        if response == 'Good ciphertext.':
            break
        if response == 'Bad ciphertext!':
            secretkey += 3^i

for i in range(3):
    trialkey = secretkey + i * 3^(e3 - 1)
    if isogen3(trialkey) == pk3:
        break
else:
    raise ValueError

secretkey = trialkey
super_secret_hash = hashlib.sha256(str(secretkey).encode()).digest()[:16]

pwn.info('sk3: {}'.format(secretkey))
pwn.info('super_secret_hash: {}'.format(super_secret_hash.hex()))

send_pk2(pk2)

pwn.context.log_level = 'DEBUG'
t.recvuntil('ciphertext: ')
t.sendline(cipher.encrypt(super_secret_hash).hex())

t.recvline()
flag = t.recvline(keepends=False).decode()

pwn.context.log_level = 'INFO'
t.close()

pwn.log.info(flag)

# PCTF{if_you_wish_for_postquantum_crypto_ask_a_supersingular_isogenie}
