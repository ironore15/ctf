#!/usr/bin/sage
from Crypto.Util.number import long_to_bytes


def solve(a, b, c):
    D = b ** 2 - 4 * a * c
    x1 = (-b + sqrt(D)) / (2 * a)
    x2 = (-b - sqrt(D)) / (2 * a)
    return x1, x2


def merge_message(blocks):
    # Merge blocks
    blocks = [Integer(round(block)).bits()[::-1] for block in blocks]
    blocks = [[0] * (block_size - len(block)) + block for block in blocks]
    bits = flatten(blocks)
    # Remove padding
    bits = bits[:-bits[::-1].index(1)-1]
    # Convert back
    return long_to_bytes(Integer(bits, base=2))


R = RealField(prec=200)
block_size = 192

yA, yB, yC = [None] * 3, [None] * 3, [None] * 3

yA[0] = [R(5.8537179772742871378006829317359804640034149162093776176771e75), R(2.0260990893806965307943860314007373888732002921518840941414e76)]
yB[0] = [R(4.0652782673020986683538918237010543408982543019306057179496e95), R(-5.0285426513783822097670201376390415563936061484095492229894e94)]
yC[0] = [R(4.3083595977562861674637990303350994431503203162436044206961e76), R(-3.1928247205608247346546681530367209122491766171698701927922e76)]
yA[1] = [R(3.9886651421460868244883042163468164077791762065632163641999e76), R(-1.2487387183806776412156661578750877275468860853692530589115e77)]
yB[1] = [R(2.5644531171906756537679808003501733255703504126650573479133e95), R(-1.6570541229598112699074962433815055733294177769576178678896e96)]
yC[1] = [R(4.5893614625576224795913782492661186902913334535507951850089e76), R(6.8611881934867127810471276550294069221078140676008042683634e76)]
yA[2] = [R(-6.5089227887140404010136240391818701730482514213358150433451e75), R(5.5620733870042242270647223203879530885369669489378834804472e76)]
yB[2] = [R(1.0017374772520318947002755790705886607122203555146923369286e95), R(1.2876407911288161811207561236370324382394428286338064237471e96)]
yC[2] = [R(1.1418280384822587553925695577555385627605037374102719431688e77), R(-1.9966984339634055590175475802847306340483261373340080568330e76)]

results = []

for i in range(3):
    A = yA[i][0]^2 + yA[i][1]^2
    B = yB[i][0]^2 + yB[i][1]^2
    r = sqrt(B / A)

    # x == sin(2 * theta)
    c = yA[i][0]^2 - yA[i][1]^2
    k = (yB[i][0]^2 - yB[i][1]^2) / r^2
    s = 2 * yA[i][0] * yA[i][1]

    a = c^2 + s^2
    b = 2 * s * k
    c = k^2 - c^2

    x1, x2 = solve(a, b, c)
    t1, t2 = arcsin(x1) / 2, arcsin(x2) / 2
    assert x1 == sin(2 * t1)

    B1 = matrix(R, [[r * cos(t1), r * sin(t1)], [r * -sin(t1), r * cos(t1)]])
    B2 = matrix(R, [[r * cos(t2), r * sin(t2)], [r * -sin(t2), r * cos(t2)]])

    yB1 = vector(R, yA[i]) * B1
    yB2 = vector(R, yA[i]) * B2

    d1 = yB1[0] - vector(R, yB[i])[0]
    d2 = yB2[0] - vector(R, yB[i])[0]

    if -1e50 < d1 < 1e50:
        Bc = matrix(R, [[cos(-t1) / r, sin(-t1) / r], [-sin(-t1) / r, cos(-t1) / r]])
    elif -1e50 < d2 < 1e50:
        Bc = matrix(R, [[cos(-t2) / r, sin(-t2) / r], [-sin(-t2) / r, cos(-t2) / r]])
    else:
        print('No solution at {}'.format(i))
        continue

    m = vector(R, yC[i]) * Bc
    results.extend(m)

print(merge_message(results))

# hxp{p33r_r3v13w3d_m4y_n0t_b3_1337_r3v13w3d}
