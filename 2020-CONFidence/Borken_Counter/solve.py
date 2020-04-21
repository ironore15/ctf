with open('out.txt', 'r') as f:
    data = list(map(lambda x: int(x), f.read().split()))

idx = 0
flag = ''

while data[idx] != 217:
    char = 0
    for j in range(7):
        idx = data.index(143, idx) + 1
        char |= (data[idx] == 142) << j
    flag += chr(char)

    idx = data.index(207, idx) + 1

print(flag)
