import subprocess


def rule126(state):
    state = '{:064b}'.format(int(state, 16))
    state = [int(i) for i in state]
    new = [None] * 64
    for i in range(64):
        if state[(i - 1) % 64] == state[i] == state[(i + 1) % 64]:
            new[i] = 0
        else:
            new[i] = 1
    return new


def check(prev, state, i):
    if prev[(i - 1) % 64] == prev[i % 64] == prev[(i + 1) % 64]:
        return state[i] == 0
    else:
        return state[i] == 1


def DFS(state, stack):
    prev, i = stack.pop()
    if None not in prev:
        if check(prev, state, i) and check(prev, state, (i + 1) % 64):
            prev = ''.join(list(map(str, prev)))
            prev = '{:016x}'.format(int(prev, 2))
            assert rule126(prev) == state
            return prev
    if state[i % 64] == 0 and prev[(i - 1) % 64] != prev[i % 64]:
        return None
    elif state[i % 64] == 0 and prev[(i - 1) % 64] == prev[i % 64]:
        prev[(i + 1) % 64] = prev[i % 64]
        stack.append((prev, (i + 1) % 64))
        return None
    elif state[i % 64] == 1 and prev[(i - 1) % 64] != prev[i % 64]:
        prev0 = prev.copy()
        prev0[(i + 1) % 64] = 0
        prev1 = prev.copy()
        prev1[(i + 1) % 64] = 1
        stack.append((prev0, (i + 1) % 64))
        stack.append((prev1, (i + 1) % 64))
        return None
    elif state[i % 64] == 1 and prev[(i - 1) % 64] == prev[i % 64]:
        prev[(i + 1) % 64] = 1 - prev[i % 64]
        stack.append((prev, (i + 1) % 64))
        return None


def reverse_rule126(state):
    state = '{:064b}'.format(int(state, 16))
    state = [int(i) for i in state]
    stack = []
    for i, v in enumerate(state):
        if v == 0:
            prev0 = [None] * 64
            prev0[(i - 1) % 64] = 0
            prev0[i % 64] = 0
            prev0[(i + 1) % 64] = 0
            stack.append((prev0, i + 1))

            prev1 = [None] * 64
            prev1[(i - 1) % 64] = 1
            prev1[i % 64] = 1
            prev1[(i + 1) % 64] = 1
            stack.append((prev1, i + 1))
            break

    while stack:
        prev = DFS(state, stack)
        if prev is not None:
            yield prev


for prev in reverse_rule126('66de3c1bf87fdfcf'):
    with open('enc.key', 'wb') as f:
        f.write(bytes.fromhex(prev))
    try:
        output = subprocess.check_output(['sh', './solve.sh'])
        if b'CTF' in output:
            flag = output.decode().strip()
            break
    except subprocess.CalledProcessError:
        pass

print(flag)
