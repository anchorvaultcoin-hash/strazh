"""Pure-Python Keccak-256 (Ethereum variant, 0x01 padding). No external libraries.

Note this is Keccak-256 as used by Ethereum, not NIST SHA3-256: the padding
byte is 0x01, not 0x06. Using the wrong one silently produces valid-looking
but completely different addresses.
"""

RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]

MASK = (1 << 64) - 1


def rol(x, n):
    n %= 64
    return ((x << n) | (x >> (64 - n))) & MASK


def keccak_f1600(state):
    # state: 5x5 list of 64-bit ints, state[x][y]
    for rnd in range(24):
        C = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
        D = [C[(x - 1) % 5] ^ rol(C[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x][y] ^= D[x]
        B = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                B[y % 5][(2 * x + 3 * y) % 5] = rol(state[x][y], ROT[x][y])
        for x in range(5):
            for y in range(5):
                state[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & MASK & B[(x + 2) % 5][y])
        state[0][0] ^= RC[rnd]
    return state


def keccak256(data: bytes) -> bytes:
    rate = 136  # bytes (1088 bits)
    # padding: 0x01 ... 0x80
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != 0:
        padded.append(0x00)
    padded[-1] ^= 0x80

    state = [[0] * 5 for _ in range(5)]
    for i in range(0, len(padded), rate):
        block = padded[i:i + rate]
        for j in range(rate // 8):
            lane = int.from_bytes(block[j * 8:j * 8 + 8], "little")
            x, y = j % 5, j // 5
            state[x][y] ^= lane
        keccak_f1600(state)

    out = bytearray()
    while len(out) < 32:
        for j in range(rate // 8):
            x, y = j % 5, j // 5
            out += state[x][y].to_bytes(8, "little")
            if len(out) >= 32:
                break
        if len(out) < 32:
            keccak_f1600(state)
    return bytes(out[:32])


if __name__ == "__main__":
    # Known Keccak-256 digest of the empty input.
    EMPTY = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    got = keccak256(b"").hex()
    assert got == EMPTY, f"expected {EMPTY}, got {got}"
    print("pure_keccak.py: self-check passed")
    print(got)
