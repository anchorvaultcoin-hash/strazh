"""Pure-Python secp256k1: private key -> uncompressed public key. No external libraries."""

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def inv_mod(a, m):
    return pow(a, -1, m)


def on_curve(x, y) -> bool:
    """Curve equation for secp256k1: y^2 = x^3 + 7 (mod P)."""
    return (y * y - (x * x * x + 7)) % P == 0


def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1) * inv_mod(2 * y1, P) % P
    else:
        lam = (y2 - y1) * inv_mod(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def scalar_mult(k, point):
    """Double-and-add."""
    result = None
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def private_key_to_pubkey(priv_hex: str) -> bytes:
    k = int(priv_hex, 16)
    if not (0 < k < N):
        raise ValueError("private key is outside the valid secp256k1 range")
    x, y = scalar_mult(k, (GX, GY))
    return x.to_bytes(32, "big") + y.to_bytes(32, "big")


if __name__ == "__main__":
    import secrets

    # Self-check: the generator must satisfy the curve equation, and so must
    # the public point derived from a freshly generated random private key.
    assert on_curve(GX, GY), "generator point G is not on the curve"

    priv = secrets.token_bytes(32).hex()
    pub = private_key_to_pubkey(priv)
    px = int.from_bytes(pub[:32], "big")
    py = int.from_bytes(pub[32:], "big")
    assert on_curve(px, py), "derived public point is not on the curve"

    print("pure_secp256k1.py: self-check passed")
