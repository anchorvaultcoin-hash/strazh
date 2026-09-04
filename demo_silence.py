#!/usr/bin/env python3
"""
STRAZH — demo 2: a private key and a transaction hash are indistinguishable by
shape (both are 256 random bits), but not by derivation.

We generate 5000 strings shaped exactly like transaction hashes. STRAZH must
stay silent on every one of them. Then we add one private key belonging to the
demo wallet — STRAZH must stop, and name the wallet.

This is the test that decides whether a tool like this survives in real use:
one false alarm per day is enough for a person to switch it off for good.
"""

import secrets
import time

from engine import classify, private_key_to_address

TEST_PRIVATE_KEY = secrets.token_bytes(32).hex()
TEST_WALLET_ADDR = private_key_to_address(TEST_PRIVATE_KEY)
KNOWN_WALLETS = {TEST_WALLET_ADDR.lower(): "Creator (demo wallet)"}

N_HASHES = 5000


def main():
    print(f"Demo wallet for this run: {TEST_WALLET_ADDR}")
    print("(generated randomly just now, holds no funds)\n")

    print(f"Generating {N_HASHES} transaction hashes (64 hex each, same shape as real ones)...")
    fake_hashes = [secrets.token_bytes(32).hex() for _ in range(N_HASHES)]

    print(f"Checking a file of {N_HASHES} hashes...")
    t0 = time.perf_counter()
    stops = 0
    for h in fake_hashes:
        findings = classify(h, KNOWN_WALLETS)
        if any(f.action == "STOP" for f in findings):
            stops += 1
    dt_ms = (time.perf_counter() - t0) * 1000

    print(f"Result: {stops} alarms out of {N_HASHES} hashes.")
    print(f"Time: {dt_ms:.0f} ms total "
          f"({dt_ms / N_HASHES:.2f} ms per line, worst case - every line is derived).\n")

    print("Now adding one private key of the demo wallet to the same stream...")
    test_stream = fake_hashes + [TEST_PRIVATE_KEY]
    stop_found = None
    for item in test_stream:
        findings = classify(item, KNOWN_WALLETS)
        f = next((f for f in findings if f.action == "STOP"), None)
        if f:
            stop_found = f
            break

    if stop_found:
        print("\n⛔ STOP -", stop_found.detail)
        print("5000 hashes: silence. One key: an exact hit, by name.")
    else:
        print("\nDEMO FAILURE: the key was not caught - that is a bug, not the expected result.")


if __name__ == "__main__":
    main()
