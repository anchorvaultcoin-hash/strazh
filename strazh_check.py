#!/usr/bin/env python3
"""
STRAZH — demo 1: a recreation of the incident of 18 August 2026.

A tool (in real life a contract-verification script) asks for an API key.
Here a *private key* is pasted instead — exactly what happened that night.
STRAZH checks the input before it goes any further.

The wallet used here is generated from random bytes at run time. It is not a
real wallet, it holds no funds, and it exists only for this demonstration.
"""

import secrets
import sys

from engine import classify, private_key_to_address

TEST_PRIVATE_KEY = secrets.token_bytes(32).hex()
TEST_WALLET_ADDR = private_key_to_address(TEST_PRIVATE_KEY)
KNOWN_WALLETS = {TEST_WALLET_ADDR.lower(): "Creator (demo wallet)"}

WIDTH = 68  # inner width of the frame


def row(text=""):
    text = text[:WIDTH]
    print("║ " + text.ljust(WIDTH) + " ║")


def stop_screen(program_name, asked_for, wallet_name, wallet_addr):
    print()
    print("╔" + "═" * (WIDTH + 2) + "╗")
    row("⛔ STOPPED")
    row()
    row("Found:     Ethereum private key")
    row(f"Wallet:    {wallet_name}")
    row(f"           {wallet_addr}")
    row(f"Program:   {program_name}")
    row(f"Asked for: {asked_for}")
    row()
    row("The program asked for an API key - this is a wallet key.")
    row("Different key, different consequences.")
    row()
    row("❌ Nothing was delivered to the process.")
    print("╚" + "═" * (WIDTH + 2) + "╝")
    print()


def main():
    program_name = "forge (verify-contract)"
    prompt = "Enter your Etherscan API key: "

    print(f"$ {program_name}")
    print(prompt, end="", flush=True)

    if len(sys.argv) > 1 and sys.argv[1] == "--demo-paste-key":
        pasted = TEST_PRIVATE_KEY
        print("•" * 64)  # the secret is never shown, not even in the demo
    else:
        pasted = input()

    findings = classify(pasted, KNOWN_WALLETS)
    stop_finding = next((f for f in findings if f.action == "STOP"), None)

    if stop_finding:
        stop_screen(program_name, prompt.strip(" :"), "Creator (demo wallet)", TEST_WALLET_ADDR)
        print("The demo wallet was generated randomly just now. It holds no funds.")
        sys.exit(1)
    else:
        print("[STRAZH] Input looks like an ordinary API key - passed through.")
        sys.exit(0)


if __name__ == "__main__":
    main()
