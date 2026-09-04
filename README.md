# STRAZH

**A seatbelt for private keys.** STRAZH checks what a human types or pastes *before* it reaches a program, a network call, or a git commit — and stops a secret from leaving the machine by mistake.

**Status:** day 1 of ETHOnline 2026. Working today: the detection core, git-commit blocking, and two runnable demos. In progress: full terminal (PTY) interception.

## Why this exists

On 18 August 2026 I was verifying a contract. A tool asked for an Etherscan API key. I pasted a **private key** instead. It left the machine in a URL query string. That night I had to hand over the owner role of a live protocol.

STRAZH is the thing that would have stopped me.

## What it is — and what it is not

STRAZH is a **seatbelt, not armor**. It catches the mistake of a tired human. It does **not** stop an attacker who already has code execution on your machine.

This limitation is written here on purpose. A tool that sells a false sense of security is worse than no tool at all.

## The core problem

An Ethereum private key and a transaction hash are **indistinguishable by shape** — both are 256 random bits. A rule like "64 hex characters = alarm" produces dozens of false alarms a day, and then people switch the tool off. That is the main reason tools like this die.

STRAZH does not guess by shape. It derives:

```
64 hex  →  secp256k1 private key  →  public address
                                          |
                                          v
                        compared with the owner's known addresses
```

If the derived address is one of yours, this is not a hash — it is your key, and it is stopped by name. If it is not, STRAZH stays silent.

Everything is computed locally. **STRAZH itself makes no network requests of any kind.**

## What is in this repository today

| File | What it does |
|------|--------------|
| `pure_keccak.py` | Keccak-256 (Ethereum variant, `0x01` padding), written from scratch |
| `pure_secp256k1.py` | secp256k1 point arithmetic, written from scratch |
| `engine.py` | Detection core: HEX64 pre-filter → derivation → comparison with known wallets |
| `strazh_check.py` | Demo 1 — recreation of the 18 August incident |
| `demo_silence.py` | Demo 2 — 5000 transaction hashes, zero alarms; then one real key, caught by name |
| `hooks/pre-commit` | Demo 3 — a git hook that blocks a commit containing a key |

**Zero external dependencies.** Pure Python, standard library only. The elliptic-curve math and the hash function are implemented *in this repository*, not imported.

## Verification

The from-scratch cryptography is checked byte-for-byte against `coincurve` and `pycryptodome` on randomly generated keys. Those libraries are used **only to verify correctness during development** — STRAZH itself never imports them.

Every key used in the demos is generated randomly at runtime and holds no funds. No real key is ever committed, printed, or logged.

## STRAZH must never become the leak itself

A detected secret is never written to a log, not even partially. It is not kept longer than the check itself. It is not shown in the warning. There is no telemetry, and no network activity at all.

## Threat model

In scope: a human typing or pasting a secret into the wrong place — a prompt, a command, a commit.

Out of scope: a secret that already sits in a file and is piped into a program, and anything an attacker does after gaining code execution.

## Roadmap — not built yet, stated honestly

- PTY wrapper for full terminal interception
- BIP39 seed-phrase detection with checksum validation across languages
- Extended key formats: `xprv` / `yprv` / `zprv`, WIF, keystore JSON
- Network-layer adapter with chain-id awareness (local / testnet / mainnet)

## ETHOnline 2026

Track: **Building from Scratch.** Work on this repository started on 4 September 2026, the first day of the event.

## License

MIT
