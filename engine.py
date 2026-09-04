"""
STRAZH — detection core.

Pure Python, no external libraries: secp256k1 derivation + keccak256.

The rule this is built on: an Ethereum private key and a transaction hash are
both 256 random bits and are indistinguishable by shape. So STRAZH does not
guess from the shape of the string. It derives the address from the 64 hex
characters and compares it with the owner's list of known wallets.
"""

import re

from pure_keccak import keccak256
from pure_secp256k1 import private_key_to_pubkey

HEX64 = re.compile(r"\b[0-9a-fA-F]{64}\b")


def to_checksum_address(addr_hex: str) -> str:
    """EIP-55 checksum, so the wallet is shown exactly as in MetaMask/Etherscan."""
    addr_hex = addr_hex.lower().replace("0x", "")
    hash_hex = keccak256(addr_hex.encode("ascii")).hex()
    out = "0x"
    for i, ch in enumerate(addr_hex):
        if ch in "0123456789":
            out += ch
        else:
            out += ch.upper() if int(hash_hex[i], 16) >= 8 else ch
    return out


def private_key_to_address(priv_hex: str) -> str:
    pub = private_key_to_pubkey(priv_hex)
    addr = keccak256(pub)[-20:].hex()
    return to_checksum_address(addr)


class Finding:
    def __init__(self, kind, confidence, action, detail, secret_value=None):
        self.kind = kind                  # "private_key" / "hex64_unknown" / ...
        self.confidence = confidence      # CERTAIN / LIKELY / WEAK
        self.action = action              # STOP / ASK / SILENT
        self.detail = detail              # human-readable, never contains the secret
        self.secret_value = secret_value  # kept in memory only for masking; never logged


def classify(text: str, known_wallets: dict):
    """
    known_wallets: {lowercase_address: "human readable name"}

    Returns a list of Finding. The secret itself never goes into .detail.
    """
    findings = []
    for m in HEX64.finditer(text):
        candidate = m.group(0)
        try:
            addr = private_key_to_address(candidate)
        except ValueError:
            continue  # outside the secp256k1 range - definitely not a private key
        wallet_name = known_wallets.get(addr.lower())
        if wallet_name:
            findings.append(Finding(
                kind="private_key",
                confidence="CERTAIN",
                action="STOP",
                detail=f"Ethereum private key, wallet: {wallet_name} ({addr})",
            ))
        else:
            # Derivation succeeded, but the address is not one of the owner's.
            # In practice this means the string was a transaction or block hash,
            # not a key. Staying silent here is the whole point: a tool that
            # cries wolf on every 64-hex string gets switched off within a day.
            findings.append(Finding(
                kind="hex64_unknown",
                confidence="WEAK",
                action="SILENT",
                detail="64 hex characters, derivation matched no known wallet",
            ))
    return findings


if __name__ == "__main__":
    import secrets

    # Self-check on a freshly generated throwaway key.
    test_priv = secrets.token_bytes(32).hex()
    test_addr = private_key_to_address(test_priv)
    wallets = {test_addr.lower(): "Test Wallet"}

    result = classify(f"echo {test_priv}", wallets)
    assert len(result) == 1 and result[0].action == "STOP"

    # A random 64-hex string that is not one of ours must stay silent.
    noise = classify(secrets.token_bytes(32).hex(), wallets)
    assert all(f.action == "SILENT" for f in noise)

    print("engine.py: self-check passed")
    print("test address:", test_addr)
