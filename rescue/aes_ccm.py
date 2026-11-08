"""AES-128-CCM in pure Python, byte-for-byte compatible with the firmware.

This mirrors firmware/lib/rescue_core/aes_ccm.cpp exactly: AES-128, a 13-byte
nonce (L=2), an 8-byte authentication tag (M=8), RFC 3610 formatting. It exists so
the console's simulated periodic check-in (rescue/periodic.py) can build and verify
the same encrypted beacons the real dog and wristband exchange, with no third-party
install. tests/test_periodic.py checks it against the RFC 3610 vector and, when the
`cryptography` package is present, against its AESCCM.

Only AES encryption is needed: CCM uses the block cipher for both the CBC-MAC and
the CTR keystream.
"""
from __future__ import annotations

# --- AES-128 (encrypt only) --------------------------------------------------

_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16"
)

_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _expand_key(key: bytes) -> list[list[int]]:
    """11 round keys of 16 bytes each (AES-128)."""
    assert len(key) == 16
    words = [list(key[i * 4:i * 4 + 4]) for i in range(4)]
    for i in range(4, 44):
        temp = list(words[i - 1])
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]                         # RotWord
            temp = [_SBOX[b] for b in temp]                    # SubWord
            temp[0] ^= _RCON[i // 4 - 1]
        words.append([words[i - 4][j] ^ temp[j] for j in range(4)])
    return [sum(words[r * 4:r * 4 + 4], []) for r in range(11)]


def _xtime(a: int) -> int:
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _encrypt_block(round_keys: list[list[int]], block: bytes) -> bytes:
    s = list(block)
    rk = round_keys[0]
    for i in range(16):
        s[i] ^= rk[i]
    for rnd in range(1, 10):
        s = [_SBOX[b] for b in s]
        # ShiftRows (state is column-major: byte index = col*4 + row)
        s = [
            s[0], s[5], s[10], s[15],
            s[4], s[9], s[14], s[3],
            s[8], s[13], s[2], s[7],
            s[12], s[1], s[6], s[11],
        ]
        # MixColumns
        out = [0] * 16
        for c in range(4):
            a0, a1, a2, a3 = s[c * 4:c * 4 + 4]
            out[c * 4 + 0] = _xtime(a0) ^ (_xtime(a1) ^ a1) ^ a2 ^ a3
            out[c * 4 + 1] = a0 ^ _xtime(a1) ^ (_xtime(a2) ^ a2) ^ a3
            out[c * 4 + 2] = a0 ^ a1 ^ _xtime(a2) ^ (_xtime(a3) ^ a3)
            out[c * 4 + 3] = (_xtime(a0) ^ a0) ^ a1 ^ a2 ^ _xtime(a3)
        s = out
        rk = round_keys[rnd]
        for i in range(16):
            s[i] ^= rk[i]
    # final round (no MixColumns)
    s = [_SBOX[b] for b in s]
    s = [
        s[0], s[5], s[10], s[15],
        s[4], s[9], s[14], s[3],
        s[8], s[13], s[2], s[7],
        s[12], s[1], s[6], s[11],
    ]
    rk = round_keys[10]
    return bytes(s[i] ^ rk[i] for i in range(16))


# --- CCM (M=8, L=2), matching aes_ccm.cpp ------------------------------------

def _authenticate(rk, nonce: bytes, aad: bytes, plain: bytes) -> bytes:
    state = bytearray(16)

    def mac(block: bytes):
        nonlocal state
        xored = bytes(state[i] ^ block[i] for i in range(16))
        state = bytearray(_encrypt_block(rk, xored))

    length = len(plain)
    b0 = bytearray(16)
    b0[0] = (0x40 if aad else 0) | 0x18 | 1                    # M=8, L=2
    b0[1:14] = nonce
    b0[14] = (length >> 8) & 0xFF
    b0[15] = length & 0xFF
    mac(bytes(b0))

    if aad:
        block = bytearray(16)
        block[0] = (len(aad) >> 8) & 0xFF
        block[1] = len(aad) & 0xFF
        used = min(len(aad), 14)
        block[2:2 + used] = aad[:used]
        mac(bytes(block))
        while used < len(aad):
            block = bytearray(16)
            n = min(len(aad) - used, 16)
            block[:n] = aad[used:used + n]
            mac(bytes(block))
            used += n

    pos = 0
    while pos < length:
        block = bytearray(16)
        n = min(length - pos, 16)
        block[:n] = plain[pos:pos + n]
        mac(bytes(block))
        pos += n

    s0 = bytearray(16)
    s0[0] = 1
    s0[1:14] = nonce                                          # ctr blocks: last two bytes = counter
    keystream = _encrypt_block(rk, bytes(s0))                 # counter 0 for the tag
    return bytes(state[i] ^ keystream[i] for i in range(8))


def _crypt(rk, nonce: bytes, data: bytes) -> bytes:
    out = bytearray(len(data))
    counter = 1
    pos = 0
    while pos < len(data):
        block = bytearray(16)
        block[0] = 1
        block[1:14] = nonce
        block[14] = (counter >> 8) & 0xFF
        block[15] = counter & 0xFF
        keystream = _encrypt_block(rk, bytes(block))
        n = min(len(data) - pos, 16)
        for i in range(n):
            out[pos + i] = data[pos + i] ^ keystream[i]
        pos += n
        counter += 1
    return bytes(out)


def ccm_seal(key: bytes, nonce: bytes, aad: bytes, plain: bytes) -> tuple[bytes, bytes]:
    """Return (cipher, 8-byte tag). ``nonce`` is 13 bytes."""
    if len(key) != 16 or len(nonce) != 13:
        raise ValueError("AES-128-CCM needs a 16-byte key and 13-byte nonce")
    if len(plain) > 65535 or len(aad) >= 0xFF00:
        raise ValueError("length out of range")
    rk = _expand_key(key)
    tag = _authenticate(rk, nonce, aad, plain)
    cipher = _crypt(rk, nonce, plain)
    return cipher, tag


def ccm_open(key: bytes, nonce: bytes, aad: bytes, cipher: bytes, tag: bytes):
    """Return the plaintext on success, or None if authentication fails."""
    if len(key) != 16 or len(nonce) != 13:
        raise ValueError("AES-128-CCM needs a 16-byte key and 13-byte nonce")
    if len(cipher) > 65535 or len(aad) >= 0xFF00 or len(tag) != 8:
        return None
    rk = _expand_key(key)
    plain = _crypt(rk, nonce, cipher)
    expected = _authenticate(rk, nonce, aad, plain)
    # constant-time compare
    diff = 0
    for a, b in zip(expected, tag):
        diff |= a ^ b
    return plain if diff == 0 else None
