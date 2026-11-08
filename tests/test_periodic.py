"""The Python port of the v2 periodic check-in (rescue/periodic.py) and its AES-CCM.

These check the pure-Python crypto against the firmware's RFC 3610 vector and, when
the optional `cryptography` package is installed, against its AESCCM; then they run
the full dog<->band beacon exchange the console drives.
"""
import struct

import pytest

from rescue import periodic as PP
from rescue.aes_ccm import ccm_open, ccm_seal

KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
DOG, BAND = 0xD001, 0xB0000000AA


# --- AES-CCM primitive -------------------------------------------------------

def test_rfc3610_vector_one():
    # The same packet vector #1 the firmware test (tests/test_aes_ccm.py) uses.
    key = bytes(range(0xC0, 0xD0))
    nonce = bytes.fromhex("00000003020100a0a1a2a3a4a5")
    aad, plain = bytes(range(8)), bytes(range(8, 31))
    expected = bytes.fromhex("588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0")
    cipher, tag = ccm_seal(key, nonce, aad, plain)
    assert cipher + tag == expected
    assert ccm_open(key, nonce, aad, cipher, tag) == plain


@pytest.mark.parametrize("length", [0, 1, 15, 16, 17, 23, 32])
@pytest.mark.parametrize("aad_length", [0, 8, 15, 30])
def test_matches_cryptography_if_present(length, aad_length):
    aead = pytest.importorskip("cryptography.hazmat.primitives.ciphers.aead")
    key, nonce = bytes(range(16)), bytes(range(13))
    plain = bytes((i * 13 + length) % 256 for i in range(length))
    aad = bytes((i * 7) % 256 for i in range(aad_length))
    expected = aead.AESCCM(key, tag_length=8).encrypt(nonce, plain, aad)
    cipher, tag = ccm_seal(key, nonce, aad, plain)
    assert cipher + tag == expected


def test_open_rejects_tampering():
    key, nonce, aad, plain = bytes(range(16)), bytes(range(13)), bytes(range(8)), bytes(range(16))
    cipher, tag = ccm_seal(key, nonce, aad, plain)
    assert ccm_open(key, nonce, aad, cipher, tag) == plain
    bad = bytearray(cipher)
    bad[0] ^= 1
    assert ccm_open(key, nonce, aad, bytes(bad), tag) is None
    assert ccm_open(key, nonce, aad, cipher, bytes(8)) is None
    assert ccm_open(bytes(16), nonce, aad, cipher, tag) is None


# --- beacon build / verify ---------------------------------------------------

def test_beacon_roundtrip_and_layout():
    counter = struct.pack(">I", 7)
    slot = 0x1234_5678
    raw = PP.make_beacon(KEY, PP.BEACON, counter, slot, DOG, BAND)
    assert len(raw) == PP.PACKET_LEN
    assert raw[0] == PP.BEACON and raw[1] == PP.PERIODIC_VERSION
    assert raw[2:6] == counter
    assert raw[6] == (slot >> 8) & 0xFF and raw[7] == slot & 0xFF
    assert raw[16:32] != PP.put_id(DOG) + PP.put_id(BAND)   # IDs are encrypted
    assert PP.verify_beacon(KEY, raw, PP.BEACON, slot, DOG, BAND) == slot


def test_verify_tolerates_one_slot_drift_and_rejects_more():
    counter = struct.pack(">I", 1)
    slot = 1000
    raw = PP.make_beacon(KEY, PP.BEACON, counter, slot, DOG, BAND)
    assert PP.verify_beacon(KEY, raw, PP.BEACON, slot + 1, DOG, BAND) == slot
    assert PP.verify_beacon(KEY, raw, PP.BEACON, slot - 1, DOG, BAND) == slot
    assert PP.verify_beacon(KEY, raw, PP.BEACON, slot + 2, DOG, BAND) is None


def test_verify_rejects_wrong_pair_type_and_key():
    counter = struct.pack(">I", 1)
    slot = 500
    raw = PP.make_beacon(KEY, PP.BEACON, counter, slot, DOG, BAND)
    assert PP.verify_beacon(KEY, raw, PP.BEACON_REPLY, slot, DOG, BAND) is None   # wrong type
    assert PP.verify_beacon(KEY, raw, PP.BEACON, slot, DOG, BAND + 1) is None     # wrong band
    assert PP.verify_beacon(KEY, raw, PP.BEACON, slot, DOG + 1, BAND) is None     # wrong dog
    assert PP.verify_beacon(bytes(16), raw, PP.BEACON, slot, DOG, BAND) is None   # wrong key


# --- full dog <-> band exchange ---------------------------------------------

def run_exchange(dog, band, slot, now):
    """Drive one full check-in; return the ordered list of (who, event/type)."""
    trail = []
    beacon = dog.challenge(now, slot)
    assert beacon is not None
    trail.append(("dog", PP.NAMES[beacon[0]]))
    event, reply, bits = band.on_packet(beacon, now, slot)
    trail.append(("band", event))
    assert event == PP.PROMPT and reply is not None and bits is not None
    assert dog.receive(reply, now, slot)                 # BEACON_REPLY -> BAND_SEEN
    trail.append(("dog", "BAND_SEEN"))
    alive = band.press(now)                              # wearer gesture
    assert alive is not None
    trail.append(("band", PP.NAMES[alive[0]]))
    assert dog.receive(alive, now, slot)                 # BEACON_ALIVE -> CONFIRMED
    trail.append(("dog", "CONFIRMED"))
    ack = dog.receipt(alive, now, slot)                 # dog ACKs
    assert ack is not None
    trail.append(("dog", PP.NAMES[ack[0]]))
    event, reply, bits = band.on_packet(ack, now, slot)
    trail.append(("band", event))
    assert event == PP.ACKNOWLEDGED
    return trail


def test_happy_path_and_cooldown():
    dog = PP.PeriodicDog(KEY, DOG, BAND)
    band = PP.PeriodicBand(KEY, DOG, BAND)
    slot, now = 2000, 10_000
    run_exchange(dog, band, slot, now)
    assert dog.state(now) == PP.PeriodicDog.CONFIRMED
    assert band.success_led(now)
    # cooldown: the dog does not re-challenge for 2 hours
    assert not dog.due(now + 60_000)
    assert dog.cooling(now + 60_000)
    assert not dog.cooling(now + PP.CHECKIN_COOLDOWN_MS + 1)


def test_band_stays_silent_to_wrong_pair():
    band = PP.PeriodicBand(KEY, DOG, BAND)
    counter = struct.pack(">I", 3)
    slot, now = 100, 5_000
    impostor = PP.make_beacon(bytes(16), PP.BEACON, counter, slot, DOG, BAND)
    assert band.on_packet(impostor, now, slot) == (PP.SILENT, None, None)


def test_retry_recovers_lost_button_packet_without_reprompting():
    dog = PP.PeriodicDog(KEY, DOG, BAND)
    band = PP.PeriodicBand(KEY, DOG, BAND)
    slot, now = 300, 1_000
    beacon = dog.challenge(now, slot)
    event, reply, bits = band.on_packet(beacon, now, slot)
    assert event == PP.PROMPT
    alive = band.press(now)                              # confirmation "lost"
    assert alive is not None
    # the dog, not having seen ALIVE, re-sends the same beacon; band re-sends ALIVE, no new prompt
    again = dog.challenge(now + PP.RETRY_INTERVAL_MS, slot)
    assert again is not None
    event, reply, bits = band.on_packet(again, now + PP.RETRY_INTERVAL_MS, slot)
    assert event == PP.RETRY_CONFIRMATION and reply is not None and bits is None


def test_replayed_beacon_is_ignored():
    band = PP.PeriodicBand(KEY, DOG, BAND)
    slot, now = 77, 2_000
    beacon = PP.make_beacon(KEY, PP.BEACON, struct.pack(">I", 9), slot, DOG, BAND)
    assert band.on_packet(beacon, now, slot)[0] == PP.PROMPT
    # same nonce replayed after the window: not a fresh prompt
    assert band.on_packet(beacon, now + PP.CHECKIN_RESPONSE_MS + 1, slot)[0] == PP.SILENT
