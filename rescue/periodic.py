"""Paired periodic check-in (wire v2), ported from the firmware to Python.

This mirrors firmware/lib/rescue_core/periodic_link.h and periodic_dog.h so the
console can send and verify the same encrypted beacons the real dog and wristband
exchange over the air. The wire is AES-128-CCM (rescue/aes_ccm.py), 32-byte packets:

    TYPE(1) VER(1=2) COUNTER(4) SLOT16(2) TAG(8) ENC_IDS(16)

The clear 8-byte header (TYPE..SLOT16) is authenticated as associated data; the two
8-byte IDs (dog, band) are encrypted. Types 6/7/8/9 are request / radio reply /
human confirmation / dog ACK. See firmware/docs/periodic-rfm69.md for the protocol.

The per-pair AES key is HMAC-SHA256(pair_key, "RESCUE-CCM-v2" || dog_id || band_id)[:16]
with big-endian 64-bit IDs. The 13-byte CCM nonce is type || counter32 || slot32 || RB 02 00.
"""
from __future__ import annotations

import hashlib
import hmac
import struct

from .aes_ccm import ccm_open, ccm_seal

# Packet types (continue the v1 numbering 1..5 used by rescue/protocol.py).
BEACON, BEACON_REPLY, BEACON_ALIVE, BEACON_ACK = 6, 7, 8, 9
PERIODIC_VERSION = 2
PACKET_LEN = 32
KEY_LEN = 16
COUNTER_LEN = 4

NAMES = {BEACON: "BEACON", BEACON_REPLY: "BEACON REPLY",
         BEACON_ALIVE: "BEACON ALIVE", BEACON_ACK: "BEACON ACK"}

# Band events (also exposed as PeriodicBand class attributes below).
SILENT, PROMPT, RETRY_CONFIRMATION, ACKNOWLEDGED = "SILENT", "PROMPT", "RETRY_CONFIRMATION", "ACKNOWLEDGED"

# Timers (milliseconds), matching the firmware.
CHECKIN_COOLDOWN_MS = 7_200_000   # 2 hours: skip a confirmed band
CHECKIN_RESPONSE_MS = 30_000      # the wearer's response window
RETRY_INTERVAL_MS = 2_000         # confirmation retransmit cadence


def put_id(value: int) -> bytes:
    return struct.pack(">Q", value & 0xFFFFFFFFFFFFFFFF)


def get_id(raw: bytes) -> int:
    return struct.unpack(">Q", raw[:8])[0]


def periodic_ccm_key(master: bytes, dog: int, band: int) -> bytes:
    """First 16 bytes of HMAC-SHA256(master, "RESCUE-CCM-v2" || dog || band)."""
    context = b"RESCUE-CCM-v2" + put_id(dog) + put_id(band)
    return hmac.new(master, context, hashlib.sha256).digest()[:16]


def periodic_ccm_nonce(ptype: int, counter: bytes, slot: int) -> bytes:
    """13-byte CCM nonce: type(1) counter(4) slot32-BE(4) 'R' 'B' 0x02 0x00."""
    return bytes([ptype]) + counter[:COUNTER_LEN] + struct.pack(">I", slot & 0xFFFFFFFF) + b"RB\x02\x00"


def make_beacon(key: bytes, ptype: int, counter: bytes, slot: int, dog: int, band: int) -> bytes:
    """Build one 32-byte encrypted, authenticated beacon packet."""
    out = bytearray(PACKET_LEN)
    out[0] = ptype
    out[1] = PERIODIC_VERSION
    out[2:6] = counter[:COUNTER_LEN]
    out[6] = (slot >> 8) & 0xFF
    out[7] = slot & 0xFF
    aad = bytes(out[0:8])
    plain = put_id(dog) + put_id(band)
    enc_key = periodic_ccm_key(key, dog, band)
    nonce = periodic_ccm_nonce(ptype, counter, slot)
    cipher, tag = ccm_seal(enc_key, nonce, aad, plain)
    out[8:16] = tag
    out[16:32] = cipher
    return bytes(out)


def verify_beacon(key: bytes, raw: bytes, ptype: int, now_slot: int, dog: int, band: int):
    """Return the matched absolute slot if the packet is a valid ``ptype`` beacon for
    this (dog, band) pair within +/- 1 slot, else None."""
    if not dog or not band or len(raw) != PACKET_LEN or raw[0] != ptype or raw[1] != PERIODIC_VERSION:
        return None
    slot16 = (raw[6] << 8) | raw[7]
    counter = raw[2:6]
    aad = raw[0:8]
    cipher = raw[16:32]
    tag = raw[8:16]
    enc_key = periodic_ccm_key(key, dog, band)
    expected = put_id(dog) + put_id(band)
    for off in (0, -1, 1):
        slot = now_slot + off
        if (slot & 0xFFFF) != slot16:
            continue
        nonce = periodic_ccm_nonce(ptype, counter, slot)
        plain = ccm_open(enc_key, nonce, aad, cipher, tag)
        if plain is not None and hmac.compare_digest(plain, expected):
            return slot
    return None


class NonceCounter:
    """Monotonic uniqueness counter for the dog's beacons. The firmware keeps this in
    an EEPROM journal with reserved blocks; here a simple incrementing counter is enough
    for the simulation. Never a random-number generator: just never reused."""

    def __init__(self, start: int = 1):
        self._value = start

    def next(self) -> bytes:
        counter = struct.pack(">I", self._value & 0xFFFFFFFF)
        self._value += 1
        return counter

    @property
    def value(self) -> int:
        return self._value


class PeriodicDog:
    """The dog side: addresses one band, opens a 30 s window, and confirms the wearer.

    Faithful to firmware periodic_dog.h. ``now`` is milliseconds (monotonic)."""

    WAITING, BAND_SEEN, CONFIRMED = "WAITING", "BAND_SEEN", "CONFIRMED"

    def __init__(self, key: bytes, dog: int, band: int, counter: NonceCounter | None = None):
        self.key = key
        self.dog = dog
        self.band = band
        self.counter = counter or NonceCounter()
        self.period_ms = RETRY_INTERVAL_MS
        self._nonce = None
        self._slot = 0
        self._began = 0
        self._sent = False
        self._sent_at = 0
        self._active = False
        self._confirmed = False
        self._confirmed_at = 0
        self._state = self.WAITING

    def cooling(self, now: int) -> bool:
        return self._confirmed and (now - self._confirmed_at) < CHECKIN_COOLDOWN_MS

    def active(self, now: int) -> bool:
        return self._active and (now - self._began) < CHECKIN_RESPONSE_MS

    def remaining_seconds(self, now: int) -> int:
        if not self.cooling(now):
            return 0
        return (CHECKIN_COOLDOWN_MS - (now - self._confirmed_at) + 999) // 1000

    def state(self, now: int) -> str:
        if self.cooling(now):
            return self.CONFIRMED
        return self._state if self.active(now) else self.WAITING

    def due(self, now: int) -> bool:
        if not self.period_ms or not self.dog or not self.band or self.cooling(now):
            return False
        if not self.active(now):
            return not self._sent or (now - self._sent_at) >= self.period_ms
        return self._state != self.CONFIRMED and (not self._sent or (now - self._sent_at) >= self.period_ms)

    def challenge(self, now: int, slot: int):
        """Return the BEACON to transmit, or None if not due."""
        if not self.due(now):
            return None
        if not self.active(now):
            self._nonce = self.counter.next()
            self._slot = slot
            self._began = now
            self._active = True
            self._confirmed = False
            self._state = self.WAITING
        out = make_beacon(self.key, BEACON, self._nonce, self._slot, self.dog, self.band)
        self._sent = True
        self._sent_at = now
        return out

    def receive(self, raw: bytes, now: int, slot: int) -> bool:
        """Process a BEACON_REPLY (radio answered) or BEACON_ALIVE (wearer pressed)."""
        if not self.period_ms or not self.active(now) or self.cooling(now) or len(raw) != PACKET_LEN:
            return False
        if raw[0] not in (BEACON_ALIVE, BEACON_REPLY) or raw[2:6] != self._nonce:
            return False
        matched = verify_beacon(self.key, raw, raw[0], slot, self.dog, self.band)
        if matched is None or matched != self._slot:
            return False
        if raw[0] == BEACON_ALIVE:
            self._state = self.CONFIRMED
            self._confirmed = True
            self._confirmed_at = now
            self._active = False
            return True
        if raw[0] == BEACON_REPLY and self._state == self.WAITING:
            self._state = self.BAND_SEEN
            return True
        return False

    def receipt(self, raw: bytes, now: int, slot: int):
        """After a confirmation, return the BEACON_ACK for a (possibly duplicate)
        BEACON_ALIVE, for up to 30 s. Does not extend the cooldown."""
        if not self.cooling(now) or (now - self._confirmed_at) >= CHECKIN_RESPONSE_MS or len(raw) != PACKET_LEN:
            return None
        if raw[2:6] != self._nonce:
            return None
        matched = verify_beacon(self.key, raw, BEACON_ALIVE, slot, self.dog, self.band)
        if matched is None or matched != self._slot:
            return None
        return make_beacon(self.key, BEACON_ACK, self._nonce, self._slot, self.dog, self.band)


class PeriodicBand:
    """The wristband side: prompts the wearer, sends the confirmation, awaits the ACK.

    Faithful to firmware periodic_link.h PeriodicBand. ``now`` is milliseconds."""

    SILENT, PROMPT, RETRY_CONFIRMATION, ACKNOWLEDGED = SILENT, PROMPT, RETRY_CONFIRMATION, ACKNOWLEDGED

    def __init__(self, key: bytes, dog: int, band: int):
        self.key = key
        self.dog = dog
        self.band = band
        self._nonce = None
        self._slot = 0
        self._seen = []                     # nonces already handled (replay guard)
        self._began = 0
        self._pending = False
        self._confirmed = False
        self._confirmed_at = 0
        self._awaiting_ack = False
        self._acknowledged = False
        self._acknowledged_at = 0
        self._last_confirmation_tx = 0

    def cooling(self, now: int) -> bool:
        return self._confirmed and (now - self._confirmed_at) < CHECKIN_COOLDOWN_MS

    def waiting(self, now: int) -> bool:
        return self._pending and (now - self._began) < CHECKIN_RESPONSE_MS and not self.cooling(now)

    def success_led(self, now: int) -> bool:
        return self._acknowledged and (now - self._acknowledged_at) < 5000

    def status_led(self, now: int) -> bool:
        return (self.waiting(now)
                or (self._awaiting_ack and (now - self._confirmed_at) < CHECKIN_RESPONSE_MS)
                or self.success_led(now))

    def on_packet(self, raw: bytes, now: int, slot: int):
        """Process an incoming BEACON or BEACON_ACK.

        Returns (event, reply_or_None, blink_bits_or_None). ``event`` is one of
        SILENT / PROMPT / RETRY_CONFIRMATION / ACKNOWLEDGED. PROMPT means buzz the
        wearer and wait for the gesture; the reply is the BEACON_REPLY to send."""
        from . import protocol as P
        if len(raw) == PACKET_LEN and raw[0] == BEACON_ACK:
            if (not self._awaiting_ack or (now - self._confirmed_at) >= CHECKIN_RESPONSE_MS
                    or raw[2:6] != self._nonce):
                return self.SILENT, None, None
            matched = verify_beacon(self.key, raw, BEACON_ACK, slot, self.dog, self.band)
            if matched is None or matched != self._slot:
                return self.SILENT, None, None
            self._awaiting_ack = False
            self._acknowledged = True
            self._acknowledged_at = now
            self._confirmed = True
            self._confirmed_at = now
            return self.ACKNOWLEDGED, None, None

        matched = verify_beacon(self.key, raw, BEACON, slot, self.dog, self.band)
        if matched is None:
            return self.SILENT, None, None
        if self.cooling(now) or (self._awaiting_ack and (now - self._confirmed_at) < CHECKIN_RESPONSE_MS):
            # recover a lost button packet without buzzing again
            if raw[2:6] != self._nonce or self._slot != matched:
                return self.SILENT, None, None
            reply = make_beacon(self.key, BEACON_ALIVE, self._nonce, self._slot, self.dog, self.band)
            return self.RETRY_CONFIRMATION, reply, None
        if raw[2:6] in self._seen:
            return self.SILENT, None, None
        self._seen.append(raw[2:6])
        if len(self._seen) > 64:
            self._seen.pop(0)
        self._nonce = raw[2:6]
        self._slot = matched
        self._began = now
        self._pending = True
        self._confirmed = False
        self._awaiting_ack = False
        self._acknowledged = False
        reply = make_beacon(self.key, BEACON_REPLY, self._nonce, self._slot, self.dog, self.band)
        bits = P.blink_bits(self.key, self._slot)
        return self.PROMPT, reply, bits

    def press(self, now: int):
        """The wearer completed the gesture: return the BEACON_ALIVE to send, or None."""
        if not self._pending or (now - self._began) >= CHECKIN_RESPONSE_MS or self.cooling(now):
            return None
        out = make_beacon(self.key, BEACON_ALIVE, self._nonce, self._slot, self.dog, self.band)
        self._pending = False
        self._confirmed = False
        self._confirmed_at = now
        self._awaiting_ack = True
        self._acknowledged = False
        self._last_confirmation_tx = now
        return out

    def retry_confirmation(self, now: int):
        """Retransmit the confirmation every 2 s while awaiting the ACK, else None."""
        if (not self._awaiting_ack or (now - self._confirmed_at) >= CHECKIN_RESPONSE_MS
                or (now - self._last_confirmation_tx) < RETRY_INTERVAL_MS):
            return None
        self._last_confirmation_tx = now
        return make_beacon(self.key, BEACON_ALIVE, self._nonce, self._slot, self.dog, self.band)
