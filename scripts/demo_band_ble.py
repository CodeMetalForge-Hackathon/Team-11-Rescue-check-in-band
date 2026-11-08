#!/usr/bin/env python3
"""Trigger a rescue wristband to DO THINGS over Bluetooth, on cue, during a demo.

A paired band won't answer a legacy challenge (its real cue comes from the dog's
encrypted beacon), but it always obeys its direct output commands over BLE. This
drives those so the wristband buzzes / vibrates / blinks exactly when you want.

Cues (what the wearer sees and feels):
  cue    #C   the 3-pulse code on LED + motor + buzzer   (the "verified!" moment)
  buzz   #B   buzzer 0.3 s
  motor  #M   vibration motor 0.3 s
  tone   #Z   buzzer tone 0.3 s
  led    #L   LED on/off cycle (slow, clearly visible)

Run (uses the project .venv, which has bleak):
  .venv/bin/python scripts/demo_band_ble.py cue                 # one cue, then exit
  .venv/bin/python scripts/demo_band_ble.py --timeline "0:cue,8:buzz,16:cue"
  .venv/bin/python scripts/demo_band_ble.py --interactive       # type c/b/m/z/l, q to quit
  .venv/bin/python scripts/demo_band_ble.py --loop cue --every 10   # a cue every 10 s

--target picks the band by name or address; the default auto-picks the first
"Rescue-Band-*" it sees. Bluetooth connects are flaky, so it retries automatically.
"""
import argparse
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from rescue.ble_band import BleStream           # noqa: E402
from rescue.radio import SerialLoRaRadio        # noqa: E402

CUES = {"cue": "#C", "buzz": "#B", "motor": "#M", "tone": "#Z", "led": "#L"}
SHORT = {"c": "cue", "b": "buzz", "m": "motor", "z": "tone", "l": "led"}


def connect(target, tries=8):
    for i in range(tries):
        try:
            return SerialLoRaRadio(stream=BleStream(target), sync_clock=False, boot_wait=3.0)
        except Exception as e:                    # noqa: BLE001  (bleak timeouts are common)
            print("  connect attempt %d/%d failed (%s), retrying..."
                  % (i + 1, tries, type(e).__name__), flush=True)
            time.sleep(2)
    raise SystemExit("could not connect to the wristband over Bluetooth after %d tries" % tries)


def fire(radio, name):
    cmd = CUES.get(SHORT.get(name, name))
    if not cmd:
        print("  unknown cue %r (use: %s)" % (name, ", ".join(CUES)), flush=True)
        return
    radio.clear()
    radio.command(cmd)
    ack = radio.wait_line("#TEST", 3.0)           # every cue answers with a "#TEST ... done" line
    print("  %-5s -> %s   band: %s" % (name, cmd, ack or "(no ack)"), flush=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--target", default=None, help="band name or address (default: first Rescue-Band-*)")
    ap.add_argument("--timeline", help='timed sequence, e.g. "0:cue,8:buzz,16:cue" (seconds:cue)')
    ap.add_argument("--interactive", action="store_true", help="type cues live (c/b/m/z/l, q to quit)")
    ap.add_argument("--loop", metavar="CUE", help="repeat CUE forever")
    ap.add_argument("--every", type=float, default=10.0, help="--loop interval in seconds (default 10)")
    ap.add_argument("cue", nargs="?", help="single cue: " + ", ".join(CUES))
    args = ap.parse_args()

    print("connecting to %s ..." % (args.target or "first Rescue-Band-*"), flush=True)
    radio = connect(args.target)
    print("connected:", radio.hello, flush=True)
    try:
        if args.timeline:
            steps = sorted((float(t), c.strip())
                           for t, _, c in (p.strip().partition(":") for p in args.timeline.split(",")))
            t0 = time.time()
            for when, c in steps:
                dt = when - (time.time() - t0)
                if dt > 0:
                    time.sleep(dt)
                print("[t=%5.1fs]" % (time.time() - t0), end=" ", flush=True)
                fire(radio, c)
        elif args.loop:
            print("looping %r every %.1fs (Ctrl-C to stop)" % (args.loop, args.every), flush=True)
            while True:
                fire(radio, args.loop)
                time.sleep(args.every)
        elif args.interactive:
            print("keys: c=cue b=buzz m=motor z=tone l=led   q=quit", flush=True)
            for line in sys.stdin:
                k = line.strip().lower()
                if k in ("q", "quit", "exit"):
                    break
                if k:
                    fire(radio, k)
        else:
            fire(radio, args.cue or "cue")
        time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nstopped.", flush=True)
    finally:
        radio.close()
    print("done.", flush=True)


if __name__ == "__main__":
    main()
