# Auto-split from original bridge.py
# Module: wf_switches
from __future__ import annotations

import time
import json
import hashlib
from typing import Any

import paho.mqtt.client as mqtt

from wf_config import (
    log,
    DEDUP_MS, SEND_STRATEGY, CMD_GRACE_SECONDS, OBSERVER_ONLY,
    CHGLIMIT_MIN, CHGLIMIT_MAX, CHGLIMIT_CMD_TOPIC,

    BUS_TOPIC, LOCAL_OUT_PREFIX,

    LED_CMD_TOPIC, LED_STATE_TOPIC,
    AC_CMD_TOPIC, AC_STATE_TOPIC,
    DC_CMD_TOPIC, DC_STATE_TOPIC,

    LED_ON_HEX, LED_OFF_HEX,
    AC_ON_HEX, AC_OFF_HEX,
    DC_ON_HEX, DC_OFF_HEX,

    hex_bytes,
)

def attach(Bridge):
    def _on_local_message(self, client, userdata, msg):
        t = msg.topic
        p = (msg.payload or b"").decode(errors="ignore").strip()


        if t == LED_CMD_TOPIC:
            on = p.upper() == "ON"
            self._send_cmd(LED_ON_HEX if on else LED_OFF_HEX, "led_status", LED_STATE_TOPIC, on, CMD_GRACE_SECONDS)
            return
        if t == AC_CMD_TOPIC:
            on = p.upper() == "ON"
            self._send_cmd(AC_ON_HEX if on else AC_OFF_HEX, "ac_switch", AC_STATE_TOPIC, on, CMD_GRACE_SECONDS)
            return
        if t == DC_CMD_TOPIC:
            on = p.upper() == "ON"
            self._send_cmd(DC_ON_HEX if on else DC_OFF_HEX, "dc_switch", DC_STATE_TOPIC, on, CMD_GRACE_SECONDS)
            return
        if t == CHGLIMIT_CMD_TOPIC:
            try:
                val = int(float(p))
            except Exception:
                log.warning(f"[CMD] ac_charging_limit payload non valido: {p!r}")
                return
            val = max(CHGLIMIT_MIN, min(CHGLIMIT_MAX, val))
            self._send_charging_limit(val)
            return

    # ---- Command helpers (NoBeep routing + dedup) ----
    Bridge._on_local_message = _on_local_message

    def _route_and_publish(self, payload: bytes):
        if OBSERVER_ONLY:
            log.debug("[CMD] OBSERVER_ONLY=true, comando ignorato")
            return
        # dedup
        h = hashlib.md5(payload).hexdigest()
        now = time.time()
        if (
            getattr(self, "_last_cmd_hash", None) == h and
            (now - getattr(self, "_last_cmd_time", 0.0)) * 1000 < DEDUP_MS
        ):
            return  # drop duplicate very-close command
        self._last_cmd_hash = h
        self._last_cmd_time = now

        remote_ok = self.remote is not None
        strat = SEND_STRATEGY

        if strat == "cloud":
            if remote_ok:
                self.remote.publish(BUS_TOPIC, payload=payload, qos=0, retain=False)
            return

        if strat == "local":
            if self.local:
                self.local.publish(LOCAL_OUT_PREFIX + BUS_TOPIC, payload, qos=0, retain=False)
            return

        if strat == "both":
            if self.local:
                self.local.publish(LOCAL_OUT_PREFIX + BUS_TOPIC, payload, qos=0, retain=False)
            if remote_ok:
                self.remote.publish(BUS_TOPIC, payload=payload, qos=0, retain=False)
            return

        # auto
        if remote_ok:
            self.remote.publish(BUS_TOPIC, payload=payload, qos=0, retain=False)
        else:
            if self.local:
                self.local.publish(LOCAL_OUT_PREFIX + BUS_TOPIC, payload, qos=0, retain=False)
    Bridge._route_and_publish = _route_and_publish

    def _send_cmd(self, hx: str, key: str, state_topic: str, desired_on: bool, grace: int):
        payload = hex_bytes(hx)
        self._route_and_publish(payload)

        # optimistic state
        self.pending[key] = {"desired": desired_on, "until": time.time() + grace}
        if self.local:
            self.local.publish(state_topic, b"ON" if desired_on else b"OFF", qos=0, retain=True)
        log.debug(f"[CMD] {key} -> {'ON' if desired_on else 'OFF'} (grace {grace}s)")
    Bridge._send_cmd = _send_cmd

    def _send_charging_limit(self, pct: int):
        """Invia ac_charging_limit (0-100%) via BUS frame.

        Struttura catturata da Frida:
          AA AA 00 09 [seq:1] [pkt:2] 00 14 00 A2 00 [pct:1]
        Dove pct è direttamente la percentuale decimale (0x00–0x64).
        """
        if OBSERVER_ONLY:
            log.debug("[CMD] OBSERVER_ONLY — ac_charging_limit ignorato")
            return

        pct = max(0, min(100, int(pct)))

        seq = getattr(self, "_chglimit_seq", None)
        if seq is None:
            seq = 0x4E  # valore app-like iniziale
        else:
            seq = (seq + 1) & 0xFF
        self._chglimit_seq = seq

        pkt = getattr(self, "_chglimit_pkt", None)
        if pkt is None:
            pkt = 0x0E8A  # valore app-like iniziale
        else:
            pkt = (pkt + 1) & 0xFFFF
        self._chglimit_pkt = pkt

        frame = (
            b"\xAA\xAA"
            + b"\x00\x09"
            + bytes([seq])
            + pkt.to_bytes(2, "big")
            + b"\x00\x13"
            + b"\x00\xA2"
            + b"\x00"
            + bytes([pct])
        )

        self._route_and_publish(frame)
        log.debug(f"[CMD] ac_charging_limit -> {pct}% hex={frame.hex()}")
    Bridge._send_charging_limit = _send_charging_limit

    return Bridge