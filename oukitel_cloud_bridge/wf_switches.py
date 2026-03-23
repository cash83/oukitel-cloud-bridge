# Auto-split from original bridge.py
# Module: wf_switches — Oukitel variant
#
# NOTA: I comandi AC/DC/USB/FAN per Oukitel usano frame HEX diretti sul BUS topic.
# I frame qui sotto sono stati ricavati da reverse engineering del protocollo BLE/BUS.
#
# AC/DC HEX commands not verified - contributions welcome
#
#   AC ON:  AA AA 00 07 74 00 07 00 13 01 59
#   AC OFF: AA AA 00 17 FF 00 0E 00 13 00 34 00 03 00 12 00 00 00 1A 00 00 00 22 00 00 01 58
#   DC ON:  AA AA 00 07 95 00 10 00 13 01 71
#   DC OFF: AA AA 00 2F AE 00 13 00 13 00 4C 00 09 00 12 00 00 00 1A 00 00 00 22 00 00 00 2A 00 00 00 32 00 00 00 3A 00 00 00 42 00 00 00 4A 00 00 00 52 00 00 01 70
#
from __future__ import annotations

import time
import json
import hashlib
from typing import Any

import paho.mqtt.client as mqtt

from wf_config import (
    log,
    DEDUP_MS, SEND_STRATEGY, CMD_GRACE_SECONDS, OBSERVER_ONLY,

    BUS_TOPIC, LOCAL_OUT_PREFIX,

    AC_CMD_TOPIC, AC_STATE_TOPIC,
    DC_CMD_TOPIC, DC_STATE_TOPIC,
    USB_CMD_TOPIC, USB_STATE_TOPIC,
    FAN_CMD_TOPIC, FAN_STATE_TOPIC,

    AC_ON_HEX, AC_OFF_HEX,
    DC_ON_HEX, DC_OFF_HEX,

    hex_bytes,
)

def attach(Bridge):
    def _on_local_message(self, client, userdata, msg):
        t = msg.topic
        p = (msg.payload or b"").decode(errors="ignore").strip()

        if t == AC_CMD_TOPIC:
            on = p.upper() == "ON"
            self._send_cmd(AC_ON_HEX if on else AC_OFF_HEX, "ac_switch", AC_STATE_TOPIC, on, CMD_GRACE_SECONDS)
            return
        if t == DC_CMD_TOPIC:
            on = p.upper() == "ON"
            self._send_cmd(DC_ON_HEX if on else DC_OFF_HEX, "dc_switch", DC_STATE_TOPIC, on, CMD_GRACE_SECONDS)
            return
        if t == USB_CMD_TOPIC:
            on = p.upper() == "ON"
            # USB ON/OFF HEX not verified - contributions welcome
            log.warning(f"[CMD] usb_switch command received but USB HEX not verified - ignoring")
            return
        if t == FAN_CMD_TOPIC:
            on = p.upper() == "ON"
            # Fan ON/OFF HEX not verified - contributions welcome
            log.warning(f"[CMD] fan_switch command received but Fan HEX not verified - ignoring")
            return

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

    return Bridge
