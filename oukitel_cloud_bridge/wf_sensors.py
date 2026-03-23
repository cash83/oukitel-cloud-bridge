# Auto-split from original bridge.py
# Module: wf_sensors — Oukitel variant
# Sensor mappings adapted for Oukitel power stations (Acceleronix / Wonderfree backend).
# Keys differ from the Wonderfree device: flat top-level keys + nested ac_data/dc_data/usb_data/typec_data.
from __future__ import annotations

from wf_config import * # noqa: F403,F401
from wf_config import OBSERVER_ONLY
import os
import json
import time
import random
import threading
import hashlib
from typing import Any, Dict, Optional

import requests

from wf_crypto import normalize_bearer


def _num(v):
    """Convert various numeric-ish values to int/float safely.
    Returns None if conversion fails or input is None/empty.
    """
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return v
    try:
        s = str(v).strip()
        if s == "" or s.lower() in ("none", "null", "nan"):
            return None
        # handle commas as decimal separators
        s = s.replace(",", ".")
        f = float(s)
        # if it's an integer-like float, return int to keep JSON compact
        return int(f) if f.is_integer() else f
    except Exception:
        return None

# Opzione: pulizia retained all'avvio (se non definita in wf_config)
try:
    CLEAR_RETAINED  # type: ignore[name-defined]
except Exception:
    CLEAR_RETAINED = os.getenv("CLEAR_RETAINED", "0").strip() in ("1", "true", "yes", "on")


def attach(Bridge):
    def start(self):
        self.token_mgr.ensure()
        self._connect_local()

        if CLEAR_RETAINED and self.local:
            log.debug('[INIT] Clearing retained under state/* and JSON topics')
            self._clear_retained()

        self._connect_remote()

        threading.Thread(target=self._poll_loop, daemon=True).start()
        threading.Thread(target=self._watchdog_loop, daemon=True).start()

        log.debug(
            f"FINAL (Verbose + Beep) bridge started. "
            f"SEND_STRATEGY={SEND_STRATEGY.upper()} DEDUP_MS={DEDUP_MS} STALE_SEC={STALE_SEC}"
        )
    Bridge.start = start

    def _get_first(self, kv: dict, *candidates, default=None):
        for c in candidates:
            if c in kv and kv[c] is not None:
                return kv[c]
        return default
    Bridge._get_first = _get_first

    def _bus_chan(self) -> int:
        """Ritorna il 'channel' word osservato nei frame BUS.

        Dai tuoi log:
          - topic q/1/... usa 0x0013
          - topic q/2/... usa 0x0014
        """
        try:
            t = BUS_TOPIC  # noqa: F405
            return 0x0013 if str(t).startswith("q/1/") else 0x0014
        except Exception:
            return 0x0014

    Bridge._bus_chan = _bus_chan

    def _publish_bus_frame(self, frame: bytes):
        """Pubblica un frame BUS sul topic principale (q/1).

        Dalla Frida, i PUBLISH dell'app vanno SOLO su q/1/.../bus.
        NON inviamo su q/2 per evitare che il device riceva ogni comando due volte,
        il che può causare il freeze del firmware.
        """
        try:
            if getattr(self, "remote", None) is None:
                return

            main_topic = BUS_TOPIC  # noqa: F405
            self.remote.publish(main_topic, payload=frame, qos=0, retain=False)

        except Exception as e:
            log.warning(f"[TX] publish BUS frame failed: {e}")

    Bridge._publish_bus_frame = _publish_bus_frame

    def _send_bus_refresh(self, mode: int = 0x02, throttle_s: float = 30.0):
        """Invia refresh BUS 0x009A *identico a Frida/app*.

        Frida:
          aaaa0009 b3 0004 0013 009a 0002
        Struttura:
          AA AA | 00 09 | SEQ(1) | PKT(2) | CHAN(2) | 00 9A | 00 MODE

        In OBSERVER_ONLY mode non invia nulla.
        """
        if OBSERVER_ONLY:
            return
        try:
            if not hasattr(self, "_next_bus_refresh"):
                self._next_bus_refresh = 0.0

            now = time.time()
            if now < self._next_bus_refresh:
                return

            # SEQ: 1 byte incrementale
            seq = getattr(self, "_bus_seq", None)
            if seq is None:
                seq = 0xB3  # app-like start
            else:
                seq = (seq + 1) & 0xFF
            self._bus_seq = seq

            # PKT: 2 byte incrementali (Frida: 0004, 0005...)
            pkt = getattr(self, "_bus_pkt", None)
            if pkt is None:
                pkt = 0x0004  # app-like start
            else:
                pkt = (pkt + 1) & 0xFFFF
            self._bus_pkt = pkt

            chan = self._bus_chan()

            frame = (
                b"\xAA\xAA" +
                b"\x00\x09" +
                bytes([seq]) +
                pkt.to_bytes(2, "big") +
                chan.to_bytes(2, "big") +
                b"\x00\x9A" +
                bytes([0x00, mode & 0xFF])
            )

            self._publish_bus_frame(frame)

            log.debug(f"[TX] BUS refresh sent chan=0x{chan:04x} mode=0x{mode:02x} hex={frame.hex()}")
            self._next_bus_refresh = now + float(throttle_s)
        except Exception as e:
            log.warning(f"[TX] BUS refresh failed: {e}")

    Bridge._send_bus_refresh = _send_bus_refresh


    def _send_bus_mask_0011(self, ids, throttle_s: float = 3600.0):
        """Invia frame BUS 0x0011 (mask/list) come da Frida.

        Frida esempio (len=0x0041):
          AA AA 00 41 49 0003 0011 <lista 2-byte ids...>
        Qui:
          - SEQ: 1 byte
          - PKT: 2 byte
          - CMD: 0x0011
          - PAYLOAD: ids (ognuno 2 byte big endian)
        """
        try:
            if not hasattr(self, "_next_bus_mask"):
                self._next_bus_mask = 0.0

            now = time.time()
            if now < self._next_bus_mask:
                return

            seq = getattr(self, "_mask_seq", None)
            if seq is None:
                seq = 0x49  # app-like start
            else:
                seq = (seq + 1) & 0xFF
            self._mask_seq = seq

            pkt = getattr(self, "_mask_pkt", None)
            if pkt is None:
                pkt = 0x0003  # app-like start
            else:
                pkt = (pkt + 3) & 0xFFFF
            self._mask_pkt = pkt

            ids_bytes = b"".join(int(x).to_bytes(2, "big") for x in (ids or []))
            # length = 1(seq) + 2(pkt) + 2(cmd) + payload_len
            ln = 1 + 2 + 2 + len(ids_bytes)

            frame = b"\xAA\xAA" + ln.to_bytes(2, "big") + bytes([seq]) + pkt.to_bytes(2, "big") + b"\x00\x11" + ids_bytes

            self._publish_bus_frame(frame)

            log.debug(f"[TX] BUS mask 0x0011 sent ids={len(ids or [])} len=0x{ln:04x} hex={frame.hex()}")
            self._next_bus_mask = now + float(throttle_s)
        except Exception as e:
            log.warning(f"[TX] BUS mask 0x0011 failed: {e}")

    Bridge._send_bus_mask_0011 = _send_bus_mask_0011

    def _maybe_send_periodic_mask(self, throttle_s: Optional[float] = None):
        """Invia il frame mask 0x0011 periodicamente per imitare meglio l'app.

        L'app tende a reinviare la mask quando la sessione è attiva; qui lo facciamo
        in modo molto conservativo per evitare raffiche inutili.
        In OBSERVER_ONLY mode non invia nulla.
        """
        try:
            if OBSERVER_ONLY:
                return False
            if DISABLE_STARTUP_MASK:
                return False
            if throttle_s is None:
                throttle_s = float(MASK_REFRESH_INTERVAL)
            self._send_bus_mask_0011(
                [0x001e,0x0027,0x0021,0x001c,0x0020,0x0026,0x0022,0x001f,0x000b,0x001d,0x0010,0x0011,0x000d,0x002f,0x000a,0x0005,0x0008,0x0009,0x0003,0x0006,0x0002,0x001b,0x0010,0x0001,0x000f,0x000c,0x0011,0x000e,0x0012,0x0004],
                throttle_s=float(throttle_s),
            )
            return True
        except Exception:
            return False
    Bridge._maybe_send_periodic_mask = _maybe_send_periodic_mask

    def _poll_loop(self):
        sess = requests.Session()
        for k, v in APP_HEADERS.items():
            sess.headers[k] = v

        last_digest = None
        consecutive_errors = 0
        max_errors = 3

        while not self.stop.is_set():
            now = time.time()
            if now - self.start_t <= STARTUP_BURST_SECONDS:
                period = STARTUP_BURST_PERIOD
            else:
                period = self.adaptive_period

            did_refresh = False

            # throttle per warning/errore HTTP, per non "spammare" i log
            if not hasattr(self, "_rt_last_warn_no_data"):
                self._rt_last_warn_no_data = 0.0
            if not hasattr(self, "_rt_last_warn_http"):
                self._rt_last_warn_http = 0.0

            try:
                # Aggiorna token se necessario
                tok = self.token_mgr.ensure()
                sess.headers["Authorization"] = normalize_bearer(tok)

                # App-like BUS mask (0x0011) + refresh (0x009A0002) per stimolare il BURST.
                # IMPORTANTISSIMO: niente "mitragliate".
                if not getattr(self, "_startup_bus_done", False) and (time.time() - self.start_t < 15):
                    self._startup_bus_done = True

                    # 1) mask (opzionale)
                    if not DISABLE_STARTUP_MASK:
                        self._maybe_send_periodic_mask(throttle_s=3600.0)

                    # 2) startup refresh: pochi, con jitter e gap minimo
                    cnt = max(0, int(STARTUP_REFRESH_COUNT))
                    if cnt:
                        for i in range(cnt):
                            self._send_bus_refresh(mode=0x02, throttle_s=0.0)
                            did_refresh = True
                            if i < cnt - 1:
                                jitter = max(0, int(STARTUP_REFRESH_JITTER_MS)) / 1000.0
                                time.sleep(max(float(REFRESH_MIN_GAP), 1.0) + random.uniform(0.0, jitter))

                    self._next_periodic_refresh = time.time() + random.uniform(float(REFRESH_MIN), float(REFRESH_MAX))

                else:
                    # refresh periodico BUS 0x009A mode=0x02
                    now = time.time()
                    burst_until = getattr(self, "_burst_until", 0.0)

                    if not hasattr(self, "_next_refresh_02"):
                        self._next_refresh_02 = now + random.uniform(float(REFRESH_MIN), float(REFRESH_MAX))

                    if not hasattr(self, "_next_any_refresh"):
                        self._next_any_refresh = 0.0

                    can_send = (now >= float(burst_until)) and (now >= float(self._next_any_refresh))

                    if can_send and now >= float(getattr(self, "_next_refresh_02", now + 1e9)):
                        self._maybe_send_periodic_mask()
                        self._send_bus_refresh(mode=0x02, throttle_s=0.0)
                        did_refresh = True
                        self._next_refresh_02 = now + random.uniform(float(REFRESH_MIN), float(REFRESH_MAX))
                        self._next_any_refresh = now + max(float(REFRESH_MIN_GAP), 1.0)

                if did_refresh:
                    delay_s = max(0.0, float(REFRESH_HTTP_DELAY_MS) / 1000.0)
                    if delay_s > 0:
                        time.sleep(delay_s)

                # Se onl_ ha dichiarato il device offline, salta HTTP completamente:
                # evita spam al cloud e il BUS refresh mantiene viva la sessione WebSocket.
                # onl_ value=1 notificherà l'accensione in tempo reale.
                if getattr(self, '_device_force_offline', False):
                    time.sleep(float(period))
                    continue

                # Salta HTTP solo se: ACK fresco (<30s) E last_publish_ts è recente (<STALE_SEC/2).
                # Se last_publish_ts è vecchio (device potenzialmente offline) HTTP deve girare
                # per ottenere il vero updateTime e far scattare il watchdog correttamente.
                _ack_age   = time.time() - getattr(self, '_last_ack_ts', 0)
                _ts_age    = time.time() - self.last_publish_ts if self.last_publish_ts > 0 else 9999
                if not did_refresh and _ack_age < 30 and _ts_age < (STALE_SEC / 2):
                    time.sleep(float(period))
                    continue

                # Fetch dati real-time (HTTP)
                kv, dev_update, dev_data = self._fetch_attrs_raw(sess)
                if did_refresh and QUICK_REFETCH_AFTER_REFRESH and not kv:
                    time.sleep(max(0.8, float(REFRESH_HTTP_DELAY_MS) / 1000.0))
                    kv, dev_update, dev_data = self._fetch_attrs_raw(sess)

                if kv and self.local:
                    st = self._normalize_state(kv, dev_update)

                    # Enrichment da deviceData (stessa risposta HTTP)
                    try:
                        if dev_data:
                            sig = _num(dev_data.get("signalStrength"))
                            if sig is not None:
                                st["signal_strength"] = sig
                    except Exception:
                        pass

                    self._publish_state(st, kv, debug=True)
                    self._reconcile_switch_states(st)

                    # Logging ridotto per non intasare
                    age = int(time.time()) - int(st.get("updated_at", 0))

                    # Se i dati diventano vecchi, accelera il polling e manda un refresh BUS.
                    if age > STALE_SEC:
                        self.adaptive_period = max(POLL_MIN, 2)
                        now2 = time.time()
                        if now2 >= float(getattr(self, "_next_any_refresh", 0.0)):
                            self._send_bus_refresh(mode=0x02, throttle_s=0.0)
                            self._next_any_refresh = now2 + max(float(REFRESH_MIN_GAP), 1.0)
                            self._next_refresh_02 = min(float(getattr(self, "_next_refresh_02", now2)), now2 + max(float(REFRESH_MIN_GAP), 1.0))

                    if not MUTE_POLL or age > 30:
                        log.debug(
                            f"[REALTIME] battery={st.get('battery_percentage')}% "
                            f"in={st.get('total_input_power')}W "
                            f"out={st.get('total_output_power')}W age={age}s"
                        )

                    # Adaptive polling basato sui cambiamenti
                    st_digest = dict(st)
                    st_digest.pop("updated_at", None)
                    digest = hashlib.md5(json.dumps(st_digest, sort_keys=True).encode()).hexdigest()
                    changed = (digest != last_digest) or (
                        dev_update is not None and dev_update != getattr(self, "_last_dev_update", None)
                    )
                    self._last_dev_update = dev_update
                    last_digest = digest

                    if changed:
                        self.adaptive_period = max(POLL_MIN, 2)
                        consecutive_errors = 0
                    else:
                        self.adaptive_period = min(POLL_MAX, self.adaptive_period + 1)

                else:
                    consecutive_errors += 1
                    tnow = time.time()
                    if (tnow - float(self._rt_last_warn_no_data)) >= 300.0:
                        log.warning("[REALTIME] nessun dato")
                        self._rt_last_warn_no_data = tnow

            except Exception as e:
                consecutive_errors += 1

                if isinstance(e, requests.exceptions.RequestException) or "RemoteDisconnected" in repr(e):
                    try:
                        sess.close()
                    except Exception:
                        pass
                    sess = requests.Session()
                    for k, v in APP_HEADERS.items():
                        sess.headers[k] = v

                tnow = time.time()
                if (tnow - float(self._rt_last_warn_http)) >= 300.0:
                    log.warning(f"[REALTIME] Fetch error: {e!r}")
                    self._rt_last_warn_http = tnow
                else:
                    log.debug(f"[REALTIME] Fetch error (throttled): {e!r}")

            finally:
                if consecutive_errors >= max_errors:
                    time.sleep(min(5.0, float(period)))
                else:
                    time.sleep(float(period))
    Bridge._poll_loop = _poll_loop

    def _parse_customize_tsl(self, tsl_list):
        kv = {}
        for item in tsl_list or []:
            code = item.get("resourceCode")
            val = item.get("resourceValce")
            if not code:
                continue

            if isinstance(val, str):
                v = val.strip()
                if v.startswith("{") and v.endswith("}"):
                    try:
                        kv[code] = json.loads(v)
                        continue
                    except Exception:
                        pass
            kv[code] = val

        def _int(n):
            if n in kv:
                try:
                    kv[n] = int(float(kv[n]))
                except Exception:
                    pass

        def _bool(n):
            if n in kv:
                v = str(kv[n]).strip().lower()
                if v in ("true", "1", "on", "yes"):
                    kv[n] = True
                elif v in ("false", "0", "off", "no"):
                    kv[n] = False

        # Oukitel integer fields
        for n in ["device_status", "signal_strength", "remain_time", "remain_charging_time",
                  "total_input_power", "total_output_power", "ac_input", "dc_input",
                  "ACvoltage_Switchover", "Frequency_Switchover", "ac_charging_limit", "Parallel"]:
            _int(n)

        # Oukitel boolean fields
        for n in ["ac_switch", "dc_switch", "usb_switch", "Fan_Switch"]:
            _bool(n)

        # Nested dicts: normalise numeric values
        for key in ("ac_data", "dc_data", "usb_data", "typec_data"):
            if isinstance(kv.get(key), dict):
                for k in list(kv[key].keys()):
                    kv[key][k] = _num(kv[key][k])

        return kv
    Bridge._parse_customize_tsl = _parse_customize_tsl

    def _publish_state(self, st: Dict[str, Any], raw: Dict[str, Any], debug: bool = True):
        changed_only = PUBLISH_ONLY_CHANGED
        try:
            # Il topic JSON aggregato viene pubblicato sempre (è usato da tutti i sensori via value_template)
            self.local.publish(SENSOR_JSON_TOPIC, json.dumps(st).encode(), qos=0, retain=True)
            if isinstance(raw, dict):
                self.local.publish(SENSOR_JSON_RAW_TOPIC, json.dumps(raw).encode(), qos=0, retain=True)

            for k, v in st.items():
                t = f"{SENSOR_BASE_TOPIC}/{k}"
                if v is None:
                    payload = b""
                elif isinstance(v, (dict, list)):
                    payload = json.dumps(v).encode()
                else:
                    payload = str(v).encode()

                if changed_only and self._last_published.get(t) == payload:
                    continue
                self._last_published[t] = payload
                self.local.publish(t, payload, qos=0, retain=True)

            # bridge health
            uptime_min = int((time.time()-self.start_t)/60)
            self.local.publish(f"{SENSOR_BASE_TOPIC}/bridge_uptime", str(uptime_min).encode(), qos=0, retain=True)
            self.local.publish(f"{SENSOR_BASE_TOPIC}/bridge_relogins", b"0", qos=0, retain=True)
            ts_val = int(st.get("updated_at") or 0)
            if ts_val > 0 and not getattr(self, '_device_force_offline', False):
                self.last_publish_ts = ts_val

            if debug:
                try:
                    snap = {k: st.get(k) for k in [
                        "updated_at", "battery_percentage", "temp",
                        "total_input_power", "total_output_power",
                        "ac_input", "dc_input", "remain_time"
                    ]}
                    self.local.publish(SENSOR_DEBUG_TOPIC, json.dumps(snap).encode(), qos=0, retain=True)
                except Exception:
                    pass

        except Exception:
            pass
    Bridge._publish_state = _publish_state

    def _normalize_state(self, kv: Dict[str, Any], dev_update) -> Dict[str, Any]:
        """Normalize Oukitel device data to HA-publishable state dict.

        Oukitel key mapping (from Acceleronix/Wonderfree backend):
          battery_percentage       → Battery Capacity (%)
          remain_time              → Remaining Available Time (min) — raw
          remain_time_h            → Remaining Available Time (h) — derived
          remain_charging_time     → Remaining Charging Time (min)
          temp                     → Device Temperature (°C)
          total_input_power        → Total Input Power (W)
          total_output_power       → Total Output Power (W)
          ac_input                 → AC Charging Input (W)
          dc_input                 → PV Solar Input (W)
          ac_data.ac1_output       → AC1 Output Power (W)
          ac_data.ac1_output_voltage → AC1 Output Voltage (V)
          dc_data.car1_output      → 12V Output Power (W)
          dc_data.watt_24v         → 24V Output Power (W)
          usb_data.USB_A_output    → USB-A Output (W)
          usb_data.USB_QC1_output  → USB-C1 Output (W)
          usb_data.USB_QC2_output  → USB-C2 Output (W)
          typec_data.Typec1_output → TypeC1 Output (W)
          typec_data.Typec2_output → TypeC2 Output (W)
          ac_switch                → AC Switch (bool)
          dc_switch                → DC Switch (bool)
          usb_switch               → USB Switch (bool)
          Fan_Switch               → Cooling Fan (bool)
          ACvoltage_Switchover     → Output Voltage Setting (V)
          Frequency_Switchover     → Output Frequency Setting (Hz)
          ac_charging_limit        → Max AC Charging (%)
          Parallel                 → Parallel Units
        """
        st: Dict[str, Any] = {}

        # ---- Battery ----
        st["battery_percentage"] = _num(kv.get("battery_percentage"))

        # remaining_time in minutes (raw); derive hours
        raw_remain = _num(kv.get("remain_time"))
        # 65535 (0xFFFF) = sentinel "not available"
        if raw_remain is not None and raw_remain < 65535:
            st["remain_time"] = raw_remain
            st["remain_time_h"] = round(raw_remain / 60, 2)
        else:
            st["remain_time"] = 0
            st["remain_time_h"] = 0

        # remaining charging time (minutes, raw)
        raw_chg = _num(kv.get("remain_charging_time"))
        if raw_chg is not None and raw_chg < 65535:
            st["remain_charging_time"] = raw_chg
        else:
            st["remain_charging_time"] = 0

        # ---- Temperature ----
        st["temp"] = _num(kv.get("temp"))

        # ---- Power inputs ----
        st["ac_input"]  = _num(kv.get("ac_input"))   # AC Charging Input (W)
        st["dc_input"]  = _num(kv.get("dc_input"))   # PV Solar Input (W)

        # total_input_power: prefer explicit cloud value, fallback to sum
        tip = _num(kv.get("total_input_power"))
        if tip is not None:
            st["total_input_power"] = tip
        else:
            _ac_in = st.get("ac_input") or 0
            _dc_in = st.get("dc_input") or 0
            st["total_input_power"] = round(_ac_in + _dc_in, 2)

        # ---- AC output block ----
        ad = kv.get("ac_data") or {}
        st["ac1_output"]         = _num(ad.get("ac1_output"))          # AC1 Output Power (W)
        st["ac1_output_voltage"] = _num(ad.get("ac1_output_voltage"))  # AC1 Output Voltage (V)

        # ---- DC output block ----
        dd = kv.get("dc_data") or {}
        st["car1_output"] = _num(dd.get("car1_output"))  # 12V Output Power (W)
        st["watt_24v"]    = _num(dd.get("watt_24v"))     # 24V Output Power (W)

        # ---- USB output block ----
        ud = kv.get("usb_data") or {}
        st["usb_a_output"]   = _num(ud.get("USB_A_output"))   # USB-A Output (W)
        st["usb_qc1_output"] = _num(ud.get("USB_QC1_output")) # USB-C1 Output (W)
        st["usb_qc2_output"] = _num(ud.get("USB_QC2_output")) # USB-C2 Output (W)

        # ---- TypeC output block ----
        td = kv.get("typec_data") or {}
        st["typec1_output"] = _num(td.get("Typec1_output"))  # TypeC1 Output (W)
        st["typec2_output"] = _num(td.get("Typec2_output"))  # TypeC2 Output (W)

        # ---- Total output power ----
        top = _num(kv.get("total_output_power"))
        if top is not None:
            st["total_output_power"] = top
        else:
            _ac1_out   = st.get("ac1_output") or 0
            _car1      = st.get("car1_output") or 0
            _w24v      = st.get("watt_24v") or 0
            _usb_a     = st.get("usb_a_output") or 0
            _usb_qc1   = st.get("usb_qc1_output") or 0
            _usb_qc2   = st.get("usb_qc2_output") or 0
            _typec1    = st.get("typec1_output") or 0
            _typec2    = st.get("typec2_output") or 0
            st["total_output_power"] = round(
                _ac1_out + _car1 + _w24v + _usb_a + _usb_qc1 + _usb_qc2 + _typec1 + _typec2, 2
            )

        # ---- Switches ----
        st["ac_switch"]   = kv.get("ac_switch")    # AC Switch (bool)
        st["dc_switch"]   = kv.get("dc_switch")    # DC Switch (bool)
        st["usb_switch"]  = kv.get("usb_switch")   # USB Switch (bool)
        st["fan_switch"]  = kv.get("Fan_Switch")   # Cooling Fan (bool)

        # ---- Settings ----
        st["ac_voltage_switchover"]  = _num(kv.get("ACvoltage_Switchover"))  # Output Voltage Setting (V)
        st["frequency_switchover"]   = _num(kv.get("Frequency_Switchover"))  # Output Frequency Setting (Hz)
        st["ac_charging_limit"]      = _num(kv.get("ac_charging_limit"))     # Max AC Charging (%)
        st["parallel"]               = _num(kv.get("Parallel"))              # Parallel Units

        # ---- Signal strength (enriched later from deviceData) ----
        st["signal_strength"] = _num(kv.get("signal_strength"))

        # ---- Debug power components ----
        st["_debug_power_components"] = {
            "input": {
                "ac": st.get("ac_input"),
                "dc_pv": st.get("dc_input"),
            },
            "output": {
                "ac1": st.get("ac1_output"),
                "car1_12v": st.get("car1_output"),
                "watt_24v": st.get("watt_24v"),
                "usb_a": st.get("usb_a_output"),
                "usb_qc1": st.get("usb_qc1_output"),
                "usb_qc2": st.get("usb_qc2_output"),
                "typec1": st.get("typec1_output"),
                "typec2": st.get("typec2_output"),
            }
        }

        st["updated_at"] = int(dev_update) if dev_update else 0
        st["_ts"] = int(time.time())  # cambia sempre → forza HA ad aggiornare il timestamp "X secondi fa"
        return st

    Bridge._normalize_state = _normalize_state


    def _reconcile_switch_states(self, st: Dict[str, Any]):
        """Pubblica SEMPRE gli stati reali del cloud sui topic HA.

        - Così Home Assistant segue l'app (e viceversa).
        - La logica "pending" serve solo a:
          1) evitare flicker immediato dopo un comando HA
          2) chiudere il pending quando il cloud conferma.
        """
        now = time.time()

        def _as_bool(v):
            if v is None:
                return None
            if isinstance(v, bool):
                return v
            if isinstance(v, (int, float)):
                return v != 0
            s = str(v).strip().lower()
            if s in ("1", "true", "on", "yes"):
                return True
            if s in ("0", "false", "off", "no"):
                return False
            return None

        def maybe_pub_bool(key: str, state_topic: str, cloud_val):
            pend = self.pending.get(key)
            cloud_b = _as_bool(cloud_val)

            if cloud_b is not None and self.local:
                self.local.publish(state_topic, b"ON" if cloud_b else b"OFF", qos=0, retain=True)

            if pend and cloud_b is not None:
                desired_b = _as_bool(pend.get("desired"))
                if desired_b is not None and cloud_b == desired_b:
                    self.pending.pop(key, None)

            if pend and now >= pend["until"]:
                self.pending.pop(key, None)

        maybe_pub_bool("ac_switch",  AC_STATE_TOPIC,  st.get("ac_switch"))   # noqa: F405
        maybe_pub_bool("dc_switch",  DC_STATE_TOPIC,  st.get("dc_switch"))   # noqa: F405
        maybe_pub_bool("usb_switch", USB_STATE_TOPIC, st.get("usb_switch"))  # noqa: F405
        maybe_pub_bool("fan_switch", FAN_STATE_TOPIC, st.get("fan_switch"))  # noqa: F405

    Bridge._reconcile_switch_states = _reconcile_switch_states

    # ---- Connectors ----

    def _watchdog_loop(self):
        while not self.stop.is_set():
            try:
                now = int(time.time())
                last_ts    = self.last_publish_ts
                bridge_age = now - int(self.start_t)
                force_off = getattr(self, '_device_force_offline', False)
                is_stale = force_off or (
                    (last_ts > 0 and now - last_ts > STALE_SEC) or
                    (last_ts == 0 and bridge_age > STALE_SEC + 30)
                )
                if is_stale:
                    if self.local:
                        self.local.publish(AVAIL_TOPIC, AVAIL_PAYLOAD_OFF, qos=0, retain=True)
                else:
                    if self.local:
                        self.local.publish(AVAIL_TOPIC, AVAIL_PAYLOAD_ON, qos=0, retain=True)
            except Exception:
                pass

            time.sleep(5)
    Bridge._watchdog_loop = _watchdog_loop

    def run_forever(self):
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            log.debug("Shutting down bridge...")
            self.stop.set()
            if self.local:
                self.local.publish(AVAIL_TOPIC, AVAIL_PAYLOAD_OFF, qos=0, retain=True)
                time.sleep(0.5)
                self.local.disconnect()
            log.debug("Bridge stopped")

    Bridge.run_forever = run_forever
    return Bridge
