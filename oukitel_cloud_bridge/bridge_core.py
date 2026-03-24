# Auto-split from original bridge.py
# Module: bridge_core
from __future__ import annotations

from wf_config import *
from wf_token import TokenManager

import json
import time
import uuid
import threading
import urllib.parse
from typing import Any, Dict, Optional, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

class Bridge:

    def __init__(self):
        u = urllib.parse.urlparse(ACCEL_URL)
        if u.scheme not in ("ws", "wss"):
            raise ValueError("ACCEL_URL must be ws:// or wss://")
        self.rhost = u.hostname or "iot-south.acceleronix.io"
        self.rport = u.port or (443 if u.scheme == "wss" else 80)
        self.rpath = u.path or "/ws/v2"

        self.token_mgr = TokenManager(WF_EMAIL, WF_PASSWORD, WF_USER_DOMAIN)
        self.remote = None
        self.local  = None
        self.stop = threading.Event()

        self.pending: Dict[str, Dict[str, Any]] = {}
        self.next_poll = time.time()
        self.adaptive_period = POLL_MIN
        self.start_t = time.time()
        self._last_cmd_hash = None
        self._last_cmd_time = 0.0
        self.last_publish_ts = 0
        self._last_published = {}

    def _on_local_connect(self, client, userdata, flags, rc, properties=None):
        if rc != 0:
            log.error(f"LOCAL connect failed rc={rc}")
            return
        log.info(f"LOCAL connected {LOCAL_HOST}:{LOCAL_PORT}")
        client.will_set(AVAIL_TOPIC, AVAIL_PAYLOAD_OFF, retain=True)
        client.publish(AVAIL_TOPIC, AVAIL_PAYLOAD_ON, qos=0, retain=True)

        client.subscribe(f"{HA_BASE}/{DEVICE_KEY}/set/#", qos=0)
        client.subscribe(f"{LOCAL_OUT_PREFIX}#", qos=0)

        base_dev = {
            "identifiers": [f"wonderfree_{DEVICE_KEY}"],
            "manufacturer": "Wonderfree",
            "model": PRODUCT_KEY,
            "name": "Wonderfree Power Station"
        }

        def publish_cfg(topic, payload):
            payload["availability_topic"] = AVAIL_TOPIC
            payload["payload_available"] = AVAIL_PAYLOAD_ON
            payload["payload_not_available"] = AVAIL_PAYLOAD_OFF
            client.publish(topic, json.dumps(payload).encode(), qos=0, retain=True)

        publish_cfg(AC_CFG_TOPIC, {"name":"AC Output","uniq_id":f"wf_ac_{DEVICE_KEY}","cmd_t":AC_CMD_TOPIC,"stat_t":AC_STATE_TOPIC,"pl_on":"ON","pl_off":"OFF","icon":"mdi:power-plug-outline","device":base_dev})
        client.publish(AC_STATE_TOPIC, b"OFF", qos=0, retain=True)
        publish_cfg(DC_CFG_TOPIC, {"name":"DC Output","uniq_id":f"wf_dc_{DEVICE_KEY}","cmd_t":DC_CMD_TOPIC,"stat_t":DC_STATE_TOPIC,"pl_on":"ON","pl_off":"OFF","icon":"mdi:current-dc","device":base_dev})
        client.publish(DC_STATE_TOPIC, b"OFF", qos=0, retain=True)
        publish_cfg(LED_CFG_TOPIC, {"name":"LED","uniq_id":f"wf_led_{DEVICE_KEY}","cmd_t":LED_CMD_TOPIC,"stat_t":LED_STATE_TOPIC,"pl_on":"ON","pl_off":"OFF","icon":"mdi:flashlight","device":base_dev})
        client.publish(LED_STATE_TOPIC, b"OFF", qos=0, retain=True)

        def disc_sensor(obj_id, name, unit=None, device_class=None, state_class=None):
            uniq = f"wonderfree_{DEVICE_KEY}_{obj_id}"
            cfg_topic = f"{DISCOVERY_PREFIX}/sensor/{uniq}/config"
            cfg = {
                "name": name, "uniq_id": uniq,
                "state_topic": SENSOR_JSON_TOPIC,
                "value_template": "{{ value_json.%s }}" % obj_id,
                "device": base_dev,
                "availability_topic": AVAIL_TOPIC,
                "payload_available": AVAIL_PAYLOAD_ON,
                "payload_not_available": AVAIL_PAYLOAD_OFF,
            }
            if unit: cfg["unit_of_measurement"] = unit
            if device_class: cfg["device_class"] = device_class
            if state_class: cfg["state_class"] = state_class
            client.publish(cfg_topic, json.dumps(cfg).encode(), qos=0, retain=True)

        for s in [
            # --- Battery ---
            ("battery_percentage",       "Battery",                      "%",   "battery",         "measurement"),
            ("remain_time",              "Remaining Use Time",           "min", None,              "measurement"),
            ("remain_time_h",            "Remaining Use Time (h)",       "h",   None,              "measurement"),
            ("remain_charging_time",     "Remaining Charge Time",        "min", None,              "measurement"),
            # --- Temperature ---
            ("temp",                     "Device Temperature",           "°C",  "temperature",     "measurement"),
            # --- Power input ---
            ("ac_input",                 "AC Input Power",               "W",   "power",           "measurement"),
            ("dc_input",                 "DC Input Power (Solar)",       "W",   "power",           "measurement"),
            ("total_input_power",        "Total Input Power",            "W",   "power",           "measurement"),
            # --- AC output ---
            ("ac1_output",               "AC1 Output Power",             "W",   "power",           "measurement"),
            ("ac1_output_voltage",       "AC1 Output Voltage",           "V",   "voltage",         "measurement"),
            # --- DC 12V output ---
            ("car1_output",              "12V Output Power",             "W",   "power",           "measurement"),
            ("car1_output_voltage",      "12V Output Voltage",           "V",   "voltage",         "measurement"),
            ("car1_output_current",      "12V Output Current",           "A",   "current",         "measurement"),
            # --- USB output ---
            ("usb_qc1_output",           "USB-A1 Output Power",          "W",   "power",           "measurement"),
            ("usb_qc2_output",           "USB-QC2 Output Power",         "W",   "power",           "measurement"),
            # --- Type-C output ---
            ("typec1_output",            "Type-C1 Output Power",         "W",   "power",           "measurement"),
            ("typec2_output",            "Type-C2 Output Power",         "W",   "power",           "measurement"),
            # --- Total output ---
            ("total_output_power",       "Total Output Power",           "W",   "power",           "measurement"),
            # --- Settings ---
            ("ac_voltage_switchover",    "AC Output Voltage Setting",    "V",   "voltage",         None),
            ("frequency_switchover",     "AC Output Frequency Setting",  None,  None,              None),
            ("ac_charging_limit",        "AC Charging Limit",            "%",   None,              "measurement"),
            ("led_status",               "LED Mode",                     None,  None,              None),
            ("high_frequency_reporting", "High-Rate Reporting Mode",     None,  None,              None),
            # --- Firmware ---
            ("bms_version",              "BMS Firmware Version",         None,  None,              None),
            ("ac_version",               "Inverter Firmware Version",    None,  None,              None),
            # --- Signal ---
            ("signal_strength",          "Signal Strength",              "dBm", "signal_strength", "measurement"),
        ]:
            disc_sensor(*s)

        def publish_cfg2(topic, payload):
            payload["availability_topic"] = AVAIL_TOPIC
            payload["payload_available"] = AVAIL_PAYLOAD_ON
            payload["payload_not_available"] = AVAIL_PAYLOAD_OFF
            client.publish(topic, json.dumps(payload).encode(), qos=0, retain=True)

        publish_cfg2(CHGLIMIT_CFG_TOPIC, {
            "name": "AC Charging Limit",
            "uniq_id": f"wonderfree_{DEVICE_KEY}_ac_charging_limit_ctrl",
            "cmd_t": CHGLIMIT_CMD_TOPIC,
            "stat_t": SENSOR_JSON_TOPIC,
            "val_tpl": "{{ value_json.ac_charging_limit }}",
            "min": CHGLIMIT_MIN,
            "max": CHGLIMIT_MAX,
            "step": CHGLIMIT_STEP,
            "unit_of_measurement": "%",
            "icon": "mdi:battery-charging-50",
            "mode": "slider",
            "device": base_dev,
        })

        # Sensore che mostra la potenza di carica calcolata in watt
        disc_sensor("ac_charging_limit_w", "AC Charging Limit (W)", "W", "power", "measurement")

        publish_cfg2(f"{DISCOVERY_PREFIX}/sensor/wonderfree_{DEVICE_KEY}_bridge_uptime/config", {
            "name": "Bridge Uptime (min)",
            "uniq_id": f"wonderfree_{DEVICE_KEY}_bridge_uptime",
            "state_topic": f"{SENSOR_BASE_TOPIC}/bridge_uptime",
            "unit_of_measurement": "min",
            "state_class": "measurement",
            "device": base_dev,
        })
        publish_cfg2(f"{DISCOVERY_PREFIX}/sensor/wonderfree_{DEVICE_KEY}_bridge_relogins/config", {
            "name": "Bridge Relogins",
            "uniq_id": f"wonderfree_{DEVICE_KEY}_bridge_relogins",
            "state_topic": f"{SENSOR_BASE_TOPIC}/bridge_relogins",
            "device": base_dev,
        })

    def _fetch_attrs_raw(self, session: requests.Session):
        url = f"{REALTIME_ATTRS_URL}?dk={DEVICE_KEY}&pk={PRODUCT_KEY}&_t={int(time.time()*1000)}"

        if not getattr(session, "_wf_retry_configured", False):
            try:
                retry = Retry(
                    total=2, connect=2, read=2, backoff_factor=0.3,
                    status_forcelist=(502, 503, 504),
                    allowed_methods=frozenset(["GET"]), raise_on_status=False,
                )
                adapter = HTTPAdapter(max_retries=retry, pool_connections=2, pool_maxsize=2)
                session.mount("https://", adapter)
                session.mount("http://", adapter)
            except Exception:
                pass
            session._wf_retry_configured = True

        timeout = float(HTTP_TIMEOUT) if HTTP_TIMEOUT else 10.0

        if not hasattr(self, "_rt_fail_count"):
            self._rt_fail_count = 0
            self._rt_last_warn = 0.0

        for attempt in (0, 1):
            try:
                headers = {"Connection": "close"} if attempt == 1 else None
                r = session.get(url, timeout=timeout, headers=headers)
                r.raise_for_status()
                j = r.json()
                if j.get("code") == 200:
                    data = j.get("data") or {}
                    dev_data = data.get("deviceData") or {}
                    update_time = dev_data.get("updateTime")
                    if update_time and update_time > 1e12:
                        update_time = update_time // 1000
                    # La funzione self._parse_customize_tsl è in wf_sensors, chiamata da qui:
                    kv = self._parse_customize_tsl(data.get("customizeTslInfo") or [])
                    self._rt_fail_count = 0
                    return kv, update_time, dev_data
                return None, None, None
            except Exception as e:
                self._rt_fail_count += 1
                if self._rt_fail_count <= 2:
                    log.debug(f"[REALTIME] Fetch transient error ({type(e).__name__}): {e}")
                else:
                    now = time.time()
                    if now - self._rt_last_warn > 120:
                        log.warning(f"[REALTIME] Fetch error: {e}")
                        log.warning("[REALTIME] nessun dato")
                        self._rt_last_warn = now
                if attempt == 0:
                    time.sleep(0.2)
                    continue
                return None, None, None

    def _clear_retained(self):
        """Pubblica payload vuoto su tutti i topic retained noti.

        HA rimuove automaticamente un'entity quando riceve payload vuoto
        sul suo topic di discovery config (retain=true).
        Copre: state/*, JSON aggregati, debug, availability,
               discovery config sensori attivi, switch/select/number,
               bridge health, e topic legacy di versioni precedenti.
        """
        if not self.local:
            return

        def _pub(t):
            try:
                self.local.publish(t, b"", qos=0, retain=True)
            except Exception:
                pass

        # ── 1. Topic JSON aggregati e debug ──────────────────────────────
        _pub(SENSOR_JSON_TOPIC)
        _pub(SENSOR_JSON_RAW_TOPIC)
        _pub(SENSOR_DEBUG_TOPIC)

        # ── 2. Availability ──────────────────────────────────────────────
        _pub(AVAIL_TOPIC)

        # ── 3. Tutti i topic state/* attualmente noti ─────────────────────
        _state_keys = [
            "battery_percentage",
            "remain_time", "remain_time_h", "remain_charging_time",
            "temp",
            "ac_input", "dc_input", "total_input_power", "total_output_power",
            "ac1_output", "ac1_output_voltage",
            "car1_output", "car1_output_voltage", "car1_output_current",
            "usb_qc1_output", "usb_qc2_output",
            "typec1_output", "typec2_output",
            "ac_voltage_switchover", "frequency_switchover",
            "ac_charging_limit", "led_status",
            "bms_version", "ac_version", "high_frequency_reporting",
            "signal_strength", "updated_at",
            "ac_switch", "dc_switch",
            "bridge_uptime", "bridge_relogins",
        ]
        for k in _state_keys:
            _pub(f"{SENSOR_BASE_TOPIC}/{k}")

        # ── 4. Discovery config switch / number (attivi) ─────────────────
        for cfg_t in (AC_CFG_TOPIC, DC_CFG_TOPIC, LED_CFG_TOPIC, CHGLIMIT_CFG_TOPIC):
            _pub(cfg_t)

        # ── 4b. Discovery config legacy (da rimuovere dal broker) ─────────
        _legacy_cfg = [
            f"{DISCOVERY_PREFIX}/switch/wonderfree_screen/config",
            f"{DISCOVERY_PREFIX}/switch/wonderfree_{DEVICE_KEY}_grid_output/config",
            f"{DISCOVERY_PREFIX}/switch/wonderfree_{DEVICE_KEY}_beep/config",
            f"{DISCOVERY_PREFIX}/switch/wonderfree_{DEVICE_KEY}_slowcharge/config",
            f"{DISCOVERY_PREFIX}/select/wonderfree_mode/config",
            f"{DISCOVERY_PREFIX}/number/wonderfree_{DEVICE_KEY}_output_power_set/config",
        ]
        for t in _legacy_cfg:
            _pub(t)

        # ── 5. Discovery config sensori attivi ───────────────────────────
        _sensor_ids = [
            "battery_percentage",
            "remain_time", "remain_time_h", "remain_charging_time",
            "temp",
            "ac_input", "dc_input", "total_input_power", "total_output_power",
            "ac1_output", "ac1_output_voltage",
            "car1_output", "car1_output_voltage", "car1_output_current",
            "usb_qc1_output", "usb_qc2_output",
            "typec1_output", "typec2_output",
            "ac_voltage_switchover", "frequency_switchover",
            "ac_charging_limit", "led_status",
            "bms_version", "ac_version", "high_frequency_reporting",
            "signal_strength",
            "bridge_uptime", "bridge_relogins",
        ]
        for sid in _sensor_ids:
            uniq = f"wonderfree_{DEVICE_KEY}_{sid}"
            _pub(f"{DISCOVERY_PREFIX}/sensor/{uniq}/config")

        # ── 6. Discovery config topic legacy (vecchie versioni) ───────────
        _legacy_sensor_ids = [
            "battery_total_charged",
            "solar_panel_power_generation",
            "ac_charging_power",
            "dc_charging_power",
        ]
        for sid in _legacy_sensor_ids:
            uniq = f"wonderfree_{DEVICE_KEY}_{sid}"
            _pub(f"{DISCOVERY_PREFIX}/sensor/{uniq}/config")

        # Legacy switch topics senza device_key (alcune versioni vecchie)
        for slug in ("wonderfree_ac", "wonderfree_dc", "wonderfree_led",
                     "wonderfree_screen", "wonderfree_mode"):
            _pub(f"{DISCOVERY_PREFIX}/switch/{slug}/config")
            _pub(f"{DISCOVERY_PREFIX}/select/{slug}/config")

        log.debug("[INIT] _clear_retained: tutti i topic retained puliti")