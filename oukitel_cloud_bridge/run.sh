#!/usr/bin/with-contenv bashio

export WF_EMAIL=$(bashio::config 'wf_email')
export WF_PASSWORD=$(bashio::config 'wf_password')
export APP=$(bashio::config 'app')
export MQTT_HOST=$(bashio::config 'mqtt_host')
export MQTT_PORT=$(bashio::config 'mqtt_port')
export MQTT_USER=$(bashio::config 'mqtt_user')
export MQTT_PASS=$(bashio::config 'mqtt_pass')
export HA_BASE=$(bashio::config 'ha_base')
export DISCOVERY_PREFIX=$(bashio::config 'discovery_prefix')
export LOG_LEVEL=$(bashio::config 'log_level')
export PUBLISH_ONLY_CHANGED=$(bashio::config 'publish_only_changed')
export DEDUP_MS=$(bashio::config 'dedup_ms')
export POLL_MIN=$(bashio::config 'poll_min')
export POLL_MAX=$(bashio::config 'poll_max')
export STALE_SEC=$(bashio::config 'stale_sec')
export SEND_STRATEGY=$(bashio::config 'send_strategy')
export OBSERVER_ONLY=$(bashio::config 'observer_only')
export CLEAR_RETAINED=$(bashio::config 'clear_retained')
export CHGLIMIT_MAX_WATTS=$(bashio::config 'chglimit_max_watts')

exec python3 /app/bridge.py
