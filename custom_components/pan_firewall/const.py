"""Constants for the PAN Firewall integration."""

DOMAIN = "pan_firewall"

CONF_HOST = "host"
CONF_PORT = "port"
CONF_USERNAME = "username"
CONF_PASSWORD = "password"
CONF_VSYS = "vsys"
CONF_VERIFY_SSL = "verify_ssl"
CONF_SCAN_INTERVAL = "scan_interval"          # ← NEW

DEFAULT_PORT = 443
DEFAULT_VSYS = "vsys1"
DEFAULT_VERIFY_SSL = True
DEFAULT_SCAN_INTERVAL = 30
MIN_SCAN_INTERVAL = 10
