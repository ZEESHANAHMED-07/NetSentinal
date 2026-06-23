# NetSentinel Configuration

NETWORK_INTERFACE = 'Wi-Fi'

# Detection thresholds
SYN_FLOOD_THRESHOLD = 100
ICMP_FLOOD_THRESHOLD = 50
PORT_SCAN_THRESHOLD = 15
ARP_SPOOF_CHECK = True
DNS_AMP_THRESHOLD = 10

# Logging
DB_PATH = 'data/netsentinel.db'
LOG_LEVEL = 'INFO'

# API
API_HOST = '127.0.0.1'
API_PORT = 8002

# Report output
REPORT_OUTPUT_DIR = 'reports/'

# API Security Authentication
API_KEY = 'netsentinel_secure_token_123'

