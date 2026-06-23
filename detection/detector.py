from collections import defaultdict
from datetime import datetime
import time
from config import SYN_FLOOD_THRESHOLD, ICMP_FLOOD_THRESHOLD, PORT_SCAN_THRESHOLD, DNS_AMP_THRESHOLD

class Detector:
    def __init__(self, alert_callback=None):
        self.alert_callback = alert_callback

        # Tracking dictionaries
        self.syn_tracker = defaultdict(list)
        self.icmp_tracker = defaultdict(list)
        self.port_scan_tracker = defaultdict(list)
        self.arp_table = {}
        self.dns_tracker = defaultdict(list)
        self.packet_count = 0

    def analyze(self, packet):
        protocol = packet.get('protocol')
        src_ip = packet.get('src_ip')

        if not src_ip:
            return

        # Periodic cleanup of trackers every 1000 packets to prevent state bloat DoS
        self.packet_count += 1
        if self.packet_count % 1000 == 0:
            self.cleanup_trackers()

        if protocol == 'TCP':
            self.check_syn_flood(packet)
            self.check_port_scan(packet)

        elif protocol == 'ICMP':
            self.check_icmp_flood(packet)

        elif protocol == 'ARP':
            self.check_arp_spoof(packet)

        elif protocol == 'DNS':
            self.check_dns_amplification(packet)

    def cleanup_trackers(self):
        now = time.time()
        
        # Clean SYN tracker
        for ip in list(self.syn_tracker.keys()):
            self.syn_tracker[ip] = [t for t in self.syn_tracker[ip] if now - t < 1]
            if not self.syn_tracker[ip]:
                del self.syn_tracker[ip]

        # Clean ICMP tracker
        for ip in list(self.icmp_tracker.keys()):
            self.icmp_tracker[ip] = [t for t in self.icmp_tracker[ip] if now - t < 1]
            if not self.icmp_tracker[ip]:
                del self.icmp_tracker[ip]

        # Clean Port Scan tracker
        for ip in list(self.port_scan_tracker.keys()):
            self.port_scan_tracker[ip] = [x for x in self.port_scan_tracker[ip] if now - x[1] < 10]
            if not self.port_scan_tracker[ip]:
                del self.port_scan_tracker[ip]

        # Clean DNS tracker
        for ip in list(self.dns_tracker.keys()):
            self.dns_tracker[ip] = [t for t in self.dns_tracker[ip] if now - t < 1]
            if not self.dns_tracker[ip]:
                del self.dns_tracker[ip]

        # Clean ARP table if too large
        if len(self.arp_table) > 1000:
            keys = list(self.arp_table.keys())
            for k in keys[:-500]:
                del self.arp_table[k]

    def check_syn_flood(self, packet):
        flags = packet.get('flags')
        src_ip = packet.get('src_ip')

        # Matches SYN flag presence (ECN/CWR compatible) but ignores SYN-ACK (A present)
        if flags and 'S' in str(flags) and 'A' not in str(flags):
            now = time.time()
            self.syn_tracker[src_ip].append(now)
            self.syn_tracker[src_ip] = [t for t in self.syn_tracker[src_ip] if now - t < 1]

            if len(self.syn_tracker[src_ip]) > SYN_FLOOD_THRESHOLD:
                self.raise_alert('SYN Flood', src_ip, 'HIGH',
                    f'{len(self.syn_tracker[src_ip])} SYN packets/sec detected')

    def check_icmp_flood(self, packet):
        src_ip = packet.get('src_ip')
        now = time.time()
        self.icmp_tracker[src_ip].append(now)
        self.icmp_tracker[src_ip] = [t for t in self.icmp_tracker[src_ip] if now - t < 1]

        if len(self.icmp_tracker[src_ip]) > ICMP_FLOOD_THRESHOLD:
            self.raise_alert('ICMP Flood', src_ip, 'MEDIUM',
                f'{len(self.icmp_tracker[src_ip])} ICMP packets/sec detected')

    def check_port_scan(self, packet):
        src_ip = packet.get('src_ip')
        dst_port = packet.get('dst_port')
        now = time.time()

        if dst_port:
            self.port_scan_tracker[src_ip].append((dst_port, now))

        # Keep only scan attempts in the last 10 seconds
        self.port_scan_tracker[src_ip] = [x for x in self.port_scan_tracker[src_ip] if now - x[1] < 10]

        # Calculate unique ports accessed
        unique_ports = {x[0] for x in self.port_scan_tracker[src_ip]}

        if len(unique_ports) > PORT_SCAN_THRESHOLD:
            self.raise_alert('Port Scan', src_ip, 'MEDIUM',
                f'{len(unique_ports)} unique ports scanned in 10s')
            self.port_scan_tracker[src_ip] = []

    def check_arp_spoof(self, packet):
        src_ip = packet.get('src_ip')
        raw = packet.get('raw')

        try:
            from scapy.layers.l2 import ARP
            if raw.haslayer(ARP):
                mac = raw.getlayer(ARP).hwsrc
                if src_ip in self.arp_table:
                    if self.arp_table[src_ip] != mac:
                        self.raise_alert('ARP Spoofing', src_ip, 'CRITICAL',
                            f'MAC changed from {self.arp_table[src_ip]} to {mac}')
                        return  # Do not update mapping with spoofed MAC to prevent state poisoning
                self.arp_table[src_ip] = mac
        except Exception:
            pass

    def check_dns_amplification(self, packet):
        src_ip = packet.get('src_ip')
        length = packet.get('length', 0)
        now = time.time()

        if length > 512:
            self.dns_tracker[src_ip].append(now)
            self.dns_tracker[src_ip] = [t for t in self.dns_tracker[src_ip] if now - t < 1]

            if len(self.dns_tracker[src_ip]) > DNS_AMP_THRESHOLD:
                self.raise_alert('DNS Amplification', src_ip, 'HIGH',
                    f'{len(self.dns_tracker[src_ip])} large DNS responses/sec')

    def raise_alert(self, attack_type, src_ip, severity, detail):
        alert = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'attack_type': attack_type,
            'src_ip': src_ip,
            'severity': severity,
            'detail': detail
        }
        print(f'[ALERT] [{severity}] {attack_type} from {src_ip} - {detail}')
        if self.alert_callback:
            self.alert_callback(alert)
