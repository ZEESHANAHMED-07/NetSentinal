from scapy.all import sniff, rdpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS
import threading
import queue
from datetime import datetime

class PacketCapture:
    def __init__(self, interface='Wi-Fi', packet_callback=None):
        self.interface = interface
        self.packet_callback = packet_callback
        self.running = False
        self.packet_queue = queue.Queue(maxsize=10000)
        self.worker_thread = None

    def process_packet(self, packet):
        parsed = self.parse_packet(packet)
        if parsed and self.packet_callback:
            self.packet_callback(parsed)

    def parse_packet(self, packet):
        try:
            parsed = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'src_ip': None,
                'dst_ip': None,
                'protocol': None,
                'src_port': None,
                'dst_port': None,
                'flags': None,
                'length': len(packet),
                'raw': packet
            }

            if packet.haslayer(IP):
                parsed['src_ip'] = packet[IP].src
                parsed['dst_ip'] = packet[IP].dst

            if packet.haslayer(TCP):
                parsed['protocol'] = 'TCP'
                parsed['src_port'] = packet[TCP].sport
                parsed['dst_port'] = packet[TCP].dport
                parsed['flags'] = packet[TCP].flags

            elif packet.haslayer(UDP):
                parsed['protocol'] = 'UDP'
                parsed['src_port'] = packet[UDP].sport
                parsed['dst_port'] = packet[UDP].dport

            elif packet.haslayer(ICMP):
                parsed['protocol'] = 'ICMP'

            elif packet.haslayer(ARP):
                parsed['protocol'] = 'ARP'
                parsed['src_ip'] = packet[ARP].psrc
                parsed['dst_ip'] = packet[ARP].pdst

            if packet.haslayer(DNS):
                parsed['protocol'] = 'DNS'

            if parsed['protocol'] is None:
                return None

            return parsed

        except Exception as e:
            print(f'[!] Error parsing packet: {e}')
            return None

    def start_live(self):
        self.running = True
        # Start worker thread to process queued packets asynchronously
        self.worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self.worker_thread.start()

        print(f'[*] Sniffing on interface: {self.interface}')
        try:
            sniff(
                iface=self.interface,
                prn=self._enqueue_packet,
                store=False,
                stop_filter=lambda p: not self.running
            )
        except Exception as e:
            print(f'[!] Sniffing error: {e}')
            self.running = False

    def _enqueue_packet(self, packet):
        try:
            # Non-blocking enqueue to prevent blocking the sniffer loop
            self.packet_queue.put_nowait(packet)
        except queue.Full:
            # Drop packets if the processing queue overflows under heavy load
            pass

    def _worker_loop(self):
        while self.running:
            try:
                # Retrieve packet with a timeout to allow checking self.running status
                packet = self.packet_queue.get(timeout=0.1)
                self.process_packet(packet)
                self.packet_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                print(f'[!] Worker thread error: {e}')

    def start_from_pcap(self, pcap_path):
        print(f'[*] Reading from pcap: {pcap_path}')
        packets = rdpcap(pcap_path)
        for packet in packets:
            self.process_packet(packet)

    def stop(self):
        self.running = False
        if self.worker_thread:
            self.worker_thread.join(timeout=1.0)
        print('[*] Capture stopped.')
