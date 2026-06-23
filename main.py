import argparse
import uvicorn
import sys
from config import API_HOST, API_PORT, NETWORK_INTERFACE
from capture.capture import PacketCapture
from detection.detector import Detector
from logger.logger import AlertLogger

def print_banner():
    print('''
    ==========================================
         NetSentinel v1.0 - NIDS
         Made by Zeeshan Ahmed
    ==========================================
    ''')

def main():
    parser = argparse.ArgumentParser(description='NetSentinel - Network Intrusion Detection System')
    parser.add_argument('--interface', '-i', default=NETWORK_INTERFACE)
    parser.add_argument('--mode', '-m', choices=['live', 'report', 'api'], default='live')
    parser.add_argument('--pcap', '-p', default=None)
    args = parser.parse_args()

    print_banner()

    if args.mode == 'live':
        logger = AlertLogger()
        def on_alert(alert):
            logger.log(alert)
        print(f'[*] Starting live capture on interface: {args.interface}')
        detector = Detector(alert_callback=on_alert)
        capture = PacketCapture(interface=args.interface, packet_callback=detector.analyze)
        try:
            if args.pcap:
                capture.start_from_pcap(args.pcap)
            else:
                capture.start_live()
        except KeyboardInterrupt:
            print('\n[*] Stopping NetSentinel...')
            capture.stop()
            logger.close()

    elif args.mode == 'report':
        logger = AlertLogger()
        alerts = logger.get_all()
        stats = logger.get_stats()
        print(f'[*] Found {len(alerts)} alerts in database')
        print('\n[*] Attack breakdown:')
        for s in stats:
            print(f"    {s['attack_type']}: {s['count']} alerts")
        print('\n[*] Recent alerts:')
        for a in alerts[:20]:
            print(f"    [{a['severity']}] {a['attack_type']} from {a['src_ip']} at {a['timestamp']}")
        logger.close()

    elif args.mode == 'api':
        print(f'[*] Starting dashboard at http://{API_HOST}:{API_PORT}')
        print(f'[*] Open your browser at http://127.0.0.1:{API_PORT}')
        try:
            uvicorn.run('api.api:app', host=API_HOST, port=API_PORT, reload=False)
        except KeyboardInterrupt:
            print('\n[*] Shutting down NetSentinel dashboard...')
            sys.exit(0)

if __name__ == '__main__':
    main()
