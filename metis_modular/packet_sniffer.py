from analyzer.spoof_detection import is_ip_checksum_valid, is_ttl_suspicious, is_ip_reachable
from analyzer.geoip_util import get_country
from analyzer.score_calculator import calculate_threat_score

from logger.log_saver import save_log
from logger.syslog_sender import send_syslog_alert

from sender.unity_sender import send_packet_to_unity, send_live_packet_to_unity, send_scan_alert_to_unity
from sender.stats_sender import send_port_ip_stats, send_threat_scores_to_unity, send_stats_periodically

from config.config_loader import load_config, config_watcher, config, trusted_ips

from scapy.all import sniff, IP
import threading
from datetime import datetime

INTERFACE = "\\Device\\NPF_{23FE3796-0B4B-461E-999E-C711816C4C61}"

def packet_callback(packet):
    try:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            if not is_ip_checksum_valid(packet):
                alert_log = {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "type": "spoof_alert",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "reason": "invalid_checksum",
                    "alert": "IP checksum mismatch detected"
                }
                save_log(alert_log)

            if is_ttl_suspicious(packet):
                alert_log = {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "type": "spoof_alert",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "reason": "suspicious_ttl",
                    "alert": "Suspiciously low TTL value detected"
                }
                save_log(alert_log)

            # ✅ Unity送信するパケット情報（最低限）
            packet_data = {
                "type": "packet",
                "src": src_ip,
                "dst": dst_ip,
                "protocol": "IP",
                "size": len(packet),
                "src_port": None,
                "dst_port": None,
                "payload": None
            }

            print(f"[DEBUG] Unity送信直前: {src_ip} → {dst_ip}")
            send_packet_to_unity(packet_data)

    except Exception as e:
        print(f"[❌] packet_callback error: {e}")

def start_sniffing():
    print("[*] Starting packet sniffing...")
    threading.Thread(target=send_stats_periodically, daemon=True).start()
    sniff(prn=packet_callback, store=False, iface=INTERFACE)

if __name__ == "__main__":
    load_config()
    threading.Thread(target=config_watcher, daemon=True).start()
    save_log({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "test": "Initial log from modular version"
    })
    start_sniffing()
