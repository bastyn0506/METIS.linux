import requests

UNITY_SERVER_URL = "http://localhost:8765"

def send_packet_to_unity(packet_data):
    try:
        response = requests.post(UNITY_SERVER_URL, json=packet_data)
        print(f"[📤] Unity送信成功（type={packet_data.get('type')}）: {response.status_code}")
    except Exception as e:
        print(f"[!] Packet send error: {e}")

def send_live_packet_to_unity(src_ip, dst_ip):
    try:
        payload = {"type": "live_packet", "src": src_ip, "dst": dst_ip}
        requests.post(UNITY_SERVER_URL, json=payload)
    except Exception as e:
        print(f"[!] Live packet send error: {e}")

def send_scan_alert_to_unity(ip):
    try:
        payload = {"type": "scan_alert", "src_ip": ip}
        requests.post(UNITY_SERVER_URL, json=payload)
    except Exception as e:
        print(f"[!] Scan alert send error: {e}")