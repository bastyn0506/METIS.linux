from scapy.all import IP, TCP, UDP

def calculate_threat_score(packet, malicious_ips):
    score = 0
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    dst_port = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else None)
    size = len(packet)
    dangerous_ports = set()
    if dst_port in dangerous_ports:
        score += 40
    if size > 1500 or size == 0:
        score += 10
    if src_ip in malicious_ips or dst_ip in malicious_ips:
        score += 60
    return src_ip, score