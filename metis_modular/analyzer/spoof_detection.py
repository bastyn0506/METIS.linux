from scapy.all import IP
import subprocess

def is_ip_checksum_valid(pkt):
    if IP in pkt:
        ip = pkt[IP]
        original = ip.chksum
        del ip.chksum
        recalculated = IP(bytes(ip))
        return original == recalculated.chksum
    return True

def is_ttl_suspicious(pkt):
    if IP in pkt:
        ttl = pkt[IP].ttl
        return ttl <= 5
    return False

def is_ip_reachable(ip):
    try:
        result = subprocess.run(
            ["ping", "-n", "1", "-w", "1000", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return result.returncode == 0
    except Exception:
        return False