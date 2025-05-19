from scapy.all import IP, UDP, send

# 故意に間違ったチェックサムを設定
pkt = IP(dst="172.31.2.80", src="192.168.1.123") / UDP(dport=12345, sport=54321)
pkt.chksum = 0x1234  # 不正なチェックサムに書き換え

send(pkt)
