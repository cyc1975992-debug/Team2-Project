# 간단한 네트워크 패킷 스니퍼
# 차단학고 싶은 IP 설정(ACL 규칙)
# 터미널 글자 색깔 지정
from pickle import REDUCE

from scapy.all import sniff, IP, TCP, ICMP
import sys
import logging
import os
from datetime import datetime
import csv
from collections import defaultdict
import subprocess
import time

# ICMP 패킷 하나 생성하고 전송
# packet = IP(dst ="211.248.187.20") /ICMP()
# for _ in range(4):
#     send(packet)
#
# # TCP로 SYN 하나 생성하고 전송
# packet = IP(dst="211.248.187.20") / TCP(dport=80, flags="S")
# for _ in range(4):
#     send(packet)

# 터미널 색상 지정(ANCI Code)
# 이스케이프 시퀀스로 색상 지정 :ESC[코드m
#\0는 8진수, 33는 아스키코드의 27->27, 제어명령 시작을 알림
# m:색상 SGR 형식(색상 굵기 밑줄 반전)으로 표기
RED = '\033[91m' #\0는 8진수, 33는 아스키코드의 27
GREEN= '\033[92m'
RESET= '\033[0m'

icmp_count = defaultdict(int)
syn_count = defaultdict(int)
# 패킷이 캡쳐될 때마다 호출되는 함수
# def process_packet(packet):
#     # 1. IP 레이어가 있는 확인
#     # 네트워크에는 IP가 없는 패킷도 존재할 수 있음 - 주의 요망!
#     if packet.haslayer(IP):
#         ip_src = packet[IP].src
#         icmp_count[ip_src] += 1
#
#         if syn_count[ip_src] > BLOCK_THRESHOLD:
#             print(f"{RED}" + "="*50)
#             print(f"[!!!경고!!!] 차단된 IP가 감지되었습니다!!")
#             print(f"{RED}" + "="*50 + f"{RESET}")
#             logging.warning(f"SYN 패킷 과다 | IP={ip_src}")

# def block_ip(ip):
#     subprocess.run(
#         ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
#         check=True
#     )
#     print(f"{RED}" + "="*50)
#     print(f"[!!!경고!!!] 의심스런 IP가 감지되었습니다!!")
#     print(f"{RED}" + "="*50 + f"{RESET}")
if __name__ == "__main__":
    print(">>> 패킷 감시를 시작합니다...(중지는 Ctrl+C)")

    # sniff : 패킷을 낚아채는 함수
    # filter : 낚아챌 패킷 지정
    # prn : 패킷을 잡을 때마다 호출할 함수 지정
    # store : 잡은 패킷을 메모리에 저장하지 않음(메모리 부족 방지)

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    filename="logs/icmp.log",
    level=logging.WARNING,
    format="%(asctime)s | %(levelname)s | %(message)s",
    encoding="utf-8"
)

def detect_icmp(packet):
    if packet.haslayer(ICMP):
        ip_src = packet[IP].src
        icmp_count[ip_src] += 1

        if icmp_count[ip_src] > 5:
            print(f"{RED}" + "="*50)
            print(f"[ICMP 과다] 의심스런 IP가 감지되었습니다!!")
            print(f"{RED}" + "="*50 + f"{RESET}")
            logging.warning(f"IP={ip_src}")

sniff(filter="icmp", prn=detect_icmp,store=0)

def detect_tcp(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == "S":
        ip_src = packet[IP].src
        syn_count[ip_src] += 1

        if syn_count[ip_src] > 2:
            print(f"SYN 패킷 과다 → {packet[IP].src}")
            logging.warning(f"IP={ip_src}")
sniff(filter="tcp", prn=detect_tcp, store=0)



    # else:
    #     print(f"[기타 IP패킷] {ip_src}->{ip_dst}")

# # 차단하고 싶은 IP 지정(ACL)
# BLOCKED_IP = "8.8.8.8"
# # BLOCKED_IP = "210.115.158.17"
#
# # 패킷이 캡쳐될 때마다 호출되는 함수
# def process_packet(packet):
#     # 1. IP 레이어가 있는 확인
#     # 네트워크에는 IP가 없는 패킷도 존재할 수 있음 - 주의 요망!
#     if packet.haslayer(IP):
#
#         # IP 헤더에서 출발지/도착지 IP 주소 축출(프로토콜 번호도 함께)
#         ip_src = packet[IP].src
#         ip_dst = packet[IP].dst
#
#
#         # 2. 출발 IP가 우리가 지정한 차단 IP와 같다면
#
#         if ip_src == BLOCKED_IP:
#             print(f"{RED}" + "="*50)
#             print(f"[!!!경고!!!] 차단된 IP가 감지되었습니다!!")
#             print(f"{RED}" + "="*50 + f"{RESET}")
#             # 정상 패킷이면
#             if packet.haslayer(TCP):
#                 print(f"포트정보:{packet[TCP].sport}->{packet[TCP].dport}")
#                 print(f"{GREEN} [통과 패킷] {ip_src} -> {ip_dst} {RESET}")
#                 # SYN만 켜져 있는 경우
#                 if tcp.flags == "S":
#                     print(f"[SYN] Port Scan 의심 → {packet[IP].src}")
#         else:
#             print(f"[기타 IP패킷] {ip_src}->{ip_dst}")
#


# 메인 실행 부분 - 프로그램의 시작점(실행 진입점)
# 현재 파이썬 파일을 직접호출했을 때만 실행되게 하고
# import 했을 때는 자동으로 실행되지 않게 하기 위한 코드

# if __name__ == "__main__":
#     print(">>> 패킷 감시를 시작합니다...(중지는 Ctrl+C)")
#
#     # sniff : 패킷을 낚아채는 함수
#     # filter : 낚아챌 패킷 지정
#     # prn : 패킷을 잡을 때마다 호출할 함수 지정
#     # store : 잡은 패킷을 메모리에 저장하지 않음(메모리 부족 방지)
#     sniff(filter="icmp", prn=detect)
#     sniff(filter="tcp", prn=detect)



# BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# LOG_DIR = os.path.join(BASE_DIR, "logs")
# LOG_FILE = os.path.join(LOG_DIR, "app.log")
# 로그 설정
# logging.basicConfig(
#     filename=logging.log,
#     level=logging.warning,
#     format='%(asctime)s | %(levelname)s | %(message)s'

# def block_ip(ip, reason):
#     # 실제 차단 로직 (예: iptables, firewall, 리스트 등록 등)
#     print(f"[BLOCK] {ip} 차단됨")
#
#     # 로그 기록
#     logging.info(f"사유={reason}")


# def log_to_csv(ip, reason):
#     with open('blocked_ips.csv', 'a', newline='') as f:
#         writer = csv.writer(f)
#         writer.writerow([datetime.now(), ip, reason])

# 
# def log_to_sql_file(ip, reason):
#     with open("blocked_ips.sql", "a", encoding="utf-8") as f:
#         f.write(
#             f"INSERT INTO blocked_ips (time, reason),ip "
#             f"VALUES ('{datetime.now().isoformat()}','{reason}, '{ip}'');\n"
#         )
