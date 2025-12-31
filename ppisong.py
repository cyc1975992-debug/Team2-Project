
from scapy.all import sniff, IP, TCP, UDP, ICMP, Fragment
import sys
import logging
import os
from collections import defaultdict
import subprocess
import time

# 터미널 색상 지정(ANCI Code)
# 이스케이프 시P퀀스로 색상 지정 :ESC[코드m
#\0는 8진수, 33는 아스키코드의 27->27, 제어명령 시작을 알림
# m:색상 SGR 형식(색상 굵기 밑줄 반전)으로 표기
RED = '\033[91m' #\0는 8진수, 33는 아스키코드의 27
PURPLE = '\033[92m'
YELLOW = '\033[92m'
RESET= '\033[0m'

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    filename="logs/icmp.log",
    level=logging.WARNING,
    format="%(asctime)s | %(levelname)s | %(message)s",
    encoding="utf-8"
)
icmp_count = defaultdict(int)
def detect_icmp(packet):
    if packet.haslayer(ICMP):
        ip_src = packet[IP].src
        icmp_count[ip_src] += 1

        if icmp_count[ip_src] > 5:
            print(f"{RED}" + "="*50)
            print(f"ICMP 과다] → {packet[IP].src}")
            print(f"{RED}" + "="*50 + f"{RESET}")
            logging.warning(f"IP={ip_src}")


sniff(filter="icmp", prn=detect_icmp,store=0)

syn_count = defaultdict(int)
def detect_tcp(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == "S":
        ip_src = packet[IP].src
        syn_count[ip_src] += 1

        if syn_count[ip_src] > 2:
            print(f"{YELLOW}" + "="*50)
            print(f"SYN 패킷 과다 → {packet[IP].src}")
            print(f"{YELLOW}" + "="*50 + f"{RESET}")
            logging.warning(f"IP={ip_src}")

sniff(filter="tcp", prn=detect_tcp, store=0)


# 단편화 공격탐지
from scapy.all import *
from collections import defaultdict
import time

fragment_count = defaultdict(int)
THRESHOLD = 10   # 동일 IP에서 fragment 10개 이상이면 의심

def detect_fragment_attack(pkt):
    if IP in pkt:
        ip = pkt[IP]
        if ip.flags.MF == 1 or ip.frag > 0:
            fragment_count[ip.src] += 1

            if fragment_count[ip.src] >= THRESHOLD:
                print(f"단편화 공격 의심 from {pkt[IP].src}")
                logging.warning(f"IP={ip.src}")


sniff(filter="ip", prn=detect_fragment_attack, store=0)

# UDP 공격 탐지

udp_count = defaultdict(int)
THRESHOLD = 20   # 일정 시간 내 UDP 20개 이상이면 공격 의심
WINDOW = 5       # 5초 기준

last_reset = time.time()


def detect_udp_attack(pkt):
    global last_reset

    if IP in pkt and UDP in pkt:
        ip_src = pkt[IP].src
        udp_count[ip_src] += 1

        if udp_count[ip_src] >= THRESHOLD:
            print(f"{PURPLE}" + "="*50)
            print(f"UDP 무차별 공격 의심 → {packet[IP].src}")
            print(f"{PURPLE}" + "="*50 + f"{RESET}")
            logging.warning(f"IP={ip_src}")

    # 카운터 주기적 초기화
    # if time.time() - last_reset > WINDOW:
    #     udp_count.clear()
    #     last_reset = time.time()

sniff(filter="udp", prn=detect_udp_attack, store=0)


if __name__ == "__main__":
    print(">>> 패킷 감시를 시작합니다...(중지는 Ctrl+C)")


# def block_ip(ip):
#     subprocess.run(
#         ["iptables", "-A", "INPUT", "-s", ip, "-p", "udp", "-j", "DROP"],
#         stdout=subprocess.DEVNULL,
#         stderr=subprocess.DEVNULL
#     )
#     print(f"[BLOCKED] UDP traffic from {ip}")