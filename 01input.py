from scapy.all import IP, TCP, ICMP, send
# ICMP 패킷 하나 생성하고 전송
packet = IP(dst ="172.30.1.15") /ICMP()
for _ in range(4):
    send(packet)

# TCP로 SYN 하나 생성하고 전송
packet = IP(dst="210.115.158.17") / TCP(dport=80, flags="S")
for _ in range(4):
    send(packet)

# sr1 = send + receive1 response
# packet = IP(dst="210.115.158.17") / ICMP()
# reply = sr1(packet, timeout=2, verbose=False)
#
# if reply:
#     reply.summary()




# 패킷 5개 캡처 후 출력
# sniff(count = 5, prn=lambda x: print(x))sr