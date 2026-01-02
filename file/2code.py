import streamlit as st
import pandas as pd
import plotly.express as px
from scapy.all import sniff, IP, TCP, ICMP
from datetime import datetime
import threading
import time

# =========================================================
# 1. 설정 및 초기화
# =========================================================
st.set_page_config(page_title="AI 보안 관제 시스템", layout="wide")

# 세션 상태 초기화
if 'logs' not in st.session_state:
    st.session_state['logs'] = pd.DataFrame(columns=['시간', '출발지', '도착지', '프로토콜', '상태', '상세내용'])

if 'blocked_ips' not in st.session_state:
    st.session_state['blocked_ips'] = ["8.8.8.8", "1.1.1.1"]

# 공유 버퍼
@st.cache_resource
def get_shared_buffer():
    return []

packet_buffer = get_shared_buffer()

# =========================================================
# 2. 패킷 수집 엔진
# =========================================================
def packet_analyzer(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if packet.haslayer(TCP):
            proto = "TCP"
            detail = f"Port: {packet[TCP].sport} -> {packet[TCP].dport}"
        elif packet.haslayer(ICMP):
            proto = "ICMP"
            detail = "Ping 요청/응답"
        else:
            proto = "기타"
            detail = "UDP/기타"

        status = "🚨 위협" if src_ip in st.session_state['blocked_ips'] else "정상"

        new_entry = {
            '시간': datetime.now().strftime('%H:%M:%S'),
            '출발지': src_ip,
            '도착지': dst_ip,
            '프로토콜': proto,
            '상태': status,
            '상세내용': detail
        }
        packet_buffer.append(new_entry)

def start_sniffing(interface):
    sniff(iface=interface, prn=packet_analyzer, store=0)

# =========================================================
# 3. 메인 UI (09 파일 스타일 참고)
# =========================================================

# 사이드바 메뉴 구성
st.sidebar.title("🛡️ IDS Dashboard")
menu = st.sidebar.selectbox('메뉴 선택', ['실시간 관제', '블랙리스트 관리', '시스템 정보'])
show_code = st.sidebar.checkbox('Source Code 표시')

# 1. 실시간 데이터 업데이트 로직
if packet_buffer:
    while packet_buffer:
        item = packet_buffer.pop(0)
        new_row = pd.DataFrame([item])
        st.session_state['logs'] = pd.concat([new_row, st.session_state['logs']], ignore_index=True).head(100)

# --- 메뉴별 화면 구성 ---

if menu == '실시간 관제':
    st.title("📡 실시간 네트워크 관제 모드")

    # 지표 표시
    logs_df = st.session_state['logs']
    total_pkts = len(logs_df)
    threat_pkts = len(logs_df[logs_df['상태'] == "🚨 위협"])

    col1, col2, col3 = st.columns(3)
    col1.metric("총 분석 패킷", f"{total_pkts} PKT")
    col2.metric("탐지된 위협", f"{threat_pkts} 건", delta=f"{threat_pkts}", delta_color="inverse")
    col3.metric("엔진 상태", "Running" if 'engine_on' in st.session_state else "Stopped")

    # 관제 시작 버튼
    if st.sidebar.button("관제 엔진 가동"):
        if 'engine_on' not in st.session_state:
            # 인터페이스 이름은 환경에 맞게 수정 (예: "Ethernet", "en0", "ens33")
            t = threading.Thread(target=start_sniffing, args=("ens33",), daemon=True)
            t.start()
            st.session_state['engine_on'] = True
            st.sidebar.success("엔진 가동 중...")

    # 데이터프레임 출력 (09 파일의 st.dataframe 참고)
    st.subheader("📋 최근 패킷 로그 (최신 100개)")
    st.dataframe(logs_df, use_container_width=True, height=300)

    # 시각화 영역 (Plotly 활용)
    if not logs_df.empty:
        st.divider()
        st.subheader("📊 프로토콜별 통계")
        proto_counts = logs_df['프로토콜'].value_counts().reset_index()
        proto_counts.columns = ['프로토콜', '개수']

        fig = px.pie(proto_counts, values='개수', names='프로토콜',
                     title="네트워크 프로토콜 점유율",
                     color_discrete_sequence=px.colors.sequential.RdBu)
        st.plotly_chart(fig, use_container_width=True)

elif menu == '블랙리스트 관리':
    st.title("🚫 블랙리스트 관리")

    with st.form("ip_form"):
        new_ip = st.text_input("차단할 IP 주소를 입력하세요")
        submit = st.form_submit_button("차단 목록에 추가")

        if submit and new_ip:
            if new_ip not in st.session_state['blocked_ips']:
                st.session_state['blocked_ips'].append(new_ip)
                st.success(f"{new_ip}가 블랙리스트에 추가되었습니다.")
            else:
                st.warning("이미 등록된 IP입니다.")

    st.subheader("현재 차단된 IP 리스트")
    st.table(pd.DataFrame(st.session_state['blocked_ips'], columns=["IP Address"]))

    if st.button("목록 전체 초기화"):
        st.session_state['blocked_ips'] = []
        st.rerun()

elif menu == '시스템 정보':
    st.title("ℹ️ System Information")
    st.info("본 시스템은 Scapy와 Streamlit을 결합한 실시간 네트워크 침입 탐지 데모입니다.")
    st.write("사용된 라이브러리: Streamlit, Pandas, Plotly, Scapy")

# 코드 표시 기능 (09 파일 로직)
if show_code:
    st.divider()
    st.subheader("🔍 Source Code")
    with open(__file__, "r", encoding="utf-8") as f:
        st.code(f.read(), language="python")

# 자동 새로고침 (실시간 관제 메뉴일 때만 작동)
if menu == '실시간 관제' and 'engine_on' in st.session_state:
    time.sleep(2)
    st.rerun()