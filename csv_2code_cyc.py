import streamlit as st
import pandas as pd
import plotly.express as px
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import threading
import time
import os
import subprocess
import psutil
import platform

# [설정] 로그 파일 및 시각화 대상 프로토콜 정의
LOG_FILE = "network_logs.csv"
LOG_COLUMNS = ['시간', '출발지', '도착지', '프로토콜', '상태', '상세내용']
ALL_PROTOCOLS = ['TCP', 'UDP', 'ICMP', '기타']

# [파일 초기화] 원본 로직 유지: 파일이 없거나 비어 있으면 헤더 생성
def initialize_csv():
    if not os.path.exists(LOG_FILE) or os.stat(LOG_FILE).st_size == 0:
        pd.DataFrame(columns=LOG_COLUMNS).to_csv(LOG_FILE, index=False, encoding='utf-8-sig')

initialize_csv()

# =========================================================
# 1. 설정 및 세션 관리
# =========================================================
st.set_page_config(page_title="AI 보안 관제 시스템", layout="wide")

for key, default in [('run_engine', False), ('logs', pd.DataFrame(columns=LOG_COLUMNS)),
                     ('blocked_ips', ["8.8.8.8", "1.1.1.1"]), ('engine_on', False)]:
    if key not in st.session_state:
        st.session_state[key] = default

@st.cache_resource
def get_shared_buffer(): return []
packet_buffer = get_shared_buffer()

def style_threat_rows(row):
    if "🚨 위협" in str(row['상태']):
        return ['background-color: #FF4B4B; color: white; font-weight: bold'] * len(row)
    return [''] * len(row)

# =========================================================
# 2. 핵심 기능 (패킷 분석 및 CSV 필터링 저장)
# =========================================================

def save_filtered_csv():
    """위협 패킷 상위 20개, 하위 20개 추출 (에러 방지 예외처리 포함)"""
    try:
        if not os.path.exists(LOG_FILE) or os.stat(LOG_FILE).st_size == 0:
            return

        full_df = pd.read_csv(LOG_FILE, encoding='utf-8-sig')
        if full_df.empty: return

        threat_df = full_df[full_df['상태'] == "🚨 위협"]

        # 위협 패킷이 많을 때만 잘라내고, 나머지는 유지
        if len(threat_df) > 40:
            final_df = pd.concat([threat_df.head(20), threat_df.tail(20)]).drop_duplicates()
            # 정상 패킷 일부도 보존하고 싶다면 여기에 추가 가능
            final_df.to_csv(LOG_FILE, index=False, encoding='utf-8-sig')
    except Exception:
        pass

def packet_analyzer(packet):
    if not packet.haslayer(IP): return
    try:
        src_ip, dst_ip = packet[IP].src, packet[IP].dst
        proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "ICMP" if packet.haslayer(ICMP) else "기타"
        status = "🚨 위협" if any(ip in st.session_state['blocked_ips'] for ip in [src_ip, dst_ip]) else "정상"

        entry = {'시간': datetime.now().strftime('%H:%M:%S'), '출발지': src_ip, '도착지': dst_ip,
                 '프로토콜': proto, '상태': status, '상세내용': f"{len(packet)} bytes"}

        packet_buffer.append(entry)

        # 실시간 CSV 기록
        pd.DataFrame([entry]).to_csv(LOG_FILE, mode='a', header=False, index=False, encoding='utf-8-sig')

    except: pass

def start_sniffing():
    sniff(prn=packet_analyzer, store=0, stop_filter=lambda x: not st.session_state.get('run_engine', False))

# =========================================================
# 3. 메인 UI 및 사이드바
# =========================================================
st.sidebar.title("🛡️ IDS Dashboard")
menu = st.sidebar.selectbox('메뉴 선택', ['실시간 관제', '블랙리스트 관리', '시스템 정보'])
show_code = st.sidebar.checkbox('Source Code 표시')

st.sidebar.divider()
st.sidebar.subheader("🕹️ 시스템 제어")

if st.session_state['engine_on']:
    if st.sidebar.button("🔴 관제 엔진 중지", use_container_width=True):
        st.session_state.update({'run_engine': False, 'engine_on': False})
        st.rerun()
else:
    if st.sidebar.button("🟢 관제 엔진 가동", use_container_width=True):
        st.session_state.update({'run_engine': True, 'engine_on': True})
        from streamlit.runtime.scriptrunner import add_script_run_ctx
        t = threading.Thread(target=start_sniffing, daemon=True)
        add_script_run_ctx(t)
        t.start()
        st.rerun()

if st.sidebar.button("🗑️ 로그 초기화", use_container_width=True):
    st.session_state['logs'] = pd.DataFrame(columns=LOG_COLUMNS)
    packet_buffer.clear()
    initialize_csv() # 다시 헤더만 있는 파일로 생성
    st.rerun()

# [Made by] 최하단 배치
for _ in range(15): st.sidebar.write("")
st.sidebar.divider()
st.sidebar.caption("👨‍💻 **Made by**")
st.sidebar.caption("조용철, 송평인, 김광민")

# 데이터 업데이트 (최신 50개)
while packet_buffer:
    item = packet_buffer.pop(0)
    st.session_state['logs'] = pd.concat([pd.DataFrame([item]), st.session_state['logs']], ignore_index=True).head(50)

# =========================================================
# 4. 실시간 관제 화면
# =========================================================
if menu == '실시간 관제':
    st.title("📡 실시간 네트워크 관제 모드")
    df = st.session_state['logs']

    c1, c2, c3 = st.columns(3)
    c1.metric("최근 패킷", f"{len(df)} PKT")
    c2.metric("탐지된 위협", f"{len(df[df['상태'] == '🚨 위협'])} 건")
    c3.metric("엔진 상태", "Running" if st.session_state['engine_on'] else "Stopped")

    st.subheader("📋 최근 패킷 로그 (최신 50개)")
    if not df.empty:
        st.dataframe(df.style.apply(style_threat_rows, axis=1), use_container_width=True, height=350)
    else:
        st.info("데이터 수집 중...")

    # [CSV 다운로드 로직 - 에러 방지 처리]
    try:
        if os.path.exists(LOG_FILE) and os.stat(LOG_FILE).st_size > 50: # 파일에 데이터가 있을 때만
            full_log = pd.read_csv(LOG_FILE, encoding='utf-8-sig')
            threats = full_log[full_log['상태'] == "🚨 위협"]

            if not threats.empty:
                if len(threats) > 40:
                    csv_data = pd.concat([threats.head(20), threats.tail(20)]).to_csv(index=False, encoding='utf-8-sig')
                else:
                    csv_data = threats.to_csv(index=False, encoding='utf-8-sig')
                st.download_button("📥 위협 분석 로그 다운로드 (위/아래 20)", csv_data, "threat_log.csv", "text/csv")
    except:
        pass

    # 그래프 섹션
    if not df.empty:
        st.divider()
        g1, g2 = st.columns(2)
        with g1:
            st.subheader("📊 프로토콜별 통계")
            counts = df['프로토콜'].value_counts()
            fig_bar = px.bar(pd.DataFrame({'프로토콜': ALL_PROTOCOLS, 'count': [counts.get(p, 0) for p in ALL_PROTOCOLS]}),
                             x='프로토콜', y='count', color='프로토콜', text_auto=True, color_discrete_sequence=px.colors.qualitative.Safe)
            fig_bar.update_traces(width=0.4)
            st.plotly_chart(fig_bar, use_container_width=True)
        with g2:
            st.subheader("📈 실시간 종류별 추이")
            t_trend = df.groupby(['시간', '프로토콜']).size().reset_index(name='패킷수').sort_values('시간')
            st.plotly_chart(px.line(t_trend, x='시간', y='패킷수', color='프로토콜', markers=True), use_container_width=True)

elif menu == '블랙리스트 관리':
    # ... (생략: 기존과 동일)
    st.title("🚫 블랙리스트 관리")
    with st.form("ip_form"):
        new_ip = st.text_input("IP 주소 입력")
        if st.form_submit_button("✅ 추가") and new_ip:
            if new_ip not in st.session_state['blocked_ips']:
                st.session_state['blocked_ips'].append(new_ip)
                st.rerun()
    st.table(pd.DataFrame(st.session_state['blocked_ips'], columns=["IP Address"]))

elif menu == '시스템 정보':
    st.title("🖥️ 시스템 리소스 모니터")
    #     cpu, mem = psutil.cpu_percent(), psutil.virtual_memory().percent
    st.metric("CPU 사용률", f"{cpu}%")
    st.metric("RAM 사용률", f"{mem}%")
    st.bar_chart(pd.DataFrame({"사용량": [cpu, mem]}, index=["CPU", "RAM"]))

if show_code:
    st.divider()
    st.code(open(__file__, "r", encoding="utf-8").read(), language="python")

if menu == '실시간 관제' and st.session_state['engine_on']:
    time.sleep(1)
    st.rerun()