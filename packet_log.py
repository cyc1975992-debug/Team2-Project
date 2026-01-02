import streamlit as st
import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import pandas as pd
import time
import os

# --- 세션 상태 초기화 ---
if 'engine_on' not in st.session_state:
    st.session_state['engine_on'] = False
if 'logs' not in st.session_state:
    st.session_state['logs'] = pd.DataFrame(columns=['시간', '출발지', '도착지', '프로토콜', '상태', '상세내용'])
if 'blocked_ips' not in st.session_state:
    st.session_state['blocked_ips'] = []
# PPS 및 Top Talkers를 위한 상태
if 'pps_history' not in st.session_state:
    st.session_state['pps_history'] = []
if 'packet_count' not in st.session_state:
    st.session_state['packet_count'] = 0
if 'top_talkers' not in st.session_state:
    st.session_state['top_talkers'] = {}

st.set_page_config(page_title="Network Monitor", layout="wide")
st.title("📡 실시간 네트워크 관제 및 PPS 통계")

# --- 패킷 분석 엔진 ---
def packet_analyzer(packet):
    if not packet.haslayer(IP): return

    src_ip, dst_ip = packet[IP].src, packet[IP].dst
    proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "ICMP" if packet.haslayer(ICMP) else "기타"

    # PPS 카운트 및 Top Talkers 집계
    st.session_state['packet_count'] += 1
    st.session_state['top_talkers'][src_ip] = st.session_state['top_talkers'].get(src_ip, 0) + 1

    # 위협 감지 및 로그 생성
    # 차단 DB(표)가 비어있지 않고, 현재 IP가 그 표의 'IP' 항목에 있는지 확인
    if not st.session_state['blocked_db'].empty and (src_ip in st.session_state['blocked_db']['IP'].values):
        status = "🚨 위협"
    else:
        status = "정상"
    entry = {'시간': datetime.now().strftime('%H:%M:%S'), '출발지': src_ip, '도착지': dst_ip,
            '프로토콜': proto, '상태': status, '상세내용': f"{len(packet)} bytes"}

    df_save = pd.DataFrame([entry])
    df_save.to_csv("network_logs.csv", mode='a', header=not os.path.exists("network_logs.csv"), index=False, encoding='utf-8-sig')

    st.session_state['logs'] = pd.concat([df_save, st.session_state['logs']], ignore_index=True).head(50)

    # 로그 업데이트 (최신 50개)
    new_df = pd.DataFrame([entry])
    st.session_state['logs'] = pd.concat([new_df, st.session_state['logs']], ignore_index=True).head(50)

def start_engine():
    sniff(prn=packet_analyzer, store=0, stop_filter=lambda x: not st.session_state.get('engine_on', False))

# --- UI 레이아웃 ---

# 1. 상단 대시보드 (PPS & Top Talkers)
dash_col1, dash_col2 = st.columns([2, 1])

with dash_col1:
    st.subheader("📈 실시간 PPS 추이")
    # PPS 계산 (간이 구현: 1초마다 호출되는 rerun 시점의 카운트)
    current_pps = st.session_state['packet_count']
    st.session_state['pps_history'].append(current_pps)
    if len(st.session_state['pps_history']) > 20: st.session_state['pps_history'].pop(0)
    st.session_state['packet_count'] = 0 # 카운트 리셋

    st.line_chart(st.session_state['pps_history'])
    st.metric("현재 Packets Per Second", f"{current_pps} pps")

with dash_col2:
    st.subheader("🏆 Top Talkers (투머치토커)")
    if st.session_state['top_talkers']:
        top_df = pd.DataFrame(st.session_state['top_talkers'].items(), columns=['IP 주소', '패킷 수'])
        top_df = top_df.sort_values(by='패킷 수', ascending=False).head(5)
        st.table(top_df)
    else:
        st.write("데이터 수집 중...")

st.divider()

# 2. 제어 버튼
col1, col2, col3 = st.columns([0.1, 0.1, 0.8])
with col1:
    if st.session_state['engine_on']:
        if st.button("🔴 엔진 중지"):
            st.session_state['engine_on'] = False
            st.rerun()
    else:
        if st.button("🟢 엔진 시작"):
            st.session_state['engine_on'] = True
            t = threading.Thread(target=start_engine, daemon=True)
            from streamlit.runtime.scriptrunner import add_script_run_ctx
            add_script_run_ctx(t); t.start()
            st.rerun()

with col2:
    if st.button("🗑️ 초기화"):
        st.session_state['logs'] = pd.DataFrame(columns=['시간', '출발지', '도착지', '프로토콜', '상태', '상세내용'])
        st.session_state['top_talkers'] = {}
        st.session_state['pps_history'] = []

        if os.path.exists("network_logs.csv"):
            # 빈 데이터프레임을 만들어서 파일에 덮어쓰기 (내용 삭제)
            pd.DataFrame(columns=['시간', '출발지', '도착지', '프로토콜', '상태', '상세내용']).to_csv("network_logs.csv", index=False, encoding='utf-8-sig')

        st.rerun()

# 3. 실시간 패킷 로그 테이블
def color_red(row):
    return ['background-color: #FFCCCC' if "위협" in row['상태'] else '' for _ in row]

st.subheader("📋 실시간 패킷 로그")
if not st.session_state['logs'].empty:
    st.dataframe(st.session_state['logs'].style.apply(color_red, axis=1), use_container_width=True, height=300)
else:
    st.info("엔진을 시작하여 패킷을 수집하세요.")

# --- 자동 갱신 (1초마다) ---
if st.session_state['engine_on']:
    time.sleep(1)
    st.rerun()