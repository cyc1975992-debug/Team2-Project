import streamlit as st
import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import pandas as pd
import time
import os
log_cols = ['시간', '출발지', '도착지', '프로토콜', '포트번호', 'MAC주소(출발→도착)', '상태', '상세내용']

# --- 세션 상태 초기화 ---
if 'engine_on' not in st.session_state:
    st.session_state['engine_on'] = False
if 'logs' not in st.session_state:
    st.session_state['logs'] = pd.DataFrame(columns=log_cols)
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
    # MAC 주소 추출 (Ethernet 계층)
    src_mac = packet.src if packet.haslayer("Ether") else "Unknown"
    dst_mac = packet.dst if packet.haslayer("Ether") else "Unknown"
    combined_mac = f"{src_mac} → {dst_mac}"

    if packet.haslayer(TCP):
        proto = "TCP"
        port = f"{packet[TCP].sport} → {packet[TCP].dport}"
    elif packet.haslayer(UDP):
        proto = "UDP"
        port = f"{packet[UDP].sport} → {packet[UDP].dport}"
    elif packet.haslayer(ICMP):
        proto = "ICMP"
        port = "-" # ICMP는 포트가 없음
    else:
        proto = "기타"
        port = "-"

    # PPS 카운트 및 Top Talkers 집계
    st.session_state['packet_count'] += 1
    st.session_state['top_talkers'][src_ip] = st.session_state['top_talkers'].get(src_ip, 0) + 1

    if src_ip not in st.session_state['top_protocols']:
        st.session_state['top_protocols'][src_ip] = {}
    st.session_state['top_protocols'][src_ip][proto] = st.session_state['top_protocols'][src_ip].get(proto, 0) + 1

    # 위협 감지 및 로그 생성
    # 차단 DB(표)가 비어있지 않고, 현재 IP가 그 표의 'IP' 항목에 있는지 확인
    if not st.session_state['blocked_db'].empty and (src_ip in st.session_state['blocked_db']['IP'].values):
        status = "🚨 위협"
    else:
        status = "정상"
    entry = {
        '시간': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        '출발지': src_ip,
        '도착지': dst_ip,
        '프로토콜': proto,
        '포트번호': port,
        'MAC주소(출발→도착)': combined_mac,
        '상태': status,
        '상세내용': f"{len(packet)} bytes"
    }

    df_save = pd.DataFrame([entry])
    df_save.to_csv("network_logs.csv", mode='a', header=not os.path.exists("network_logs.csv"), index=False, encoding='utf-8-sig')

    # 로그 업데이트 (최신 50개)
    st.session_state['logs'] = pd.concat([df_save, st.session_state['logs']], ignore_index=True).head(50)

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
    st.subheader("📊 IP별 패킷 발생 빈도")

    # 1. 수집된 딕셔너리 데이터를 정제된 데이터프레임으로 변환 (표시용)
    if st.session_state['top_talkers']:
        # 상위 5개 IP만 추출하여 정렬합니다.
        top_talkers_data = pd.DataFrame(
            list(st.session_state['top_talkers'].items()),
            columns=['IP 주소', '패킷 수']
        ).sort_values(by='패킷 수', ascending=False).head(5)
        st.table(top_talkers_data)
    else:
        st.write("표시할 패킷 데이터가 없습니다.")

    st.divider()

    # 2. 하단: 보안 전문가 검토 대기열 (Top Talkers 바로 아래 배치)
    st.subheader("🧐 보안 검토 대기열")

    # 현재 PPS 임계치 분석
    limit_pps = int(st.session_state.get('pps_threshold', 500))
    if current_pps > limit_pps:
        top_ip = max(st.session_state['top_talkers'], key=st.session_state['top_talkers'].get)

        # 이미 대기열에 있는 IP가 아니라면 새로 추가
        ip_protos = st.session_state['top_protocols'].get(top_ip, {})
        main_proto = max(ip_protos, key=ip_protos.get) if ip_protos else "Unknown"

        if top_ip not in st.session_state['pending_blocks']['IP'].values:
            new_pending = {
                '감지시간': datetime.now().strftime('%H:%M:%S'),
                'IP': top_ip,
                'PPS': current_pps,
                '프로토콜': main_proto # 프로토콜 정보 추가
                }
            st.session_state['pending_blocks'] = pd.concat([st.session_state['pending_blocks'], pd.DataFrame([new_pending])], ignore_index=True)

    # [수정] 대기열 목록을 표로 보여주고 버튼 생성
    pending_df = st.session_state.get('pending_blocks', pd.DataFrame())
    if not pending_df.empty:
        for index, row in pending_df.iterrows():
            col_info, col_btn = st.columns([3, 1])
            with col_info:
                # row['프로토콜'] 대신 row.get('프로토콜', 'N/A')를 사용하여 에러를 방어합니다.
                p_time = row['감지시간']
                p_ip = row['IP']
                p_proto = row.get('프로토콜', 'N/A') # 컬럼이 없으면 N/A 표시
                p_pps = row['PPS']

                st.info(f"📍 {row['감지시간']} | {row['IP']} ({row['프로토콜']}) | {row['PPS']} PPS (기준: {limit_pps})")
            with col_btn:
                # 차단 버튼
                if st.button("🚫 차단", key=f"block_{row['IP']}"):
                    # blocked_db에 추가하는 로직
                    new_entry = {'차단시간': row['감지시간'], 'IP': row['IP'], '포트': 'Any', '프로토콜': 'ALL', '이유': 'PPS 초과'}
                    st.session_state['blocked_db'] = pd.concat([st.session_state['blocked_db'], pd.DataFrame([new_entry])], ignore_index=True)
                    # 대기열에서 삭제
                    st.session_state['pending_blocks'] = st.session_state['pending_blocks'].drop(index)
                    st.rerun()

                # 허용(삭제) 버튼
                if st.button("✅ 허용", key=f"allow_{row['IP']}"):
                    st.session_state['pending_blocks'] = st.session_state['pending_blocks'].drop(index)
                    st.rerun()
    else:
        st.success("🟢 검토가 필요한 위협이 없습니다.")

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
        new_cols = ['시간', '출발지', '도착지', '프로토콜', '포트번호', 'MAC주소(출발→도착)', '상태', '상세내용']
        st.session_state['logs'] = pd.DataFrame(columns=new_cols)
        st.session_state['top_talkers'] = {}
        st.session_state['pps_history'] = []
        st.session_state['packet_count'] = 0
        st.session_state['pending_blocks'] = pd.DataFrame(columns=['감지시간', 'IP', 'PPS', '프로토콜']) # 대기열도 초기화

        if os.path.exists("network_logs.csv"):
            # 빈 데이터프레임을 만들어서 파일에 덮어쓰기 (내용 삭제)
            if os.path.exists("network_logs.csv"):
                try:
                    # 'w' 모드는 기존 내용을 싹 지우고 새로 쓰는 모드입니다.
                    # 빈 데이터프레임에 컬럼명만 담아서 저장합니다.
                    pd.DataFrame(columns=new_cols).to_csv(
                        "network_logs.csv",
                        index=False,
                        encoding='utf-8-sig'
                    )
                except PermissionError:
                    st.error("⚠️ 파일이 열려 있어 내용을 지울 수 없습니다.")
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