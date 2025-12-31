import streamlit as st
import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import pandas as pd

st.title("📡 실시간 패킷 항목")

# 패킷 수집 및 분석 함수
def packet_analyzer(packet):
    if not packet.haslayer(IP): return
    src_ip, dst_ip = packet[IP].src, packet[IP].dst
    proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "ICMP" if packet.haslayer(ICMP) else "기타"
    status = "🚨 위협" if any(ip in st.session_state['blocked_ips'] for ip in [src_ip, dst_ip]) else "정상"
    entry = {'시간': datetime.now().strftime('%H:%M:%S'), '출발지': src_ip, '도착지': dst_ip,
             '프로토콜': proto, '상태': status, '상세내용': f"{len(packet)} bytes"}


    # 세션 로그 업데이트
    new_df = pd.DataFrame([entry])
    st.session_state['logs'] = pd.concat([pd.DataFrame([entry]), st.session_state['logs']], ignore_index=True).head(50)
    # 실시간 로그 저장
    new_df.to_csv('network_logs.csv', mode='a', index=False, header=not pd.io.common.file_exists('network_logs.csv'), encoding='utf-8-sig')

def start_engine():
    sniff(prn=packet_analyzer, store=0, stop_filter=lambda x: not st.session_state.get('engine_on', False))

# 제어 버튼
col1, col2 = st.columns([0.03, 0.14], gap='small')
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
# 로그 삭제 및 csv 초기화
with col2:
    if st.button("🗑️ 패킷 초기화"):
        st.session_state['logs'] = pd.DataFrame(columns=['시간', '출발지', '도착지', '프로토콜', '상태', '상세내용'])
        st.session_state['logs'].to_csv('network_logs.csv', index=False, encoding='utf-8-sig')
        st.rerun()


def color_red(row):
    if "위협" in row['상태']:
        return ['background-color: #FFCCCC'] * len(row)
    return [''] * len(row)

# 2. 스타일을 입혀서 다시 그리기 (기존 한 줄을 대체)
if not st.session_state['logs'].empty:
    st.dataframe(st.session_state['logs'].style.apply(color_red, axis=1), use_container_width=True, height=400)
else:
    st.dataframe(st.session_state['logs'], use_container_width=True, height=400)


if st.session_state['engine_on']:
    import time; time.sleep(1); st.rerun()