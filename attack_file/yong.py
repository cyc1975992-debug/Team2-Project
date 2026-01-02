# [파일명: app.py] 경고 해결 및 동적 IP 관리 통합본
import streamlit as st
import pandas as pd
from scapy.all import sniff, IP, TCP, ICMP, send
from datetime import datetime
import threading
import time

# ==========================================
# [초기화] 웹 화면 데이터 및 정책 저장소`
# ==========================================
# 1. 패킷 로그 저장소
if 'logs' not in st.session_state:
    st.session_state['logs'] = pd.DataFrame(columns=['시간', '출발지', '도착지', '프로토콜', '상태', '상세분석'])

# 2. 동적 블랙리스트 저장소 (웹 툴에서 수정 가능)
if 'blocked_ips' not in st.session_state:
    st.session_state['blocked_ips'] = ["8.8.8.8", "1.1.1.1"]

# 3. 전역 버퍼 (버전 충돌 방지용)
@st.cache_resource
def get_packet_buffer():
    return []

packet_buffer = get_packet_buffer()

# ---------------------------------------------------------
# [1. 수집 & 2. 분석] 백그라운드 엔진
# ---------------------------------------------------------
def sniffing_process(interface):
    """네트워크 카드에서 패킷을 낚아채서 분석함"""
    def packet_handler(packet):
        if packet.haslayer(IP):
            src, dst = packet[IP].src, packet[IP].dst
            proto = "TCP" if packet.haslayer(TCP) else ("ICMP" if packet.haslayer(ICMP) else "기타")
            detail = f"Port: {packet[TCP].sport}->{packet[TCP].dport}" if packet.haslayer(TCP) else "ICMP Data"

            # [실시간 분석] 웹 세션에 저장된 최신 차단 목록과 대조
            # 스레드 외부의 st.session_state에 직접 접근이 어려우므로 분석 시점에 대조
            status = "🚨 위협(차단)" if src in st.session_state['blocked_ips'] else "정상"

            new_data = {
                '시간': datetime.now().strftime('%H:%M:%S'),
                '출발지': src, '도착지': dst,
                '프로토콜': proto, '상태': status, '상세분석': detail
            }
            packet_buffer.append(new_data)

    sniff(iface=interface, prn=packet_handler, store=0)

# ---------------------------------------------------------
# [3. 대응 및 시각화] Streamlit 메인 화면
# ---------------------------------------------------------
def main():
    st.set_page_config(page_title="보안 관제 센터", layout="wide")
    st.title("🛡️ 지능형 실시간 보안 관제 시스템")

    # --- 사이드바: 웹 기반 IP 변경 툴 ---
    st.sidebar.header("🚫 블랙리스트 IP 관리")

    # 1. IP 추가 기능
    input_ip = st.sidebar.text_input("차단할 IP 입력", placeholder="예: 192.168.0.1")
    if st.sidebar.button("목록에 추가"):
        if input_ip and input_ip not in st.session_state['blocked_ips']:
            st.session_state['blocked_ips'].append(input_ip)
            st.sidebar.success(f"{input_ip} 추가 완료")

    # 2. 현재 목록 표시 및 초기화
    st.sidebar.write("현재 차단 대상:", st.session_state['blocked_ips'])
    if st.sidebar.button("차단 목록 전체 삭제"):
        st.session_state['blocked_ips'] = []
        st.sidebar.warning("목록이 초기화되었습니다.")

    st.sidebar.markdown("---")

    # 관제 제어
    if st.sidebar.button("📡 실시간 관제 시작"):
        if 'thread_started' not in st.session_state:
            t = threading.Thread(target=sniffing_process, args=("ens33",), daemon=True)
            t.start()
            st.session_state['thread_started'] = True
            st.sidebar.success("수집/분석 엔진 가동!")

    # --- 메인 화면: 데이터 로드 및 경고 해결 ---
    if packet_buffer:
        while packet_buffer:
            data = packet_buffer.pop(0)
            new_df = pd.DataFrame([data])
            st.session_state['logs'] = pd.concat([new_df, st.session_state['logs']], ignore_index=True).head(30)

    logs = st.session_state['logs']
    threats = len(logs[logs['상태'] != "정상"])

    c1, c2, c3 = st.columns(3)
    c1.metric("총 수집 패킷", f"{len(logs)}건")
    c2.metric("위협 분석 결과", f"{threats}건", delta="-위험" if threats > 0 else "안전")
    c3.metric("로컬 IP", "192.168.125.145")

    st.subheader("📋 실시간 상세 패킷 분석 로그")
    # [경고 해결] use_container_width=True를 width='stretch'로 변경
    st.dataframe(logs, width='stretch')

    if not logs.empty:
        st.bar_chart(logs['프로토콜'].value_counts())

    time.sleep(2)
    st.rerun()

if __name__ == "__main__":
    main()