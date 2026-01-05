import streamlit as st
import pandas as pd
from datetime import datetime
import subprocess

st.title("🛡️ 방어 설정 (심플 DB)")

# 1. DB 초기화 (main1.py에서 해도 되지만 여기서 확인 사살)
if 'blocked_db' not in st.session_state:
    st.session_state['blocked_db'] = pd.DataFrame(columns=['차단시간', 'IP', '포트', '프로토콜', '이유'])

# 2. 자동 차단 설정 (PPS 기준)
st.subheader("⚙️ 자동 방어 설정")

st.info("""
💡 **PPS 설정 가이드**
* **10 ~ 30**: 테스트용 (접속만 해도 즉시 감지)
* **100 ~ 500**: 일반 사무/가정용 (추천 기본값)
* **1,000+**: 고성능 서버 환경 (DDoS 방어용)
""")

# 1. 값이 없을 때만 초기화 (다른 페이지 갔다 와도 유지되는 핵심 로직)
if 'pps_threshold' not in st.session_state:
    st.session_state['pps_threshold'] = 500

def update_pps():
    st.session_state['pps_threshold'] = st.session_state['pps_input_key']

# 2. value에 직접 숫자를 쓰지 말고 세션 변수를 넣으세요
st.number_input(
    "차단 기준 PPS",
    min_value=1,
    value=st.session_state['pps_threshold'], # 저장된 세션 값을 보여줌
    key='pps_input_key',                     # 위젯 전용 내부 키
    on_change=update_pps                     # 값이 바뀔 때마다 실행
)
st.divider()

# 3. 차단 규칙 추가
with st.form("add_rule"):
    st.write("➕ 수동 차단 규칙 추가")
    col1, col2, col3 = st.columns(3)
    with col1: ip = st.text_input("IP 주소")
    with col2: port = st.text_input("포트(기본 Any)")
    with col3: proto = st.selectbox("프로토콜", ["ALL", "TCP", "UDP", "ICMP"])

    if st.form_submit_button("차단 목록에 추가"):
        if ip:
            # 실제 윈도우 방화벽에 차단 규칙 추가 (관리자 권한 필요)
            cmd = f'netsh advfirewall firewall add rule name="BLOCK_{ip}" dir=in action=block remoteip={ip}'
            subprocess.run(cmd, shell=True)

            # 세션 DB에 저장
            new_row = {'차단시간': datetime.now().strftime('%H:%M:%S'), 'IP': ip,
                    '포트': port if port else "Any", '프로토콜': proto, '이유': "수동"}
            st.session_state['blocked_db'] = pd.concat([st.session_state['blocked_db'], pd.DataFrame([new_row])], ignore_index=True)

            st.success(f"✅ {ip}가 실제 방화벽 및 목록에 등록되었습니다.")
            st.rerun()

# 4. 표 보여주기
st.subheader("🚫 차단 목록")
st.table(st.session_state['blocked_db'])

# 목록 비우기(방화벽 규칙도 같이 삭제)
if st.button("목록 비우기"):
    # 목록에 있는 모든 IP의 방화벽 규칙 삭제 시도
    for ip in st.session_state['blocked_db']['IP']:
        del_cmd = f'netsh advfirewall firewall delete rule name="BLOCK_{ip}"'
        subprocess.run(del_cmd, shell=True)

    st.session_state['blocked_db'] = pd.DataFrame(columns=['차단시간', 'IP', '포트', '프로토콜', '이유'])
    st.warning("모든 차단 규칙이 방화벽과 목록에서 삭제되었습니다.")
    st.rerun()