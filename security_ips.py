import streamlit as st
import pandas as pd
from datetime import datetime

st.title("🛡️ 방어 설정 (심플 DB)")

# 1. DB 초기화 (main1.py에서 해도 되지만 여기서 확인 사살)
if 'blocked_db' not in st.session_state:
    st.session_state['blocked_db'] = pd.DataFrame(columns=['차단시간', 'IP', '포트', '프로토콜', '이유'])

# 2. 자동 차단 설정 (PPS 기준)
st.subheader("⚙️ 자동 방어 설정")
st.session_state['auto_block_on'] = st.checkbox("자동 차단 활성화")
st.session_state['pps_threshold'] = st.number_input("차단 기준 PPS", value=500)

st.divider()

# 3. 차단 규칙 추가
with st.form("add_rule"):
    col1, col2, col3 = st.columns(3)
    with col1: ip = st.text_input("IP 주소")
    with col2: port = st.text_input("포트(기본 Any)")
    with col3: proto = st.selectbox("프로토콜", ["ALL", "TCP", "UDP", "ICMP"])

    if st.form_submit_button("차단 목록에 추가"):
        if ip:
            new_row = {'차단시간': datetime.now().strftime('%H:%M:%S'), 'IP': ip,
                    '포트': port if port else "Any", '프로토콜': proto, '이유': "수동"}
            st.session_state['blocked_db'] = pd.concat([st.session_state['blocked_db'], pd.DataFrame([new_row])], ignore_index=True)
            st.rerun()

# 4. 표 보여주기
st.subheader("🚫 차단 목록")
st.table(st.session_state['blocked_db'])

if st.button("목록 비우기"):
    st.session_state['blocked_db'] = pd.DataFrame(columns=['차단시간', 'IP', '포트', '프로토콜', '이유'])
    st.rerun()