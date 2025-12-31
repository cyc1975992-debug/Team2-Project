import streamlit as st
import pandas as pd
from datetime import datetime

st.title("🛡️ 방어 설정 (심플 DB)")

# 1. DB 초기화 (main1.py의 리스트 방식과 충돌나지 않게 데이터프레임으로 생성)
if 'blocked_db' not in st.session_state:
    st.session_state['blocked_db'] = pd.DataFrame(columns=['차단시간', 'IP', '포트', '프로토콜', '이유'])

# 2. 자동 차단 설정
st.subheader("⚙️ 자동 방어 설정")
st.session_state['auto_block_on'] = st.checkbox("PPS 초과 시 자동 차단 활성화")
st.session_state['pps_threshold'] = st.number_input("차단 기준 (PPS)", value=500)

st.divider()

# 3. 차단 규칙 추가 입력창
st.subheader("➕ 차단 규칙 추가")
with st.form("security_input_form", clear_on_submit=True):
    col1, col2, col3 = st.columns(3)
    with col1:
        ip_input = st.text_input("IP 주소 (예: 8.8.8.8)")
    with col2:
        port_input = st.text_input("포트 (비우면 전체)")
    with col3:
        proto_input = st.selectbox("프로토콜", ["ALL", "TCP", "UDP", "ICMP"])

    reason_input = st.text_input("차단 이유", value="사용자 수동 지정")

    if st.form_submit_button("차단 목록(DB)에 추가"):
        if ip_input:
            new_row = {
                '차단시간': datetime.now().strftime('%H:%M:%S'),
                'IP': ip_input,
                '포트': port_input if port_input else "Any",
                '프로토콜': proto_input,
                '이유': reason_input
            }
            # 표에 한 줄 추가
            st.session_state['blocked_db'] = pd.concat([st.session_state['blocked_db'], pd.DataFrame([new_row])], ignore_index=True)
            st.success(f"{ip_input} 규칙이 성공적으로 저장되었습니다.")
            st.rerun()

st.divider()

# 4. 차단 목록 확인 (표 형태)
st.subheader("🚫 현재 차단 목록")
if not st.session_state['blocked_db'].empty:
    # 표로 보여주기
    st.table(st.session_state['blocked_db'])

    if st.button("목록 전체 비우기"):
        st.session_state['blocked_db'] = pd.DataFrame(columns=['차단시간', 'IP', '포트', '프로토콜', '이유'])
        st.rerun()
else:
    st.write("현재 차단된 내역이 없습니다. (정상 상태)")