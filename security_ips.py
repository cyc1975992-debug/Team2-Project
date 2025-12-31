import streamlit as st

st.title("🛡️ 방어 항목 (IP 차단)")

with st.form("ip_form"):
    new_ip = st.text_input("차단할 IP 주소 입력")
    if st.form_submit_button("차단 목록 추가"):
        if new_ip not in st.session_state['blocked_ips']:
            st.session_state['blocked_ips'].append(new_ip)
            st.success(f"{new_ip} 차단 완료")

st.subheader("현재 차단된 목록")
st.write(st.session_state['blocked_ips'])