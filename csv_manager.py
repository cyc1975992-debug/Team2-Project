import streamlit as st
import os

st.title("💾 CSV DB 생성")
df = st.session_state['logs']

if st.button("현재 로그를 CSV로 저장"):
    df.to_csv("network_db.csv", index=False, encoding='utf-8-sig')
    st.success("network_db.csv 파일이 생성되었습니다.")

if os.path.exists("network_db.csv"):
    with open("network_db.csv", "rb") as f:
        st.download_button("📥 파일 다운로드", f, file_name="network_db.csv")