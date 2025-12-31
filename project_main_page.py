import streamlit as st
import time

# 1. 페이지 설정 (브라우저 탭에 표시될 이름과 아이콘)
st.set_page_config(page_title="PyWall - 실시간 보안 관제", page_icon="🛡️", layout="wide")

# 2. 메인 로고 및 타이틀 섹션
# 로고 이미지를 중앙에 배치하기 위해 컬럼을 나눕니다.
col1, col2, col3 = st.columns([1, 2, 1])

with col2:
    st.image("main_photo.png", use_container_width=True)
    st.markdown("<h1 style='text-align: center;'>네트워크 보안 관제 시스템</h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center; color: gray;'>PyWall - 안전한 네트워크 환경을 보장합니다.</p>", unsafe_allow_html=True)


