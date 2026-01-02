import streamlit as st
import pandas as pd

# [필수] 모든 페이지에서 공유할 데이터 저장소 초기화
# 1. 패킷 로그 구조 업데이트 (화살표 형식 MAC 주소 반영)
if 'logs' not in st.session_state:
    st.session_state['logs'] = pd.DataFrame(columns=[
        '시간', '출발지', '도착지', '프로토콜', '포트번호', 'MAC주소(출발→도착)', '상태', '상세내용'
    ])

# 2. 통계 및 엔진 상태 관련
if 'engine_on' not in st.session_state:
    st.session_state['engine_on'] = False
if 'packet_count' not in st.session_state:
    st.session_state['packet_count'] = 0
if 'pps_history' not in st.session_state:
    st.session_state['pps_history'] = []
if 'top_talkers' not in st.session_state:
    st.session_state['top_talkers'] = {}
if 'top_protocols' not in st.session_state:
    st.session_state['top_protocols'] = {}

# 3. 보안 및 차단 관련
if 'blocked_db' not in st.session_state:
    st.session_state['blocked_db'] = pd.DataFrame(columns=['차단시간', 'IP', '포트', '프로토콜', '이유'])
if 'pending_blocks' not in st.session_state:
    st.session_state['pending_blocks'] = pd.DataFrame(columns=['감지시간', 'IP', 'PPS', '프로토콜'])
if 'pps_threshold' not in st.session_state:
    st.session_state['pps_threshold'] = 500

# [내비게이션 설정] 첨부하신 13streamlit_multi_pages.py 스타일 적용
pg = st.navigation([
    st.Page("project_main_page.py", title="Main", icon="🗼"),
    st.Page("packet_log.py", title="패킷 항목", icon="📡"),
    st.Page("visual_charts.py", title="그래프 항목", icon="📈"),
    st.Page("csv_manager.py", title="CSV DB 생성", icon="💾"),
    st.Page("security_ips.py", title="차단 목록", icon="🛡️")
])

pg.run()