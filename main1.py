import streamlit as st
import pandas as pd

# [필수] 모든 페이지에서 공유할 데이터 저장소 초기화
if 'logs' not in st.session_state:
    st.session_state['logs'] = pd.DataFrame(columns=['시간', '출발지', '도착지', '프로토콜', '상태', '상세내용'])
if 'blocked_ips' not in st.session_state:
    st.session_state['blocked_ips'] = []
if 'engine_on' not in st.session_state:
    st.session_state['engine_on'] = False

# [내비게이션 설정] 첨부하신 13streamlit_multi_pages.py 스타일 적용
pg = st.navigation([
    st.Page("project_main_page.py", title="Main", icon="🗼"),
    st.Page("packet_log.py", title="패킷 항목", icon="📡"),
    st.Page("visual_charts.py", title="그래프 항목", icon="📈"),
    st.Page("csv_manager.py", title="CSV DB 생성", icon="💾"),
    st.Page("security_ips.py", title="차단 목록", icon="🛡️")
])

pg.run()