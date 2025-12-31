import streamlit as st
import plotly.express as px

st.title("📈 그래프 분석 항목")
df = st.session_state['logs']

if not df.empty:
    fig = px.pie(df, names='프로토콜', title="프로토콜별 비율", hole=0.3)
    st.plotly_chart(fig, use_container_width=True)
else:
    st.info("수집된 데이터가 없습니다. 패킷 항목에서 엔진을 가동하세요.")