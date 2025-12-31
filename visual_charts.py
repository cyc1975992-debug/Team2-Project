import streamlit as st
import plotly.express as px

st.title("📈 그래프 분석 항목")
df = st.session_state['logs']

if not df.empty:
    # 1. 화면을 두 개의 컬럼으로 분할 (5:5 비율)
    col1, col2 = st.columns(2)

    with col1:
        # 기존 파이 차트
        fig_pie = px.pie(df, names='프로토콜', title="프로토콜별 비율", hole=0.3)
        st.plotly_chart(fig_pie, use_container_width=True)

    with col2:
        # 1. 데이터 가공: 시간과 프로토콜별로 그룹화하여 패킷 개수를 셉니다.
        line_data = df.groupby(['시간', '프로토콜']).size().reset_index(name='패킷수')

        # 2. 시간순으로 정렬 (그래프 선이 꼬이지 않게 함)
        line_data = line_data.sort_values('시간')

        # 3. 줄그래프 생성 (color='프로토콜' 옵션 추가)
        fig_line = px.line(
            line_data,
            x='시간',
            y='패킷수',
            color='프로토콜',  # 프로토콜별로 선 색상을 다르게 표시
            title="시간별 프로토콜 흐름",
            markers=True      # 데이터 지점에 점 표시
        )

        # 4. 그래프 출력
        st.plotly_chart(fig_line, use_container_width=True)

else:
    st.info("수집된 데이터가 없습니다. 패킷 항목에서 엔진을 가동하세요.")