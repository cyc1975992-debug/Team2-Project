import streamlit as st
import pandas as pd
import os
import time

# 페이지 설정 (아이콘 추가)
st.set_page_config(page_icon="💾", layout="centered")

st.title("💾 CSV 위협 로그 관리 센터")
st.caption("네트워크 로그 파일에서 위협 요소를 필터링하고 관리합니다.")

st.divider()

# 파일 존재 여부에 따른 카드형 레이아웃
if os.path.exists("network_logs.csv"):

    # 1. 파일 정보 요약 (고급스러운 대시보드 느낌)
    try:
        df_preview = pd.read_csv("network_logs.csv")
        total_logs = len(df_preview)
        threat_count = len(df_preview[df_preview['상태'].str.contains("위협", na=False)])

        col1, col2 = st.columns(2)
        col1.metric("전체 로그 수", f"{total_logs} 건")
        col2.metric("감지된 위협", f"{threat_count} 건", delta_color="inverse")
    except:
        st.info("로그 파일을 분석 중입니다...")

    st.write("") # 간격 조절

    # 2. 작업 영역을 컨테이너로 묶어 깔끔하게 표현
    with st.container(border=True):
        st.subheader("🛠️ 로그 최적화 작업")
        st.write("불필요한 정상 로그를 제거하고 **위협 데이터**만 남깁니다.")

        if st.button("🚨 위협 로그만 남기기 (파일 업데이트)", use_container_width=True, type="primary"):
            full_df = pd.read_csv("network_logs.csv")
            threat_df = full_df[full_df['상태'].str.contains("위협", na=False)]

            if not threat_df.empty:
                threat_df.to_csv("network_logs.csv", index=False, encoding='utf-8-sig')
                st.toast(f"업데이트 완료! ({len(threat_df)}건)", icon="✅")
                time.sleep(1) # 토스트 메시지 보여줄 시간
                st.rerun()
            else:
                st.warning("필터링할 위협 항목이 없습니다.")

    st.write("")

    # 3. 다운로드 영역 (Expander로 숨겨서 깔끔하게)
    with st.expander("📥 리포트 다운로드"):
        st.info("현재 저장된 `network_logs.csv` 파일을 다운로드합니다.")
        with open("network_logs.csv", "rb") as f:
            st.download_button(
                label="📥 위협 로그 리포트 받기",
                data=f,
                file_name=f"threat_report_{pd.Timestamp.now().strftime('%m%d_%H%M')}.csv",
                mime="text/csv",
                use_container_width=True
            )

else:
    # 파일이 없을 때 예쁜 알림
    with st.status("파일을 찾을 수 없습니다", state="error"):
        st.write("저장된 `network_logs.csv` 파일이 없습니다.")
        st.write("먼저 **네트워크 엔진**을 가동하여 데이터를 수집하세요.")