import streamlit as st
import pandas as pd
import os

st.title("💾 CSV 위협 로그 관리")

# 파일이 존재하는지 먼저 확인
if os.path.exists("network_logs.csv"):
    if st.button("🚨 위협 로그만 남기기 (파일 업데이트)"):
        # 1. 파일에서 데이터 불러오기
        full_df = pd.read_csv("network_logs.csv")

        # 2. '🚨 위협' 상태인 데이터만 필터링
        # 상태 열에 '위협' 단어가 포함된 행만 추출합니다.
        threat_df = full_df[full_df['상태'].str.contains("위협", na=False)]

        if not threat_df.empty:
            # 3. [핵심] 기존 network_logs.csv 파일에 위협 데이터만 덮어쓰기
            # 별도의 임시 파일을 만들지 않고 원본 파일명을 그대로 사용합니다.
            threat_df.to_csv("network_logs.csv", index=False, encoding='utf-8-sig')
            st.success(f"network_logs.csv 파일이 업데이트되었습니다. (총 {len(threat_df)}건의 위협 로그)")
            st.rerun() # 화면을 갱신하여 변경된 파일 상태 반영
        else:
            st.warning("기록된 로그 중 위협 항목이 없어 파일을 업데이트하지 않았습니다.")

    # 4. 업데이트된 network_logs.csv 파일 다운로드 버튼
    # 이제 network_logs.csv 자체가 위협 로그만 담고 있게 됩니다.
    with open("network_logs.csv", "rb") as f:
        st.download_button(
            label="📥 현재 위협 로그 파일 다운로드",
            data=f,
            file_name="network_logs_threat_only.csv",
            mime="text/csv"
        )
else:
    st.error("저장된 network_logs.csv 파일이 없습니다. 먼저 엔진을 가동하여 로그를 생성하세요.")