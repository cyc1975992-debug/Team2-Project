import streamlit as st
import pandas as pd
import os

st.title("💾 CSV DB 생성")

# 파일이 존재하는지 먼저 확인
if os.path.exists("network_logs.csv"):
    if st.button("🚨 위협 로그 추출"):
        # 1. 파일에서 데이터 불러오기
        full_df = pd.read_csv("network_logs.csv")

        # 2. '🚨 위협' 상태인 데이터만 필터링
        # (문자열에 '위협'이 포함되어 있는지 확인하는 방식이 더 안전합니다)
        threat_df = full_df[full_df['상태'].str.contains("위협", na=False)]

        if not threat_df.empty:
            # 3. 추출된 위협 로그를 새로운 파일로 임시 저장
            threat_df.to_csv("threat_db_temp.csv", index=False, encoding='utf-8-sig')
            st.success(f"파일에서 총 {len(threat_df)}건의 위협 로그를 찾아냈습니다.")
        else:
            st.warning("기록된 로그 중 위협 항목이 없습니다.")

    # 4. 추출된 임시 파일이 있다면 다운로드 버튼 표시
    if os.path.exists("threat_db_temp.csv"):
        with open("threat_db_temp.csv", "rb") as f:
            st.download_button("📥 위협 로그 다운로드", f, file_name="threat_only_logs.csv")
else:
    st.error("저장된 network_logs.csv 파일이 없습니다. 먼저 엔진을 가동하여 로그를 생성하세요.")