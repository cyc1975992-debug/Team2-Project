

import csv

log_file = "logs/icmp.log"
csv_file = "logs/icmp.csv"

with open(log_file, "r", encoding="utf-8") as lf, \
        open(csv_file, "w", newline="", encoding="utf-8") as cf:

    writer = csv.writer(cf)
    # CSV 헤더
    writer.writerow(["시간", "사유", "ip 주소"])

    for line in lf:
        parts = line.strip().split(" | ")
        if len(parts) == 3:
            writer.writerow(parts)

# import streamlit as st
# import pandas as pd
# from pathlib import Path
#
# BASE_DIR = Path(__file__).resolve().parent
# csv_path = BASE_DIR / "logs" / "icmp.csv" # 경로 지정
# st.header("Dataframes and Tables")
# df = pd.read_csv(csv_path)
#
# # 데이터 집합을 가변적으로 출력
#
# st.dataframe(df.head(10))
# # 데이터 집합을 정적으로 출력
# st.table(df.head(10))
#
# st.area_chart(df[["mpg","cylinders"]])
#
# st.bar_chart(df[["mpg","cylinders"]].head(20))
#
# st.line_chart(df[["mpg","cylinders"]].head(20))
