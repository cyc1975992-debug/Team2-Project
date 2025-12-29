import streamlit as st
import pandas as pd
import plotly.express as px
from scapy.all import sniff, IP, TCP, ICMP
from datetime import datetime
import threading
import time
import os

LOG_FILE = "network_logs.csv"

# 파일이 없으면 헤더와 함께 생성
if not os.path.exists(LOG_FILE):
    df_empty = pd.DataFrame(columns=['시간', '출발지', '도착지', '프로토콜', '상태', '상세내용'])
    df_empty.to_csv(LOG_FILE, index=False, encoding='utf-8-sig')

# =========================================================
# 1. 설정 및 초기화
# =========================================================
st.set_page_config(page_title="AI 보안 관제 시스템", layout="wide")

# (추가) 엔진 제어를 위한 플래그 초기화
if 'run_engine' not in st.session_state:
    st.session_state['run_engine'] = False

# 세션 상태 초기화
if 'logs' not in st.session_state:
    st.session_state['logs'] = pd.DataFrame(columns=['시간', '출발지', '도착지', '프로토콜', '상태', '상세내용'])

if 'blocked_ips' not in st.session_state:
    st.session_state['blocked_ips'] = ["8.8.8.8", "1.1.1.1"]

# 공유 버퍼
@st.cache_resource
def get_shared_buffer():
    return []

packet_buffer = get_shared_buffer()

# =========================================================
# 2. 패킷 수집 엔진
# =========================================================
def packet_analyzer(packet):
    # 1. IP 레이어가 있는지 먼저 확인
    if not packet.haslayer(IP):
        return

    try:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # 프로토콜 판별
        if packet.haslayer(TCP):
            proto = "TCP"
            detail = f"Port: {packet[TCP].sport} -> {packet[TCP].dport}"
        elif packet.haslayer(ICMP):
            proto = "ICMP"
            detail = "Ping 요청/응답"
        else:
            proto = "기타"
            detail = f"{packet[IP].proto} 프로토콜"

        # 2. 위협 탐지 로직 수정 (출발지 OR 도착지 모두 체크)
        # 스레드 에러를 피하기 위해 함수 안에서 리스트를 직접 선언합니다.
        danger_ips = ["8.8.8.8", "1.1.1.1"]

        # 내가 8.8.8.8에 핑을 쏴도 탐지되도록 dst_ip 추가
        if src_ip in danger_ips or dst_ip in danger_ips:
            status = "🚨 위협"
        else:
            status = "정상"

        new_entry = {
            '시간': datetime.now().strftime('%H:%M:%S'),
            '출발지': src_ip,
            '도착지': dst_ip,
            '프로토콜': proto,
            '상태': status,
            '상세내용': detail
        }

        # 3. 버퍼에 담기 (가장 안전한 데이터 전달 방식)
        packet_buffer.append(new_entry)

        # 4. 파일 저장은 선택사항 (에러 방지를 위해 예외처리)
        try:
            df_to_save = pd.DataFrame([new_entry])
            df_to_save.to_csv(LOG_FILE, mode='a', header=False, index=False, encoding='utf-8-sig')
        except:
            pass

    except Exception as e:
        # 에러 발생 시 엔진이 죽지 않도록 무시
        pass

def start_sniffing():
    # stop_filter를 추가하여 st.session_state['run_engine']이 False가 되면 멈추게 함
    sniff(
        prn=packet_analyzer,
        store=0,
        iface=None,
        stop_filter=lambda x: not st.session_state.get('run_engine', False)
    )

# =========================================================
# 3. 메인 UI (09 파일 스타일 참고)
# =========================================================

# 사이드바 메뉴 구성
st.sidebar.title("🛡️ IDS Dashboard")
menu = st.sidebar.selectbox('메뉴 선택', ['실시간 관제', '블랙리스트 관리', '시스템 정보'])
show_code = st.sidebar.checkbox('Source Code 표시')

st.sidebar.divider()
st.sidebar.subheader("🕹️ 시스템 제어")

# 1. 엔진 중지/시작 버튼
if st.session_state.get('engine_on', False):
    if st.sidebar.button("🔴 관제 엔진 중지", use_container_width=True):
        st.session_state['run_engine'] = False  # 스레드 중지 신호
        st.session_state['engine_on'] = False
        st.sidebar.warning("엔진 중지 중... (잠시만 기다려주세요)")
        time.sleep(1)
        st.rerun()
else:
    if st.sidebar.button("🟢 관제 엔진 가동", use_container_width=True):
        st.session_state['run_engine'] = True   # 스레드 가동 신호
        st.session_state['engine_on'] = True

        # [중요] Streamlit의 현재 실행 환경(Context)을 가져옵니다.
        from streamlit.runtime.scriptrunner import add_script_run_ctx

        t = threading.Thread(target=start_sniffing, daemon=True)

        # [중요] 생성한 스레드에 Context를 주입합니다.
        add_script_run_ctx(t)
        t.start()
        st.sidebar.success("엔진 가동 시작!")
        st.rerun()

# 2. 패킷 로그 초기화 버튼
if st.sidebar.button("🗑️ 패킷 로그 초기화", use_container_width=True):
    # 세션 데이터 삭제
    st.session_state['logs'] = pd.DataFrame(columns=['시간', '출발지', '도착지', '프로토콜', '상태', '상세내용'])
    # 공유 버퍼 비우기
    packet_buffer.clear()
    # CSV 파일 초기화
    df_empty = pd.DataFrame(columns=['시간', '출발지', '도착지', '프로토콜', '상태', '상세내용'])
    df_empty.to_csv(LOG_FILE, index=False, encoding='utf-8-sig')
    st.sidebar.info("모든 로그가 삭제되었습니다.")
    time.sleep(1)
    st.rerun()

st.sidebar.divider()

# 1. 실시간 데이터 업데이트 로직
if packet_buffer:
    while packet_buffer:
        item = packet_buffer.pop(0)
        new_row = pd.DataFrame([item])
        st.session_state['logs'] = pd.concat([new_row, st.session_state['logs']], ignore_index=True).head(100)

# --- 메뉴별 화면 구성 ---

if menu == '실시간 관제':
    st.title("📡 실시간 네트워크 관제 모드")

    # 지표 표시
    logs_df = st.session_state['logs']

    col1, col2, col3 = st.columns(3)
    col1.metric("총 분석 패킷", f"{len(logs_df)} PKT")
    col2.metric("탐지된 위협", f"{len(logs_df[logs_df['상태'] == '🚨 위협'])} 건")
    col3.metric("엔진 상태", "Running" if 'engine_on' in st.session_state else "Stopped")

    # 데이터프레임 출력 (09 파일의 st.dataframe 참고)
    st.subheader("📋 최근 패킷 로그 (최신 100개)")
    st.dataframe(logs_df, use_container_width=True, height=400)

    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "rb") as f:
            st.download_button("📥 전체 로그 CSV 다운로드", f, file_name="logs.csv")


    # 시각화 영역 (Plotly 활용)
    if not logs_df.empty:
        st.divider()
        st.subheader("📊 프로토콜별 통계")
        proto_counts = logs_df['프로토콜'].value_counts().reset_index()
        proto_counts.columns = ['프로토콜', '개수']

        fig = px.pie(proto_counts, values='개수', names='프로토콜',
                     title="네트워크 프로토콜 점유율",
                     color_discrete_sequence=px.colors.sequential.RdBu)
        st.plotly_chart(fig, use_container_width=True)

elif menu == '블랙리스트 관리':
    st.title("🚫 블랙리스트 관리")

    with st.form("ip_form"):
        new_ip = st.text_input("차단할 IP 주소를 입력하세요")
        submit = st.form_submit_button("차단 목록에 추가")

        if submit and new_ip:
            if new_ip not in st.session_state['blocked_ips']:
                st.session_state['blocked_ips'].append(new_ip)
                st.success(f"{new_ip}가 블랙리스트에 추가되었습니다.")
            else:
                st.warning("이미 등록된 IP입니다.")

    st.subheader("현재 차단된 IP 리스트")
    st.table(pd.DataFrame(st.session_state['blocked_ips'], columns=["IP Address"]))

    if st.button("목록 전체 초기화"):
        st.session_state['blocked_ips'] = []
        st.rerun()

elif menu == '시스템 정보':
    st.title("ℹ️ System Information")
    st.info("본 시스템은 Scapy와 Streamlit을 결합한 실시간 네트워크 침입 탐지 데모입니다.")
    st.write("사용된 라이브러리: Streamlit, Pandas, Plotly, Scapy")

    st.divider() # 시각적 구분선
    if st.button("🗑️ 로그 파일 초기화"):
        if os.path.exists(LOG_FILE):
            os.remove(LOG_FILE)
            st.success("로그 파일이 삭제되었습니다. 새로고침 시 다시 생성됩니다.")

# 코드 표시 기능 (09 파일 로직)
if show_code:
    st.divider()
    st.subheader("🔍 Source Code")
    with open(__file__, "r", encoding="utf-8") as f:
        st.code(f.read(), language="python")

# 자동 새로고침 (실시간 관제 메뉴일 때만 작동)
if menu == '실시간 관제' and 'engine_on' in st.session_state:
    time.sleep(2)
    st.rerun()




