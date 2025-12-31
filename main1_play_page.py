import subprocess
import sys

def run_streamlit(appName):
    subprocess.run([sys.executable,
                    '-m', 'streamlit', 'run', str(appName)])

# 실행 진입점
# 위치는 파일 맨 아래
if __name__ == "__main__":
    run_streamlit('main1.py')
