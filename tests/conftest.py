# tests/conftest.py
import sys
import os

# 이 conftest.py 파일의 위치를 기준으로 프로젝트 루트 경로를 계산합니다.
# 현재 파일 -> tests -> ansible-collection-customapi-inventory (프로젝트 루트)
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

# sys.path에 프로젝트 루트를 추가합니다.
# 이렇게 하면 'plugins' 패키지를 찾을 수 있게 됩니다.
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)