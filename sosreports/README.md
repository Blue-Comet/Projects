# SOSReport Analyzer (`sosreport.py`)

Linux 시스템 진단 아카이브(`sosreport-*.tar.xz`, `.tar.gz`)를 분석하여 단일 대화형 HTML 보고서를 생성하는 Python 진단 도구입니다. 디스크에 압축을 풀지 않고 메모리에서 직접 스트리밍 분석합니다.

---

## 💻 사용 환경 (Requirements)

- **Python**: Python 3.8 이상 (Python 3.10+ 권장)
- **운영체제**: Linux, macOS, Windows
- **외부 패키지**: 설치 불필요 (`pip install` 불필요, Python 표준 라이브러리만 사용)
- **네트워크**: 외부 통신 없음 (완전 폐쇄망 지원)

---

## 🚀 사용 방법 (Usage)

### 1. 기본 실행 명령

```bash
python3 sosreport.py <아카이브_경로> <출력_경로>
```

- **디렉토리로 출력 시** (파일명 자동 생성: `Outputs/<호스트명>.html`):
  ```bash
  python3 sosreport.py Files/sosreport-example-server.tar.xz Outputs/
  ```

- **특정 파일명으로 출력 시**:
  ```bash
  python3 sosreport.py Files/sosreport-example-server.tar.xz Outputs/report.html
  ```

### 2. 대상 서버에서 SOSReport 수집 방법

```bash
# Ubuntu / Debian
sudo apt-get install -y sosreport && sudo sos report --batch

# RHEL / CentOS / Rocky / Amazon Linux
sudo yum install -y sos && sudo sos report --batch
```
> 생성된 `/var/tmp/sosreport-*.tar.xz` 파일을 로컬로 복사하여 분석합니다.

---

## ✨ 핵심 기능 (Features)

- **100점 만점 헬스 스코어**: 서비스 실패, 디스크 포화(85%+), 메모리 고갈, 커널 OOM, 시스템 고부하 등을 종합 평가하여 감점 산출.
- **위험 항목 우선 정렬**: Warning 및 Critical 항목(고용량 파티션, 고부하/좀비 프로세스, 비정상 네트워크 소켓 등)을 화면 최상단에 우선 배치.
- **Bastion 서버 지능형 진단**: 호스트명에 `bastion`이 포함된 경우 SSH 패스워드 인증 점검을 정상 처리하여 불필요한 감점 방지 (일반 서버는 패스워드 인증 시 10점 감점).
- **가독성 최적화 UI**:
  - **5개 기본 노출 및 토글**: 카드/테이블별 상위 5개 항목만 기본 노출하고 `+더보기` / `-접기` 지원.
  - **2줄 교차 배경색 로그**: `dmesg`, `journalctl` 및 원본 로그 뷰어에 2행 단위 교차 배경색과 에러 키워드 하이라이팅 적용.
- **진단 수집 원본 파일 뷰어 (Tab 8)**: 수집된 44종의 시스템 명령어 결과 원본 파일 실시간 열람 및 원클릭 복사.
- **단일 파일 HTML (Standalone)**: 외부 의존성 없는 단일 HTML 파일로 생성되며 다크/라이트 모드, 한/영 전환 및 실시간 필터링 지원.

---

## 📂 프로젝트 구조

```text
sosreports/
├── sosreport.py         # 분석 엔진 및 HTML 리포트 생성 스크립트
├── Files/               # 분석 대상 SOSReport 아카이브(.tar.xz) 보관 디렉토리
├── Outputs/             # 생성된 HTML 리포트 파일 저장 디렉토리
└── README.md            # 사용 가이드
```
