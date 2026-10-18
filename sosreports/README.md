# SOSReport Automated Analyzer & HTML Report Generator

Linux 시스템 진단 도구인 **SOSReport** 아카이브(`.tar.xz`, `.tar.gz`, `.tar`)를 자동으로 파싱하고 종합 헬스 체크 및 대화형 단일 파일(Single-File) HTML 보고서를 생성하는 Python 도구입니다.

외부 종속성(External Dependency) 없이 Python 표준 라이브러리만으로 동작하며, 아카이브를 디스크에 압축 해제하지 않고 메모리 내에서 직접 스트리밍 방식으로 분석합니다.

---

## 📌 주요 특징 (Key Features)

- **Zero External Dependencies**: `pip install` 없이 Python 3 표준 라이브러리(`tarfile`, `json`, `re`, `pathlib`, `argparse` 등)만으로 구동.
- **In-Memory Streaming Extraction**: 대용량 압축 아카이브(`.tar.xz` 등)를 디스크에 풀지 않고 필요한 진단 파일만 메모리 상에서 심볼릭 링크를 자동 추적하여 초고속 분석.
- **Rule-based Health Scoring**: 시스템 부하, 메모리 고갈(OOM), 디스크/Inode 임계치, 실패한 Systemd 서비스, 보안 취약 설정(SSH 등)을 종합 평가하여 100점 만점 헬스 스코어 및 상태 배지(정상/주의/위험) 산출.
- **Source Path Traceability**: 분석된 모든 항목에 SOSReport 내 실제 명령어 결과 파일 경로(`sos_commands/...`, `etc/...`)를 명시하여 원본 로그 역추적 지원.
- **Standalone Interactive HTML**: CDN이나 외부 네트워크 통신이 전혀 필요 없는 완전 자립형 단일 HTML 파일로 생성 (폐쇄망/오프라인 환경 완벽 지원).
  - **다크 모드 / 라이트 모드 (Dual Theme)** 전환 지원
  - **한국어 / English** 실시간 다국어 지원
  - **실시간 검색 및 필터링**: 테이블 내 프로세스, 포트, 사용자, 서비스 즉시 필터
  - **원클릭 클립보드 복사**: 원본 집계 JSON 데이터 및 주요 정보 간편 복사

---

## 📊 분석 및 진단 영역 (Audit Scope)

| 탭 / 영역 | 주요 분석 내용 및 참조 소스 |
| :--- | :--- |
| **진단 및 개요** *(Overview)* | 시스템 기본 스펙(OS, 커널, Arch, Hostname, Uptime), AWS EC2 메타데이터(Instance ID, Type, AZ 등), 종합 헬스 스코어 및 핵심 조치 권장사항 |
| **사용자 및 보안** *(Users & Security)* | 대화형/시스템 계정 분류, UID/GID, Sudo 권한 상세 규칙(`/etc/sudoers`, `/etc/sudoers.d/*`), 사용자별 프로세스 점유 수, 최근 로그인 이력(`last -F`), SSH Daemon 보안 설정(`sshd -T`) |
| **스토리지 및 디스크** *(Storage & Disks)* | 마운트별 디스크 사용량(`df -h`) 및 Inode 사용 현황, 블록 디바이스 계층 구조(`lsblk`), 루트 볼륨 및 추가 EBS/데이터 디스크 자동 분류 |
| **CPU 및 메모리** *(CPU & Memory)* | CPU 코어 수, 모델, 캐시, 실시간 Load Average(1m/5m/15m), 메모리/Swap 점유율(`free`, `/proc/meminfo`), OOM Killer 발생 이력 |
| **서비스 및 부팅** *(Services & Boot)* | 실패한 Systemd 유닛 목록(`systemctl --failed`), 부팅 단계별 지연 서비스 분석(`systemd-analyze blame`), 활성 Systemd 타이머(`systemctl list-timers`) |
| **스케줄러** *(Crontabs & Timers)* | 사용자별 Crontab(`/var/spool/cron/crontabs/*`), 시스템 Crontab(`/etc/crontab`, `/etc/cron.d/*`), 주기적 Cron 작업(`cron.daily`, `cron.hourly` 등) |
| **네트워크 및 포트** *(Network & Ports)* | 네트워크 인터페이스별 IP/MAC/MTU 상태, 라우팅 테이블(`ip route`), TCP/UDP 리스닝 포트 및 바인딩 프로세스, 활성 소켓 연결, DNS 해석 설정(`resolvectl`) |
| **프로세스** *(Processes)* | CPU / 메모리 사용률 상위 프로세스 Top 랭킹, 프로세스 상태 및 인라인 검색 |
| **로그 및 커널 이슈** *(Logs & Audit)* | 커널 링 버퍼(`dmesg`) 및 시스템 부트 저널(`journalctl -b`) 내 에러/경고/Segfault/I/O 오류 필터링 및 카운트 |
| **원본 JSON** *(Raw JSON)* | 파싱된 모든 구조화 데이터를 JSON 형식으로 내장하여 확인 및 Export 가능 |

---

## 🛠️ 요구 사항 (Prerequisites)

- **Python**: 3.8 이상 (권장: Python 3.10+)
- **운영체제**: Linux, macOS, Windows (플랫폼 독립적)
- **외부 패키지 설치 불필요** (`pip` 설치 없음)

---

## 🚀 사용 방법 (Usage)

### 1. 기본 실행 명령

```bash
python3 sosreport.py <sourcefile> <outputfile>
```

- `<sourcefile>`: SOSReport 압축 파일 경로 (`.tar.xz`, `.tar.gz`, `.tar.bz2`, `.tar` 등 지원)
- `<outputfile>`: 생성될 HTML 파일 경로 또는 출력 디렉토리 경로

### 2. 실행 예시

#### 디렉토리를 출력 경로로 지정하는 경우 (파일명 자동 생성)
```bash
python3 sosreport.py Files/sosreport-example-server-2026-10-11-xxxxxxx.tar.xz Outputs/
```
> `Outputs/sosreport-example-server-2026-10-11-xxxxxxx_report.html` 파일로 자동 저장됩니다.

#### 출력 HTML 파일명을 직접 지정하는 경우
```bash
python3 sosreport.py Files/sosreport-example-server.tar.xz Outputs/custom_report.html
```

### 3. 실행 결과 출력 예시

```text
[*] Reading archive: sosreport-example-server-2026-10-11-xxxxxxx.tar.xz (46.42 MB)...
[+] Loaded 43 diagnostic command outputs with symlinks resolved.

============================================================
🎉 SOSReport Analysis Completed Successfully!
📌 Input Archive : /path/to/Files/sosreport-example-server-2026-10-11-xxxxxxx.tar.xz
📊 Target Host   : example-server
🩺 Health Score  : 90/100
📄 Output Report : /path/to/Outputs/sosreport-example-server-2026-10-11-xxxxxxx_report.html
============================================================
```

---

## 📂 프로젝트 구조 (Directory Structure)

```text
sosreports/
├── sosreport.py         # SOSReport 분석 및 HTML 생성 핵심 엔진
├── Files/               # 수집된 sosreport 아카이브(.tar.xz) 보관 디렉토리
│   └── sosreport-*.tar.xz
├── Outputs/             # 생성된 진단 리포트 HTML 파일 저장 디렉토리
│   └── *.html
└── README.md            # 본 프로젝트 문서
```

---

## 💡 참고 사항 (Reference & Tips)

### 대상 서버에서 SOSReport 수집하는 방법
대상 Linux 서버에서 SOSReport를 생성하려면 다음 명령을 실행합니다:
```bash
# Ubuntu / Debian
sudo apt-get install -y sosreport
sudo sos report --batch

# RHEL / CentOS / Rocky / AlmaLinux / Amazon Linux
sudo yum install -y sos
sudo sos report --batch
```
생성된 `/tmp/sosreport-*.tar.xz` 파일을 로컬의 `Files/` 디렉토리로 다운로드한 후 `sosreport.py`로 분석하면 됩니다.
