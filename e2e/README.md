# E2E Test Suite

`e2e` 프레임워크(`@e2e-dev/web`) 및 LLM 에이전트를 활용한 웹 애플리케이션 End-to-End (E2E) 자동화 테스트 프로젝트입니다.

---

## 📌 주요 특징

- **Agentic E2E Runner**: Playwright 기반 브라우저 제어 및 AI 에이전트 자율 탐색 지원
- **LLM 연동**: `@ai-sdk/openai-compatible`을 통한 Google Gemini(`gemini-3.8-flash`) 모델 연계
- **DOM 심층 분석**: 지연 로딩(Lazy Loading) 스크롤 처리 및 텍스트/이미지(`alt`, `src`)/클래스 기반의 Sold out 상품 자동 판독
- **MCP Server 지원**: IDE/AI Agent 환경 연동을 위한 Model Context Protocol (`npx e2e mcp`) 구성

---

## 📂 프로젝트 구조

```plaintext
e2e/
├── .agents/                    # Agent Skill 정의 및 레퍼런스
├── .e2e/                       # 테스트 실행 결과물 (리포트, 트레이스, 캐시 - gitignore 대상)
├── .mcp.json                   # e2e MCP 서버 설정
├── e2e.config.ts               # e2e 실행 환경 및 Agent/Target 설정
├── package.json                # 의존성 및 실행 스크립트 정의
└── tests/                      # 테스트 시나리오 파일
    └── dev.example.com.e2e.ts
```

---

## ⚙️ 사전 요구 사항 (Prerequisites)

- **Node.js**: v18.0.0 이상 (LTS 권장)
- **API Key**: Gemini API 엔드포인트 연동용 `OPENAI_API_KEY` (에이전트 기능 사용 시 필요)

---

## 🚀 설치 및 환경 변수 설정

### 1. 패키지 설치
```bash
npm install
```

### 2. 환경 변수 설정
```bash
# Gemini OpenAI 호환 엔드포인트용 API Key 설정
export OPENAI_API_KEY="your-gemini-api-key"

# 대상 애플리케이션 URL (기본값: https://dev.example.com/welcome)
export APP_URL="https://dev.example.com/welcome"
```

---

## 🧪 테스트 실행 방법

### 전체 테스트 실행
```bash
npm run test:e2e
```

### 특정 테스트 파일 실행
```bash
npx e2e run tests/dev.example.com.e2e.ts
```

### 브라우저 UI 모드 (Headed) 실행
```bash
npx e2e run --headed
```

### 디버그 모드 실행
```bash
npx e2e run --debug
```

### AI Trace 추적
```bash
npx e2e run --ai-trace
```

---

## 📋 테스트 시나리오 요약

### [dev.example.com.e2e.ts](file:///home/comet/문서/GitHub/Projects/e2e/tests/dev.example.com.e2e.ts)
1. **app opens**: 대상 URL 접속 후 `body` 태그 정상 렌더링 확인
2. **the agent drives a flow**:
   - 페이지 진입 및 로딩 대기
   - 2단계 스크롤을 통한 상품 동적 지연 로딩(Lazy Loading) 유도
   - 텍스트 노드, 클래스명, 이미지 태그(`alt`, `src`) 종합 스캔을 통해 "Sold out" 상태 요소 식별 및 개수 집계

---

## 🛠️ MCP (Model Context Protocol) 연동

AI 에이전트(Claude Desktop, Cursor 등)가 live 브라우저를 탐색 및 제어할 수 있도록 MCP 서버가 구성되어 있습니다.

```bash
npx e2e mcp
```
자세한 설정은 [.mcp.json](file:///home/comet/문서/GitHub/Projects/e2e/.mcp.json)을 참조하십시오.
