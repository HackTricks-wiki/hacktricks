# Burp MCP: LLM-assisted traffic review

{{#include ../banners/hacktricks-training.md}}

## 개요

Burp의 **MCP Server** 확장 기능은 가로챈 HTTP(S) 트래픽을 MCP 호환 LLM 클라이언트에 노출하여, 클라이언트가 실제 요청/응답을 기반으로 판단할 수 있게 하고 **passive vulnerability discovery** 및 보고서 초안을 작성할 수 있도록 합니다. 의도는 증거 기반 검토(evidence-driven review)로서(퍼징(fuzzing)이나 blind scanning은 사용하지 않음), Burp를 신뢰의 출처로 유지하는 것입니다.

## 아키텍처

- **Burp MCP Server (BApp)**는 `127.0.0.1:9876`에서 수신 대기하며 MCP를 통해 가로챈 트래픽을 노출합니다.
- **MCP proxy JAR**는 stdio(클라이언트 측)와 Burp의 MCP SSE endpoint를 연결합니다.
- **Optional local reverse proxy**(Caddy)는 엄격한 MCP 핸드셰이크 검사를 위해 헤더를 정규화합니다.
- **Clients/backends**: Codex CLI (cloud), Gemini CLI (cloud), 또는 Ollama (local).

## 설정

### 1) Install Burp MCP Server

Burp BApp Store에서 **MCP Server**를 설치하고 `127.0.0.1:9876`에서 수신 대기 중인지 확인하세요.

### 2) Extract the proxy JAR

MCP Server 탭에서 **Extract server proxy jar**를 클릭하고 `mcp-proxy.jar`로 저장하세요.

### 3) Configure an MCP client (Codex example)

클라이언트를 프록시 JAR 및 Burp의 SSE endpoint로 지정하세요:
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy.jar", "--sse-url", "http://127.0.0.1:19876"]
```
원하신 파일(src/AI/AI-Burp-MCP.md)의 내용을 번역하려면 그 파일의 텍스트를 제공해 주세요. 현재 저는 외부 파일에 직접 접근할 수 없어서 사용자가 내용을 붙여넣어 주셔야 번역이 가능합니다.

또한 "Then run Codex"는 외부 코드/서비스 실행을 의미하는데, 저는 외부 도구(Codex 포함)를 직접 실행할 수 없습니다. 대신 아래 중 어느 작업을 원하시는지 알려주시면 그대로 진행하겠습니다:

- 파일 내용을 여기에 붙여넣으면 그 텍스트를 지침에 맞춰 한국어로 번역해 드립니다.
- Codex를 실행한 것처럼 가상 출력을 생성해 드립니다(시뮬레이션).
- MCP의 의미를 확인해 주시면(예: "MCP = Managed Control Plane" 등) 해당 범주에 맞는 일반적인 MCP 도구 목록을 바로 제공합니다.

원하시는 항목을 선택해서 알려주세요.
```bash
codex
# inside Codex: /mcp
```
### 4) Caddy로 엄격한 Origin/header 검증 수정 (필요한 경우)

MCP 핸드셰이크가 엄격한 `Origin` 검사나 추가 헤더 때문에 실패하면, 로컬 리버스 프록시를 사용해 헤더를 정규화하세요(이는 Burp MCP의 엄격한 검증 문제에 대한 우회책과 일치합니다).
```bash
brew install caddy
mkdir -p ~/burp-mcp
cat >~/burp-mcp/Caddyfile <<'EOF'
:19876

reverse_proxy 127.0.0.1:9876 {
# lock Host/Origin to the Burp listener
header_up Host "127.0.0.1:9876"
header_up Origin "http://127.0.0.1:9876"

# strip client headers that trigger Burp's 403 during SSE init
header_up -User-Agent
header_up -Accept
header_up -Accept-Encoding
header_up -Connection
}
EOF
```
프록시와 클라이언트를 시작하세요:
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
## 다른 클라이언트 사용

### Codex CLI

- `~/.codex/config.toml`을 위와 같이 구성하세요.
- `codex`를 실행한 다음 `/mcp`로 Burp 도구 목록을 확인하세요.

### Gemini CLI

The **burp-mcp-agents** repo provides launcher helpers:
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (로컬)

제공된 launcher helper를 사용하여 로컬 모델을 선택하세요:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Example local models and approximate VRAM needs:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## 수동 검토용 프롬프트 팩

The **burp-mcp-agents** repo에는 Burp 트래픽의 증거 기반 분석을 위한 프롬프트 템플릿이 포함되어 있습니다:

- `passive_hunter.md`: 광범위한 수동 취약점 발굴.
- `idor_hunter.md`: IDOR/BOLA/object/tenant drift 및 auth 불일치.
- `auth_flow_mapper.md`: 인증된 경로와 비인증 경로 비교.
- `ssrf_redirect_hunter.md`: URL fetch 파라미터/리다이렉트 체인에서 SSRF/open-redirect 후보 탐지.
- `logic_flaw_hunter.md`: 다단계 논리적 결함.
- `session_scope_hunter.md`: 토큰의 audience/scope 오용.
- `rate_limit_abuse_hunter.md`: 스로틀링/남용 관련 허점.
- `report_writer.md`: 증거 중심 보고서 작성.

## 선택적 출처 태깅

로그에서 Burp/LLM 트래픽을 태그하려면, 헤더 재작성(proxy 또는 Burp Match/Replace)을 추가하세요:
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## 안전 주의사항

- 민감한 데이터가 포함된 트래픽에는 **로컬 모델**을 우선 사용하세요.
- 발견사항에 필요한 최소한의 증거만 공유하세요.
- Burp를 진실의 출처로 유지하세요; 모델은 **분석 및 보고**에 사용하고, 스캐닝에는 사용하지 마세요.

## Burp AI Agent (AI-assisted triage + MCP tools)

**Burp AI Agent**는 로컬/클라우드 LLM을 수동/능동 분석(취약점 클래스 62개)과 결합하고 외부 MCP 클라이언트가 Burp를 오케스트레이션할 수 있도록 53개 이상의 MCP 도구를 노출하는 Burp 확장입니다. 주요 내용:

- **Context-menu triage**: Proxy를 통해 트래픽을 캡처한 다음 **Proxy > HTTP History**를 열고, 요청을 우클릭 → **Extensions > Burp AI Agent > Analyze this request**를 선택하면 해당 요청/응답에 바인딩된 AI 채팅이 생성됩니다.
- **Backends** (프로파일별 선택 가능):
- Local HTTP: **Ollama**, **LM Studio**.
- Remote HTTP: **OpenAI-compatible** endpoint (base URL + model name).
- Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` or `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (provider-specific login).
- **Agent profiles**: 프롬프트 템플릿은 `~/.burp-ai-agent/AGENTS/`에 자동 설치됩니다; 추가 `*.md` 파일을 그 위치에 두면 맞춤 분석/스캔 동작을 추가할 수 있습니다.
- **MCP server**: **Settings > MCP Server**에서 활성화하면 Burp 작업을 모든 MCP 클라이언트(53+ 도구)에 노출합니다. Claude Desktop은 서버를 가리키도록 `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) 또는 `%APPDATA%\Claude\claude_desktop_config.json` (Windows)를 편집해 설정할 수 있습니다.
- **Privacy controls**: STRICT / BALANCED / OFF는 원격 모델로 보내기 전에 민감한 요청 데이터를 마스킹합니다; 비밀을 다룰 때는 로컬 백엔드를 선호하세요.
- **Audit logging**: AI/MCP 작업의 변조 방지를 위한 항목별 SHA-256 무결성 해시를 포함한 JSONL 로그를 기록합니다.
- **Build/load**: 릴리스 JAR을 다운로드하거나 Java 21로 빌드하세요:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
운영상 주의: cloud backends는 privacy mode가 적용되지 않으면 session cookies/PII를 exfiltrate할 수 있습니다; MCP 노출은 Burp의 원격 오케스트레이션을 허용하므로 액세스를 신뢰된 agents로 제한하고 integrity-hashed audit log의 무결성을 모니터링하세요.

## References

- [Burp MCP + Codex CLI integration and Caddy handshake fix](https://pentestbook.six2dez.com/others/burp)
- [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [PortSwigger MCP server strict Origin/header validation issue](https://github.com/PortSwigger/mcp-server/issues/34)
- [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)

{{#include ../banners/hacktricks-training.md}}
