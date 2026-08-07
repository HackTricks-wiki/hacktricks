# Burp MCP: LLM 지원 traffic review

{{#include ../banners/hacktricks-training.md}}

## 개요

Burp의 **MCP Server** extension은 가로챈 HTTP(S) traffic을 MCP를 지원하는 LLM client에 노출하여, 실제 request/response를 **분석**하고 passive vulnerability discovery 및 report 초안 작성을 수행할 수 있도록 합니다. 목적은 fuzzing이나 blind scanning 없이, Burp를 source of truth로 유지하면서 evidence-driven review를 수행하는 것입니다.

## Architecture

- **Burp MCP Server (BApp)**는 `127.0.0.1:9876`에서 수신 대기하며, 가로챈 traffic을 MCP를 통해 노출합니다.<sup>[[1]](#references)[[2]](#references)</sup>
- **MCP proxy JAR**는 stdio (client side)와 Burp의 MCP SSE endpoint를 연결합니다.
- **Optional local reverse proxy** (Caddy)는 strict MCP handshake checks를 위해 headers를 정규화합니다.
- **Clients/backends**: Codex CLI (cloud), Gemini CLI (cloud), 또는 Ollama (local).

## Setup

### 1) Burp MCP Server 설치

Burp BApp Store에서 **MCP Server**를 설치하고 `127.0.0.1:9876`에서 수신 대기 중인지 확인합니다.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) proxy JAR 추출

MCP Server tab에서 **Extract server proxy jar**를 클릭하고 `mcp-proxy.jar`로 저장합니다.

### 3) MCP client 구성 (Codex 예시)

client가 proxy JAR 및 Burp의 SSE endpoint를 사용하도록 지정합니다:
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy.jar", "--sse-url", "http://127.0.0.1:19876"]
```
그런 다음 Codex를 실행하고 MCP 도구를 나열합니다:
```bash
codex
# inside Codex: /mcp
```
### 4) Caddy로 strict Origin/header 검증 수정 (필요한 경우)

strict `Origin` 검사 또는 추가 headers로 인해 MCP handshake가 실패하는 경우, local reverse proxy를 사용해 headers를 정규화합니다 (이는 Burp MCP strict validation issue에 대한 workaround와 일치합니다).<sup>[[1]](#references)[[3]](#references)</sup>
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
프록시와 클라이언트를 시작합니다:
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
## 다른 client 사용

### Codex CLI

- 위와 같이 `~/.codex/config.toml`을 구성합니다.
- `codex`를 실행한 다음 `/mcp`를 입력하여 Burp tools 목록을 확인합니다.

### Gemini CLI

**burp-mcp-agents** repo는 launcher helpers를 제공합니다:<sup>[[4]](#references)</sup>
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (로컬)

제공된 launcher helper를 사용하고 로컬 model을 선택합니다:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
예시 local models 및 대략적인 VRAM 요구 사항:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## passive review용 Prompt pack

**burp-mcp-agents** repo에는 Burp traffic의 evidence-driven analysis를 위한 prompt templates가 포함되어 있습니다:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: 광범위한 passive vulnerability surfacing.
- `idor_hunter.md`: IDOR/BOLA/object/tenant drift 및 auth mismatches.
- `auth_flow_mapper.md`: authenticated 및 unauthenticated paths 비교.
- `ssrf_redirect_hunter.md`: URL fetch params/redirect chains에서 SSRF/open-redirect candidates 탐색.
- `logic_flaw_hunter.md`: multi-step logic flaws.
- `session_scope_hunter.md`: token audience/scope misuse.
- `rate_limit_abuse_hunter.md`: throttling/abuse gaps.
- `report_writer.md`: evidence-focused reporting.

## Optional attribution tagging

logs에서 Burp/LLM traffic을 tag하려면 header rewrite를 추가합니다(proxy 또는 Burp Match/Replace):<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Safety notes

- 트래픽에 민감한 데이터가 포함된 경우 **local models**를 우선 사용하세요.
- finding에 필요한 최소한의 evidence만 공유하세요.
- Burp를 source of truth로 유지하고, model은 scanning이 아닌 **analysis 및 reporting**에 사용하세요.

## Burp AI Agent (AI-assisted triage + MCP tools)

**Burp AI Agent**는 local/cloud LLM을 passive/active analysis(62개 vulnerability class)와 결합하고, 외부 MCP client가 Burp를 orchestrate할 수 있도록 53개 이상의 MCP tool을 제공하는 Burp extension입니다.<sup>[[5]](#references)</sup> 주요 기능:

- **Context-menu triage**: Proxy를 통해 traffic을 캡처하고, **Proxy > HTTP History**를 연 다음 request를 마우스 오른쪽 버튼으로 클릭 → **Extensions > Burp AI Agent > Analyze this request**를 선택하면 해당 request/response에 연결된 AI chat이 생성됩니다.
- **Backends** (profile별 선택 가능):
- Local HTTP: **Ollama**, **LM Studio**.
- Remote HTTP: **OpenAI-compatible** endpoint (base URL + model name).
- Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` 또는 `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (provider별 login).
- **Agent profiles**: prompt template은 `~/.burp-ai-agent/AGENTS/`에 자동 설치됩니다. 추가 `*.md` 파일을 해당 위치에 넣으면 custom analysis/scanning behavior를 추가할 수 있습니다.
- **MCP server**: **Settings > MCP Server**에서 활성화하면 모든 MCP client에 Burp operation을 노출합니다(53개 이상의 tool). Claude Desktop은 `~/Library/Application Support/Claude/claude_desktop_config.json`(macOS) 또는 `%APPDATA%\Claude\claude_desktop_config.json`(Windows)을 편집하여 server를 지정할 수 있습니다.
- **Privacy controls**: STRICT / BALANCED / OFF는 remote model로 전송하기 전에 민감한 request data를 redact합니다. secrets를 처리할 때는 local backend를 우선 사용하세요.
- **Audit logging**: AI/MCP action의 변조 방지 traceability를 위해 entry별 SHA-256 integrity hashing이 적용된 JSONL log를 기록합니다.
- **Build/load**: release JAR을 다운로드하거나 Java 21로 build합니다:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
운영 시 주의사항: privacy mode가 적용되지 않으면 cloud backend가 session cookies/PII를 exfiltrate할 수 있습니다. 또한 MCP 노출은 Burp에 대한 원격 오케스트레이션을 허용하므로, trusted agents로 접근을 제한하고 integrity hash가 적용된 audit log의 무결성을 모니터링하세요.

## References

- [1] [Burp MCP + Codex CLI 통합 및 Caddy handshake 수정](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [PortSwigger MCP server의 엄격한 Origin/header validation 문제](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)

{{#include ../banners/hacktricks-training.md}}
