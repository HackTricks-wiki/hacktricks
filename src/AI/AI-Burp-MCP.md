# Burp MCP: LLM 지원 traffic review

{{#include ../banners/hacktricks-training.md}}

## 개요

Burp의 **MCP Server** extension은 intercept된 HTTP(S) traffic을 MCP를 지원하는 LLM clients에 노출하여, vulnerability discovery 및 report 초안 작성을 위해 **실제 requests/responses를 분석**할 수 있도록 합니다. Burp를 신뢰할 수 있는 기준으로 유지하고, 무차별 scanning 대신 passive analysis 또는 의도적으로 한 변수만 변경한 replay를 사용하세요.<sup>[[8]](#references)</sup>

## Architecture

- **Burp MCP Server (BApp)**는 기본적으로 `127.0.0.1:9876`에서 listen하며 intercept된 traffic을 MCP를 통해 노출합니다.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR**는 stdio (client side)와 Burp의 MCP SSE endpoint를 연결합니다.
- **Optional local reverse proxy** (Caddy)는 엄격한 MCP handshake checks를 위해 headers를 정규화합니다.
- **Clients/backends**: Codex CLI (cloud), Gemini CLI (cloud) 또는 Ollama (local).

## Setup

### 1) Burp MCP Server 설치

Burp BApp Store에서 **MCP Server**를 설치하고 `127.0.0.1:9876`에서 listen 중인지 확인합니다.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) proxy JAR 추출

MCP Server tab에서 **Extract server proxy jar**를 클릭하고 `mcp-proxy-all.jar`를 저장합니다.<sup>[[7]](#references)</sup>

### 3) MCP client 구성 (Codex 예시)

client가 proxy JAR와 Burp의 direct SSE endpoint를 사용하도록 지정합니다. 패키징된 proxy는 stdio-to-SSE bridge이며 Burp listener를 대체하지 않습니다.<sup>[[7]](#references)</sup>
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]
```
해당하는 Codex 명령은 다음과 같습니다:<sup>[[7]](#references)[[8]](#references)</sup>
```bash
codex mcp add burp -- /path/to/java -jar /path/to/mcp-proxy-all.jar \
--sse-url http://127.0.0.1:9876
```
그런 다음 Codex를 실행하고 MCP tools를 나열합니다:
```bash
codex
# inside Codex: /mcp
```
### 4) 필요한 경우 Caddy로 엄격한 Origin/header validation 수정

엄격한 `Origin` checks 또는 추가 headers로 인해 MCP handshake가 실패하면, local reverse proxy를 사용하여 headers를 정규화합니다(Burp MCP strict validation issue의 workaround와 일치).<sup>[[1]](#references)[[3]](#references)</sup>
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
프록시와 클라이언트를 시작하고, 이 Caddy listener를 사용하는 동안에만 설정된 `--sse-url`을 `http://127.0.0.1:19876`로 변경합니다.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
### 5) 브라우저 상태를 proxy 증거와 연결하기 (Playwright MCP)

Playwright MCP를 등록하여 해당 browser가 Burp의 proxy를 사용하도록 설정합니다. 이를 통해 agent가 렌더링된 DOM/accessibility 상태와 이를 생성한 정확한 HTTP history를 서로 연관지을 수 있습니다.<sup>[[6]](#references)[[8]](#references)</sup>
```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
--proxy-server=http://127.0.0.1:8080 \
--ignore-https-errors
```
Listener address를 조정하고 Codex를 재시작한 다음, `/mcp`를 사용해 두 integration을 모두 확인합니다. 이 예제에서는 Burp가 로컬에서 생성한 certificate로 인해 HTTPS interception이 차단되지 않도록 browser certificate errors를 비활성화합니다.<sup>[[6]](#references)[[8]](#references)</sup>

## Using different clients

### Codex CLI

- 위와 같이 `~/.codex/config.toml`을 구성합니다.
- `codex`를 실행한 다음 `/mcp`를 사용해 Burp tools 목록을 확인합니다.

### Gemini CLI

**burp-mcp-agents** repo는 launcher helpers를 제공합니다:<sup>[[4]](#references)</sup>
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (local)

제공된 launcher helper를 사용하고 로컬 model을 선택합니다:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Example local models and approximate VRAM needs:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## 증거 기반 재현 및 검증

agent가 그럴듯한 설명이나 중간 응답을 증거로 취급하지 않도록 하세요. 모든 테스트를 반증 가능하게 만들려면 Burp requests/responses와 독립적으로 관찰한 browser state를 사용하세요.<sup>[[8]](#references)</sup>

1. baseline request/response pair를 저장하고 정확히 attacker-controlled component를 식별합니다.
2. authorization 비교를 위해 identifier, cookie 또는 token을 변경하기 전에 두 계정에서 동일한 workflow를 각각 독립적으로 캡처합니다.
3. mutation을 replay하기 전에 hypothesis, evidence location, expected signal 및 이를 반증할 result를 기록합니다.
4. 한 번에 하나의 component만 mutate하고 결과 pair를 보존하며 direct observations와 inference를 별도로 표시합니다.
5. 각 candidate를 `open`, `blocked`, `rejected` 또는 `confirmed`로 추적합니다. 새로운 evidence가 mechanism 또는 prerequisite를 변경할 때만 다시 검토합니다.
6. attacker control, reachability, repeatability, constraint bypass, impact 및 최종 application state를 확인합니다. 주장한 state change가 downstream에서 발생한다면 redirect 또는 성공적인 tool call은 증거가 아닙니다.

exploitation details는 관련 technique page에 유지하세요. 예를 들어 browser-message candidates는 [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md)에, token key-selection behavior는 [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md)에 속합니다.<sup>[[8]](#references)</sup>

간결한 hypothesis record는 parallel agents가 동일한 매력적인 branch를 반복하지 않도록 합니다:<sup>[[8]](#references)</sup>
```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```
## passive review용 Prompt pack

**burp-mcp-agents** repo에는 Burp 트래픽의 증거 기반 분석을 위한 Prompt 템플릿이 포함되어 있습니다:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: 광범위한 passive vulnerability 탐지.
- `idor_hunter.md`: IDOR/BOLA/object/tenant drift 및 auth 불일치.
- `auth_flow_mapper.md`: authenticated 경로와 unauthenticated 경로 비교.
- `ssrf_redirect_hunter.md`: URL fetch 파라미터/redirect chain에서 SSRF/open-redirect 후보 탐지.
- `logic_flaw_hunter.md`: 다단계 logic flaw 탐지.
- `session_scope_hunter.md`: token audience/scope 오용.
- `rate_limit_abuse_hunter.md`: throttling/abuse 공백.
- `report_writer.md`: 증거 중심 보고서 작성.

## Optional attribution tagging

로그에서 Burp/LLM 트래픽을 태그하려면 header rewrite를 추가합니다(proxy 또는 Burp Match/Replace):<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## 안전 참고 사항

- 트래픽에 민감한 데이터가 포함된 경우 **local models**를 우선 사용하세요.
- finding에 필요한 최소한의 evidence만 공유하세요.
- Burp를 source of truth로 유지하고, model은 scanning이 아닌 **analysis and reporting**에 사용하세요.

## Burp AI Agent (AI-assisted triage + MCP tools)

**Burp AI Agent**는 local/cloud LLM을 passive/active analysis(62개 vulnerability classes)와 결합하고, 외부 MCP clients가 Burp를 조정할 수 있도록 53개 이상의 MCP tools를 제공하는 Burp extension입니다.<sup>[[5]](#references)</sup> 주요 기능:

- **Context-menu triage**: Proxy를 통해 traffic을 캡처하고 **Proxy > HTTP History**를 연 다음, request를 마우스 오른쪽 버튼으로 클릭하고 → **Extensions > Burp AI Agent > Analyze this request**를 선택하면 해당 request/response에 연결된 AI chat이 생성됩니다.
- **Backends** (profile별 선택 가능):
- Local HTTP: **Ollama**, **LM Studio**.
- Remote HTTP: **OpenAI-compatible** endpoint (base URL + model name).
- Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` 또는 `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (provider별 login).
- **Agent profiles**: prompt templates가 `~/.burp-ai-agent/AGENTS/`에 자동으로 설치됩니다. 추가 `*.md` files를 해당 위치에 넣으면 custom analysis/scanning behaviors를 추가할 수 있습니다.
- **MCP server**: **Settings > MCP Server**를 통해 enable하면 모든 MCP client에 Burp operations를 노출합니다(53개 이상의 tools). Claude Desktop은 `~/Library/Application Support/Claude/claude_desktop_config.json`(macOS) 또는 `%APPDATA%\Claude\claude_desktop_config.json`(Windows)를 편집하여 server를 지정할 수 있습니다.
- **Privacy controls**: STRICT / BALANCED / OFF는 remote models로 전송하기 전에 민감한 request data를 redact합니다. secrets를 처리할 때는 local backends를 우선 사용하세요.
- **Audit logging**: AI/MCP actions의 tamper-evident traceability를 위해 각 entry에 SHA-256 integrity hashing이 적용된 JSONL logs를 생성합니다.
- **Build/load**: release JAR를 다운로드하거나 Java 21로 build하세요:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Operational 주의사항: privacy mode가 적용되지 않으면 cloud backends가 session cookies/PII를 exfiltrate할 수 있습니다. MCP exposure를 통해 Burp를 원격으로 orchestrate할 수 있으므로, trusted agents로 access를 제한하고 integrity-hashed audit log를 모니터링하세요.

## References

- [1] [Burp MCP + Codex CLI 통합 및 Caddy handshake 수정](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [PortSwigger MCP server의 엄격한 Origin/header validation 문제](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Bug Bounty research에 Codex를 사용하는 방법: 폭넓게 탐색하고 엄격하게 검증하기](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
{{#include ../banners/hacktricks-training.md}}
