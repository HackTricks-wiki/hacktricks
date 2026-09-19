# Burp MCP: LLM 지원 traffic review

{{#include ../banners/hacktricks-training.md}}

## 개요

Burp의 **MCP Server** extension은 가로챈 HTTP(S) traffic을 MCP를 지원하는 LLM client에 노출하여, vulnerability discovery 및 report drafting을 위해 **실제 requests/responses를 분석**할 수 있도록 합니다. Burp를 source of truth로 유지하고, 무분별한 scanning보다는 passive analysis 또는 의도적으로 한 가지 변수만 변경한 replay를 사용하세요.<sup>[[8]](#references)</sup>

## 아키텍처

- **Burp MCP Server (BApp)**는 기본적으로 `127.0.0.1:9876`에서 수신 대기하며 MCP를 통해 가로챈 traffic을 노출합니다.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR**는 stdio(client side)와 Burp의 MCP SSE endpoint를 연결합니다.
- **Optional local reverse proxy**(Caddy)는 엄격한 MCP handshake 검사를 위해 headers를 정규화합니다.
- **Clients/backends**: Codex CLI(cloud), Gemini CLI(cloud) 또는 Ollama(local).

## 설정

### 1) Burp MCP Server 설치

Burp BApp Store에서 **MCP Server**를 설치하고 `127.0.0.1:9876`에서 수신 대기 중인지 확인합니다.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) proxy JAR 추출

MCP Server tab에서 **Extract server proxy jar**를 클릭하고 `mcp-proxy-all.jar`를 저장합니다.<sup>[[7]](#references)</sup>

### 3) MCP client 구성(Codex 예시)

client가 proxy JAR 및 Burp의 direct SSE endpoint를 사용하도록 지정합니다. 패키지에 포함된 proxy는 stdio-to-SSE bridge이며 Burp listener를 대체하지 않습니다.<sup>[[7]](#references)</sup>
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]
```
동등한 Codex 명령은 다음과 같습니다:<sup>[[7]](#references)[[8]](#references)</sup>
```bash
codex mcp add burp -- /path/to/java -jar /path/to/mcp-proxy-all.jar \
--sse-url http://127.0.0.1:9876
```
그런 다음 Codex를 실행하고 MCP 도구를 나열합니다:
```bash
codex
# inside Codex: /mcp
```
### 4) Caddy로 엄격한 Origin/header 검증 수정 (필요한 경우)

엄격한 `Origin` 검사 또는 추가 header로 인해 MCP handshake가 실패하면, 로컬 reverse proxy를 사용하여 header를 정규화하세요(Burp MCP strict validation 문제에 대한 workaround와 동일합니다).<sup>[[1]](#references)[[3]](#references)</sup>
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
proxy와 client를 시작하고, 이 Caddy listener를 사용하는 동안에만 설정된 `--sse-url`을 `http://127.0.0.1:19876`로 변경하세요:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
### 5) 브라우저 상태를 proxy 증거와 페어링하기 (Playwright MCP)

Playwright MCP를 등록하여 브라우저가 Burp의 proxy를 사용하도록 합니다. 이를 통해 agent가 렌더링된 DOM/accessibility 상태를 해당 상태를 생성한 정확한 HTTP history와 연관 지을 수 있습니다.<sup>[[6]](#references)[[8]](#references)</sup>
```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
--proxy-server=http://127.0.0.1:8080 \
--ignore-https-errors
```
리스너 주소를 조정하고 Codex를 다시 시작한 다음 `/mcp`를 사용하여 두 통합이 모두 작동하는지 확인합니다. 이 예제에서는 브라우저 인증서 오류를 비활성화하므로 Burp가 로컬에서 생성한 인증서로 인해 HTTPS interception이 차단되지 않습니다.<sup>[[6]](#references)[[8]](#references)</sup>

## Proxy-aware browser automation (OpenBurp)

Burp MCP 연결과 interception된 브라우저 경로는 서로 별개의 데이터 흐름입니다. MCP service는 `127.0.0.1:9876`에서 Burp tools를 노출하는 반면, 전용 Chromium instance는 `127.0.0.1:8080`의 Burp proxy를 통해 HTTP(S) traffic을 전송합니다. 따라서 MCP tool에서 직접 생성된 requests는 **Proxy > HTTP history**에 표시되지 않을 수 있습니다. request/response를 확인하거나, 수정하거나, 증거로 보존해야 하는 경우에는 proxied browser를 사용합니다.<sup>[[2]](#references)[[9]](#references)</sup>

SSE support가 있는 client는 Burp를 직접 등록할 수 있습니다. stdio-only client는 대신 PortSwigger의 proxy JAR를 실행할 수 있습니다. 두 경우 모두 두 번째 browser-control MCP를 등록하고 Burp의 embedded Chromium(`BURP_CHROMIUM`은 local executable path)에 연결합니다:<sup>[[9]](#references)</sup>
```bash
# Claude Code: direct SSE plus a proxied browser
claude mcp add -s project -t sse burpsuite http://127.0.0.1:9876/
claude mcp add -s project -t stdio chrome-devtools -- chrome-devtools-mcp \
--executablePath "$BURP_CHROMIUM" --proxy-server=http://127.0.0.1:8080 \
--accept-insecure-certs --isolated

# Codex: SSE-to-stdio bridge plus a proxied browser
codex mcp add burp -- /path/to/java -jar /path/to/mcp-proxy-all.jar \
--sse-url http://127.0.0.1:9876
codex mcp add burp-browser -- npx -y @playwright/mcp@latest \
--executable-path "$BURP_CHROMIUM" --proxy-server=http://127.0.0.1:8080 \
--ignore-https-errors --isolated
```
TLS-bypass flag는 interception proxy가 생성한 인증서를 허용하며, `--isolated`는 assessment가 operator의 일반 브라우저 프로필을 재사용하지 않도록 합니다. Isolation은 프로필 상태를 보호하지만 **security sandbox가 아닙니다**: controller는 해당 테스트 브라우저에서 열린 authenticated sessions에 여전히 액세스할 수 있으며, Burp MCP는 민감한 requests, responses 및 configuration을 노출할 수 있습니다.<sup>[[9]](#references)</sup>

client bridge를 디버깅하기 전에 SSE listener를 독립적으로 테스트하십시오:<sup>[[9]](#references)</sup>
```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```
정상적인 listener는 `Content-Type: text/event-stream`을 반환합니다. headers 이후 timeout이 발생하는 것은 SSE 스트림이 향후 events를 위해 열린 상태로 유지되므로 예상되는 동작입니다. client가 계속 실패하는 경우 extension에 설정된 route를 확인하세요. PortSwigger에 따르면 client와 extension configuration에 따라 endpoint가 root path 또는 `/sse`일 수 있습니다.<sup>[[9]](#references)[[7]](#references)</sup>

## 다른 client 사용

### Codex CLI

- 위와 같이 `~/.codex/config.toml`을 설정합니다.
- `codex`를 실행한 다음 `/mcp`를 실행하여 Burp tools 목록을 확인합니다.

### Gemini CLI

**burp-mcp-agents** repo는 launcher helpers를 제공합니다:<sup>[[4]](#references)</sup>
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (로컬)

제공된 launcher helper를 사용하고 로컬 모델을 선택합니다:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Example local models and approximate VRAM needs:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## 근거 기반 replay 및 검증

agent가 그럴듯한 설명이나 중간 응답을 증거로 취급하지 않도록 합니다. 모든 테스트를 반증 가능하게 만들려면 Burp requests/responses와 독립적으로 관찰한 browser state를 사용하세요.<sup>[[8]](#references)</sup>

1. baseline request/response 쌍을 저장하고, 공격자가 제어하는 정확한 component를 식별합니다.
2. authorization 비교를 위해 identifier, cookie 또는 token을 변경하기 전에 두 계정에서 동일한 workflow를 각각 독립적으로 캡처합니다.
3. mutation을 replay하기 전에 hypothesis, evidence location, expected signal 및 이를 반증할 결과를 기록합니다.
4. 한 번에 하나의 component만 mutate하고, 그 결과로 생성된 쌍을 보존하며, 직접 관찰한 내용과 inference를 별도로 표시합니다.
5. 각 candidate를 `open`, `blocked`, `rejected` 또는 `confirmed`로 추적하고, 새로운 evidence가 mechanism 또는 prerequisite를 변경할 때만 다시 검토합니다.
6. attacker control, reachability, repeatability, constraint bypass, impact 및 최종 application state를 확인합니다. 주장된 state change가 downstream에서 발생한다면 redirect나 성공적인 tool call은 증거가 아닙니다.

exploitation 세부 사항은 관련 technique page에 유지하세요. 예를 들어 browser-message candidate는 [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md)에, token key-selection behavior는 [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md)에 해당합니다.<sup>[[8]](#references)</sup>

간결한 hypothesis record는 parallel agent가 동일한 매력적인 branch를 반복하지 않도록 합니다:<sup>[[8]](#references)</sup>
```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```
## 수동 검토를 위한 Prompt pack

**burp-mcp-agents** repo에는 Burp 트래픽의 evidence-driven 분석을 위한 prompt template이 포함되어 있습니다:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: 광범위한 passive vulnerability 탐지.
- `idor_hunter.md`: IDOR/BOLA/object/tenant drift 및 auth 불일치.
- `auth_flow_mapper.md`: authenticated 경로와 unauthenticated 경로 비교.
- `ssrf_redirect_hunter.md`: URL fetch parameter 및 redirect chain에서 SSRF/open-redirect 후보 탐지.
- `logic_flaw_hunter.md`: multi-step logic flaw.
- `session_scope_hunter.md`: token audience/scope 오용.
- `rate_limit_abuse_hunter.md`: throttling/abuse gap.
- `report_writer.md`: evidence 중심 reporting.

## 선택적 attribution tagging

로그에서 Burp/LLM 트래픽을 tagging하려면 header rewrite를 추가합니다(proxy 또는 Burp Match/Replace):<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## 안전 참고 사항

- 트래픽에 민감한 데이터가 포함된 경우 **local models**를 우선 사용합니다.
- finding에 필요한 최소한의 evidence만 공유합니다.
- Burp를 source of truth로 유지하고, model은 scanning이 아닌 **analysis and reporting**에 사용합니다.

## Burp AI Agent (AI-assisted triage + MCP tools)

**Burp AI Agent**는 local/cloud LLM을 passive/active analysis(62개 vulnerability classes)와 결합하고, 외부 MCP clients가 Burp를 orchestrate할 수 있도록 53개 이상의 MCP tools를 제공하는 Burp extension입니다.<sup>[[5]](#references)</sup> 주요 기능:

- **Context-menu triage**: Proxy를 통해 traffic을 캡처하고 **Proxy > HTTP History**를 연 다음, request를 마우스 오른쪽 버튼으로 클릭 → **Extensions > Burp AI Agent > Analyze this request**를 선택하면 해당 request/response에 연결된 AI chat이 시작됩니다.
- **Backends** (profile별 선택 가능):
- Local HTTP: **Ollama**, **LM Studio**.
- Remote HTTP: **OpenAI-compatible** endpoint (base URL + model name).
- Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` 또는 `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (provider-specific login).
- **Agent profiles**: prompt templates가 `~/.burp-ai-agent/AGENTS/`에 자동 설치됩니다. 추가 `*.md` 파일을 해당 위치에 넣으면 custom analysis/scanning behaviors를 추가할 수 있습니다.
- **MCP server**: **Settings > MCP Server**를 통해 활성화하면 모든 MCP client에 Burp operations(53개 이상의 tools)을 노출합니다. macOS에서는 `~/Library/Application Support/Claude/claude_desktop_config.json`, Windows에서는 `%APPDATA%\Claude\claude_desktop_config.json`를 편집하여 Claude Desktop이 server를 사용하도록 설정할 수 있습니다.
- **Privacy controls**: STRICT / BALANCED / OFF는 remote models로 전송하기 전에 민감한 request data를 redact합니다. secrets를 처리할 때는 local backends를 우선 사용합니다.
- **Audit logging**: AI/MCP actions의 변조 여부를 확인할 수 있는 traceability를 위해 각 entry에 SHA-256 integrity hashing이 적용된 JSONL logs를 사용합니다.
- **Build/load**: release JAR를 다운로드하거나 Java 21로 build합니다:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
운영 시 주의사항: privacy mode가 적용되지 않으면 cloud backend가 session cookies/PII를 exfiltrate할 수 있습니다. MCP exposure는 Burp에 대한 원격 orchestration을 허용하므로 trusted agents로 access를 제한하고 integrity-hashed audit log를 monitor하세요.

## References

- [1] [Burp MCP + Codex CLI 통합 및 Caddy handshake 수정](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [PortSwigger MCP server의 엄격한 Origin/header validation 문제](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Bug Bounty research에 Codex를 사용하는 방법: 폭넓게 탐색하고 엄격하게 검증하기](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp: Claude Code 및 Codex를 위한 Burp Suite orchestration](https://github.com/luispacheco22/OpenBurp)
{{#include ../banners/hacktricks-training.md}}
