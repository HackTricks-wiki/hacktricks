# Burp MCP: LLM 지원 트래픽 검토

{{#include ../banners/hacktricks-training.md}}

## 개요

Burp의 **MCP Server** 확장 기능은 가로챈 HTTP(S) 트래픽을 MCP-호환 LLM 클라이언트에 노출시켜 이들이 실제 요청/응답을 기반으로 **분석(reason over real requests/responses)**하여 수동적 취약점 발견 및 보고서 초안을 작성할 수 있게 합니다. 의도는 증거 기반 리뷰(evidence-driven review)이며, fuzzing이나 blind scanning 같은 방법은 사용하지 않고 Burp를 진실의 근원(source of truth)으로 유지합니다.

## Architecture

- **Burp MCP Server (BApp)**는 `127.0.0.1:9876`에서 대기하며 가로챈 트래픽을 MCP로 노출합니다.
- **MCP proxy JAR**는 stdio (클라이언트 측)와 Burp의 MCP SSE endpoint를 연결합니다.
- **Optional local reverse proxy** (Caddy)는 엄격한 MCP 핸드쉐이크 검사를 위해 헤더를 정규화합니다.
- **Clients/backends**: Codex CLI (cloud), Gemini CLI (cloud), or Ollama (local).

## 설정

### 1) Burp MCP Server 설치

Burp BApp Store에서 **MCP Server**를 설치하고 `127.0.0.1:9876`에서 수신 대기 중인지 확인하세요.

### 2) 프록시 JAR 추출

MCP Server 탭에서 **Extract server proxy jar**를 클릭하고 `mcp-proxy.jar`로 저장하세요.

### 3) MCP 클라이언트 구성 (Codex 예시)

클라이언트를 proxy JAR과 Burp의 SSE endpoint로 가리키도록 설정하세요:
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy.jar", "--sse-url", "http://127.0.0.1:19876"]
```
해당 파일의 내용을 번역하려면 src/AI/AI-Burp-MCP.md 파일의 텍스트를 붙여 넣어 주세요. 

또한 "Then run Codex"가 구체적으로 무엇을 의미하는지 알려주세요—OpenAI Codex API를 호출해 실행하길 원하시는지, 아니면 문서 내의 "Codex" 섹션을 읽고 처리를 원하시는지요? "list MCP tools"는 문서에 나와 있는 도구 목록을 번역해서 나열해 달라는 의미인가요?

위 사항들 확인해 주시면 요청에 맞게 동일한 마크다운/HTML 구문을 유지하면서 영어를 한국어로 번역해 드리겠습니다.
```bash
codex
# inside Codex: /mcp
```
### 4) Caddy로 엄격한 Origin/header 검증을 해결하기 (필요한 경우)

MCP 핸드셰이크가 엄격한 `Origin` 검사나 추가 헤더 때문에 실패하면, 로컬 리버스 프록시를 사용해 헤더를 정규화하세요 (이 방법은 Burp MCP의 엄격 검증 문제에 대한 우회책과 일치합니다).
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

- 위와 같이 `~/.codex/config.toml`을 설정합니다.
- `codex`를 실행한 다음 `/mcp`로 Burp 도구 목록을 확인합니다.

### Gemini CLI

The **burp-mcp-agents** repo provides launcher helpers:
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (local)

제공된 launcher helper를 사용하여 로컬 모델을 선택하세요:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
예시 로컬 모델 및 대략적인 VRAM 요구량:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## 수동 검토용 프롬프트 팩

The **burp-mcp-agents** repo는 Burp 트래픽에 대한 증거 기반 분석을 위한 프롬프트 템플릿을 포함합니다:

- `passive_hunter.md`: 광범위한 passive 취약점 표면화.
- `idor_hunter.md`: IDOR/BOLA/object/tenant drift 및 auth 불일치.
- `auth_flow_mapper.md`: authenticated 경로와 unauthenticated 경로 비교.
- `ssrf_redirect_hunter.md`: URL fetch 파라미터/redirect 체인에서 SSRF/open-redirect 후보.
- `logic_flaw_hunter.md`: 다단계 logic flaw.
- `session_scope_hunter.md`: token audience/scope 오용.
- `rate_limit_abuse_hunter.md`: throttling/abuse 허점.
- `report_writer.md`: 증거 중심 리포팅.

## 선택적 어트리뷰션 태깅

로그에서 Burp/LLM 트래픽에 태그를 붙이려면, 헤더 재작성(header rewrite)을 추가하세요(프록시 또는 Burp Match/Replace):
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## 안전 주의사항

- 트래픽에 민감한 데이터가 포함된 경우 **로컬 모델**을 우선 사용하세요.
- 발견사항을 위해 필요한 최소한의 증거만 공유하세요.
- 진실의 출처로 Burp를 유지하세요; 모델은 **분석 및 보고** 용도로 사용하고, scanning에는 사용하지 마세요.

## 참고자료

- [Burp MCP + Codex CLI integration and Caddy handshake fix](https://pentestbook.six2dez.com/others/burp)
- [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [PortSwigger MCP server strict Origin/header validation issue](https://github.com/PortSwigger/mcp-server/issues/34)

{{#include ../banners/hacktricks-training.md}}
