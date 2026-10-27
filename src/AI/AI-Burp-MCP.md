# Burp MCP: LLM 보조 트래픽 검토

{{#include ../banners/hacktricks-training.md}}

## 개요

Burp의 **MCP Server** 확장은 가로챈 HTTP(S) 트래픽을 MCP를 지원하는 LLM 클라이언트에 노출하여, 취약점 탐지 및 보고서 초안 작성을 위해 **실제 요청/응답을 분석**할 수 있게 합니다. Burp를 신뢰할 수 있는 기준으로 유지하세요. 무분별한 스캔 대신 수동 분석이나 의도적으로 한 번에 하나의 변수만 변경해 재전송하는 방식을 사용하세요.<sup>[[8]](#references)</sup>

## 아키텍처

- **Burp MCP Server (BApp)**는 기본적으로 `127.0.0.1:9876`에서 수신 대기하며, 가로챈 트래픽을 MCP를 통해 노출합니다.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR**는 stdio(클라이언트 측)와 Burp의 MCP SSE 엔드포인트를 연결합니다.
- **선택적 로컬 reverse proxy**(Caddy)는 엄격한 MCP 핸드셰이크 검사에 맞게 헤더를 정규화합니다.
- **클라이언트/백엔드**: Codex CLI (cloud), Gemini CLI (cloud) 또는 Ollama (local).

## 설정

### 1) Burp MCP Server 설치

Burp BApp Store에서 **MCP Server**를 설치하고 `127.0.0.1:9876`에서 수신 대기 중인지 확인합니다.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) proxy JAR 추출

MCP Server 탭에서 **Extract server proxy jar**를 클릭하고 `mcp-proxy-all.jar`로 저장합니다.<sup>[[7]](#references)</sup>

### 3) MCP 클라이언트 구성 (Codex 예시)

클라이언트가 proxy JAR과 Burp의 직접 SSE 엔드포인트를 사용하도록 설정합니다. 패키지에 포함된 proxy는 stdio와 SSE를 연결하는 브리지이며, Burp 리스너를 대체하지 않습니다.<sup>[[7]](#references)</sup>

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

그런 다음 Codex를 실행하고 MCP 도구를 나열하세요:

```bash
codex
# inside Codex: /mcp
```

### 4) 필요한 경우 Caddy로 엄격한 Origin/header 검증 해결

엄격한 `Origin` 검사나 추가 header로 인해 MCP 핸드셰이크가 실패하면, 로컬 reverse proxy를 사용해 header를 정규화하세요(Burp MCP의 엄격한 검증 문제에 대한 우회 방법과 동일합니다).<sup>[[1]](#references)[[3]](#references)</sup>

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

### 5) 브라우저 상태와 프록시 증거 연결하기 (Playwright MCP)

Playwright MCP를 등록해 브라우저가 Burp의 프록시를 사용하도록 합니다. 이렇게 하면 agent가 렌더링된 DOM/accessibility 상태와 이를 생성한 정확한 HTTP 기록을 연관 지을 수 있습니다.<sup>[[6]](#references)[[8]](#references)</sup>

```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
  --proxy-server=http://127.0.0.1:8080 \
  --ignore-https-errors
```

리스너 주소를 변경하고 Codex를 다시 시작한 다음 `/mcp`를 사용해 두 통합을 모두 확인합니다. 이 예에서는 Burp에서 로컬로 생성한 인증서로 인해 HTTPS 가로채기가 차단되지 않도록 브라우저 인증서 오류를 비활성화합니다.<sup>[[6]](#references)[[8]](#references)</sup>

## 프록시를 사용하는 브라우저 자동화 (OpenBurp)

Burp MCP 연결과 가로채는 브라우저 경로는 별도의 데이터 흐름입니다. MCP 서비스는 `127.0.0.1:9876`에서 Burp 도구를 제공하는 반면, 전용 Chromium 인스턴스는 HTTP(S) 트래픽을 `127.0.0.1:8080`의 Burp 프록시를 통해 전송합니다. 따라서 MCP 도구에서 직접 생성한 요청은 **Proxy > HTTP history**에 표시되지 않을 수 있습니다. 요청/응답을 관찰하거나 편집하거나 증거로 보존해야 할 경우에는 프록시를 사용하는 브라우저를 이용하세요.<sup>[[2]](#references)[[9]](#references)</sup>

SSE를 지원하는 클라이언트는 Burp를 직접 등록할 수 있습니다. stdio만 지원하는 클라이언트는 대신 PortSwigger의 proxy JAR를 실행할 수 있습니다. 두 경우 모두 두 번째 브라우저 제어 MCP를 등록하고, Burp에 내장된 Chromium을 지정하세요 (`BURP_CHROMIUM`은 로컬 실행 파일 경로입니다).<sup>[[9]](#references)</sup>

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

TLS-bypass 플래그를 사용하면 interception proxy가 생성한 인증서를 허용할 수 있으며, `--isolated`는 assessment에서 operator의 일반 브라우저 프로필을 재사용하지 않도록 합니다. 격리는 프로필 상태를 보호하지만 **security sandbox는 아닙니다**. controller는 해당 테스트 브라우저에서 열린 인증된 세션에 계속 접근할 수 있으며, Burp MCP는 민감한 요청, 응답 및 구성을 노출할 수 있습니다.<sup>[[9]](#references)</sup>

client bridge를 디버깅하기 전에 SSE listener를 독립적으로 테스트하세요:<sup>[[9]](#references)</sup>

```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```

정상 listener는 `Content-Type: text/event-stream`을 반환합니다. 헤더를 받은 뒤 timeout이 발생하는 것은 SSE stream이 향후 이벤트를 위해 열린 상태로 유지되므로 예상되는 동작입니다. 그래도 client가 실패하면 extension에 설정된 route를 확인하세요. PortSwigger에 따르면 endpoint는 client와 extension 설정에 따라 root path 또는 `/sse`일 수 있습니다.<sup>[[9]](#references)[[7]](#references)</sup>

## 다른 client 사용하기

### Codex CLI

- 위와 같이 `~/.codex/config.toml`을 설정합니다.
- `codex`를 실행한 다음 `/mcp`를 실행해 Burp tools 목록을 확인합니다.

### Gemini CLI

**burp-mcp-agents** repo는 launcher helper를 제공합니다:<sup>[[4]](#references)</sup>

```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```

### Ollama (로컬)

제공된 launcher helper를 사용하고 로컬 모델을 선택하세요:

```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```

Example local models and approximate VRAM 요구량:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## 증거 기반 재현 및 검증

에이전트가 그럴듯한 설명이나 중간 응답을 증거로 취급하지 않도록 하세요. Burp 요청/응답과 독립적으로 관찰한 브라우저 상태를 사용해 모든 테스트를 반증 가능하게 만드세요.<sup>[[8]](#references)</sup>

1. 기준 요청/응답 쌍을 저장하고 공격자가 제어하는 정확한 구성 요소를 식별합니다.
2. 권한 비교를 위해 식별자, 쿠키 또는 토큰을 변경하기 전에 두 계정에서 동일한 워크플로를 각각 캡처합니다.
3. 변경 사항을 재현하기 전에 가설, 증거 위치, 예상 신호, 그리고 가설을 반증할 결과를 기록합니다.
4. 한 번에 구성 요소 하나만 변경하고, 그 결과 쌍을 보존하며, 직접 관찰한 사실과 추론을 구분해 표시합니다.
5. 각 후보를 `open`, `blocked`, `rejected` 또는 `confirmed`로 추적하고, 새로운 증거가 메커니즘이나 전제 조건을 바꿀 때만 다시 검토합니다.
6. 공격자 제어 여부, 도달 가능성, 반복 가능성, 제약 우회, 영향, 최종 애플리케이션 상태를 확인합니다. 리디렉션이나 성공적인 tool 호출만으로는, 주장된 상태 변경이 그 이후에 발생한다면 증거가 되지 않습니다.

악용 세부 정보는 관련 기법 페이지에 작성하세요. 예를 들어, browser-message 후보는 [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md)에, token key-selection 동작은 [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md)에 작성합니다.<sup>[[8]](#references)</sup>

간결한 가설 기록을 작성하면 여러 에이전트가 똑같이 매력적인 분기를 반복해서 조사하는 일을 막을 수 있습니다.<sup>[[8]](#references)</sup>

```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```

## Burp MCP를 이용한 WebSocket 프레임 분류

공식 extension은 Burp의 WebSocket 기록을 읽기 전용으로 페이지 단위 검색하는 `get_proxy_websocket_history_regex`를 제공합니다. 이 기능은 `regex`, `count`, `offset`을 받으며, `send_http1_request`와 달리 WebSocket frame을 전송하지 않습니다. Intercept가 꺼져 있어도 Burp는 양방향 메시지를 모두 기록하므로, 모델에 소수의 관련 프레임을 전달하기 전에 기록을 필터링하세요.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>

1. Burp 프록시를 사용하는 브라우저에서 서로 독립적으로 인증된 두 개의 테스트 계정으로 동일한 WebSocket 기반 동작을 수행하세요. 각 upgrade handshake와 해당 쿠키, connection ID, 프레임 방향, 응답 프레임을 함께 보관하세요. 첫 번째 계정의 connection에서 서버가 클라이언트로 보낸 이벤트는 두 번째 계정이 이를 받았다는 증거가 아닙니다.
2. `get_proxy_websocket_history_regex`에서 `(?i)(subscribe|room|tenant|objectId)` 같은 범위가 좁은 표현식과 `count: 20`, `offset: 0`을 사용해 검색하세요. 이후 일치 항목을 살펴보려면 `offset`을 늘리세요. 아웃바운드 프레임의 object 또는 topic 식별자를 **같은 connection**의 응답과 비교하세요.
3. **Proxy > WebSockets history**에서 후보 아웃바운드 프레임을 Repeater로 보내세요. 적절한 열린 connection에 연결하거나 두 번째 계정의 handshake를 사용해 다시 연결하세요. object/topic 식별자만 변경하고, 그 결과로 나온 서버 메시지와 애플리케이션 상태를 두 기준선과 비교하세요. MCP history 도구는 이 재전송을 수행할 수 없습니다. WebSocket Repeater에서는 프레임을 편집하고 다시 보내거나 재연결할 수 있습니다.

cross-site WebSocket hijacking 및 broker topic authorization 같은 protocol별 테스트는 [WebSocket Attacks](../pentesting-web/websocket-attacks.md)를 참고하세요. upgrade가 수락되었거나 클라이언트 측 echo가 발생했다는 사실만으로 보호된 subscription이 성공했다고 판단하지 마세요.

## Burp MCP를 이용한 표적화된 out-of-band 검증

Burp Suite Professional은 공식 MCP extension을 통해 `generate_collaborator_payload`와 `get_collaborator_interactions`를 제공합니다. 이를 `get_proxy_http_history_regex` 및 단일 `send_http1_request` 재전송과 함께 사용하면 전체 대상을 스캔하지 않고도 의심되는 server-side URL fetch를 테스트할 수 있습니다. Burp에서 기록을 읽고 요청을 보내는 작업에 각각 별도의 승인이 필요할 수 있습니다.<sup>[[2]](#references)[[10]](#references)</sup>

1. `url=`, `webhook`, `callback` 등을 포함하는 요청처럼 URL이 포함된 후보 요청을 기록에서 필터링하세요. 원본 요청과 응답을 저장하세요. history 도구는 `regex`, `count`, `offset`을 받으므로, 모델에 모든 항목을 살펴보게 하는 대신 페이지 단위로 검색하세요.<sup>[[10]](#references)</sup>
2. 새 Collaborator payload를 생성하고 반환된 **payload ID**를 보관하세요. 캡처한 요청을 같은 호스트와 포트로 재전송하면서 후보 URL만 해당 payload 도메인의 HTTPS URL로 변경하세요. `send_http1_request`에는 `content`로 완전한 HTTP/1.1 요청을 전달하고, `targetHostname`, `targetPort`, `usesHttps`도 지정하세요. destination 필드는 Collaborator 호스트가 아니라 **애플리케이션**을 식별합니다.<sup>[[10]](#references)</sup>
3. 해당 payload ID로 `get_collaborator_interactions`를 폴링하고, 상호작용 시점을 재전송 시점과 대조하세요. HTTP 상호작용은 fetch가 있었음을 뒷받침하지만, DNS만으로는 해석은 확인되어도 HTTP 요청이 완료되었다고 볼 수 없습니다. 상호작용의 source와 요청 헤더를 확인해 서버의 egress와 브라우저 측 로딩을 구분한 다음, 관련 없는 트래픽이 아니었는지 확인하기 위해 새 payload로 반복하세요.<sup>[[10]](#references)[[11]](#references)</sup>

MCP request 도구는 응답을 직접 반환하므로 **Proxy > HTTP history**에 기록되지 않을 수 있습니다. request/response 결과를 보관하거나, history에 남는 증거가 필요하면 프록시를 사용하는 브라우저 또는 Repeater를 사용하세요. SSRF payload 선택 및 후속 테스트는 [SSRF chapter](../pentesting-web/ssrf-server-side-request-forgery/)를 참고하세요. out-of-band callback이 발생했다는 사실만으로 내부 네트워크에 영향을 미쳤다고 판단하지 마세요. MCP server 자체를 테스트하려면 [MCP server testing](AI-MCP-Servers.md#remote-mcp-server-testing-workflow)을 참고하세요.<sup>[[7]](#references)[[11]](#references)</sup>

## 수동 검토용 prompt 모음

**burp-mcp-agents** repo에는 Burp 트래픽을 근거 기반으로 분석하기 위한 prompt 템플릿이 포함되어 있습니다.<sup>[[4]](#references)</sup>

- `passive_hunter.md`: 광범위한 수동 취약점 탐지.
- `idor_hunter.md`: IDOR/BOLA/object/tenant 변경 및 인증 불일치.
- `auth_flow_mapper.md`: 인증된 경로와 인증되지 않은 경로 비교.
- `ssrf_redirect_hunter.md`: URL fetch 매개변수/redirect chain에서 SSRF/open-redirect 후보 탐지.
- `logic_flaw_hunter.md`: 여러 단계로 이루어진 logic flaw.
- `session_scope_hunter.md`: token audience/scope 오용.
- `rate_limit_abuse_hunter.md`: throttling/abuse 공백.
- `report_writer.md`: 증거 중심 보고서 작성.

## 선택적 attribution 태그 지정

로그에서 Burp/LLM 트래픽에 태그를 지정하려면 header rewrite(proxy 또는 Burp Match/Replace)를 추가하세요:<sup>[[1]](#references)</sup>

```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```

## 안전 참고 사항

- 트래픽에 민감한 데이터가 포함된 경우 **로컬 모델**을 우선 사용하세요.
- 발견 사항에 필요한 최소한의 증거만 공유하세요.
- Burp를 신뢰할 수 있는 기준으로 유지하고, 모델은 스캔이 아닌 **분석 및 보고**에 사용하세요.

## Burp AI Agent (AI 지원 분류 + MCP 도구)

**Burp AI Agent**는 로컬/클라우드 LLM을 수동/능동 분석(취약점 유형 62개)과 결합하고, 외부 MCP 클라이언트가 Burp를 제어할 수 있도록 53개 이상의 MCP 도구를 제공하는 Burp 확장 프로그램입니다.<sup>[[5]](#references)</sup> 주요 기능:

- **컨텍스트 메뉴 분류**: Proxy를 통해 트래픽을 캡처하고 **Proxy > HTTP History**를 연 다음, 요청을 마우스 오른쪽 버튼으로 클릭하여 **Extensions > Burp AI Agent > Analyze this request**를 선택하면 해당 요청/응답에 연결된 AI 채팅이 열립니다.
- **백엔드** (프로필별 선택 가능):
  - 로컬 HTTP: **Ollama**, **LM Studio**.
  - 원격 HTTP: **OpenAI 호환** 엔드포인트(base URL + 모델 이름).
  - 클라우드 CLI: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` 또는 `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (공급자별 로그인).
- **에이전트 프로필**: 프롬프트 템플릿은 `~/.burp-ai-agent/AGENTS/`에 자동 설치됩니다. 여기에 추가 `*.md` 파일을 넣어 분석/스캔 동작을 맞춤 설정할 수 있습니다.
- **MCP 서버**: **Settings > MCP Server**에서 활성화하여 모든 MCP 클라이언트에 Burp 작업을 제공할 수 있습니다(도구 53개 이상). Claude Desktop에서 서버를 사용하려면 `~/Library/Application Support/Claude/claude_desktop_config.json`(macOS) 또는 `%APPDATA%\Claude\claude_desktop_config.json`(Windows)을 편집하면 됩니다.
- **개인정보 보호 제어**: STRICT / BALANCED / OFF 설정은 원격 모델로 전송하기 전에 민감한 요청 데이터를 마스킹합니다. 비밀 정보를 처리할 때는 로컬 백엔드를 우선 사용하세요.
- **감사 로깅**: 변조 여부를 확인할 수 있는 AI/MCP 작업 추적을 위해 항목별 SHA-256 무결성 해시가 포함된 JSONL 로그를 기록합니다.
- **빌드/로드**: 릴리스 JAR를 다운로드하거나 Java 21로 빌드하세요:

```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```

운영상 주의사항: privacy mode를 적용하지 않으면 cloud 백엔드에서 세션 쿠키/PII가 유출될 수 있습니다. MCP를 노출하면 Burp를 원격으로 오케스트레이션할 수 있으므로, 신뢰할 수 있는 agent로만 접근을 제한하고 무결성 해시가 적용된 audit log를 모니터링하세요.



## References

- [1] [Burp MCP + Codex CLI 통합 및 Caddy handshake 수정](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [PortSwigger MCP server의 엄격한 Origin/header 검증 문제](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (워크플로, 런처, 프롬프트 팩)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Bug Bounty 조사에 Codex 사용하기: 폭넓게 탐색하고 엄격하게 검증하기](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp: Claude Code와 Codex를 위한 Burp Suite 오케스트레이션](https://github.com/luispacheco22/OpenBurp)
- [10] [PortSwigger MCP Server 도구 구현 및 매개변수](https://github.com/PortSwigger/mcp-server/blob/main/src/main/kotlin/net/portswigger/mcp/tools/Tools.kt)
- [11] [PortSwigger Web Security Academy - Blind SSRF 취약점](https://portswigger.net/web-security/ssrf/blind)
- [12] [PortSwigger - WebSockets 기록](https://portswigger.net/burp/documentation/desktop/tools/proxy/websockets-history)
- [13] [PortSwigger - Burp Repeater에서 WebSocket 메시지 다루기](https://portswigger.net/burp/documentation/desktop/tools/repeater/websocket-messages)
{{#include ../banners/hacktricks-training.md}}
