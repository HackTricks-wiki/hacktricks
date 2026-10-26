# Burp MCP: Rà soát lưu lượng với sự hỗ trợ của LLM

{{#include ../banners/hacktricks-training.md}}

## Tổng quan

Extension **MCP Server** của Burp có thể cung cấp lưu lượng HTTP(S) đã chặn cho các LLM client hỗ trợ MCP, giúp chúng **phân tích các request/response thực tế** để tìm lỗ hổng và soạn thảo báo cáo. Hãy xem Burp là nguồn dữ liệu chuẩn: dùng phân tích thụ động hoặc chủ động replay với một biến mỗi lần, thay vì quét mù.<sup>[[8]](#references)</sup>

## Kiến trúc

- **Burp MCP Server (BApp)** mặc định lắng nghe trên `127.0.0.1:9876` và cung cấp lưu lượng đã chặn qua MCP.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR** làm cầu nối giữa stdio (phía client) và endpoint MCP SSE của Burp.
- **Reverse proxy cục bộ tùy chọn** (Caddy) chuẩn hóa header để đáp ứng các bước kiểm tra handshake MCP nghiêm ngặt.
- **Client/backend**: Codex CLI (cloud), Gemini CLI (cloud) hoặc Ollama (local).

## Thiết lập

### 1) Cài đặt Burp MCP Server

Cài đặt **MCP Server** từ Burp BApp Store và xác minh rằng nó đang lắng nghe trên `127.0.0.1:9876`.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Trích xuất proxy JAR

Trong tab MCP Server, nhấp **Extract server proxy jar** và lưu `mcp-proxy-all.jar`.<sup>[[7]](#references)</sup>

### 3) Cấu hình MCP client (ví dụ với Codex)

Trỏ client đến proxy JAR và endpoint SSE trực tiếp của Burp. Proxy đi kèm làm cầu nối stdio-to-SSE; nó không thay thế listener của Burp.<sup>[[7]](#references)</sup>

```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]
```

Lệnh Codex tương đương là:<sup>[[7]](#references)[[8]](#references)</sup>

```bash
codex mcp add burp -- /path/to/java -jar /path/to/mcp-proxy-all.jar \
  --sse-url http://127.0.0.1:9876
```

Sau đó chạy Codex và liệt kê các công cụ MCP:

```bash
codex
# inside Codex: /mcp
```

### 4) Khắc phục kiểm tra Origin/header nghiêm ngặt bằng Caddy (nếu cần)

Nếu quá trình bắt tay MCP thất bại do kiểm tra `Origin` nghiêm ngặt hoặc có header bổ sung, hãy dùng reverse proxy cục bộ để chuẩn hóa header (đây là cách khắc phục vấn đề kiểm tra nghiêm ngặt của Burp MCP).<sup>[[1]](#references)[[3]](#references)</sup>

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

Khởi động proxy và client, và chỉ đổi giá trị `--sse-url` đã cấu hình thành `http://127.0.0.1:19876` khi sử dụng Caddy listener này:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```

### 5) Ghép trạng thái trình duyệt với bằng chứng từ proxy (Playwright MCP)

Đăng ký Playwright MCP để trình duyệt sử dụng proxy của Burp. Nhờ đó, agent có thể đối chiếu trạng thái DOM/trợ năng đã render với lịch sử HTTP chính xác đã tạo ra trạng thái đó.<sup>[[6]](#references)[[8]](#references)</sup>

```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
  --proxy-server=http://127.0.0.1:8080 \
  --ignore-https-errors
```

Điều chỉnh địa chỉ listener, khởi động lại Codex và dùng `/mcp` để xác minh cả hai integration. Ví dụ này tắt lỗi chứng chỉ của trình duyệt để Burp không chặn việc intercept HTTPS bằng chứng chỉ do Burp tạo cục bộ.<sup>[[6]](#references)[[8]](#references)</sup>

## Tự động hóa trình duyệt nhận biết proxy (OpenBurp)

Kết nối Burp MCP và luồng trình duyệt bị intercept là hai luồng dữ liệu riêng biệt. Dịch vụ MCP cung cấp các công cụ Burp trên `127.0.0.1:9876`, trong khi một phiên bản Chromium riêng gửi lưu lượng HTTP(S) qua proxy của Burp tại `127.0.0.1:8080`. Vì vậy, các request được tạo trực tiếp bằng công cụ MCP có thể không xuất hiện trong **Proxy > HTTP history**; hãy dùng trình duyệt qua proxy khi cần quan sát, chỉnh sửa hoặc lưu request/response làm bằng chứng.<sup>[[2]](#references)[[9]](#references)</sup>

Client hỗ trợ SSE có thể đăng ký Burp trực tiếp. Client chỉ hỗ trợ stdio có thể khởi chạy proxy JAR của PortSwigger. Trong cả hai trường hợp, hãy đăng ký thêm một MCP điều khiển trình duyệt và trỏ nó đến Chromium được tích hợp trong Burp (`BURP_CHROMIUM` là đường dẫn đến tệp thực thi cục bộ):<sup>[[9]](#references)</sup>

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

Cờ TLS-bypass chấp nhận các chứng chỉ do interception proxy tạo ra, còn `--isolated` ngăn quá trình đánh giá sử dụng lại browser profile thông thường của operator. Tính năng cô lập bảo vệ trạng thái profile nhưng **không phải là sandbox bảo mật**: controller vẫn có thể truy cập các phiên đã xác thực được mở trong trình duyệt thử nghiệm đó, và Burp MCP có thể làm lộ các request, response và cấu hình nhạy cảm.<sup>[[9]](#references)</sup>

Hãy kiểm tra độc lập SSE listener trước khi debug client bridge:<sup>[[9]](#references)</sup>

```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```

Một listener hoạt động bình thường sẽ trả về `Content-Type: text/event-stream`. Việc hết thời gian chờ sau khi nhận header là bình thường vì luồng SSE vẫn mở để chờ các event tiếp theo. Nếu client vẫn gặp lỗi, hãy xác nhận route đã cấu hình cho extension: PortSwigger lưu ý endpoint có thể là đường dẫn gốc hoặc `/sse`, tùy thuộc vào cấu hình client và extension.<sup>[[9]](#references)[[7]](#references)</sup>

## Sử dụng các client khác nhau

### Codex CLI

- Cấu hình `~/.codex/config.toml` như trên.
- Chạy `codex`, sau đó chạy `/mcp` để xác minh danh sách công cụ Burp.

### Gemini CLI

Repo **burp-mcp-agents** cung cấp các helper khởi chạy:<sup>[[4]](#references)</sup>

```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```

### Ollama (cục bộ)

Sử dụng trình trợ giúp khởi chạy được cung cấp và chọn một mô hình cục bộ:

```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```

Ví dụ về model cục bộ và nhu cầu VRAM ước tính:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Replay và xác thực dựa trên bằng chứng

Không để agent xem một lời giải thích có vẻ hợp lý hoặc phản hồi trung gian là bằng chứng. Dùng request/response của Burp và trạng thái trình duyệt được quan sát độc lập để mọi phép thử đều có thể bác bỏ.<sup>[[8]](#references)</sup>

1. Lưu một cặp request/response baseline và xác định chính xác thành phần do attacker kiểm soát.
2. Khi so sánh authorization, ghi lại độc lập cùng một workflow bằng cả hai tài khoản trước khi thay đổi identifier, cookie hoặc token.
3. Trước khi replay một thay đổi, ghi lại giả thuyết, vị trí bằng chứng, tín hiệu mong đợi và kết quả có thể bác bỏ giả thuyết đó.
4. Mỗi lần chỉ thay đổi một thành phần, lưu lại cặp kết quả và phân biệt rõ quan sát trực tiếp với suy luận.
5. Theo dõi từng ứng viên bằng trạng thái `open`, `blocked`, `rejected` hoặc `confirmed`; chỉ xem xét lại khi có bằng chứng mới làm thay đổi cơ chế hoặc điều kiện tiên quyết.
6. Xác nhận attacker kiểm soát được, khả năng tiếp cận, tính lặp lại, việc bypass ràng buộc, tác động và trạng thái cuối cùng của ứng dụng. Redirect hoặc tool call thành công không phải là bằng chứng nếu trạng thái được tuyên bố là thay đổi ở bước tiếp theo.

Giữ chi tiết khai thác trong trang kỹ thuật phù hợp. Ví dụ, các ứng viên liên quan đến browser-message thuộc về [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md), còn hành vi lựa chọn key của token thuộc về [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md).<sup>[[8]](#references)</sup>

Một bản ghi giả thuyết ngắn gọn giúp các agent chạy song song không lặp lại cùng một nhánh hấp dẫn:<sup>[[8]](#references)</sup>

```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```

## Xác thực out-of-band có mục tiêu bằng Burp MCP

Burp Suite Professional cung cấp `generate_collaborator_payload` và `get_collaborator_interactions` thông qua extension MCP chính thức. Kết hợp chúng với `get_proxy_http_history_regex` và một lần replay bằng `send_http1_request` để kiểm tra nghi vấn server fetch URL mà không cần scan toàn bộ mục tiêu. Burp có thể yêu cầu phê duyệt riêng để đọc history và gửi request.<sup>[[2]](#references)[[10]](#references)</sup>

1. Lọc history để tìm request có URL tiềm năng, chẳng hạn request chứa `url=`, `webhook` hoặc `callback`. Lưu request và response gốc. Công cụ history nhận các tham số `regex`, `count` và `offset`; hãy phân trang thay vì yêu cầu model kiểm tra mọi mục.<sup>[[10]](#references)</sup>
2. Tạo một Collaborator payload mới và lưu **payload ID** được trả về. Replay request đã ghi lại đến cùng host và port, chỉ thay URL tiềm năng bằng URL HTTPS thuộc domain của payload đó. Với `send_http1_request`, truyền toàn bộ request HTTP/1.1 dưới dạng `content`, cùng với `targetHostname`, `targetPort` và `usesHttps`; các trường đích xác định **ứng dụng**, không phải host Collaborator.<sup>[[10]](#references)</sup>
3. Dùng payload ID đó để thăm dò `get_collaborator_interactions` và đối chiếu thời điểm tương tác với lần replay. Tương tác HTTP là dấu hiệu hỗ trợ giả thuyết có fetch, còn chỉ có DNS thì cho thấy đã phân giải tên miền nhưng không chứng minh có request HTTP hoàn tất. Kiểm tra nguồn tương tác và request headers để phân biệt egress từ server với việc tải từ phía browser, sau đó lặp lại với payload mới để loại trừ traffic không liên quan.<sup>[[10]](#references)[[11]](#references)</sup>

Công cụ request MCP trả response trực tiếp và không nhất thiết ghi vào **Proxy > HTTP history**. Hãy lưu kết quả request/response hoặc dùng browser qua proxy hay Repeater để có artifact được lưu trong history. Để chọn SSRF payload và thực hiện các kiểm thử tiếp theo, hãy dùng [chương SSRF](../pentesting-web/ssrf-server-side-request-forgery/) thay vì xem callback out-of-band là bằng chứng về tác động lên mạng nội bộ. Để kiểm thử chính MCP server, xem [kiểm thử MCP server](AI-MCP-Servers.md#remote-mcp-server-testing-workflow).<sup>[[7]](#references)[[11]](#references)</sup>

## Bộ prompt để rà soát thụ động

Repo **burp-mcp-agents** bao gồm các mẫu prompt để phân tích traffic Burp dựa trên bằng chứng:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: phát hiện lỗ hổng thụ động trên diện rộng.
- `idor_hunter.md`: tìm IDOR/BOLA, sai lệch object/tenant và không khớp auth.
- `auth_flow_mapper.md`: so sánh các đường dẫn đã xác thực và chưa xác thực.
- `ssrf_redirect_hunter.md`: tìm ứng viên SSRF/open-redirect từ tham số fetch URL/chuỗi redirect.
- `logic_flaw_hunter.md`: tìm lỗi logic qua nhiều bước.
- `session_scope_hunter.md`: tìm việc sử dụng sai audience/scope của token.
- `rate_limit_abuse_hunter.md`: tìm lỗ hổng về throttling/abuse.
- `report_writer.md`: viết báo cáo tập trung vào bằng chứng.

## Gắn thẻ attribution tùy chọn

Để gắn thẻ traffic Burp/LLM trong log, hãy thêm quy tắc viết lại header (proxy hoặc Burp Match/Replace):<sup>[[1]](#references)</sup>

```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```

## Lưu ý về an toàn

- Ưu tiên **local models** khi traffic chứa dữ liệu nhạy cảm.
- Chỉ chia sẻ lượng bằng chứng tối thiểu cần thiết cho một phát hiện.
- Coi Burp là nguồn thông tin chuẩn; dùng model để **phân tích và báo cáo**, không dùng để scan.

## Burp AI Agent (triage có hỗ trợ AI + công cụ MCP)

**Burp AI Agent** là một extension của Burp, kết hợp LLM local/cloud với phân tích thụ động/chủ động (62 lớp lỗ hổng) và cung cấp hơn 53 công cụ MCP để các MCP client bên ngoài điều phối Burp.<sup>[[5]](#references)</sup> Các tính năng nổi bật:

- **Triage từ menu ngữ cảnh**: capture traffic qua Proxy, mở **Proxy > HTTP History**, nhấp chuột phải vào một request → **Extensions > Burp AI Agent > Analyze this request** để mở một cuộc trò chuyện AI gắn với request/response đó.
- **Backend** (có thể chọn theo từng profile):
  - Local HTTP: **Ollama**, **LM Studio**.
  - Remote HTTP: endpoint tương thích **OpenAI** (base URL + tên model).
  - Cloud CLI: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` hoặc `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (đăng nhập tùy theo provider).
- **Agent profile**: các template prompt được tự động cài đặt trong `~/.burp-ai-agent/AGENTS/`; thêm các file `*.md` vào đó để bổ sung hành vi phân tích/scan tùy chỉnh.
- **MCP server**: bật tại **Settings > MCP Server** để cung cấp các thao tác Burp cho mọi MCP client (hơn 53 công cụ). Có thể trỏ Claude Desktop tới server bằng cách chỉnh sửa `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) hoặc `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Kiểm soát quyền riêng tư**: STRICT / BALANCED / OFF sẽ ẩn dữ liệu nhạy cảm trong request trước khi gửi tới remote model; ưu tiên backend local khi xử lý secrets.
- **Audit logging**: log JSONL với cơ chế băm toàn vẹn SHA-256 cho từng mục, giúp truy vết các thao tác AI/MCP và phát hiện việc chỉnh sửa.
- **Build/load**: tải JAR bản phát hành hoặc build bằng Java 21:

```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```

Thận trọng trong vận hành: backend cloud có thể exfiltrate session cookies/PII nếu không bật chế độ bảo mật; việc để lộ MCP cho phép điều phối Burp từ xa, vì vậy hãy giới hạn quyền truy cập cho các agent đáng tin cậy và giám sát nhật ký kiểm tra có hash bảo đảm tính toàn vẹn.



## References

- [1] [Tích hợp Burp MCP + Codex CLI và bản sửa lỗi bắt tay Caddy](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Vấn đề xác thực Origin/header nghiêm ngặt của PortSwigger MCP server](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (quy trình, trình khởi chạy, bộ prompt)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Cách dùng Codex để nghiên cứu Bug Bounty: khám phá rộng, xác thực nghiêm ngặt](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp: điều phối Burp Suite cho Claude Code và Codex](https://github.com/luispacheco22/OpenBurp)
- [10] [Triển khai công cụ và tham số của PortSwigger MCP Server](https://github.com/PortSwigger/mcp-server/blob/main/src/main/kotlin/net/portswigger/mcp/tools/Tools.kt)
- [11] [PortSwigger Web Security Academy - Lỗ hổng Blind SSRF](https://portswigger.net/web-security/ssrf/blind)
{{#include ../banners/hacktricks-training.md}}
