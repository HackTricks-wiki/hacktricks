# Burp MCP: rà soát lưu lượng với sự hỗ trợ của LLM

{{#include ../banners/hacktricks-training.md}}

## Tổng quan

Extension **MCP Server** của Burp có thể cung cấp lưu lượng HTTP(S) đã chặn cho các LLM client hỗ trợ MCP, giúp chúng **phân tích các request/response thực tế** để phát hiện lỗ hổng và soạn thảo báo cáo. Hãy xem Burp là nguồn dữ liệu đáng tin cậy: dùng phân tích thụ động hoặc phát lại có chủ đích, chỉ thay đổi một biến mỗi lần, thay vì quét mù.<sup>[[8]](#references)</sup>

## Kiến trúc

- **Burp MCP Server (BApp)** mặc định lắng nghe trên `127.0.0.1:9876` và cung cấp lưu lượng đã chặn qua MCP.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR** kết nối stdio (phía client) với endpoint MCP SSE của Burp.
- **Reverse proxy cục bộ tùy chọn** (Caddy) chuẩn hóa các header để đáp ứng các bước kiểm tra handshake MCP nghiêm ngặt.
- **Client/backend**: Codex CLI (cloud), Gemini CLI (cloud) hoặc Ollama (local).

## Cài đặt

### 1) Cài đặt Burp MCP Server

Cài **MCP Server** từ Burp BApp Store và xác nhận rằng extension đang lắng nghe trên `127.0.0.1:9876`.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Trích xuất proxy JAR

Trong tab MCP Server, nhấp **Extract server proxy jar** và lưu `mcp-proxy-all.jar`.<sup>[[7]](#references)</sup>

### 3) Cấu hình MCP client (ví dụ với Codex)

Trỏ client đến proxy JAR và endpoint SSE trực tiếp của Burp. Proxy đi kèm là cầu nối stdio-to-SSE; nó không thay thế listener của Burp.<sup>[[7]](#references)</sup>

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

### 4) Sửa lỗi xác thực Origin/header nghiêm ngặt bằng Caddy (nếu cần)

Nếu quá trình bắt tay MCP thất bại do kiểm tra Origin nghiêm ngặt hoặc có header bổ sung, hãy dùng reverse proxy cục bộ để chuẩn hóa các header (đây là cách khắc phục sự cố xác thực nghiêm ngặt của Burp MCP).<sup>[[1]](#references)[[3]](#references)</sup>

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

Khởi động proxy và client, rồi chỉ đổi `--sse-url` đã cấu hình thành `http://127.0.0.1:19876` khi sử dụng listener Caddy này:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```

### 5) Ghép trạng thái browser với bằng chứng từ proxy (Playwright MCP)

Đăng ký Playwright MCP để browser sử dụng proxy của Burp. Nhờ vậy, agent có thể đối chiếu trạng thái DOM/accessibility đã render với chính xác lịch sử HTTP tạo ra trạng thái đó.<sup>[[6]](#references)[[8]](#references)</sup>

```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
  --proxy-server=http://127.0.0.1:8080 \
  --ignore-https-errors
```

Điều chỉnh địa chỉ listener, khởi động lại Codex và dùng `/mcp` để xác minh cả hai tích hợp. Ví dụ này tắt kiểm tra lỗi chứng chỉ của trình duyệt để chứng chỉ do Burp tạo cục bộ không chặn việc chặn bắt HTTPS.<sup>[[6]](#references)[[8]](#references)</sup>

## Tự động hóa trình duyệt nhận biết proxy (OpenBurp)

Kết nối Burp MCP và luồng dữ liệu của trình duyệt bị chặn bắt là hai luồng dữ liệu riêng biệt. Dịch vụ MCP cung cấp các công cụ Burp trên `127.0.0.1:9876`, trong khi một phiên bản Chromium chuyên dụng gửi lưu lượng HTTP(S) qua proxy của Burp trên `127.0.0.1:8080`. Vì vậy, các yêu cầu được tạo trực tiếp bởi công cụ MCP có thể không xuất hiện trong **Proxy > HTTP history**; hãy dùng trình duyệt đi qua proxy khi cần quan sát, chỉnh sửa hoặc lưu lại yêu cầu/phản hồi làm bằng chứng.<sup>[[2]](#references)[[9]](#references)</sup>

Client hỗ trợ SSE có thể đăng ký Burp trực tiếp. Thay vào đó, client chỉ hỗ trợ stdio có thể khởi chạy JAR proxy của PortSwigger. Trong cả hai trường hợp, hãy đăng ký thêm một MCP điều khiển trình duyệt và trỏ nó đến Chromium tích hợp của Burp (`BURP_CHROMIUM` là đường dẫn thực thi cục bộ):<sup>[[9]](#references)</sup>

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

Cờ TLS-bypass chấp nhận các chứng chỉ do proxy chặn bắt tạo ra, còn `--isolated` ngăn quá trình đánh giá sử dụng lại hồ sơ trình duyệt thông thường của người vận hành. Tính năng cô lập bảo vệ trạng thái hồ sơ nhưng **không phải sandbox bảo mật**: controller vẫn có thể truy cập các phiên đã xác thực được mở trong trình duyệt thử nghiệm đó, và Burp MCP có thể để lộ các request, response và cấu hình nhạy cảm.<sup>[[9]](#references)</sup>

Kiểm tra riêng SSE listener trước khi gỡ lỗi client bridge:<sup>[[9]](#references)</sup>

```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```

Một listener hoạt động bình thường trả về `Content-Type: text/event-stream`. Hết thời gian chờ sau khi nhận header là điều được mong đợi vì SSE stream vẫn mở để nhận các event trong tương lai. Nếu client vẫn gặp lỗi, hãy xác nhận route đã cấu hình cho extension: PortSwigger lưu ý rằng endpoint có thể là đường dẫn gốc hoặc `/sse`, tùy thuộc vào client và cấu hình extension.<sup>[[9]](#references)[[7]](#references)</sup>

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

Sử dụng trình trợ giúp khởi chạy được cung cấp và chọn một model cục bộ:

```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```

Ví dụ về các model cục bộ và nhu cầu VRAM ước tính:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Phát lại và xác thực dựa trên bằng chứng

Không để agent xem một lời giải thích có vẻ hợp lý hoặc một phản hồi trung gian là bằng chứng. Dùng request/response của Burp và trạng thái trình duyệt được quan sát độc lập để mọi phép thử đều có thể bị bác bỏ.<sup>[[8]](#references)</sup>

1. Lưu một cặp request/response cơ sở và xác định chính xác thành phần do attacker kiểm soát.
2. Để so sánh quyền truy cập, ghi lại riêng biệt cùng một workflow trên cả hai tài khoản trước khi thay đổi identifier, cookie hoặc token.
3. Trước khi phát lại một thay đổi, ghi lại giả thuyết, vị trí bằng chứng, tín hiệu dự kiến và kết quả có thể bác bỏ giả thuyết đó.
4. Mỗi lần chỉ thay đổi một thành phần, lưu lại cặp kết quả và phân biệt rõ quan sát trực tiếp với suy luận.
5. Theo dõi từng ứng viên với trạng thái `open`, `blocked`, `rejected` hoặc `confirmed`; chỉ xem xét lại khi bằng chứng mới làm thay đổi cơ chế hoặc điều kiện tiên quyết.
6. Xác nhận quyền kiểm soát của attacker, khả năng tiếp cận, tính lặp lại, việc vượt qua ràng buộc, tác động và trạng thái cuối cùng của ứng dụng. Redirect hoặc lời gọi tool thành công không phải là bằng chứng nếu thay đổi trạng thái được tuyên bố xảy ra ở bước sau.

Giữ chi tiết khai thác trong trang kỹ thuật tương ứng. Ví dụ, các ứng viên liên quan đến browser-message thuộc về [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md), còn hành vi chọn key của token thuộc về [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md).<sup>[[8]](#references)</sup>

Một bản ghi giả thuyết ngắn gọn giúp các agent chạy song song không lặp lại cùng một nhánh hấp dẫn:<sup>[[8]](#references)</sup>

```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```

## Phân loại frame WebSocket với Burp MCP

Extension chính thức cung cấp `get_proxy_websocket_history_regex` để tìm kiếm chỉ đọc, phân trang trong lịch sử WebSocket của Burp. Công cụ này nhận `regex`, `count` và `offset`; không giống `send_http1_request`, công cụ này không gửi frame WebSocket. Burp ghi lại cả hai chiều message ngay cả khi Intercept đang tắt, vì vậy hãy lọc lịch sử trước khi cung cấp cho model một tập frame nhỏ có liên quan.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>

1. Thực hiện cùng một thao tác dựa trên WebSocket qua trình duyệt được proxy qua Burp bằng hai tài khoản kiểm thử đã xác thực độc lập. Giữ riêng từng upgrade handshake cùng cookie, connection ID, hướng frame và các frame phản hồi; một sự kiện từ server đến client trên connection của tài khoản thứ nhất không chứng minh rằng tài khoản thứ hai đã nhận được sự kiện đó.
2. Tìm kiếm bằng `get_proxy_websocket_history_regex` với biểu thức hẹp như `(?i)(subscribe|room|tenant|objectId)`, `count: 20` và `offset: 0`. Tăng `offset` để kiểm tra các kết quả khớp tiếp theo. So sánh object hoặc topic identifier của frame gửi đi với phản hồi trên **cùng connection** đó.
3. Trong **Proxy > WebSockets history**, gửi frame gửi đi đáng ngờ đến Repeater. Gắn frame đó vào connection đang mở phù hợp hoặc kết nối lại bằng handshake của tài khoản thứ hai. Chỉ thay đổi object/topic identifier rồi so sánh các message từ server và trạng thái ứng dụng với cả hai baseline. Công cụ lịch sử MCP không thể thực hiện replay này; WebSocket Repeater có thể chỉnh sửa, gửi lại và kết nối lại các frame.

Với các kiểm thử dành riêng cho giao thức như cross-site WebSocket hijacking và kiểm tra quyền truy cập topic của broker, hãy tiếp tục ở [WebSocket Attacks](../pentesting-web/websocket-attacks.md). Đừng xem một upgrade được chấp nhận hoặc echo phía client là bằng chứng cho thấy subscription được bảo vệ đã thành công.

## Kiểm tra xác thực out-of-band có mục tiêu với Burp MCP

Burp Suite Professional cung cấp `generate_collaborator_payload` và `get_collaborator_interactions` thông qua extension MCP chính thức. Kết hợp chúng với `get_proxy_http_history_regex` và một lần replay bằng `send_http1_request` để kiểm tra nghi vấn server-side URL fetch mà không cần scan toàn bộ target. Burp có thể yêu cầu phê duyệt riêng để đọc lịch sử và gửi request.<sup>[[2]](#references)[[10]](#references)</sup>

1. Lọc lịch sử để tìm request tiềm năng có chứa URL, chẳng hạn request có `url=`, `webhook` hoặc `callback`. Lưu request và response ban đầu. Công cụ lịch sử nhận `regex`, `count` và `offset`; hãy phân trang thay vì yêu cầu model kiểm tra mọi mục.<sup>[[10]](#references)</sup>
2. Tạo Collaborator payload mới và lưu lại **payload ID** được trả về. Replay request đã ghi lại đến cùng host và port, chỉ thay đổi URL đáng ngờ thành URL HTTPS thuộc payload domain đó. Với `send_http1_request`, truyền toàn bộ request HTTP/1.1 dưới dạng `content`, cùng với `targetHostname`, `targetPort` và `usesHttps`; các trường đích xác định **ứng dụng**, không phải host Collaborator.<sup>[[10]](#references)</sup>
3. Dùng payload ID đó để thăm dò `get_collaborator_interactions` và đối chiếu thời điểm interaction với lần replay. HTTP interaction là dấu hiệu hỗ trợ giả thuyết có fetch, trong khi chỉ có DNS cho thấy đã phân giải tên miền nhưng không chứng minh HTTP request đã hoàn tất. Kiểm tra nguồn interaction và request header để phân biệt egress từ server với tải nội dung phía browser, sau đó lặp lại bằng payload mới để loại trừ traffic không liên quan.<sup>[[10]](#references)[[11]](#references)</sup>

Công cụ request MCP trả về response trực tiếp và không nhất thiết thêm nó vào **Proxy > HTTP history**. Hãy lưu kết quả request/response hoặc dùng trình duyệt được proxy qua Burp hay Repeater để có artifact trong lịch sử. Để chọn SSRF payload và thực hiện các kiểm thử tiếp theo, hãy dùng [SSRF chapter](../pentesting-web/ssrf-server-side-request-forgery/) thay vì xem out-of-band callback là bằng chứng cho thấy đã tác động đến mạng nội bộ. Để kiểm thử chính MCP server, xem [MCP server testing](AI-MCP-Servers.md#remote-mcp-server-testing-workflow).<sup>[[7]](#references)[[11]](#references)</sup>

## Bộ prompt để review thụ động

Repo **burp-mcp-agents** có các mẫu prompt để phân tích traffic Burp dựa trên bằng chứng:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: phát hiện lỗ hổng thụ động trên diện rộng.
- `idor_hunter.md`: phát hiện sai lệch về IDOR/BOLA/object/tenant và lỗi không khớp xác thực.
- `auth_flow_mapper.md`: so sánh các đường dẫn đã xác thực với chưa xác thực.
- `ssrf_redirect_hunter.md`: tìm ứng viên SSRF/open-redirect từ tham số URL fetch và chuỗi redirect.
- `logic_flaw_hunter.md`: tìm lỗi logic nhiều bước.
- `session_scope_hunter.md`: phát hiện việc sử dụng sai token audience/scope.
- `rate_limit_abuse_hunter.md`: tìm lỗ hổng trong throttling/kiểm soát lạm dụng.
- `report_writer.md`: viết báo cáo tập trung vào bằng chứng.

## Gắn thẻ attribution tùy chọn

Để gắn thẻ traffic Burp/LLM trong log, thêm quy tắc viết lại header (proxy hoặc Burp Match/Replace):<sup>[[1]](#references)</sup>

```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```

## Lưu ý an toàn

- Ưu tiên **local models** khi traffic chứa dữ liệu nhạy cảm.
- Chỉ chia sẻ bằng chứng tối thiểu cần thiết cho một finding.
- Coi Burp là nguồn dữ liệu chính xác; dùng model để **phân tích và báo cáo**, không dùng để scanning.

## Burp AI Agent (triage có AI hỗ trợ + công cụ MCP)

**Burp AI Agent** là một extension của Burp, kết hợp LLM local/cloud với phân tích thụ động/chủ động (62 lớp lỗ hổng) và cung cấp hơn 53 công cụ MCP để các MCP client bên ngoài điều phối Burp.<sup>[[5]](#references)</sup> Điểm nổi bật:

- **Triage qua menu ngữ cảnh**: ghi lại traffic qua Proxy, mở **Proxy > HTTP History**, nhấp chuột phải vào một request → **Extensions > Burp AI Agent > Analyze this request** để mở cuộc trò chuyện AI gắn với request/response đó.
- **Backends** (có thể chọn theo từng profile):
  - Local HTTP: **Ollama**, **LM Studio**.
  - Remote HTTP: endpoint tương thích **OpenAI** (base URL + tên model).
  - Cloud CLI: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` hoặc `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (đăng nhập theo provider).
- **Agent profiles**: các prompt template được tự động cài đặt trong `~/.burp-ai-agent/AGENTS/`; thêm các file `*.md` khác vào đó để bổ sung hành vi phân tích/scanning tùy chỉnh.
- **MCP server**: bật qua **Settings > MCP Server** để cung cấp các thao tác Burp cho mọi MCP client (hơn 53 công cụ). Có thể kết nối Claude Desktop với server bằng cách chỉnh sửa `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) hoặc `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Kiểm soát quyền riêng tư**: STRICT / BALANCED / OFF sẽ loại bỏ dữ liệu nhạy cảm trong request trước khi gửi đến remote model; ưu tiên local backend khi xử lý secrets.
- **Audit logging**: log JSONL với mã băm toàn vẹn SHA-256 cho từng mục, giúp theo dõi các hành động AI/MCP với khả năng phát hiện giả mạo.
- **Build/load**: tải JAR của bản phát hành hoặc build bằng Java 21:

```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```

Lưu ý vận hành: cloud backend có thể exfiltrate session cookie/PII nếu không bật privacy mode; MCP cho phép điều phối Burp từ xa, vì vậy hãy giới hạn quyền truy cập cho các agent đáng tin cậy và giám sát audit log có hash kiểm tra tính toàn vẹn.



## References

- [1] [Tích hợp Burp MCP + Codex CLI và cách khắc phục handshake của Caddy](https://pentestbook.six2dez.com/others/burp)
- [2] [BApp Burp MCP Server](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Vấn đề xác thực Origin/header nghiêm ngặt của PortSwigger MCP server](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (quy trình, launcher, bộ prompt)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Cách dùng Codex để nghiên cứu Bug Bounty: khám phá rộng, xác thực nghiêm ngặt](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp: điều phối Burp Suite cho Claude Code và Codex](https://github.com/luispacheco22/OpenBurp)
- [10] [Các triển khai tool và tham số của PortSwigger MCP Server](https://github.com/PortSwigger/mcp-server/blob/main/src/main/kotlin/net/portswigger/mcp/tools/Tools.kt)
- [11] [PortSwigger Web Security Academy - Lỗ hổng Blind SSRF](https://portswigger.net/web-security/ssrf/blind)
- [12] [PortSwigger - Lịch sử WebSockets](https://portswigger.net/burp/documentation/desktop/tools/proxy/websockets-history)
- [13] [PortSwigger - Làm việc với thông điệp WebSocket trong Burp Repeater](https://portswigger.net/burp/documentation/desktop/tools/repeater/websocket-messages)
{{#include ../banners/hacktricks-training.md}}
