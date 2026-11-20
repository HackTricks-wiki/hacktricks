# Bảo mật giao thức A2A (Agent2Agent)

{{#include ../banners/hacktricks-training.md}}

## A2A là gì

A2A (Agent2Agent) là một giao thức mở cho phép một AI agent phát hiện agent khác và giao việc cho agent đó qua HTTP. MCP kết nối agent với **công cụ và dữ liệu**; A2A kết nối agent với **các agent khác**, thường là những dịch vụ từ xa do một nhóm hoặc công ty khác sở hữu. A2A server là một web API có LLM agent đứng phía sau, vì vậy các đối tượng riêng của giao thức (agent card, task, webhook push notification, extended card) bổ sung những kiểm tra xác thực, IDOR và SSRF cụ thể vào một bài kiểm thử API thông thường.<sup>[[1]](#references)[[2]](#references)</sup>

Các thành phần chính gồm:

- **Agent Card:** một tài liệu JSON mô tả agent: tên, mô tả, kỹ năng, URL dịch vụ, các transport được hỗ trợ, capabilities (streaming, push notification, extended card) và `securitySchemes` mà client phải sử dụng. Tài liệu này được công bố tại `https://<host>/.well-known/agent-card.json`. Các bản triển khai cũ theo spec 0.2.x sử dụng `/.well-known/agent.json`.<sup>[[1]](#references)[[3]](#references)</sup>
- **Task:** đơn vị công việc. Một message tạo ra một task (với `id` và `contextId` do server tạo), sau đó client đọc, hủy hoặc đăng ký theo dõi task đó.<sup>[[1]](#references)</sup>
- **Transports:** JSON-RPC 2.0 qua HTTP (dùng SSE cho streaming), gRPC và REST binding HTTP+JSON.<sup>[[1]](#references)</sup>
- **Authentication:** thông tin xác thực được đặt trong HTTP header (ví dụ `Authorization: Bearer ...`), không bao giờ nằm trong payload JSON-RPC. Agent card cho biết cần dùng scheme nào.<sup>[[1]](#references)</sup>

Tên method đã thay đổi giữa các phiên bản, vì vậy hãy thử cả hai nhóm:<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

| Thao tác | JSON-RPC 0.2/0.3 | JSON-RPC 1.0 | REST 1.0 |
| --- | --- | --- | --- |
| Gửi message | `message/send` | `SendMessage` | `POST /message:send` |
| Gửi streaming | `message/stream` | `SendStreamingMessage` | `POST /message:stream` |
| Lấy task | `tasks/get` | `GetTask` | `GET /tasks/{id}` |
| Liệt kê task | - | `ListTasks` | `GET /tasks` |
| Hủy task | `tasks/cancel` | `CancelTask` | `POST /tasks/{id}:cancel` |
| Cấu hình push notification | `tasks/pushNotificationConfig/set` | `CreateTaskPushNotificationConfig` | `POST /tasks/{id}/pushNotificationConfigs` |
| Extended card | `agent/getAuthenticatedExtendedCard` (0.3); HTTP `GET agent/authenticatedExtendedCard` (0.2.5) | `GetExtendedAgentCard` | `GET /extendedAgentCard` |

Spec 1.0 sử dụng header `A2A-Version` (hoặc tham số request) để chọn phiên bản; các request không có header này được xem là phiên bản 0.3.<sup>[[1]](#references)</sup>

## Khám phá

```bash
curl -s https://target/.well-known/agent-card.json | jq .
curl -s https://target/.well-known/agent.json | jq .
```

Từ card, ghi lại:

- Mọi `url` của dịch vụ: trong phiên bản 1.0, các URL này nằm dưới `supportedInterfaces`, còn các card cũ hơn có thể hiển thị `url` ở cấp cao nhất. Ghi lại từng endpoint và transport, bao gồm hostname nội bộ, URL staging và các port thay thế.<sup>[[1]](#references)[[7]](#references)</sup>
- `skills`: chúng cho biết agent có thể làm gì và những công cụ hoặc dữ liệu nào đứng sau nó.
- `securitySchemes` / `security`: nếu chúng trống hoặc bị thiếu, agent có thể được thiết kế để gọi mà không cần credentials.
- `capabilities.pushNotifications` và `capabilities.extendedAgentCard` (trong phiên bản 0.3 là `supportsAuthenticatedExtendedCard`).

Spec quy định card công khai không nên chứa credentials hoặc chi tiết triển khai nội bộ, vì vậy URL nội bộ, key hoặc danh sách công cụ chi tiết trong card công khai đã là một phát hiện.<sup>[[1]](#references)</sup>

### Xung đột tên Agent Card trên host nhiều agent

`name` của card là nhãn dễ đọc đối với con người, không phải định danh định tuyến ổn định.<sup>[[1]](#references)[[5]](#references)</sup> Nếu một host đăng ký hai peer từ xa riêng biệt dưới cùng một tên cục bộ, cây agent, tên công cụ được tạo, map client hoặc route broker có thể gửi task dành cho peer đáng tin cậy đến peer còn lại.<sup>[[5]](#references)</sup> Điều này đòi hỏi peer do attacker kiểm soát phải được chấp nhận vào **cùng namespace định tuyến**; chỉ đăng một card trùng lặp trên Internet là chưa đủ.<sup>[[5]](#references)</sup>

Kiểm tra luồng **từ chấp nhận đến dispatch** của host bằng hai peer do bạn kiểm soát, URL riêng biệt và một marker vô hại:<sup>[[5]](#references)</sup>

1. Ghi lại card, origin và selector cục bộ của peer đáng tin cậy. Đăng ký peer thứ hai có card cùng `name` nhưng URL trỏ đến endpoint do bạn kiểm soát.
2. Kích hoạt thao tác chọn peer đáng tin cậy theo tên. Thử cả hai thứ tự đăng ký và, nếu tên được chuyển thành định danh công cụ, thử cách chuẩn hóa tên thông thường của host. Ghi lại endpoint nào nhận marker và agent nào trả về phản hồi.
3. Chỉ thay đổi tên của card thứ hai rồi lặp lại. Nếu request chỉ đến endpoint thứ hai trong trường hợp có xung đột, điều đó chứng minh việc dispatch nhầm peer. Kiểm tra riêng xem có context nhạy cảm hoặc credential nào thực sự được đính kèm hay không; bản thân xung đột tên **không** chứng minh đã chuyển giao credential hoặc quyền sử dụng công cụ.

Nếu caller gửi request đến một endpoint cố định, gắn với origin, thay vì phân giải tên card, thì không áp dụng phép kiểm tra này.<sup>[[5]](#references)</sup> Để kiểm tra phản hồi độc hại của peer và tác động của prompt-injection tiếp theo, hãy xem [Phương pháp bảo mật AI Agent](AI-Agent-Security-Methodology.md#exploitation-cross-a-trust-boundary).

## Kiểm tra endpoint A2A

### Gửi task không cần xác thực

Gửi một message tối giản, không kèm credentials, đến mọi `url` được liệt kê trong card:

```bash
# 0.2 / 0.3 style
curl -s https://target/a2a -H 'Content-Type: application/json' -d '{
  "jsonrpc":"2.0","id":1,"method":"message/send",
  "params":{"message":{"role":"user","messageId":"6f1c2b9e-0000-4000-8000-000000000001",
            "parts":[{"kind":"text","text":"Reply only with the word PONG."}]}}}'

# 1.0 style
curl -s https://target/a2a -H 'Content-Type: application/json' -H 'A2A-Version: 1.0' -d '{
  "jsonrpc":"2.0","id":1,"method":"SendMessage",
  "params":{"message":{"role":"ROLE_USER","messageId":"6f1c2b9e-0000-4000-8000-000000000002",
            "parts":[{"text":"Reply only with the word PONG."}]}}}'
```

Kết quả `Task` hoặc `Message` có `PONG`, khi card khai báo một security scheme, nghĩa là endpoint RPC không thực thi xác thực (việc này có thể chỉ được thực hiện trên UI hoặc trên card). Nếu card không khai báo scheme, hãy kiểm tra các skill của agent có thể truy cập những gì: một agent không cần xác thực nhưng có thể đọc dữ liệu nội bộ hoặc gọi tools thì cũng tương đương với một API không cần xác thực cho các tools đó.

### Task IDOR (`tasks/get`, `GetTask`, cancel, subscribe)

Spec yêu cầu server kiểm tra trong mỗi request rằng caller có quyền truy cập task và giới hạn `ListTasks` theo caller ngay cả khi không có filter nào được cung cấp.<sup>[[1]](#references)</sup> Kiểm tra bằng hai identity (A và B):

1. Với tư cách A, tạo một task và lưu `id` cùng `contextId` của task đó.
2. Với tư cách B (hoặc không dùng credentials), gọi `tasks/get` / `GetTask` với `id` của A, sau đó gọi `ListTasks` mà không có tham số.
3. Thử cả cancel và subscribe trên task của A, đồng thời gửi một message mới với tư cách B, trong đó có `taskId` hoặc `contextId` của A (việc này sẽ thêm nội dung của B vào cuộc hội thoại của A).

```json
{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"id":"<task id of user A>","historyLength":10}}
```

Dễ bị tấn công: B nhận được lịch sử, artifact hoặc trạng thái của A, hoặc có thể thay đổi tác vụ của A. An toàn: trả về `TaskNotFoundError`, không phân biệt giữa trường hợp "tồn tại nhưng không thuộc về bạn" và "không tồn tại".<sup>[[1]](#references)</sup> ID tác vụ thường là UUID, vì vậy hãy tìm chúng ở những nơi chúng có thể bị leak (liên kết được chia sẻ, log, payload thông báo đẩy, thông báo lỗi).

### SSRF qua webhook thông báo đẩy

Khi `capabilities.pushNotifications` là true, client cung cấp cho agent một URL webhook, sau đó agent gửi các yêu cầu `POST` chứa thông tin cập nhật tác vụ đến URL đó. Spec nêu rằng agent nên từ chối các dải địa chỉ riêng tư, localhost và link-local, đồng thời dùng allowlist.<sup>[[1]](#references)</sup> Tạo một tác vụ, đăng ký cấu hình thông báo đẩy có `url` trỏ đến host OAST của bạn để xác nhận các yêu cầu gửi đi, rồi (chỉ khi phạm vi cho phép) thử các đích nội bộ như `http://127.0.0.1:<port>/` hoặc `http://169.254.169.254/`. So sánh lỗi và thời gian phản hồi để lập bản đồ các dịch vụ nội bộ. Agent cũng thêm header xác thực đã cấu hình vào các yêu cầu này, vì vậy hãy kiểm tra xem header đó có bị gửi đến host do kẻ tấn công chọn hay không khi bạn có thể thay đổi URL trong cấu hình của người dùng khác. Xem [SSRF](../pentesting-web/ssrf-server-side-request-forgery/).

### Các phần File-URL là điểm vào SSRF thứ hai

A2A 1.0 cho phép một message hoặc artifact chứa tham chiếu tệp dưới dạng `Part` có `url` (0.3 dùng `kind: "file"` và `file.uri`).<sup>[[1]](#references)[[4]](#references)[[7]](#references)</sup> Protocol truyền tham chiếu này; việc tải tệp là hành vi của ứng dụng, không phải yêu cầu của A2A SDK.<sup>[[6]](#references)</sup> Đây là luồng riêng, không liên quan đến URL callback thông báo đẩy ở trên. Hãy kiểm tra cả hai chiều: tệp do client cung cấp được gửi đến máy chủ A2A, và URL tệp do peer có độ tin cậy thấp hơn trả về cho orchestrator.<sup>[[1]](#references)[[6]](#references)</sup>

Với endpoint JSON-RPC 1.0 được phép kiểm thử, hãy thay phần văn bản thông thường bằng URL trỏ đến một đường dẫn OAST duy nhất và kiểm tra **thành phần nào** gửi yêu cầu:<sup>[[1]](#references)[[7]](#references)</sup>

```bash
curl -s https://target/a2a -H 'Content-Type: application/json' -H 'A2A-Version: 1.0' -d '{
  "jsonrpc":"2.0","id":1,"method":"SendMessage",
  "params":{"message":{"role":"ROLE_USER",
    "messageId":"6f1c2b9e-0000-4000-8000-000000000003",
    "parts":[{"url":"https://oast.example/part-probe","filename":"probe.txt","mediaType":"text/plain"}]}}}'
```

Chỉ khi người nhận dereference URL đó, bạn mới nên kiểm tra các đích nội bộ nằm trong phạm vi, redirect và thay đổi phân giải DNS bằng [quy trình SSRF](../pentesting-web/ssrf-server-side-request-forgery/). Chỉ một `Part` hợp lệ hoặc phản hồi tác vụ thành công không chứng minh được SSRF; hãy xác nhận việc fetch đã đến đích và nội dung được fetch có được chuyển đến agent hay không.<sup>[[6]](#references)</sup>

### Truy cập agent card mở rộng

`GetExtendedAgentCard` phải yêu cầu xác thực và có thể trả về nhiều skill cùng cấu hình hơn agent card công khai.<sup>[[1]](#references)</sup> Gọi nó khi không có thông tin xác thực và bằng một danh tính có quyền thấp, rồi so sánh kết quả với agent card công khai.

### Rò rỉ cấu hình push notification và thông tin xác thực trong tác vụ

Cấu hình push notification lưu URL webhook và thông tin xác thực mà agent gửi đến đó. Đặc tả yêu cầu mọi thao tác với cấu hình push notification (tạo, xem, liệt kê, xóa) phải xác minh rằng người gọi có quyền truy cập tác vụ.<sup>[[1]](#references)</sup> Lặp lại bài kiểm tra hai danh tính trong [phần task IDOR](#task-idor-tasksget-gettask-cancel-subscribe) trên các route này. Đọc được cấu hình của người dùng khác sẽ làm lộ token webhook; còn ghi được vào cấu hình đó sẽ chuyển hướng các cập nhật tác vụ của người dùng ấy đến máy chủ của bạn.

Khi agent cần thêm quyền trong lúc thực hiện tác vụ, nó chuyển tác vụ sang `TASK_STATE_AUTH_REQUIRED`. Client có thể sắp xếp việc cấp quyền ngoài băng; đặc tả nêu rằng agent phải nhận thông tin xác thực ngoài băng, trừ khi đã thỏa thuận cơ chế trao đổi trong băng. Trao đổi trong băng có thể truyền thông tin xác thực qua chuỗi agent A2A và làm lộ thông tin đó cho mọi agent trong chuỗi.<sup>[[1]](#references)</sup> Khi kiểm thử orchestrator, hãy kiểm tra xem thông tin xác thực mà người dùng cung cấp cho một agent hạ nguồn có xuất hiện trong tin nhắn, artifact hoặc lịch sử tác vụ mà các agent khác (hoặc người dùng khác thông qua task IDOR) có thể đọc hay không.

Các trường trong agent card và kết quả tác vụ cũng là đầu vào không đáng tin cậy đối với agent gọi. Hãy kiểm thử chúng bằng các kỹ thuật prompt injection gián tiếp trong [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) và các bước kiểm tra độ tin cậy giữa các agent trong [Phương pháp luận bảo mật AI Agent](AI-Agent-Security-Methodology.md).



## References

- [1] [Đặc tả giao thức A2A](https://a2a-protocol.org/latest/specification/)
- [2] [Google Developers Blog — Công bố giao thức Agent2Agent (A2A)](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)
- [3] [Đặc tả A2A v0.2.5](https://github.com/a2aproject/A2A/blob/v0.2.5/docs/specification.md)
- [4] [Đặc tả A2A v0.3.0](https://github.com/a2aproject/A2A/blob/v0.3.0/docs/specification.md)
- [5] [Tấn công va chạm tên agent trong hệ thống đa agent](https://arxiv.org/abs/2609.27624)
- [6] [Hướng dẫn bảo mật A2A .NET SDK](https://github.com/a2aproject/a2a-dotnet/blob/main/docs/security.md)
- [7] [Hướng dẫn di trú A2A Python v1.0](https://github.com/a2aproject/a2a-python/blob/main/docs/migrations/v1_0/README.md)
{{#include ../banners/hacktricks-training.md}}
