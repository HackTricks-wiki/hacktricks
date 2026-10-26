# Bảo mật giao thức A2A (Agent2Agent)

{{#include ../banners/hacktricks-training.md}}

## A2A là gì

A2A (Agent2Agent) là một giao thức mở cho phép một AI agent khám phá agent khác và giao việc cho agent đó qua HTTP. MCP kết nối một agent với **các công cụ và dữ liệu**; A2A kết nối một agent với **các agent khác**, thường là những dịch vụ từ xa do một nhóm hoặc công ty khác sở hữu. Máy chủ A2A là một web API có LLM agent chạy phía sau, vì vậy các đối tượng riêng của giao thức (agent card, task, webhook push notification, extended card) bổ sung các kiểm tra xác thực, IDOR và SSRF cụ thể cho quá trình kiểm thử API thông thường.<sup>[[1]](#references)[[2]](#references)</sup>

Các thành phần chính gồm:

- **Agent Card:** tài liệu JSON mô tả agent: tên, mô tả, kỹ năng, URL dịch vụ, transport được hỗ trợ, capability (streaming, push notification, extended card) và `securitySchemes` mà client phải dùng. Tài liệu này được công bố tại `https://<host>/.well-known/agent-card.json`. Các bản triển khai cũ theo spec 0.2.x dùng `/.well-known/agent.json`.<sup>[[1]](#references)[[3]](#references)</sup>
- **Task:** đơn vị công việc. Một message tạo ra một task (với `id` và `contextId` do máy chủ tạo), sau đó client có thể đọc, hủy hoặc đăng ký nhận task đó.<sup>[[1]](#references)</sup>
- **Transports:** JSON-RPC 2.0 qua HTTP (dùng SSE cho streaming), gRPC và HTTP+JSON REST binding.<sup>[[1]](#references)</sup>
- **Xác thực:** thông tin xác thực được đặt trong HTTP header (ví dụ `Authorization: Bearer ...`), không bao giờ nằm trong payload JSON-RPC. Agent card cho biết cần dùng scheme nào.<sup>[[1]](#references)</sup>

Tên method thay đổi giữa các phiên bản, vì vậy hãy thử cả hai bộ tên:<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

| Thao tác | JSON-RPC 0.2/0.3 | JSON-RPC 1.0 | REST 1.0 |
| --- | --- | --- | --- |
| Gửi message | `message/send` | `SendMessage` | `POST /message:send` |
| Gửi streaming | `message/stream` | `SendStreamingMessage` | `POST /message:stream` |
| Lấy task | `tasks/get` | `GetTask` | `GET /tasks/{id}` |
| Liệt kê task | - | `ListTasks` | `GET /tasks` |
| Hủy task | `tasks/cancel` | `CancelTask` | `POST /tasks/{id}:cancel` |
| Cấu hình push notification | `tasks/pushNotificationConfig/set` | `CreateTaskPushNotificationConfig` | `POST /tasks/{id}/pushNotificationConfigs` |
| Extended card | `agent/getAuthenticatedExtendedCard` (0.3); HTTP `GET agent/authenticatedExtendedCard` (0.2.5) | `GetExtendedAgentCard` | `GET /extendedAgentCard` |

Spec 1.0 dùng header `A2A-Version` (hoặc tham số request) để chọn phiên bản; các request không có header này được xem là phiên bản 0.3.<sup>[[1]](#references)</sup>

## Khám phá

```bash
curl -s https://target/.well-known/agent-card.json | jq .
curl -s https://target/.well-known/agent.json | jq .
```

Từ card, ghi lại:

- Mọi `url` của service (thường là hostname nội bộ, URL staging hoặc cổng khác với trang web công khai).
- `skills`: chúng cho biết agent có thể làm gì và những công cụ hoặc dữ liệu nào đứng sau nó.
- `securitySchemes` / `security`: nếu chúng trống hoặc không có, agent có thể được thiết kế để gọi mà không cần thông tin xác thực.
- `capabilities.pushNotifications` và `capabilities.extendedAgentCard` (trong 0.3 là `supportsAuthenticatedExtendedCard`).

Spec quy định rằng card công khai không được chứa thông tin xác thực hoặc chi tiết triển khai nội bộ, vì vậy URL nội bộ, key hoặc danh sách công cụ chi tiết trong card công khai vốn đã là một phát hiện.<sup>[[1]](#references)</sup>

## Kiểm thử các endpoint A2A

### Gửi task không cần xác thực

Gửi một message tối giản, không kèm thông tin xác thực, đến mọi `url` được liệt kê trong card:

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

Một kết quả `Task` hoặc `Message` có `PONG`, khi card khai báo một cơ chế bảo mật, có nghĩa là endpoint RPC không thực thi xác thực (việc xác thực có thể chỉ được thực thi trên UI hoặc trên card). Nếu card không khai báo cơ chế nào, hãy kiểm tra những gì các skill của agent có thể truy cập: một agent không cần xác thực nhưng có thể đọc dữ liệu nội bộ hoặc gọi tool cũng tương đương với một API không cần xác thực cho các tool đó.

### Task IDOR (`tasks/get`, `GetTask`, cancel, subscribe)

Spec yêu cầu server kiểm tra trong mọi request rằng caller được phép truy cập task, đồng thời giới hạn `ListTasks` cho caller ngay cả khi không có filter nào được cung cấp.<sup>[[1]](#references)</sup> Kiểm tra bằng hai danh tính (A và B):

1. Với danh tính A, tạo một task và lưu `id` cùng `contextId`.
2. Với danh tính B (hoặc không có credentials), gọi `tasks/get` / `GetTask` với `id` của A, sau đó gọi `ListTasks` không có tham số.
3. Cũng thử cancel và subscribe task của A, đồng thời gửi một message mới với danh tính B có chứa `taskId` hoặc `contextId` của A (việc này sẽ thêm nội dung của B vào cuộc hội thoại của A).

```json
{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"id":"<task id of user A>","historyLength":10}}
```

Dễ bị tổn thương: B nhận lịch sử, artifacts hoặc trạng thái của A, hoặc có thể thay đổi tác vụ của A. An toàn: trả về `TaskNotFoundError`, không phân biệt giữa trường hợp “tồn tại nhưng không thuộc về bạn” và “không tồn tại”.<sup>[[1]](#references)</sup> Task ID thường là UUID, vì vậy hãy tìm chúng ở những nơi chúng có thể bị leak (liên kết được chia sẻ, log, payload thông báo đẩy, thông báo lỗi).

### SSRF qua webhook thông báo đẩy

Khi `capabilities.pushNotifications` là true, client cung cấp cho agent một URL webhook, sau đó agent gửi các yêu cầu `POST` kèm cập nhật tác vụ đến URL đó. Đặc tả yêu cầu agent từ chối các dải địa chỉ riêng tư, localhost và link-local, đồng thời sử dụng allowlist.<sup>[[1]](#references)</sup> Tạo một tác vụ, đăng ký cấu hình thông báo đẩy có `url` trỏ đến máy chủ OAST của bạn để xác nhận các yêu cầu gửi đi, rồi (chỉ khi phạm vi cho phép) thử các mục tiêu nội bộ như `http://127.0.0.1:<port>/` hoặc `http://169.254.169.254/`. So sánh lỗi và thời gian phản hồi để lập bản đồ các dịch vụ nội bộ. Agent cũng thêm header xác thực đã cấu hình vào các yêu cầu này, vì vậy hãy kiểm tra xem header đó có bị gửi đến máy chủ do kẻ tấn công chọn hay không khi bạn có thể thay đổi URL trong cấu hình của người dùng khác. Xem [SSRF](../pentesting-web/ssrf-server-side-request-forgery/).

### Truy cập thẻ agent mở rộng

`GetExtendedAgentCard` phải yêu cầu xác thực và có thể trả về nhiều skill và cấu hình hơn thẻ công khai.<sup>[[1]](#references)</sup> Gọi API này không có thông tin xác thực và bằng một danh tính có đặc quyền thấp, rồi so sánh kết quả với thẻ công khai.

### Cấu hình thông báo đẩy và leak thông tin xác thực trong tác vụ

Cấu hình thông báo đẩy lưu URL webhook và thông tin xác thực mà agent gửi đến URL đó. Đặc tả yêu cầu mọi thao tác với cấu hình thông báo đẩy (tạo, lấy, liệt kê, xóa) phải xác minh rằng người gọi có quyền truy cập vào tác vụ.<sup>[[1]](#references)</sup> Lặp lại bài kiểm tra hai danh tính từ [phần task IDOR](#task-idor-tasksget-gettask-cancel-subscribe) trên các route này. Cấu hình của người dùng khác có thể đọc được sẽ làm leak token webhook; cấu hình có thể ghi được sẽ chuyển hướng cập nhật tác vụ của người dùng đó đến máy chủ của bạn.

Khi agent cần thêm quyền xác thực trong lúc thực hiện tác vụ, nó chuyển tác vụ sang `TASK_STATE_AUTH_REQUIRED`. Client có thể sắp xếp việc xác thực ngoài băng; đặc tả quy định agent phải nhận thông tin xác thực ngoài băng, trừ khi đã thỏa thuận cơ chế trong băng. Trao đổi trong băng có thể truyền thông tin xác thực qua chuỗi agent A2A và làm lộ thông tin đó cho mọi agent trong chuỗi.<sup>[[1]](#references)</sup> Trong bài kiểm tra orchestrator, hãy kiểm tra xem thông tin xác thực mà người dùng cung cấp cho một agent hạ nguồn có xuất hiện trong tin nhắn, artifacts hoặc lịch sử tác vụ mà các agent khác (hoặc người dùng khác thông qua task IDOR) có thể đọc hay không.

Các trường trong thẻ agent và kết quả tác vụ cũng là đầu vào không đáng tin cậy đối với agent gọi. Hãy kiểm tra chúng bằng các kỹ thuật prompt injection gián tiếp trong [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) và các bước kiểm tra độ tin cậy giữa các agent trong [AI Agent Security Methodology](AI-Agent-Security-Methodology.md).

## References

- [1] [Đặc tả giao thức A2A](https://a2a-protocol.org/latest/specification/)
- [2] [Blog Google Developers — Công bố giao thức Agent2Agent (A2A)](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)
- [3] [Đặc tả A2A v0.2.5](https://github.com/a2aproject/A2A/blob/v0.2.5/docs/specification.md)
- [4] [Đặc tả A2A v0.3.0](https://github.com/a2aproject/A2A/blob/v0.3.0/docs/specification.md)
{{#include ../banners/hacktricks-training.md}}
