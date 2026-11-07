# Ranh giới tin cậy của LLM Gateway

{{#include ../banners/hacktricks-training.md}}

LLM gateway xử lý việc định tuyến model và thường lưu thông tin xác thực của nhà cung cấp, vì vậy các caller API thông thường không được thừa hưởng quyền cấu hình hoặc quyền cấp nhà cung cấp. Đánh giá LiteLLM gateway trên phiên bản 1.77.7 cho thấy hai ranh giới riêng biệt: phân quyền phiên UI đối với cấu hình quản trị và cấu hình định tuyến do caller cung cấp cho inference. Các vấn đề được báo cáo đã được khắc phục ở phiên bản 1.83.9.<sup>[[1]](#references)</sup>

## Phân loại route UI không phải là phân quyền

Trong phiên bản LiteLLM được đánh giá, các khóa đăng nhập UI thuộc team `litellm-dashboard`. Cơ chế phân quyền phân loại một khóa là UI token dựa trên mã định danh team đó, bất kể role của người dùng. Sau đó, kiểm tra route UI chấp nhận mọi route bắt đầu bằng một prefix nằm trong allowlist. Vì vậy, entry `/config` cũng khớp với handler quản trị `/config/update`. Handler đó chỉ yêu cầu xác thực chung, nhưng không tự kiểm tra `PROXY_ADMIN`, khiến một phiên UI có quyền thấp hơn truy cập được quyền ghi cấu hình.<sup>[[1]](#references)</sup>

Điều này khác với lỗi lệch chuẩn hóa đường dẫn giữa proxy và backend: mã phân quyền và handler bất đồng về quyền hạn của *cùng một* route.<sup>[[1]](#references)</sup> Khi đánh giá một gateway, hãy đối chiếu việc phân loại token, khớp chính xác route và method, cùng bước kiểm tra role riêng của handler.<sup>[[1]](#references)</sup> Xem [phân quyền web API](../pentesting-web/web-api-pentesting.md), [bypass 401/403](../pentesting-web/403-and-401-bypasses.md) và [miễn trừ prefix của proxy](../pentesting-web/proxy-waf-protections-bypass.md#prefix-exemptions-become-routing-keys) để biết các ranh giới liên quan nhưng khác biệt.

## Ghi cấu hình có thể tác động đến nhiều nơi hơn kho cấu hình

Cùng endpoint cập nhật cấu hình của LiteLLM chấp nhận giá trị biến môi trường và áp dụng chúng vào tiến trình đang chạy. Một consumer xử lý `UI_LOGO_PATH` như đường dẫn cục bộ cho `FileResponse`, mà không xác thực xem đường dẫn đó có trỏ đến logo hay không; một consumer khác đọc `UI_USERNAME` và `UI_PASSWORD` khi đăng nhập không dùng SSO, rồi gán `PROXY_ADMIN` nếu chúng khớp. Vì vậy, quyền ghi cấu hình có thể dẫn đến cả việc tiết lộ tệp cục bộ lẫn thay đổi danh tính quản trị, tùy vào consumer phía sau. Media type trong response không chứng minh tệp được phục vụ là hình ảnh.<sup>[[1]](#references)</sup>

Cấu hình endpoint pass-through là một sink phía sau khác. Quá trình khởi tạo chấp nhận đích adapter S3/GCS từ xa, tải các Python module xuống và import chúng bằng `exec_module` của `importlib`. Import thực thi code ở cấp module trước khi dùng instance adapter; chỉ hạn chế việc gọi adapter sẽ không loại bỏ ranh giới thực thi đó. Hãy xem đây là việc nạp code do cấu hình kiểm soát, không phải deserialize model file.<sup>[[1]](#references)</sup> Để biết primitive đọc tệp riêng biệt, xem [file inclusion và path traversal](../pentesting-web/file-inclusion/).

## Định tuyến model theo từng request có thể làm lộ thông tin xác thực gateway

Tính năng thông tin xác thực phía client của LiteLLM chấp nhận một object `user_config` trong request LLM. Route được đánh giá tạo một `litellm.Router` tạm thời từ object đó, bao gồm danh sách model và `api_base` của nhà cung cấp. Đích nhà cung cấp do caller kiểm soát có thể nhận request completion gửi đi từ gateway cùng các header xác thực nhà cung cấp đã cấu hình. Các hạn chế áp dụng cho trường `api_base` hoặc `api_key` cấp cao nhất không bao phủ đường dẫn cấu hình lồng riêng biệt này. Đây là ranh giới SSRF có mang theo thông tin xác thực, chứ không phải vấn đề prompt injection.<sup>[[1]](#references)</sup>

Khi đánh giá gateway được cấp phép, hãy đối chiếu mọi đường dẫn có thể tạo router hoặc provider client, bao gồm cấu hình theo từng request, với chính sách đích và thông tin xác thực được dùng cho route đã cấu hình thông thường.<sup>[[1]](#references)</sup> [Hướng dẫn SSRF](../pentesting-web/ssrf-server-side-request-forgery/) trình bày việc kiểm soát đích nói chung ở phía server; lỗi đặc thù của gateway là cho phép một object request kém tin cậy hơn chọn đích, đồng thời tái sử dụng thông tin xác thực outbound có đặc quyền.<sup>[[1]](#references)</sup>

## Đăng ký guardrail có thể bypass sandbox chỉ dùng trong UI

Đường dẫn kiểm tra code và đường dẫn đăng ký code của gateway có thể áp dụng các bước validation khác nhau. Trong LiteLLM trước v1.82.0, chức năng kiểm tra custom guardrail trên UI từ chối cú pháp nguy hiểm và thực thi với `__builtins__ = {}`, nhưng `POST /guardrails` biên dịch `custom_code` được gửi lên bằng `exec(compile(...), exec_globals)` mà không áp dụng một trong hai bước kiểm tra đó. Python tự thêm builtins vào dictionary globals không có `__builtins__`, nên các lệnh import và command ở cấp module được chạy **khi guardrail được đăng ký**, trước bất kỳ lần gọi inference nào. Callback `apply_guardrail` về sau có thể làm lộ kết quả đã lưu thông qua lý do chặn.<sup>[[2]](#references)[[3]](#references)</sup>

Khi kiểm tra được cấp phép, hãy đối chiếu handler kiểm tra với handler đăng ký thay vì cho rằng việc vượt qua kiểm tra sandbox trên UI chứng minh đăng ký là an toàn. Dạng request trước khi được khắc phục đã báo cáo là:<sup>[[2]](#references)</sup>

```http
POST /guardrails HTTP/1.1
Authorization: Bearer <master_key>
Content-Type: application/json

{
  "guardrail": {
    "guardrail_name": "probe",
    "litellm_params": {
      "guardrail": "custom_code", "mode": "pre_call", "default_on": true,
      "custom_code": "import os\nresult = os.popen('id').read()\ndef apply_guardrail(inputs, request_data, input_type):\n    return {'action': 'block', 'reason': result}"
    }
  }
}
```

Endpoint đăng ký cũng chấp nhận các API key thông thường vì thiếu kiểm tra `PROXY_ADMIN`. Khi không cấu hình master key hoặc xác thực JWT/OAuth2, auth handler trước khi sửa gán `PROXY_ADMIN` ngay cả cho các request ẩn danh. Bản sửa đổi chuyển vai trò khi không có auth thành `INTERNAL_USER`, bổ sung các kiểm tra quyền admin cho guardrail, đồng thời xác thực và hạn chế builtins trong quá trình đăng ký. Các ranh giới về vai trò và thực thi mã này tách biệt với [vấn đề fallback token MCP](AI-MCP-Servers.md#mcp-token-passthrough-must-not-create-an-anonymous-session).<sup>[[2]](#references)[[3]](#references)</sup>

## Các route pass-through dành cho admin có thể proxy cloud metadata

Tính năng pass-through endpoint của LiteLLM cho phép admin cấu hình một HTTP target và tùy chọn thêm subpath. Không giống vấn đề định tuyến `user_config` theo từng request nêu trên, trường hợp này đòi hỏi **quyền ghi cấu hình**; bản thân tính năng được thiết kế để tin cậy admin. Trong deployment được báo cáo, target không được kiểm tra để ngăn trỏ đến địa chỉ private hoặc link-local.<sup>[[2]](#references)[[4]](#references)</sup> Trước v1.83.0, các key đã xác thực thông thường cũng có thể truy cập `/config/update` vì route này thiếu kiểm tra role admin; xem [phân loại UI route](#ui-route-classification-is-not-authorization) về ranh giới ghi cấu hình liên quan.<sup>[[2]](#references)[[6]](#references)</sup>

Khi có quyền đó và proxy có thể kết nối mạng đến EC2 metadata, một route như sau sẽ làm lộ metadata thông qua gateway. Cờ `include_subpath` khiến `/meta/meta-data/iam/security-credentials/` được ánh xạ vào bên dưới `/latest/`.<sup>[[2]](#references)[[4]](#references)</sup>

```http
POST /config/pass_through_endpoint HTTP/1.1
Authorization: Bearer <master_key>
Content-Type: application/json

{"path":"/meta","target":"http://169.254.169.254/latest/","headers":{},"include_subpath":true}
```

[Cloud SSRF guide](../pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf.md#aws) trình bày quy trình trao đổi token IMDSv2; route này phải cho phép yêu cầu `PUT` và chuyển tiếp cả hai metadata header.<sup>[[5]](#references)</sup> Cơ chế xử lý header pass-through chung của LiteLLM loại bỏ tiền tố `x-pass-` trước khi chuyển tiếp, vì vậy `x-pass-X-aws-ec2-metadata-token-ttl-seconds: 21600` và `x-pass-X-aws-ec2-metadata-token: <token>` có thể cung cấp các header đó.<sup>[[2]](#references)[[7]](#references)</sup> Proxy phải kết nối được với IMDS, phản hồi token phải vượt qua hop limit đã cấu hình và yêu cầu token không được chứa `X-Forwarded-For`.<sup>[[5]](#references)</sup> Biến thể riêng của gateway là **route tồn tại lâu dài do admin kiểm soát, kết hợp với chuyển tiếp request header**.

## References

- [1] [Check Point Research — Khi LLM gateway gặp sự cố: Những phát hiện từ LiteLLM](https://research.checkpoint.com/2026/when-llm-gateways-go-wrong-findings-from-litellm/)
- [2] [Wiz — Mất cảnh giác: Tấn công LiteLLM từ vượt qua xác thực đến chiếm quyền kiểm soát cloud](https://wiz.io/blog/off-guard-breaking-litellm-from-authentication-bypass-to-cloud-compromise)
- [3] [LiteLLM PR #22095 — khắc phục RCE không cần xác thực và thoát sandbox trong custom code guardrail](https://github.com/BerriAI/litellm/pull/22095)
- [4] [LiteLLM — Tạo các endpoint Pass Through](https://docs.litellm.ai/docs/proxy/pass_through)
- [5] [AWS — Cách hoạt động của Instance Metadata Service phiên bản 2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-v2-how-it-works.html)
- [6] [Thông báo bảo mật LiteLLM — endpoint cấu hình proxy không hạn chế](https://github.com/advisories/GHSA-53mr-6c8q-9789)
- [7] [Triển khai chuyển tiếp header pass-through của LiteLLM](https://github.com/BerriAI/litellm/blob/v1.84.0/litellm/passthrough/utils.py)
{{#include ../banners/hacktricks-training.md}}
