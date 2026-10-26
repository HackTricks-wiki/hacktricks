# Ranh giới tin cậy của LLM Gateway

{{#include ../banners/hacktricks-training.md}}

LLM gateway xử lý việc định tuyến model và thường lưu thông tin xác thực của nhà cung cấp, vì vậy các caller API thông thường không được thừa hưởng quyền cấu hình hoặc quyền ở cấp nhà cung cấp. Đánh giá gateway LiteLLM phiên bản 1.77.7 cho thấy hai ranh giới riêng biệt: phân quyền phiên UI đối với cấu hình quản trị và cấu hình định tuyến do caller cung cấp cho quá trình inference. Các vấn đề được báo cáo đã được khắc phục trong phiên bản 1.83.9.<sup>[[1]](#references)</sup>

## Phân loại route UI không phải là phân quyền

Trong phiên bản LiteLLM được đánh giá, các khóa đăng nhập UI thuộc team `litellm-dashboard`. Quy trình phân quyền xác định một khóa là UI token dựa trên mã định danh team đó, bất kể vai trò của người dùng. Sau đó, bước kiểm tra route UI chấp nhận mọi route bắt đầu bằng tiền tố nằm trong allowlist. Do đó, mục `/config` cũng khớp với handler quản trị `/config/update`. Handler đó chỉ yêu cầu xác thực chung, không tự kiểm tra `PROXY_ADMIN`, khiến một phiên UI có quyền thấp hơn truy cập được quyền ghi cấu hình.<sup>[[1]](#references)</sup>

Điều này khác với trường hợp proxy/backend không thống nhất trong việc chuẩn hóa đường dẫn: mã phân quyền và handler bất đồng về quyền hạn của *cùng một* route.<sup>[[1]](#references)</sup> Khi đánh giá gateway, hãy đối chiếu cách phân loại token, việc khớp chính xác route và method, cùng bước kiểm tra vai trò riêng của handler.<sup>[[1]](#references)</sup> Xem [phân quyền web API](../pentesting-web/web-api-pentesting.md), [bypass 401/403](../pentesting-web/403-and-401-bypasses.md) và [ngoại lệ tiền tố proxy](../pentesting-web/proxy-waf-protections-bypass.md#prefix-exemptions-become-routing-keys) để biết các ranh giới liên quan nhưng khác biệt.

## Ghi cấu hình tác động đến nhiều nơi hơn kho cấu hình

Cùng endpoint cập nhật cấu hình của LiteLLM chấp nhận giá trị biến môi trường và áp dụng chúng vào tiến trình đang chạy. Một thành phần sử dụng `UI_LOGO_PATH` như đường dẫn cục bộ cho `FileResponse` mà không xác thực rằng đường dẫn đó trỏ đến logo; một thành phần khác đọc `UI_USERNAME` và `UI_PASSWORD` khi đăng nhập không dùng SSO, rồi gán `PROXY_ADMIN` nếu thông tin khớp. Vì vậy, quyền ghi cấu hình có thể dẫn đến cả việc tiết lộ tệp cục bộ lẫn thay đổi danh tính quản trị, tùy thuộc vào thành phần xử lý phía sau. Media type của phản hồi không chứng minh tệp được phục vụ là hình ảnh.<sup>[[1]](#references)</sup>

Cấu hình endpoint pass-through là một sink khác ở phía sau. Quá trình khởi tạo chấp nhận các đích adapter S3/GCS từ xa, tải các module Python xuống và import chúng bằng `exec_module` của `importlib`. Việc import thực thi mã cấp cao nhất trước khi sử dụng một instance adapter; chỉ hạn chế việc gọi adapter sẽ không loại bỏ ranh giới thực thi đó. Hãy xem đây là việc nạp mã do cấu hình kiểm soát, không phải giải tuần tự hóa tệp model.<sup>[[1]](#references)</sup> Với primitive đọc tệp riêng biệt, xem [chèn tệp và path traversal](../pentesting-web/file-inclusion/).

## Định tuyến model theo từng request có thể làm lộ thông tin xác thực của gateway

Tính năng thông tin xác thực phía client của LiteLLM chấp nhận một object `user_config` trong request LLM. Route được đánh giá tạo một `litellm.Router` tạm thời từ object này, bao gồm danh sách model và `api_base` của nhà cung cấp. Đích nhà cung cấp do caller kiểm soát có thể nhận request completion outbound của gateway cùng các header xác thực nhà cung cấp đã cấu hình. Các hạn chế đối với trường `api_base` hoặc `api_key` cấp cao nhất không bao phủ đường dẫn cấu hình lồng riêng biệt này. Đây là ranh giới SSRF mang theo thông tin xác thực, không phải vấn đề prompt injection.<sup>[[1]](#references)</sup>

Khi đánh giá gateway được ủy quyền, hãy đối chiếu mọi đường dẫn có thể tạo router hoặc provider client, bao gồm cả cấu hình theo từng request, với chính sách đích và thông tin xác thực được dùng cho route thông thường đã cấu hình.<sup>[[1]](#references)</sup> [Hướng dẫn SSRF](../pentesting-web/ssrf-server-side-request-forgery/) trình bày việc kiểm soát đích đến phía server nói chung; lỗi đặc thù của gateway là cho phép một object request ít đáng tin cậy hơn chọn đích đến trong khi vẫn sử dụng lại thông tin xác thực outbound có đặc quyền.<sup>[[1]](#references)</sup>

## References

- [1] [Check Point Research — Khi LLM Gateway gặp sự cố: Các phát hiện từ LiteLLM](https://research.checkpoint.com/2026/when-llm-gateways-go-wrong-findings-from-litellm/)
{{#include ../banners/hacktricks-training.md}}
