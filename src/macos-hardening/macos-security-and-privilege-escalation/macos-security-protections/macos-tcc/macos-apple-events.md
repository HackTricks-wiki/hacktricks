# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Thông tin cơ bản

**Apple events** là các thông điệp liên tiến trình có cấu trúc mà ứng dụng dùng để yêu cầu ứng dụng khác thực hiện thao tác hoặc cung cấp dữ liệu. **Apple Event Manager** cung cấp các API để tạo, gửi, nhận và phản hồi những thông điệp này.<sup>[[1]](#references)</sup>

Trên macOS, broker chính là `/System/Library/CoreServices/appleeventsd`, đăng ký Mach service `com.apple.coreservices.appleevents`. Các ứng dụng nhận sự kiện đăng ký một cổng Mach dành cho Apple event với dịch vụ này; bên gửi lấy cổng đích thông qua dịch vụ đó.<sup>[[3]](#references)</sup>

Các quy tắc sandbox và entitlement giới hạn hoạt động giao tiếp này. Một sandbox profile thường chỉ định các thao tác cần thiết bằng `allow appleevent-send` và Mach lookup cho `com.apple.coreservices.appleevents`:<sup>[[3]](#references)</sup>

```scheme
(allow appleevent-send)
(allow mach-lookup (global-name "com.apple.coreservices.appleevents"))
```

Entitlement công khai `com.apple.security.temporary-exception.apple-events` có thể giới hạn ứng dụng trong sandbox chỉ gửi Apple events đến các bundle identifier đích được chỉ định. Khi phân tích các thành phần do Apple ký, hãy kiểm tra cả entitlement riêng tư `com.apple.private.appleevents`; các entitlement riêng tư của Apple thường không được cung cấp cho ứng dụng bên thứ ba.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

> [!TIP]
> Đặt biến môi trường **`AEDebugSends`** để ghi nhật ký thông tin về Apple events do một tiến trình gửi:<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

Để ánh xạ một quyền Automation tới bên gửi và bên nhận, xem [các quyền TCC Apple Events](index.html#identify-apple-events-sender-and-target-grants).



## References

- [1] [Tài liệu dành cho nhà phát triển của Apple - Apple Event Manager](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Tài liệu dành cho nhà phát triển của Apple - Các entitlement ngoại lệ tạm thời của App Sandbox](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Mac OS X và iOS Internals - Các biến môi trường gỡ lỗi Apple-event](https://www.newosxbook.com/MOXiI.pdf)
{{#include ../../../../banners/hacktricks-training.md}}
