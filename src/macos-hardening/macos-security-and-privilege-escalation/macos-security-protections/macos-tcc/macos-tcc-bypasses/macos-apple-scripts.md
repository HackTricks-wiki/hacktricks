# AppleScript trên macOS

{{#include ../../../../../banners/hacktricks-training.md}}

## AppleScript

AppleScript là ngôn ngữ tự động hóa có thể gửi Apple Events đến các ứng dụng hỗ trợ scripting. Với các quyền phù hợp, malware có thể chèn JavaScript vào một tab trình duyệt hỗ trợ scripting hoặc dùng System Events/Accessibility để nhấp vào hộp thoại cấp quyền. Apple Events và Accessibility là các dịch vụ TCC riêng biệt và thường cần người dùng phê duyệt riêng.<sup>[[3]](#references)</sup>

```applescript
tell window 1 of process "SecurityAgent"
     click button "Always Allow" of group 1
end tell
```

Kho lưu trữ `abbeycode/AppleScripts` chứa các ví dụ tự động hóa.<sup>[[7]](#references)</sup>\
Tìm hiểu thêm về malware sử dụng applescripts [**tại đây**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).<sup>[[3]](#references)</sup>

### Tự động hóa / các đặc điểm của TCC

Các phê duyệt Apple Events có tính **định hướng**: lời nhắc áp dụng cho một cặp **tiến trình nguồn -> tiến trình đích**. Sau khi người dùng nhấp **Cho phép**, các yêu cầu tiếp theo từ cùng tiến trình nguồn đến cùng tiến trình đích sẽ được cho phép cho đến khi mục đó được đặt lại. Trong quá trình kiểm thử, chỉ cần cấp quyền `Terminal -> Finder` hoặc `Terminal -> System Events` một lần là có thể dùng lại quyền đó sau này mà không hiện cửa sổ bật lên.<sup>[[1]](#references)</sup>

```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```

Điều này đặc biệt liên quan khi **target** là **Finder**, vì Finder luôn có **Full Disk Access** ngay cả khi không xuất hiện trong giao diện FDA. Vì vậy, bất kỳ host nào đã có Automation với Finder đều có thể được dùng làm proxy AppleScript/JXA để truy cập các tệp được TCC bảo vệ.<sup>[[1]](#references)</sup> Các payload Finder và System Events tổng quát đã được ghi lại trong [trang TCC chính](../README.md) và [trang Apple Events](../macos-apple-events.md).

### Kỹ thuật tấn công hiện đại

`/usr/bin/osascript` chỉ là điểm truy cập dễ thấy nhất. AppleScript và JXA cũng có thể được thực thi từ **Mach-O binaries** thông qua **`NSAppleScript`** / **`OSAScript`**, hữu ích cho cả việc né tránh phát hiện lẫn hoạt động bên trong một host vốn đã có các quyền TCC đáng chú ý.<sup>[[2]](#references)</sup>

```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```

Nếu bạn tạo một helper tùy chỉnh gửi Apple Events trực tiếp, việc gán cho nó một **danh tính ứng dụng thực** sẽ giúp quá trình thử nghiệm và vận hành đáng tin cậy hơn nhiều. Trên thực tế, điều này có nghĩa là nhúng `Info.plist` chứa `CFBundleIdentifier` và `NSAppleEventsUsageDescription`, ký binary và cấp entitlement `com.apple.security.automation.apple-events`. Nếu không, lời nhắc Apple Events thường được gán cho **ứng dụng host cha** (ví dụ: `Terminal`), hoặc quá trình thực thi `NSAppleScript` sẽ thất bại với các lỗi khó hiểu `-1750` / `errOSASystemError`.<sup>[[2]](#references)</sup>

AppleScripts có thể được lưu ở dạng đã biên dịch và thường có thể được giải biên dịch bằng `osadecompile`.

Tuy nhiên, các script này cũng có thể được **xuất dưới dạng "Read only"** (thông qua tùy chọn "Export..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>

```
file mal.scpt
mal.scpt: AppleScript compiled
```

Trong trường hợp đó, `osadecompile` từ chối khôi phục mã nguồn thông thường, nhưng vẫn có thể phân tích bytecode và thuật ngữ Apple Event.

Nghiên cứu về run-only của SentinelOne mô tả cách khôi phục cấu trúc dù gặp hạn chế đó. `applescript-disassembler` và `aevt_decompile` hỗ trợ kiểm tra script đã biên dịch và dữ liệu Apple Event.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Vô tình và có chủ đích vượt qua các biện pháp bảo vệ quyền riêng tư người dùng TCC của macOS](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [Giúp AppleScript hoạt động trong các công cụ CLI của macOS: Những phần không được tài liệu hóa](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [Cách các tác nhân tấn công sử dụng AppleScript để tấn công macOS](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Những cuộc phiêu lưu trong quá trình dịch ngược AppleScript run-only độc hại](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)
- [5] [Jinmo/applescript-disassembler](https://github.com/Jinmo/applescript-disassembler)
- [6] [SentineLabs/aevt_decompile](https://github.com/SentineLabs/aevt_decompile)
- [7] [Các ví dụ AppleScripts của abbeycode](https://github.com/abbeycode/AppleScripts)
{{#include ../../../../../banners/hacktricks-training.md}}
