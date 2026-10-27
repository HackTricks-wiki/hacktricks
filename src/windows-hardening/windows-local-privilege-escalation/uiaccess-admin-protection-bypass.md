# Bypass Admin Protection qua UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Tổng quan
- Windows AppInfo cung cấp đường dẫn nội bộ `RAiLaunchAdminProcess` dùng để khởi chạy ứng dụng UIAccess phục vụ trợ năng. UIAccess cho phép một số tương tác nhất định vượt qua ranh giới User Interface Privilege Isolation (UIPI); đây không phải là bypass mọi ranh giới bảo mật tiến trình.<sup>[[1]](#references)[[3]](#references)</sup>
- Bật UIAccess trực tiếp cần `NtSetInformationToken(TokenUIAccess)` với **SeTcbPrivilege**, nên các caller có quyền thấp phải dựa vào service. Service thực hiện ba bước kiểm tra binary đích trước khi thiết lập UIAccess:
  - Manifest nhúng chứa `uiAccess="true"`.
  - Được ký bằng bất kỳ certificate nào được tin cậy trong Local Machine root store (không yêu cầu EKU/Microsoft).
  - Nằm trong đường dẫn chỉ administrator mới ghi được trên ổ hệ thống (ví dụ: `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, ngoại trừ một số subpath cho phép ghi cụ thể).
- `RAiLaunchAdminProcess` không hiển thị consent prompt khi khởi chạy UIAccess (nếu không, các công cụ trợ năng sẽ không thể thao tác với prompt).<sup>[[1]](#references)</sup>

## Điều chỉnh token và integrity level
- Nếu các bước kiểm tra thành công, AppInfo **sao chép token của caller**, bật UIAccess và tăng Integrity Level (IL):
  - Người dùng admin bị giới hạn (người dùng thuộc Administrators nhưng đang chạy với token đã lọc) ➜ **High IL**.
  - Người dùng không phải admin ➜ IL tăng **+16 mức**, tối đa là **High** (không bao giờ được gán System IL).
  - Nếu token của caller đã có UIAccess, IL không đổi.
- Mẹo “Ratchet”: một tiến trình UIAccess có thể tự tắt UIAccess, khởi chạy lại qua `RAiLaunchAdminProcess` và tăng thêm 16 mức IL. Từ Medium➜High cần 255 lần khởi chạy lại (gây nhiều dấu vết, nhưng hiệu quả).<sup>[[1]](#references)</sup>

## Vì sao UIAccess cho phép thoát khỏi Admin Protection
- UIAccess cho phép tiến trình có IL thấp gửi window message đến các cửa sổ có IL cao hơn (bypass bộ lọc UIPI). Ở **cùng IL**, các primitive UI cổ điển như `SetWindowsHookEx` **có thể inject code/tải DLL** vào bất kỳ tiến trình nào sở hữu một cửa sổ (bao gồm cả **message-only window** được COM sử dụng).
- Admin Protection khởi chạy tiến trình UIAccess dưới **danh tính của người dùng bị giới hạn** nhưng ở **High IL**, mà không thông báo. Khi code tùy ý chạy bên trong tiến trình UIAccess High-IL đó, attacker có thể inject vào các tiến trình High-IL khác trên desktop (kể cả tiến trình thuộc người dùng khác), phá vỡ cơ chế phân tách dự kiến.<sup>[[1]](#references)</sup>

## Primitive lấy process handle từ HWND (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Trên Windows 10 1803 trở lên, API được chuyển vào Win32k (`NtUserGetWindowProcessHandle`) và có thể mở process handle bằng `DesiredAccess` do caller cung cấp. Đường dẫn kernel sử dụng `ObOpenObjectByPointer(..., KernelMode, ...)`, qua đó bypass các bước kiểm tra quyền truy cập thông thường ở user mode.<sup>[[2]](#references)</sup>
- Điều kiện tiên quyết trên thực tế: cửa sổ đích phải ở cùng desktop và các bước kiểm tra UIPI phải thành công. Trước đây, caller có UIAccess có thể bypass lỗi UIPI và vẫn lấy được handle ở kernel mode (đã được khắc phục trong CVE-2023-41772).
- Tác động trước đây: handle cửa sổ trở thành một **capability** để truy cập tiến trình, chẳng hạn `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE` hoặc `PROCESS_VM_OPERATION`, mà caller thường không thể lấy được. Trước khi có các bản sửa lỗi đã công bố, cách này có thể vượt qua ranh giới sandbox và protected-process khi tiến trình đích có cửa sổ, kể cả message-only window.<sup>[[2]](#references)</sup>
- Quy trình khai thác thực tế: liệt kê hoặc tìm HWND (ví dụ: `EnumWindows`/`FindWindowEx`), tra PID sở hữu cửa sổ (`GetWindowThreadProcessId`), gọi `GetProcessHandleFromHwnd`, rồi dùng handle trả về để đọc/ghi bộ nhớ hoặc thực hiện các primitive chiếm quyền điều khiển code.
- Hành vi sau khi sửa lỗi: UIAccess không còn cho phép mở handle ở kernel mode khi UIPI thất bại và các quyền truy cập được cho phép bị giới hạn ở nhóm hook cũ; Windows 11 24H2 bổ sung kiểm tra process-protection và các đường dẫn an toàn hơn được bật qua feature flag. Tắt UIPI trên toàn hệ thống (`EnforceUIPI=0`) làm suy yếu các biện pháp bảo vệ này.<sup>[[2]](#references)</sup>

## Điểm yếu trong xác thực secure-directory (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo phân giải đường dẫn được cung cấp qua `GetFinalPathNameByHandle`, sau đó áp dụng **các bước kiểm tra allow/deny bằng chuỗi** đối với các root/exclusion được hardcode. Có nhiều kiểu bypass bắt nguồn từ cách xác thực đơn giản này:
- **Named stream của thư mục**: Có thể bypass các thư mục bị loại trừ nhưng cho phép ghi (ví dụ: `C:\Windows\tracing`) bằng named stream trên chính thư mục đó, chẳng hạn `C:\Windows\tracing:file.exe`. Các bước kiểm tra chuỗi thấy `C:\Windows\` nhưng bỏ sót subpath bị loại trừ.
- **File/thư mục cho phép ghi bên trong root được cho phép**: `CreateProcessAsUser` **không yêu cầu phần mở rộng `.exe`**. Ghi đè bất kỳ file nào cho phép ghi bên dưới root được cho phép bằng payload thực thi sẽ có tác dụng; hoặc sao chép một EXE có chữ ký và `uiAccess="true"` vào bất kỳ subdirectory nào cho phép ghi (ví dụ: các file còn sót lại sau cập nhật như `Tasks_Migrated` nếu có) sẽ giúp file vượt qua bước kiểm tra secure-path.
- **MSIX vào `C:\Program Files\WindowsApps` (đã khắc phục)**: Người không phải admin có thể cài các gói MSIX đã ký được đặt trong `WindowsApps`, vốn không bị loại trừ. Đóng gói binary UIAccess bên trong MSIX rồi khởi chạy qua `RAiLaunchAdminProcess` sẽ tạo ra **tiến trình UIAccess High-IL không cần prompt**. Microsoft đã giảm thiểu rủi ro bằng cách loại trừ đường dẫn này; riêng restricted MSIX capability `uiAccess` vốn đã yêu cầu cài đặt bởi admin.<sup>[[1]](#references)</sup>

## Quy trình tấn công (High IL không cần prompt)
1. Lấy/tạo một **binary UIAccess đã ký** (manifest có `uiAccess="true"`). Để đánh giá thực tế, hãy kiểm thử bằng trust material và các đường dẫn được cho phép rõ ràng trong lab; không thêm certificate của attacker vào Local Machine root store của máy production.
2. Đặt binary vào nơi được AppInfo allowlist chấp nhận (hoặc khai thác trường hợp đặc biệt trong xác thực đường dẫn/file có sẵn cho phép ghi như trên).
3. Gọi `RAiLaunchAdminProcess` để khởi chạy nó một cách **âm thầm**, với UIAccess và IL được nâng cao.
4. Từ foothold High-IL này, nhắm đến một tiến trình High-IL khác trên desktop bằng **window hook/DLL injection** hoặc các primitive khác hoạt động ở cùng IL để chiếm hoàn toàn ngữ cảnh admin.<sup>[[1]](#references)</sup>

## Liệt kê các đường dẫn có thể ghi
Chạy PowerShell helper để tìm các đối tượng cho phép ghi/ghi đè bên trong các root vốn được xem là an toàn, theo góc nhìn của token đã chọn:<sup>[[1]](#references)</sup>

```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
  -DirectoryAccess AddFile -Recurse -ProcessId <PID>
```

- Chạy với quyền Administrator để có khả năng quan sát rộng hơn; đặt `-ProcessId` thành một tiến trình có quyền thấp để mô phỏng quyền truy cập của token đó.
- Lọc thủ công để loại trừ các thư mục con đã biết là không được phép trước khi dùng các ứng viên với `RAiLaunchAdminProcess`.

## Liên quan

Secure Desktop accessibility registry propagation LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## References

- [1] [Vượt qua Administrator Protection bằng cách lạm dụng UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [Phân tích chuyên sâu GetProcessHandleFromHwnd (GPHFH)](https://projectzero.google/2026/02/gphfh-deep-dive.html)
- [3] [Microsoft Learn — Ứng dụng UIAccess](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works#uiaccess-applications)
{{#include ../../banners/hacktricks-training.md}}
