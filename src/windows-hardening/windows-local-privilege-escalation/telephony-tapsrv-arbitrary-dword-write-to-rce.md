# Telephony tapsrv: Ghi DWORD tùy ý dẫn đến RCE (Chế độ TAPI Server)

{{#include ../../banners/hacktricks-training.md}}

Khi dịch vụ Windows Telephony (TapiSrv, `tapisrv.dll`) được cấu hình làm **TAPI server**, dịch vụ này hiển thị **giao diện MSRPC `tapsrv` qua named pipe `\pipe\tapsrv`** cho các SMB client đã xác thực. CVE-2026-20931 trong quá trình gửi sự kiện bất đồng bộ cho phép kẻ tấn công biến một handle mailslot được cho là hợp lệ thành **thao tác ghi 4 byte có kiểm soát vào một file có sẵn mà `NETWORK SERVICE` có quyền ghi**. Chain được công bố ghi đè danh sách quản trị viên Telephony, sau đó tiếp cận thao tác tải DLL chỉ dành cho quản trị viên và thực thi mã với quyền `NETWORK SERVICE`.<sup>[[1]](#references)[[2]](#references)</sup>

## Bề mặt tấn công

- **Chỉ có thể truy cập từ xa khi được bật**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\Server\DisableSharing` phải cho phép chia sẻ (hoặc được cấu hình qua `TapiMgmt.msc` / `tcmsetup /c <server>`). Theo mặc định, `tapsrv` chỉ hoạt động cục bộ.
- Giao diện: MS-TRP (`tapsrv`) qua **SMB named pipe**, vì vậy kẻ tấn công cần thông tin xác thực SMB hợp lệ.
- Tài khoản dịch vụ: `NETWORK SERVICE` (khởi động thủ công, theo yêu cầu).<sup>[[1]](#references)</sup>

## Primitive: Nhầm lẫn đường dẫn Mailslot → Ghi DWORD tùy ý
- `ClientAttach(pszDomainUser, pszMachine, ...)` khởi tạo quá trình gửi sự kiện bất đồng bộ. Ở pull mode, dịch vụ thực hiện:
  ```c
  CreateFileW(pszDomainUser, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  ```
  mà không xác thực `pszDomainUser` có phải là đường dẫn mailslot (`\\*\MAILSLOT\...`) hay không. Mọi **đường dẫn hệ thống tệp hiện có** mà `NETWORK SERVICE` có quyền ghi đều được chấp nhận.
- Mỗi lần ghi async event sẽ ghi một `DWORD` duy nhất = `InitContext` (do attacker kiểm soát trong yêu cầu `Initialize` tiếp theo) vào handle đã mở, tạo thành **write-what/write-where (4 bytes)**.<sup>[[1]](#references)</sup>

## Buộc ghi dữ liệu theo cách xác định
1. **Mở file đích**: gọi `ClientAttach` với `pszDomainUser = <existing writable path>` (ví dụ: `C:\Windows\TAPI\tsec.ini`).
2. Với mỗi `DWORD` cần ghi, thực hiện chuỗi RPC sau với `ClientRequest`:
   - `Initialize` (`Req_Func 47`): đặt `InitContext = <4-byte value>` và `pszModuleName = DIALER.EXE` (hoặc một mục khác ở đầu danh sách ưu tiên theo từng người dùng).
   - `LRegisterRequestRecipient` (`Req_Func 61`): đặt `dwRequestMode = LINEREQUESTMODE_MAKECALL`, `bEnable = 1` (đăng ký line app và tính toán lại recipient có ưu tiên cao nhất).
   - `TRequestMakeCall` (`Req_Func 121`): buộc gọi `NotifyHighestPriorityRequestRecipient`, tạo async event.
   - `GetAsyncEvents` (`Req_Func 0`): lấy event khỏi hàng đợi/hoàn tất thao tác ghi.
   - Gọi lại `LRegisterRequestRecipient` với `bEnable = 0` (hủy đăng ký).
   - `Shutdown` (`Req_Func 86`) để dọn dẹp line app.
- Kiểm soát mức ưu tiên: recipient “có ưu tiên cao nhất” được chọn bằng cách so sánh `pszModuleName` với `HKCU\Software\Microsoft\Windows\CurrentVersion\Telephony\HandoffPriorities\RequestMakeCall` (được đọc khi đang impersonate client). Nếu cần, thêm tên module của bạn bằng `LSetAppPriority` (`Req_Func 69`).
- File **phải tồn tại từ trước** vì thao tác này dùng `OPEN_EXISTING`. Một số file có thể ghi được bởi `NETWORK SERVICE`: `C:\Windows\System32\catroot2\dberr.txt`, `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\MpCmdRun.log`, `...\MpSigStub.log`.<sup>[[1]](#references)</sup>

## Từ ghi DWORD đến RCE bên trong TapiSrv
1. **Cấp cho tài khoản của bạn quyền “admin” của Telephony**: nhắm tới `C:\Windows\TAPI\tsec.ini` và nối thêm `[TapiAdministrators]\r\n<DOMAIN\\user>=1` bằng các thao tác ghi 4-byte ở trên. Bắt đầu một session **mới** (`ClientAttach`) để service đọc lại INI và đặt `ptClient->dwFlags |= 9` cho tài khoản của bạn.
2. **Nạp DLL chỉ dành cho admin**: gửi `GetUIDllName` với `dwObjectType = TUISPIDLL_OBJECT_PROVIDERID` và cung cấp đường dẫn qua `dwProviderFilenameOffset`. Với admin, service thực hiện `LoadLibrary(path)`, sau đó gọi export `TSPI_providerUIIdentify`:
   - Hoạt động với đường dẫn UNC trỏ tới SMB share Windows thật; một số SMB server của attacker gặp lỗi `ERROR_SMB_GUEST_LOGON_BLOCKED`.
   - Cách khác: từ từ ghi một DLL cục bộ bằng primitive ghi 4-byte tương tự, rồi nạp DLL đó.
3. **Payload**: export chạy dưới quyền `NETWORK SERVICE`. Một DLL tối giản có thể chạy `cmd.exe /c whoami /all > C:\Windows\Temp\poc.txt` và trả về giá trị khác 0 (ví dụ: `0x1337`) để service unload DLL, xác nhận mã đã được thực thi.<sup>[[1]](#references)</sup>

## Ghi chú về hardening / phát hiện
- Cài đặt bản cập nhật bảo mật của Microsoft cho CVE-2026-20931. Đồng thời, tắt chế độ TAPI server nếu không cần và chặn truy cập từ xa tới `\pipe\tapsrv`.
- Xác thực namespace mailslot (`\\*\MAILSLOT\`) trước khi mở các đường dẫn do client cung cấp.
- Siết chặt ACL của `C:\Windows\TAPI\tsec.ini` và giám sát các thay đổi; cảnh báo khi có lệnh gọi `GetUIDllName` nạp các đường dẫn không mặc định.<sup>[[1]](#references)</sup>

## References

- [1] [Ai đang gọi? Khai thác RCE trong Windows Telephony Service (CVE-2026-20931)](https://swarm.ptsecurity.com/whos-on-the-line-exploiting-rce-in-windows-telephony-service/)
- [2] [Microsoft Security Response Center — CVE-2026-20931](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-20931)
{{#include ../../banners/hacktricks-training.md}}
