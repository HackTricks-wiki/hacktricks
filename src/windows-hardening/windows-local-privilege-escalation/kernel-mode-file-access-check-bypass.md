# Bypass kiểm tra truy cập tệp ở kernel mode

{{#include ../../banners/hacktricks-training.md}}

## Mẫu driver dễ bị tấn công

Driver không duy trì ranh giới bảo mật của caller chỉ bằng cách mạo danh caller đó. Các thao tác mở object ở kernel mode thường bỏ qua kiểm tra quyền truy cập. `OBJ_KERNEL_HANDLE` chỉ khiến handle được tạo có thể truy cập từ kernel mode. Khi driver mở hoặc thao tác với một object thay mặt user mode, driver cũng phải dùng `OBJ_FORCE_ACCESS_CHECK` để Object Manager đánh giá quyền truy cập được yêu cầu dựa trên token hiệu lực.<sup>[[3]](#references)[[4]](#references)</sup>

Kiểm tra các IOCTL xử lý tệp và create callback để tìm chuỗi hành vi sau:<sup>[[3]](#references)[[4]](#references)</sup>

1. User mode cung cấp đường dẫn, source handle, quyền truy cập mong muốn hoặc loại thao tác.
2. Driver mạo danh caller nhưng gọi `IoCreateFileEx`, `ZwCreateFile` hoặc routine tương tự mà không có `OBJ_FORCE_ACCESS_CHECK`.
3. Handle tệp hoặc thư mục chỉ dành cho kernel được lưu trong trạng thái theo từng handle.
4. Một thao tác về sau quyết định có mạo danh hay không dựa trên trạng thái chịu ảnh hưởng của attacker, chẳng hạn access mask được yêu cầu trong lần mở đầu tiên.
5. Nhánh có đặc quyền thực hiện thao tác đổi tên hoặc tạo liên kết bằng một information class `BypassAccessCheck`.

Đây là **primitive tệp confused-deputy**, không nhất thiết là lỗi memory corruption. Một kiểu đảo ngược trạng thái đặc biệt nguy hiểm là “yêu cầu quyền ghi thì mạo danh; không yêu cầu quyền ghi thì giữ đặc quyền”. Trong thiết kế đó, cố ý chỉ yêu cầu quyền đọc có thể mở ra con đường mạnh hơn.<sup>[[3]](#references)</sup>

## Ví dụ vSMB: root có đặc quyền cộng với đổi tên có đặc quyền

`storvsp.sys` triển khai Virtual Server Message Block (vSMB). Khi bật tính năng **Virtual Machine Platform**, user mode có thể truy cập `\Device\STORVSP` thông qua `\\.\STORVSP`. Đường dẫn hệ thống tệp vSMB có dạng `\\.\STORVSP\VSMB\??\C:\path`. CVE-2025-59517 và CVE-2025-64673 cho thấy hai quyết định kiểm soát truy cập không nhất quán có thể biến giao diện này thành lỗ hổng leo thang đặc quyền cục bộ.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Ánh xạ giữa function và CVE trong nguồn được xác định bằng reverse engineering binary đã vá, chứ không dựa trên mã nguồn của Microsoft. Các nhà nghiên cứu cảnh báo rằng hai mã định danh có thể tương ứng với các function ngược lại.<sup>[[3]](#references)</sup>

### 1. Tạo share chỉ đọc có root trỏ đến thư mục được bảo vệ

Đường xử lý create dễ bị tấn công ghi lại các quyền được yêu cầu trong những flag lưu trữ lâu dài như `HasReadAccess`, `HasWriteAccess` và `HasAppendAccess`. Sau đó, nó mở đường dẫn backing bằng `OBJ_KERNEL_HANDLE` nhưng không có `OBJ_FORCE_ACCESS_CHECK`. Vì vậy, việc mạo danh không khiến thao tác mở tệp tuân thủ quyền NTFS của caller.<sup>[[3]](#references)[[4]](#references)</sup>

Chỉ yêu cầu `FILE_READ_DATA`. Thao tác này giữ `HasWriteAccess` ở trạng thái clear, đồng thời vẫn tạo được share có root nội bộ là một thư mục được bảo vệ:<sup>[[3]](#references)</sup>

```c
HANDLE root = CreateFileW(
    L"\\\\.\\STORVSP\\VSMB\\??\\C:\\Windows\\System32\\",
    FILE_READ_DATA,
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    NULL, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS | FILE_ATTRIBUTE_DIRECTORY,
    NULL
);
```

Artifact quan trọng không phải là handle đến thư mục System32 ở user mode. Đó là handle thiết bị vSMB gắn với trạng thái của driver, trong đó có một root handle đặc quyền ở kernel.<sup>[[3]](#references)</sup>

### 2. Biến sự không khớp trạng thái thành thao tác thay thế file được bảo vệ

IOCTL `0x240330` chấp nhận một file handle nguồn, một information class và một information buffer có độ dài thay đổi:<sup>[[3]](#references)</sup>

```c
#define IOCTL_VSMB_SET_INFORMATION_FILE_REQUEST 0x240330

typedef struct _VSMB_SET_INFO {
    DWORD Version;
    DWORD Reserved;
    UINT64 SourceHandle;
    DWORD InformationClass;
    DWORD BufferLength;
    BYTE Buffer[1];
} VSMB_SET_INFO;
```

Handler dễ bị tấn công chấp nhận `FileRenameInformation`, `FileLinkInformation` và `FileRenameInformationEx`. Với đường dẫn đổi tên thông thường, handler tách đường dẫn thư mục cha khỏi thành phần cuối, rồi mở thư mục cha tương đối với root handle đã lưu. Lệnh mở này cũng dùng `OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE` mà không có `OBJ_FORCE_ACCESS_CHECK`. Một `RootDirectory` khác 0 do attacker cung cấp trong cấu trúc rename sẽ bị từ chối, nên driver tự cung cấp directory handle có đặc quyền.<sup>[[3]](#references)</sup>

Nhánh có thể khai thác được chọn bằng cách **không yêu cầu quyền ghi trong stage 1**:<sup>[[3]](#references)</sup>

- `HasWriteAccess == 1`: mạo danh security context của root đã lưu.
- `HasWriteAccess == 0`: bỏ qua bước mạo danh và chuyển `FileRenameInformation` hoặc `FileRenameInformationEx` thành biến thể `BypassAccessCheck` tương ứng.

Handler sao chép source handle do attacker cung cấp vào `PsInitialSystemProcess`, tham chiếu nó dưới dạng file object, cài target-directory handle có đặc quyền vào cấu trúc rename rồi gọi `ZwSetInformationFile`. Với `ReplaceIfExists = TRUE`, một file do caller kiểm soát có thể thay thế file hiện có bên dưới protected root.<sup>[[3]](#references)</sup>

Khi xem xét handler tương tự, hãy theo dõi **cả nguồn gốc handle lẫn security context** qua mọi nhánh. Kiểm tra đầu vào, kiểm tra integer overflow, `IO_STOP_ON_SYMLINK` và giới hạn các information class được chấp nhận không thể bù đắp cho việc kết hợp root handle có đặc quyền với thao tác bỏ qua kiểm tra quyền truy cập.<sup>[[3]](#references)</sup>

## Từ ghi file được bảo vệ đến thực thi với quyền SYSTEM

Một primitive thay thế file được bảo vệ sẽ dẫn đến thực thi mã khi một process có đặc quyền sau đó tải module đã bị thay thế. Trong chuỗi tấn công được minh họa, đích là `C:\Windows\System32\wuapi.dll`. Kích hoạt local-server COM class `{72566E27-1ABB-4EB3-B4F0-EB431CB1CB32}` cho interface `{b4c1d279-966e-44e9-a9c5-ccaf4a77023d}` rồi gọi `IWaaSRemediation::LaunchDetectionOnly()` khiến một process SYSTEM tải DLL đó.<sup>[[3]](#references)</sup>

Lệnh gọi COM này là một **trigger kích hoạt**, không phải [chiếm quyền registry COM](com-hijacking.md). Primitive file cung cấp module được cài vào, còn privileged loader đảm nhiệm việc thực thi. Với các chuỗi tấn công ghi file được bảo vệ khác, hãy xác định chính xác image, đường dẫn DLL, chính sách chữ ký, bitness, các hàm được export và trigger đáng tin cậy trước khi chọn mục tiêu. Xem [kết hợp arbitrary file write với DLL hijacking](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack) để biết quy trình phân tích loader tổng quát.<sup>[[3]](#references)</sup>

### Chuyển token của Session 0 sang desktop tương tác

Payload được service tải thường chạy trong Session 0. Để tạo một process tương tác, payload có thể lấy active console session bằng `WTSGetActiveConsoleSessionId`, bật các token privilege cần thiết, sao chép token SYSTEM hiện tại thành primary token và đặt `TokenSessionId` của token này thành active session. Sau đó, `CreateProcessAsUserW` sử dụng token đó với `STARTUPINFO.lpDesktop = L"winsta0\\default"`.<sup>[[3]](#references)[[5]](#references)</sup>

```c
DWORD sid = WTSGetActiveConsoleSessionId();
DuplicateTokenEx(currentToken, MAXIMUM_ALLOWED, NULL,
                 SecurityImpersonation, TokenPrimary, &primary);
SetTokenInformation(primary, TokenSessionId, &sid, sizeof(sid));
si.lpDesktop = L"winsta0\\default";
CreateProcessAsUserW(primary, L"C:\\Windows\\System32\\cmd.exe",
                     NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE,
                     NULL, NULL, &si, &pi);
```

`SeTcbPrivilege` là quyền cần thiết để đặt session ID của token trong tình huống này. Interactive window station và desktop cũng phải cấp quyền truy cập cho token. Xem [token duplication from Session 0](sedebug-+-seimpersonate-copy-token.md) để biết quy trình sao chép token rộng hơn.<sup>[[3]](#references)[[5]](#references)</sup>

## Hướng dẫn vá lỗi và rà soát

Các bản cập nhật tháng 12 năm 2025 của Microsoft đã khắc phục chuỗi khai thác được trình diễn. Quá trình reverse engineering cho thấy đường dẫn tạo vSMB đã vá từ chối các caller không đáng tin cậy yêu cầu share root mà không có `FILE_WRITE_DATA`. Các thao tác liên quan cũng được bổ sung kiểm tra quyền bắt buộc. Điều này chặn việc đảo ngược trạng thái trước khi caller không có đặc quyền có thể lấy được root có đặc quyền.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Đối với mã driver, hãy áp dụng các quy tắc sau:<sup>[[3]](#references)[[4]](#references)</sup>

- Thêm `OBJ_FORCE_ACCESS_CHECK` bất cứ khi nào mở một object thay mặt cho yêu cầu từ user-mode. Không xem `OBJ_KERNEL_HANDLE` là cơ chế kiểm soát quyền hạn.<sup>[[4]](#references)</sup>
- Thu thập và xác thực requestor mode cùng subject context hiệu lực. Không để quyền được yêu cầu quyết định nhánh thực thi có đặc quyền cao hơn.
- Xác thực user handle bằng đúng loại object, access mask và `UserMode`. Duplicate một handle vào system process không xác thực thẩm quyền của thao tác được yêu cầu.
- Giữ việc phân giải target tương đối với một handle đáng tin cậy, nhưng đảm bảo chính handle đáng tin cậy đó đã được mở sau khi áp dụng kiểm tra quyền bắt buộc cho requestor.
- Tránh các lớp `File*BypassAccessCheck` cho thao tác do user điều khiển. Nếu mã nội bộ thực sự cần dùng chúng, hãy giới hạn đường dẫn đó bằng một quyết định cấp quyền độc lập với các cờ truy cập do user kiểm soát.
- Vá các hệ thống bị ảnh hưởng. Bề mặt dễ bị tấn công có liên quan khi Virtual Machine Platform tải `storvsp.sys`.<sup>[[3]](#references)</sup>

## References

- [1] [Microsoft Security Response Center - CVE-2025-59517](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59517)
- [2] [Microsoft Security Response Center - CVE-2025-64673](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-64673)
- [3] [Exodus Intelligence - Từ Virtual Share đến Physical Shell: Khai thác cơ chế kiểm soát truy cập thiếu nhất quán của Windows để nâng quyền cục bộ](https://blog.exodusintel.com/2026/07/27/from-virtual-share-to-physical-shell-leveraging-windows-inconsistent-access-control-for-lpe/)
- [4] [Microsoft Learn - Object Handles](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/object-handles)
- [5] [Microsoft Learn - Hàm CreateProcessAsUserW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
{{#include ../../banners/hacktricks-training.md}}
