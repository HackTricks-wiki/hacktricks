# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Giống như golden ticket**, diamond ticket là một TGT có thể dùng để **truy cập bất kỳ dịch vụ nào dưới danh nghĩa bất kỳ người dùng nào**. Golden ticket được giả mạo hoàn toàn offline, mã hóa bằng hash krbtgt của domain rồi đưa vào một phiên đăng nhập để sử dụng. Vì domain controller không theo dõi các TGT mà nó (hoặc chúng) đã cấp hợp lệ, chúng sẽ dễ dàng chấp nhận các TGT được mã hóa bằng hash krbtgt của chính mình.<sup>[[1]](#references)</sup>

Có hai kỹ thuật phổ biến để phát hiện việc sử dụng golden ticket:

- Tìm các TGS-REQ không có AS-REQ tương ứng.
- Tìm các TGT có giá trị bất thường, chẳng hạn thời hạn 10 năm mặc định của Mimikatz.

**Diamond ticket** được tạo bằng cách **sửa đổi các trường của một TGT hợp lệ do DC cấp**. Cách thực hiện là **yêu cầu** một **TGT**, **giải mã** nó bằng hash krbtgt của domain, **sửa đổi** các trường mong muốn của ticket rồi **mã hóa lại**. Cách này **khắc phục hai nhược điểm nêu trên** của golden ticket vì:<sup>[[1]](#references)</sup>

- TGS-REQ sẽ có AS-REQ đi trước.
- TGT được DC cấp nên sẽ có đầy đủ thông tin chính xác theo chính sách Kerberos của domain. Dù có thể giả mạo chính xác các thông tin này trong golden ticket, việc đó phức tạp hơn và dễ mắc lỗi.

### Yêu cầu & quy trình

- **Thông tin mã hóa**: khóa krbtgt AES256 (ưu tiên) hoặc hash NTLM để giải mã và ký lại TGT.
- **Blob TGT hợp lệ**: lấy bằng `/tgtdeleg`, `asktgt`, `s4u` hoặc bằng cách xuất ticket từ bộ nhớ.
- **Dữ liệu ngữ cảnh**: RID của người dùng mục tiêu, RID/SID của các nhóm và (tùy chọn) các thuộc tính PAC lấy từ LDAP.
- **Khóa dịch vụ** (chỉ cần nếu bạn định tạo lại service ticket): khóa AES của service SPN cần mạo danh.

1. Lấy TGT cho một người dùng do bạn kiểm soát thông qua AS-REQ (Rubeus `/tgtdeleg` rất tiện vì nó buộc client thực hiện quy trình Kerberos GSS-API mà không cần thông tin xác thực).
2. Giải mã TGT trả về bằng khóa krbtgt, rồi chỉnh sửa các thuộc tính PAC (người dùng, nhóm, thông tin đăng nhập, SID, device claims, v.v.).
3. Mã hóa/ký lại ticket bằng cùng khóa krbtgt và đưa nó vào phiên đăng nhập hiện tại (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Tùy chọn: lặp lại quy trình với service ticket bằng cách cung cấp blob TGT hợp lệ cùng khóa của dịch vụ mục tiêu để tránh bị phát hiện trên đường truyền.

### Kỹ thuật Rubeus cập nhật (2024+)

Các nghiên cứu gần đây của Huntress đã hiện đại hóa action `diamond` trong Rubeus bằng cách tích hợp các cải tiến `/ldap` và `/opsec` vốn trước đây chỉ có trong golden/silver ticket. `/ldap` hiện truy vấn LDAP để lấy ngữ cảnh PAC thực **và** mount SYSVOL để trích xuất thuộc tính tài khoản/nhóm cùng chính sách Kerberos/mật khẩu (ví dụ: `GptTmpl.inf`), trong khi `/opsec` khiến luồng AS-REQ/AS-REP giống Windows hơn bằng cách thực hiện trao đổi preauth hai bước và chỉ dùng AES + KDCOptions thực tế. Điều này giúp giảm đáng kể các dấu hiệu dễ nhận biết như thiếu trường PAC hoặc thời hạn ticket không khớp với chính sách.<sup>[[3]](#references)</sup>

```powershell
# Query RID/context data (PowerView/SharpView/AD modules all work)
Get-DomainUser -Identity <username> -Properties objectsid | Select-Object samaccountname,objectsid

# Craft a high-fidelity diamond TGT and inject it
./Rubeus.exe diamond /tgtdeleg \
  /ticketuser:svc_sql /ticketuserid:1109 \
  /groups:512,519 \
  /krbkey:<KRBTGT_AES256_KEY> \
  /ldap /ldapuser:MARVEL\loki /ldappassword:Mischief$ \
  /opsec /nowrap
```

- `/ldap` (có thể dùng thêm `/ldapuser` và `/ldappassword`) truy vấn AD và SYSVOL để sao chép dữ liệu chính sách PAC của người dùng mục tiêu.
- `/opsec` buộc thử lại AS-REQ theo cách giống Windows, xóa các flag dễ gây chú ý và chỉ dùng AES256.
- `/tgtdeleg` giúp bạn không cần xử lý mật khẩu dạng cleartext hoặc khóa NTLM/AES của nạn nhân, nhưng vẫn trả về một TGT có thể giải mã.

### Tạo lại service-ticket

Bản cập nhật Rubeus tương tự bổ sung khả năng áp dụng kỹ thuật diamond cho các blob TGS. Bằng cách cung cấp cho `diamond` một **TGT được mã hóa base64** (từ `asktgt`, `/tgtdeleg` hoặc một TGT đã được giả mạo trước đó), **SPN của service** và **khóa AES của service**, bạn có thể tạo service ticket thực tế mà không cần tương tác với KDC—về cơ bản là một silver ticket kín đáo hơn.<sup>[[3]](#references)</sup>

```powershell
./Rubeus.exe diamond \
  /ticket:<BASE64_TGT_OR_KRB-CRED> \
  /service:cifs/dc01.lab.local \
  /servicekey:<AES256_SERVICE_KEY> \
  /ticketuser:svc_sql /ticketuserid:1109 \
  /ldap /opsec /nowrap
```

Quy trình này lý tưởng khi bạn đã kiểm soát một key tài khoản dịch vụ (ví dụ: dump bằng `lsadump::lsa /inject` hoặc `secretsdump.py`) và muốn tạo một TGS dùng một lần khớp hoàn hảo với chính sách, mốc thời gian và dữ liệu PAC của AD mà không phát sinh thêm lưu lượng AS/TGS nào.<sup>[[3]](#references)</sup>

### Sapphire-style PAC swaps (2025)

Một biến thể mới hơn đôi khi được gọi là **sapphire ticket**, kết hợp nền tảng "real TGT" của Diamond với **S4U2self+U2U** để đánh cắp PAC đặc quyền rồi đưa PAC đó vào TGT của bạn. Thay vì tự tạo thêm SID, bạn yêu cầu một ticket U2U S4U2self cho người dùng có đặc quyền cao, trong đó `sname` trỏ đến requester có đặc quyền thấp; KRB_TGS_REQ mang TGT của requester trong `additional-tickets` và đặt `ENC-TKT-IN-SKEY`, cho phép giải mã service ticket bằng key của người dùng đó. Sau đó, bạn trích xuất PAC đặc quyền và ghép nó vào TGT hợp lệ của mình trước khi ký lại bằng key krbtgt.<sup>[[2]](#references)[[5]](#references)</sup>

Impacket hiện hỗ trợ sapphire trong `ticketer.py` thông qua `-impersonate` + `-request` (trao đổi trực tiếp với KDC):<sup>[[2]](#references)[[5]](#references)</sup>

```bash
python3 ticketer.py -request -impersonate 'DAuser' \
  -domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
  -aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```

- `-impersonate` chấp nhận username hoặc SID; `-request` yêu cầu thông tin xác thực còn hiệu lực của user cùng key material của krbtgt (AES/NTLM) để giải mã/vá ticket.

Các dấu hiệu OPSEC quan trọng khi dùng biến thể này:<sup>[[5]](#references)</sup>

- TGS-REQ sẽ chứa `ENC-TKT-IN-SKEY` và `additional-tickets` (TGT của nạn nhân) — hiếm gặp trong lưu lượng thông thường.
- `sname` thường trùng với user gửi yêu cầu (truy cập self-service), và Event ID 4769 hiển thị caller và target là cùng một SPN/user.
- Dự kiến có các bản ghi 4768/4769 đi theo cặp, cùng client computer nhưng khác CNAMES (requester có quyền thấp so với PAC owner có đặc quyền).

### Ghi chú về OPSEC & phát hiện

- Các heuristic truyền thống của hunter (TGS không có AS, lifetime kéo dài hàng thập kỷ) vẫn áp dụng cho golden ticket, nhưng diamond ticket chủ yếu bị phát hiện khi **nội dung PAC hoặc ánh xạ group trông bất khả thi**. Điền mọi trường PAC (logon hours, đường dẫn user profile, device ID) để các phép so sánh tự động không lập tức gắn cờ forgery.<sup>[[3]](#references)</sup>
- **Không thêm quá nhiều group/RID**. Nếu chỉ cần `512` (Domain Admins) và `519` (Enterprise Admins), hãy dừng ở đó và đảm bảo tài khoản mục tiêu có vẻ hợp lý khi thuộc các group đó ở những nơi khác trong AD. `ExtraSids` quá nhiều sẽ làm lộ dấu hiệu.
- Các kiểu hoán đổi Sapphire để lại dấu vết U2U: `ENC-TKT-IN-SKEY` + `additional-tickets`, cùng với `sname` trỏ đến một user (thường là requester) trong 4769, và một sự kiện logon 4624 tiếp theo có nguồn từ forged ticket. Đối chiếu các trường đó thay vì chỉ tìm các khoảng trống no-AS-REQ.<sup>[[5]](#references)</sup>
- Microsoft đã bắt đầu loại bỏ dần **việc cấp service ticket bằng RC4** do CVE-2026-20833; áp dụng etype chỉ dùng AES trên KDC vừa tăng cường bảo mật domain, vừa phù hợp với các công cụ diamond/sapphire (`/opsec` đã buộc dùng AES). Việc trộn RC4 vào forged PAC sẽ ngày càng dễ bị chú ý.<sup>[[6]](#references)</sup>
- Dự án Security Content của Splunk phân phối telemetry attack-range cho diamond ticket cùng các quy tắc phát hiện như *Windows Domain Admin Impersonation Indicator*, giúp đối chiếu các chuỗi Event ID 4768/4769/4624 bất thường và thay đổi group trong PAC. Phát lại dataset đó (hoặc tự tạo dataset bằng các lệnh ở trên) giúp xác thực mức độ bao phủ của SOC đối với T1558.001, đồng thời cung cấp logic cảnh báo cụ thể để né tránh.<sup>[[4]](#references)</sup>

## References

- [1] [Palo Alto Unit 42 – Đá quý quý giá: Thế hệ tấn công Kerberos mới (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Impacket: Chúng tôi thích chơi với ticket (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – Cắt lại Diamond Ticket của Kerberos (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – Dữ liệu tấn công và quy tắc phát hiện Diamond Ticket (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – Mặt tối của đá quý: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – Thực thi chính sách service ticket RC4 cho CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)
{{#include ../../banners/hacktricks-training.md}}
