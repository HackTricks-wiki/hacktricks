# Thông tin trong máy in

{{#include ../../banners/hacktricks-training.md}}

Có một số blog trên Internet **nêu bật nguy cơ khi để máy in được cấu hình LDAP với thông tin đăng nhập mặc định/yếu**.  \
Đó là vì kẻ tấn công có thể **đánh lừa máy in xác thực với một máy chủ LDAP giả mạo** (thường chỉ cần `nc -vv -l -p 389` hoặc `slapd -d 2`) rồi thu thập **thông tin đăng nhập của máy in dưới dạng văn bản thuần**.

Ngoài ra, một số máy in có **nhật ký chứa tên người dùng** hoặc thậm chí có thể **tải xuống toàn bộ tên người dùng** từ Domain Controller.

Tất cả **thông tin nhạy cảm** này cùng với **tình trạng thiếu bảo mật** phổ biến khiến máy in trở thành mục tiêu rất đáng chú ý đối với kẻ tấn công.

Một số blog nhập môn về chủ đề này:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Cấu hình máy in

- **Vị trí**: Danh sách máy chủ LDAP thường nằm trong giao diện web (ví dụ: *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **Hành vi**: Nhiều máy chủ web nhúng cho phép thay đổi máy chủ LDAP **mà không cần nhập lại thông tin đăng nhập** (tính năng tăng khả năng sử dụng → rủi ro bảo mật).
- **Khai thác**: Chuyển địa chỉ máy chủ LDAP sang một máy chủ do kẻ tấn công kiểm soát, rồi dùng nút *Test Connection* / *Address Book Sync* để buộc máy in bind với bạn.

---

## Thu thập thông tin đăng nhập

### Phương pháp 1 – Netcat Listener

```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```

Các MFP nhỏ/cũ có thể gửi một *simple-bind* đơn giản, trong đó bind DN và mật khẩu hiển thị rõ trong luồng BER thô. Các thiết bị hiện đại thường thực hiện truy vấn ẩn danh trước rồi mới thử bind, vì vậy kết quả sẽ khác nhau.<sup>[[1]](#references)</sup>

Một listener `nc` thông thường trên cổng 636/3269 chỉ nhận được ciphertext TLS; để kiểm thử LDAPS cần có endpoint LDAP hỗ trợ TLS, và việc chuyển hướng sẽ thất bại nếu thiết bị xác thực chứng chỉ máy chủ đúng cách.

### Method 2 – Full Rogue LDAP server (recommended)

Vì nhiều thiết bị sẽ thực hiện tìm kiếm ẩn danh *trước khi* xác thực, việc dựng một daemon LDAP thực sự sẽ mang lại kết quả đáng tin cậy hơn nhiều:<sup>[[1]](#references)</sup>

```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```

Khi máy in thực hiện truy vấn, bạn sẽ thấy thông tin xác thực dạng văn bản thuần trong đầu ra debug.

> 💡 Responder bao gồm các dịch vụ xác thực LDAP và SMB giả mạo. Một LDAP bind đơn giản có thể làm lộ mật khẩu đã cấu hình, trong khi xác thực NTLM tạo ra dữ liệu challenge-response; không nên mô tả cả hai kết quả là mật khẩu dạng văn bản thuần.

---

## Các lỗ hổng Pass-Back gần đây (2024-2025)

Pass-back *không phải* là vấn đề chỉ tồn tại trên lý thuyết – các nhà cung cấp liên tục công bố advisory trong năm 2024/2025 mô tả chính xác kiểu tấn công này.

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Firmware ≤ 57.69.91 của máy in đa chức năng Xerox VersaLink C70xx cho phép quản trị viên đã xác thực (hoặc bất kỳ ai nếu thông tin xác thực mặc định vẫn còn) thực hiện các thao tác sau:

* **CVE-2024-12510 – LDAP pass-back**: thay đổi địa chỉ máy chủ LDAP và kích hoạt một truy vấn, khiến thiết bị làm lộ thông tin xác thực Windows đã cấu hình đến máy chủ do kẻ tấn công kiểm soát.
* **CVE-2024-12511 – SMB/FTP pass-back**: vấn đề tương tự thông qua các đích *scan-to-folder*, làm lộ thông tin xác thực NetNTLMv2 hoặc FTP dạng văn bản thuần.<sup>[[2]](#references)</sup>

Một listener đơn giản như:

```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```

hoặc một SMB server giả mạo (`impacket-smbserver`) cũng đủ để thu thập thông tin xác thực.  

### Canon imageRUNNER / imageCLASS – Khuyến cáo ngày 20 tháng 5 năm 2025

Canon xác nhận một điểm yếu **SMTP/LDAP pass-back** ảnh hưởng đến hàng chục dòng sản phẩm Laser & MFP. Kẻ tấn công có quyền admin có thể sửa cấu hình máy chủ và lấy thông tin xác thực đã lưu cho LDAP **hoặc** SMTP (nhiều tổ chức dùng tài khoản có đặc quyền để cho phép scan-to-mail).<sup>[[3]](#references)</sup>

Hướng dẫn của nhà cung cấp khuyến nghị rõ ràng:

1. Cập nhật lên firmware đã vá ngay khi có thể.
2. Sử dụng mật khẩu admin mạnh và duy nhất.
3. Tránh dùng tài khoản AD có đặc quyền để tích hợp máy in.

---

### Thiết bị Brother và các biến thể OEM – truy cập admin dựa trên serial để lấy thông tin xác thực dịch vụ

Một đợt công bố lỗ hổng phối hợp vào năm 2025 đã trình diễn một chuỗi khai thác đặc biệt hữu ích trên các thiết bị Brother bị ảnh hưởng; một phần của nhóm lỗ hổng cũng ảnh hưởng đến các mẫu OEM, vì vậy hãy xác minh chính xác mẫu thiết bị theo khuyến cáo của nhà cung cấp. Kẻ tấn công chưa xác thực có thể lấy serial của thiết bị qua HTTP/HTTPS/IPP trên firmware dễ bị tấn công, trong khi serial cũng có thể lấy được qua các giao thức quản lý như SNMP hoặc PJL. Nếu mật khẩu mặc định của nhà máy chưa từng được thay đổi, serial sẽ xác định chính xác mật khẩu administrator. Sau khi xác thực, lỗ hổng pass-back riêng biệt CVE-2024-51984 làm lộ mật khẩu dịch vụ bên ngoài đã cấu hình, chẳng hạn như LDAP hoặc FTP, dưới dạng văn bản thuần, biến quyền truy cập quản lý máy in thành thông tin xác thực mạng có thể tái sử dụng. Firmware khắc phục việc làm lộ mật khẩu dịch vụ, nhưng các thiết bị đã được sản xuất vẫn cần người vận hành thay mật khẩu administrator ban đầu được tạo từ serial.<sup>[[6]](#references)</sup>

Metasploit hiện có một module phụ trợ có thể dò tìm serial qua HTTP, SNMP hoặc PJL, tạo mật khẩu ban đầu dự đoán được và tùy chọn xác minh mật khẩu đó với web console. `DiscoverSerialVia=AUTO` sẽ thử các phương thức dò tìm được hỗ trợ; thay vào đó, hãy cung cấp `TargetSerial` nếu danh mục tài sản đã có serial.<sup>[[7]](#references)</sup>

```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```

Chỉ sử dụng kết quả để xác thực các tài sản được ủy quyền. Mật khẩu có hoạt động hay không phụ thuộc vào model cụ thể và, quan trọng nhất, liệu mật khẩu quản trị viên mặc định tại nhà máy đã được thay đổi hay chưa.<sup>[[6]](#references)[[7]](#references)</sup>

---

## Công cụ Enumeration / Exploitation tự động

| Tool | Mục đích | Ví dụ |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Lạm dụng PostScript/PJL/PCL, truy cập hệ thống tệp, kiểm tra default-creds, *SNMP discovery* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Thu thập cấu hình (bao gồm sổ địa chỉ và LDAP creds) qua HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Chạy các dịch vụ xác thực giả mạo và thu thập/relay NetNTLM từ các callback SMB | `sudo responder -I eth0 -v` |
| **Metasploit Brother auxiliary** | Phát hiện serial, suy ra mật khẩu quản trị viên mặc định tại nhà máy có thể có và xác minh quyền truy cập web console | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## Tăng cường bảo mật & Phát hiện

1. **Vá / cập nhật firmware** cho MFP kịp thời (kiểm tra các bản tin PSIRT của nhà cung cấp).
2. **Thay mật khẩu quản trị viên mặc định tại nhà máy** – chỉ cập nhật firmware không loại bỏ các mật khẩu khởi tạo suy ra từ serial trên những thiết bị Brother/OEM bị ảnh hưởng đã sản xuất trước đó.<sup>[[6]](#references)</sup>
3. **Tài khoản dịch vụ với quyền tối thiểu** – không bao giờ dùng Domain Admin cho LDAP/SMB/SMTP; giới hạn phạm vi OU ở chế độ *chỉ đọc*.
4. **Hạn chế quyền truy cập quản lý** – đặt các giao diện web/IPP/SNMP của máy in trong VLAN quản lý hoặc phía sau ACL/VPN.
5. **Giới hạn lưu lượng egress của máy in** – chỉ cho phép mỗi thiết bị kết nối đến các đích DC/LDAP, mail, DNS/NTP, in và tệp scan dự kiến. Pass-back yêu cầu callback đến endpoint do attacker chọn.
6. **Tắt các giao thức không sử dụng** – FTP, Telnet, raw-9100, các cipher SSL cũ.
7. **Bật ghi log kiểm tra** – một số thiết bị có thể gửi lỗi LDAP/SMTP đến syslog; đối chiếu các bind bất thường.
8. **Giám sát các đích xác thực** – cảnh báo khi máy in khởi tạo LDAP, SMB, SMTP hoặc FTP đến host ngoài allowlist, đặc biệt là ngay sau khi đăng nhập quản lý hoặc thay đổi cấu hình.
9. **Dùng SNMPv3 hoặc tắt SNMP** – community `public` thường làm lộ thông tin thiết bị và serial.

---



---

## References

- [1] [Chỉ là một chiếc máy in thôi… Điều tệ nhất có thể xảy ra là gì?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Máy in đa chức năng Xerox Versalink C7025: Các lỗ hổng tấn công Pass-Back (Đã khắc phục)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 Giảm thiểu/Khắc phục lỗ hổng cho máy in sản xuất, máy in đa chức năng văn phòng/văn phòng nhỏ và máy in laser](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Lấy thông tin xác thực Domain thông qua máy in bằng Netcat](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Khai thác máy in đa chức năng trong một đợt kiểm thử xâm nhập](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [Nhiều thiết bị Brother: Nhiều lỗ hổng (ĐÃ KHẮC PHỤC)](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit: module bypass xác thực quản trị viên mặc định của Brother](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
{{#include ../../banners/hacktricks-training.md}}
