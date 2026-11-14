# Thông tin trong máy in

{{#include ../../banners/hacktricks-training.md}}

Máy in lưu thông tin xác thực LDAP có thể làm lộ chúng nếu cài đặt máy chủ bị thay đổi và máy in sau đó xác thực với một endpoint giả mạo.<sup>[[2]](#references)</sup> Kết quả phụ thuộc vào phương thức bind: simple bind không được bảo vệ sẽ làm lộ mật khẩu, còn bind kiểu SASL challenge-response thì không làm lộ mật khẩu dưới dạng văn bản thuần.<sup>[[8]](#references)</sup> Xem [xác thực LDAP và bảo mật truyền tải](../../network-services-pentesting/pentesting-ldap.md#cleartext-credentials-and-tls-downgrade-risks).

Ngoài ra, một số máy in sẽ chứa **nhật ký có tên người dùng** hoặc thậm chí có thể **tải xuống toàn bộ tên người dùng** từ Domain Controller.

Tất cả **thông tin nhạy cảm** này cùng với **việc thiếu bảo mật** phổ biến khiến máy in trở thành mục tiêu rất hấp dẫn đối với attacker.

Một số blog nhập môn về chủ đề này:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Cấu hình máy in

- **Vị trí**: Danh sách máy chủ LDAP thường nằm trong giao diện web (ví dụ: *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **Hành vi**: Nhiều web server nhúng cho phép sửa đổi máy chủ LDAP **mà không cần nhập lại thông tin xác thực** (tính năng tiện dụng → rủi ro bảo mật).
- **Khai thác**: Chuyển hướng địa chỉ máy chủ LDAP đến một host do attacker kiểm soát, rồi dùng nút *Test Connection* / *Address Book Sync* để buộc máy in bind đến bạn.

---

## Thu thập thông tin xác thực

### Phương thức 1 – Netcat Listener

```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```

Một `BindRequest` đơn giản có thể làm lộ bind DN và mật khẩu trong luồng BER, ngay cả khi máy chủ sau đó từ chối đăng nhập. Chỉ tra cứu ẩn danh hoặc đàm phán SASL thì không làm lộ mật khẩu được lưu.<sup>[[8]](#references)</sup>

Một trình nghe `nc` thông thường trên cổng 636/3269 sẽ nhận được TLS handshake, chứ không phải LDAP bind. LDAPS cần một endpoint hỗ trợ TLS. Chỉ xác thực certificate thì không ngăn được pass-back nếu máy in chấp nhận hostname đã thay đổi và endpoint mới có certificate hợp lệ cho hostname đó; client cũng phải giới hạn máy chủ nào được phép nhận thông tin xác thực đã lưu.<sup>[[8]](#references)</sup>

### Method 2 – Full Rogue LDAP server (recommended)

Máy in có thể yêu cầu phản hồi LDAP hợp lệ trước khi thử bind.<sup>[[10]](#references)</sup> Một LDAP server đầy đủ có thể xử lý trao đổi sơ bộ đó, nhưng không thể khiến client được cấu hình cố định với cơ chế SASL mạnh hoặc máy chủ TLS dự kiến tiết lộ mật khẩu.<sup>[[8]](#references)[[10]](#references)</sup>

```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # use a base DN compatible with the printer lookup

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```

Coi một lần tra cứu là bằng chứng cho thấy có kết nối, không phải bằng chứng mật khẩu đã bị tiết lộ. Mật khẩu chỉ bị lộ nếu client gửi một bind mang mật khẩu dạng văn bản thuần; hãy kiểm tra cơ chế bind thực tế và trạng thái TLS.<sup>[[8]](#references)</sup>

> 💡  Responder có các dịch vụ xác thực LDAP và SMB giả mạo. Một LDAP bind đơn giản có thể làm lộ mật khẩu đã cấu hình, trong khi xác thực NTLM tạo ra dữ liệu challenge-response; không mô tả cả hai kết quả là mật khẩu dạng văn bản thuần.

### Lựa chọn cơ chế SASL

Một số client LDAP của máy in chọn trong số các cơ chế mà máy chủ LDAP quảng bá.<sup>[[8]](#references)[[10]](#references)</sup> Nghiên cứu cho thấy client chấp nhận cơ chế SASL dạng văn bản thuần được quảng bá có thể gửi mật khẩu, trong khi quá trình thương lượng NTLM thông thường chỉ tiết lộ dữ liệu challenge-response.<sup>[[9]](#references)[[10]](#references)</sup> Đây là **lỗi chính sách của client**, không phải đặc tính của mọi SASL bind: thay vào đó, client yêu cầu cơ chế mạnh hơn hoặc ghim máy chủ TLS dự kiến sẽ từ chối kết nối nếu không đáp ứng được yêu cầu.<sup>[[8]](#references)</sup> OpenLDAP mặc định vô hiệu hóa các cơ chế SASL có thể truyền dữ liệu dạng văn bản thuần, vì vậy một daemon mặc định không chứng minh được rằng hành vi này tồn tại trên máy in.<sup>[[11]](#references)</sup>

---

## Các lỗ hổng Pass-Back gần đây (2024-2025)

Pass-back *không phải* vấn đề chỉ tồn tại trên lý thuyết – các nhà cung cấp liên tục công bố thông báo bảo mật trong năm 2024/2025 mô tả chính xác nhóm tấn công này.

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Firmware ≤ 57.69.91 của các máy in đa chức năng Xerox VersaLink C70xx cho phép quản trị viên đã xác thực (hoặc bất kỳ ai nếu thông tin đăng nhập mặc định vẫn còn) thực hiện các thao tác sau:

* **CVE-2024-12510 – LDAP pass-back**: thay đổi địa chỉ máy chủ LDAP và kích hoạt một lần tra cứu, khiến thiết bị làm lộ thông tin đăng nhập Windows đã cấu hình cho máy chủ do kẻ tấn công kiểm soát.
* **CVE-2024-12511 – SMB/FTP pass-back**: vấn đề tương tự thông qua các đích *scan-to-folder*, làm lộ thông tin xác thực NetNTLMv2 hoặc FTP dạng văn bản thuần.<sup>[[2]](#references)</sup>

Một trình nghe đơn giản như:

```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```

hoặc một SMB server giả mạo (`impacket-smbserver`) là đủ để thu thập thông tin xác thực.  

### Canon imageRUNNER / imageCLASS – Khuyến cáo ngày 20 tháng 5 năm 2025

Canon xác nhận một điểm yếu **SMTP/LDAP pass-back** ảnh hưởng đến hàng chục dòng sản phẩm Laser & MFP. Kẻ tấn công có quyền admin có thể sửa đổi cấu hình server và lấy thông tin xác thực đã lưu cho LDAP **hoặc** SMTP (nhiều tổ chức dùng tài khoản đặc quyền để cho phép scan-to-mail).<sup>[[3]](#references)</sup>

Hướng dẫn của nhà cung cấp khuyến nghị rõ ràng:

1. Cập nhật lên firmware đã vá ngay khi có thể.
2. Sử dụng mật khẩu admin mạnh và riêng biệt.
3. Tránh dùng tài khoản AD đặc quyền để tích hợp máy in.

---

### Thiết bị Brother và các biến thể OEM – truy cập admin dựa trên số serial để lấy thông tin xác thực dịch vụ

Một đợt công bố phối hợp năm 2025 đã trình diễn một chuỗi khai thác đặc biệt hữu ích trên các thiết bị Brother bị ảnh hưởng; một số lỗ hổng trong bộ này cũng ảnh hưởng đến các mẫu OEM, vì vậy hãy kiểm tra chính xác mẫu thiết bị theo khuyến cáo của nhà cung cấp. Kẻ tấn công chưa xác thực có thể lấy số serial của thiết bị qua HTTP/HTTPS/IPP trên firmware dễ bị tấn công, trong khi số serial cũng có thể được truy xuất qua các giao thức quản lý như SNMP hoặc PJL. Nếu mật khẩu gốc chưa từng được thay đổi, số serial có thể được dùng để xác định mật khẩu admin. Sau khi xác thực, lỗ hổng pass-back riêng biệt CVE-2024-51984 làm lộ ở dạng văn bản thuần các mật khẩu của dịch vụ bên ngoài đã cấu hình, chẳng hạn như LDAP hoặc FTP, biến quyền truy cập quản lý máy in thành thông tin xác thực mạng có thể tái sử dụng. Firmware khắc phục việc làm lộ mật khẩu dịch vụ, nhưng các thiết bị đã được sản xuất trước đó vẫn cần người vận hành thay mật khẩu admin ban đầu được tạo từ số serial.<sup>[[6]](#references)</sup>

Metasploit hiện có một module phụ trợ để phát hiện số serial qua HTTP, SNMP hoặc PJL, tạo mật khẩu ban đầu có thể dùng và tùy chọn xác minh mật khẩu đó với web console. `DiscoverSerialVia=AUTO` sẽ thử các phương thức phát hiện được hỗ trợ; hãy cung cấp `TargetSerial` thay thế nếu danh mục tài sản đã có số serial.<sup>[[7]](#references)</sup>

```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```

Chỉ sử dụng kết quả để xác thực các tài sản được ủy quyền. Việc mật khẩu có hoạt động hay không phụ thuộc vào model cụ thể và, quan trọng hơn, vào việc mật khẩu quản trị viên mặc định của nhà sản xuất đã được thay đổi hay chưa.<sup>[[6]](#references)[[7]](#references)</sup>

---

## Công cụ Enumeration / Exploitation tự động

| Công cụ | Mục đích | Ví dụ |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Lạm dụng PostScript/PJL/PCL, truy cập hệ thống tệp, kiểm tra default-creds, *SNMP discovery*; xem [đánh giá PJL](../../network-services-pentesting/9100-pjl.md) | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Thu thập cấu hình (bao gồm sổ địa chỉ và thông tin xác thực LDAP) qua HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Chạy các dịch vụ xác thực giả mạo và thu thập/chuyển tiếp NetNTLM từ các kết nối ngược SMB | `sudo responder -I eth0 -v` |
| **Metasploit Brother auxiliary** | Phát hiện số serial, suy ra mật khẩu quản trị viên mặc định có thể dùng và xác minh quyền truy cập vào web console | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## Tăng cường bảo mật & Phát hiện

1. **Vá lỗi / cập nhật firmware** cho MFP kịp thời (kiểm tra các bản tin PSIRT của nhà cung cấp).
2. **Thay mật khẩu quản trị viên mặc định của nhà sản xuất** – chỉ cập nhật firmware sẽ không xóa các mật khẩu ban đầu được suy ra từ số serial trên những thiết bị Brother/OEM bị ảnh hưởng đã sản xuất trước đó.<sup>[[6]](#references)</sup>
3. **Tài khoản dịch vụ có đặc quyền tối thiểu** – không bao giờ dùng Domain Admin cho LDAP/SMB/SMTP; giới hạn phạm vi OU ở mức *chỉ đọc*.
4. **Hạn chế quyền truy cập quản lý** – đặt các giao diện web/IPP/SNMP của máy in trong VLAN quản lý hoặc phía sau ACL/VPN.
5. **Giới hạn lưu lượng đi ra của máy in** – chỉ cho phép mỗi thiết bị kết nối đến các đích DC/LDAP, mail, DNS/NTP, print và scan-file dự kiến. Pass-back cần có kết nối ngược đến endpoint do attacker chọn.
6. **Tắt các giao thức không sử dụng** – FTP, Telnet, raw-9100, các cipher SSL cũ.
7. **Bật ghi nhật ký kiểm tra** – một số thiết bị có thể ghi lỗi LDAP/SMTP vào syslog; đối chiếu các bind bất thường.
8. **Giám sát các đích xác thực** – cảnh báo khi máy in khởi tạo kết nối LDAP, SMB, SMTP hoặc FTP đến host nằm ngoài allowlist, đặc biệt là ngay sau khi đăng nhập quản lý hoặc thay đổi cấu hình.
9. **Dùng SNMPv3 hoặc tắt SNMP** – community `public` thường làm lộ thông tin thiết bị và số serial.

---



---



## References

- [1] [Chỉ là một chiếc máy in… Điều tệ nhất có thể xảy ra là gì?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Máy in đa chức năng Xerox Versalink C7025: Các lỗ hổng tấn công Pass-Back (Đã khắc phục)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 Giảm thiểu/Khắc phục lỗ hổng cho máy in sản xuất, máy in đa chức năng dùng tại văn phòng/văn phòng nhỏ và máy in laser](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Lấy thông tin xác thực Domain thông qua máy in bằng Netcat](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Khai thác máy in đa chức năng trong một đợt kiểm thử xâm nhập](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [Nhiều thiết bị Brother: Nhiều lỗ hổng (ĐÃ KHẮC PHỤC)](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit: module bỏ qua xác thực quản trị viên mặc định của Brother](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
- [8] [RFC 4513 – Các phương thức xác thực và cơ chế bảo mật LDAP](https://datatracker.ietf.org/doc/html/rfc4513)
- [9] [Máy chủ Docker LDAP passback](https://github.com/cybertrinchera/ldap-passback-docker)
- [10] [Tấn công LDAP pass back – ACCEIS](https://www.acceis.fr/ldap-pass-back-attack/)
- [11] [slapd-config(5) – Các thuộc tính bảo mật SASL](https://man7.org/linux/man-pages/man5/slapd-config.5.html)
{{#include ../../banners/hacktricks-training.md}}
