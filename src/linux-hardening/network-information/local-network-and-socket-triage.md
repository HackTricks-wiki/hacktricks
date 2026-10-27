# Phân loại mạng cục bộ và socket

{{#include ../../banners/hacktricks-training.md}}

Sau khi truy cập được shell trên máy chủ Linux, các mục tiêu mạng hữu ích nhất thường không được expose ra bên ngoài. Các dịch vụ chỉ bind với loopback, mạng veth, Unix socket, listener tạm thời, packet capture và quy tắc firewall cục bộ có thể làm lộ thông tin xác thực hoặc các bề mặt tấn công chỉ khả dụng cục bộ.

Trang này tập trung vào các kỹ thuật post-exploitation cục bộ thiết thực, không phải pentesting mạng từ xa nói chung.

## Liệt kê loopback và dịch vụ cục bộ

Trước tiên, hãy xác định các dịch vụ đang lắng nghe, địa chỉ bind của chúng và tiến trình sở hữu chúng nếu có quyền.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ss -lntup
ss -lnx
ip addr
ip route
```

Các mẫu quan trọng:

- `127.0.0.1:<port>` hoặc `[::1]:<port>`: theo mặc định, chỉ máy chủ mới truy cập được.<sup>[[3]](#references)[[4]](#references)</sup>
- `0.0.0.0:<port>`: có thể truy cập qua mọi giao diện IPv4, trừ khi bị lọc.<sup>[[3]](#references)</sup>
- `10.0.0.0/8`, `172.16.0.0/12` hoặc `192.168.0.0/16` trên `veth*`, `docker*`, `br-*`, `cni*`: nhiều khả năng là mạng container hoặc mạng lab cục bộ.<sup>[[23]](#references)[[24]](#references)</sup>
- Unix socket trong `/run`, `/var/run`, `/tmp` hoặc thư mục ứng dụng: các bề mặt IPC cục bộ.<sup>[[5]](#references)</sup>

Đối với [lỗi phân tích socket snapd trong quá khứ, CVE-2019-7304](https://ubuntu.com/security/vulnerabilities/snap-socket-parsing), hãy kiểm tra daemon đang chạy, socket API cục bộ và phiên bản gói hoặc snap đã cài đặt để xác định có bản vá dành cho bản phân phối đó hay không. Lỗi nằm trong phần xác thực địa chỉ socket của peer của snapd, không phải trong `snap-confine`; chỉ riêng tệp `snap-confine` có set-user-ID hoặc chuỗi phiên bản upstream không đủ để xác định hệ thống có bị ảnh hưởng hay không. Ubuntu phát hành bản vá theo phiên bản gói riêng cho từng bản phát hành; snapd cũng có thể được cập nhật từ snap độc lập với gói của bản phân phối. Hãy xác nhận bản dựng thực sự đang chạy và khả năng truy cập socket cục bộ trước khi đánh giá ranh giới API có đặc quyền. Việc liệt kê thụ động không nên gửi yêu cầu socket được tạo thủ công hoặc cài đặt snap.

Một listener loopback được khởi chạy bằng [`socat` with `EXEC`](https://man7.org/linux/man-pages/man1/socat.1.html) có thể chuyển đầu vào từ client cục bộ đến một chương trình riêng. Hãy đối chiếu lệnh của listener, đường dẫn executable, danh tính hiệu lực của tiến trình con, khả năng truy cập cục bộ và cơ chế xác thực trước khi xem một dịch vụ tùy chỉnh thuộc sở hữu của root là manh mối leo thang đặc quyền. Cần có bằng chứng từ binary và bản dựng cụ thể để xác định lỗi an toàn bộ nhớ hoặc đường dẫn không an toàn từ đầu vào đến lệnh; chỉ riêng số cổng, tiến trình `socat` hoặc chủ sở hữu root không đủ để chứng minh điều đó. Việc liệt kê thụ động nên dừng ở metadata của tiến trình, socket và tệp, không gửi đầu vào đến dịch vụ.

Salt master cục bộ có thể lắng nghe trên TCP 4505 và 4506, kể cả trên loopback hoặc cổng host được publish từ container. [Salt's 3000.2 release notes](https://docs.saltproject.io/en/latest/topics/releases/3000.2.html) mô tả một lỗi truy cập phương thức không cần xác thực, CVE-2020-11651, được vá trong upstream 2019.2.4 và 3000.2. Hãy đối chiếu listener với tiến trình `salt-master` thực tế, giao diện có thể truy cập, gói đã cài đặt và bản vá của nhà cung cấp, cùng danh tính hiệu lực của container hoặc host trước khi xem đây là manh mối leo thang đặc quyền; chỉ riêng cổng hoặc phiên bản upstream không phải bằng chứng. Nếu master chạy bên trong container, tác động đến quyền root trên host là một ranh giới riêng: hãy xác nhận socket API runtime của host được mount và có thể truy cập từ container đó. Việc liệt kê thụ động không nên truy vấn request server của Salt hoặc tạo container để xác định mức độ phơi nhiễm. Xem [Salt's port documentation](https://docs.saltproject.io/salt/install-guide/en/latest/topics/before-you-start/check-network-ports.html) và [runtime API triage](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md).

Ánh xạ các cổng cục bộ bằng các phép thăm dò nhẹ.<sup>[[6]](#references)[[7]](#references)</sup>

```bash
for p in 80 443 8000 8080 8081 9000 5000; do
  timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```

Sử dụng `nmap` cục bộ khi có sẵn.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```

## Các subnet veth và container ẩn

Môi trường container hoặc lab thường chỉ cung cấp dịch vụ trên subnet bridge hoặc veth. Hãy liệt kê các interface và route trước khi cho rằng không thể truy cập dịch vụ.<sup>[[2]](#references)</sup>

```bash
ip -br addr
ip route
ip neigh
```

Tìm các mạng con cục bộ tiềm năng.<sup>[[2]](#references)</sup>

```bash
ip -o -4 addr show | awk '{print $2, $4}'
```

Thăm dò subnet đã phát hiện một cách cẩn thận.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```

Kỹ thuật này hữu ích khi một web panel, debug endpoint hoặc helper service bị ẩn khỏi các lần quét bên ngoài nhưng có thể truy cập từ host bị xâm nhập hoặc mạng container.

## Token của dịch vụ notebook giữa các ranh giới người dùng

Một dịch vụ notebook trên loopback có thể xác thực bằng token khởi động được in ra đầu ra của tiến trình. Nếu đầu ra đó được chuyển hướng đến một log mà tài khoản cục bộ khác có thể đọc, token có thể vượt qua ranh giới người dùng và cho phép thực thi mã bằng tài khoản của notebook server. Hãy đối chiếu chủ sở hữu tiến trình đang lắng nghe, đích đến và quyền của log, cấu hình token hiện tại cùng các kiểm soát truy cập notebook trước khi xem đường dẫn log là manh mối leo thang đặc quyền. Liệt kê metadata của log trong quá trình liệt kê thụ động; không in token hoặc kết nối tới dịch vụ chỉ để phân loại host.

Dịch vụ Jupyter Lab cũng có thể để lộ token trong `ExecStart` của systemd mà người dùng có thể đọc, hoặc trong command line đang chạy (`ps auxww`), thay vì chỉ trong log khởi động. Trong ví dụ được báo cáo, `User=analyst` và `--ServerApp.token` xác định cả thông tin xác thực lẫn tài khoản đứng sau listener `127.0.0.1:8888`. Khi có quyền truy cập host, token và `ssh -L 8888:127.0.0.1:8888 user@host` cho phép truy cập Terminal của Jupyter Lab bằng tài khoản dịch vụ đó. Hãy kiểm tra đồng thời người dùng hiệu lực của unit, đối số tiến trình, listener và tính hợp lệ của token; chỉ bind vào loopback không tạo thành ranh giới phân quyền.<sup>[[28]](#references)</sup>

## Pivot cục bộ bằng socat hoặc SSH

Nếu một dịch vụ chỉ bind vào loopback, hãy chuyển tiếp dịch vụ qua một kênh được cho phép thay vì thay đổi chính dịch vụ đó.

Chuyển tiếp một dịch vụ HTTP chỉ cục bộ bằng SSH.<sup>[[11]](#references)</sup>

```bash
ssh -L 8080:127.0.0.1:8080 user@target
```

Chuyển tiếp một cổng cục bộ bằng `socat` khi bạn đã có quyền truy cập shell.<sup>[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```

Chuyển tiếp Unix socket sang TCP để kiểm thử cục bộ.<sup>[[5]](#references)[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```

Bản thân việc này không khai thác gì cả. Nó giúp các công cụ của bạn truy cập được một bề mặt chỉ khả dụng cục bộ để bạn có thể tương tác với nó như một dịch vụ thông thường.

## Banner Grabbing and Simple Protocols

Không phải dịch vụ nào cũng dùng HTTP. Nhiều dịch vụ cục bộ làm lộ đủ thông tin qua banner hoặc giao thức một dòng.

Các phép thăm dò cơ bản.<sup>[[13]](#references)</sup>

```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```

Kiểm tra HTTP mà không cần trình duyệt.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```

Đối với TLS.<sup>[[14]](#references)[[15]](#references)</sup>

```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```

Mục tiêu là xác định giao thức, cơ chế xác thực, phiên bản và liệu dịch vụ có tin cậy các client cục bộ hay không.

Đối với listener aiohttp, hãy kiểm tra cấu hình static-route cũng như phiên bản. CVE-2024-23334 ảnh hưởng đến aiohttp trước phiên bản 3.9.2 khi một static route bật `follow_symlinks=True`: các request đến route đó có thể đọc các file nằm ngoài thư mục gốc static. Nếu dịch vụ chạy với quyền root, dịch vụ có thể để lộ các file mà root có thể đọc, miễn là route có thể truy cập được. Banner phiên bản hoặc việc bind với loopback không đủ để xác định cấu hình dễ bị tấn công hoặc khả năng truy cập file.<sup>[[27]](#references)</sup>

## Thu thập lưu lượng Loopback

Lưu lượng cục bộ có thể làm lộ header, bearer token, thông tin đăng nhập Basic Auth hoặc secret riêng của ứng dụng.<sup>[[17]](#references)[[25]](#references)</sup> Chỉ capture trong môi trường được cấp phép.

Capture lưu lượng HTTP loopback.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```

Thu thập một dịch vụ cục bộ cụ thể.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```

Giải mã Basic Auth từ header được thu thập hoặc ghi log.<sup>[[17]](#references)[[18]](#references)</sup>

```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```

Các chuỗi hữu ích cần tìm trong bản ghi văn bản:

```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```

## Ghi nhật ký khóa TLS

Nếu có thể kiểm soát môi trường của tiến trình client trong lab, `SSLKEYLOGFILE` có thể giúp giải mã các phiên TLS trong Wireshark hoặc công cụ tương thích.<sup>[[19]](#references)[[20]](#references)</sup> Điều này hữu ích để tìm hiểu lưu lượng HTTPS cục bộ mà không cần tấn công chính TLS.

Chạy client với tính năng ghi nhật ký khóa được bật.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```

Ghi lại lưu lượng mạng cùng lúc.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```

Sau đó tải `/tmp/tls.pcap` và `/tmp/sslkeys.log` vào Wireshark. Cách này chỉ hoạt động khi thư viện client hỗ trợ ghi log khóa theo kiểu NSS và bạn có thể thiết lập biến môi trường trước khi kết nối được tạo.<sup>[[20]](#references)[[21]](#references)</sup>

## Tương tác với Unix Socket và Command Injection

Unix socket là các điểm cuối IPC cục bộ.<sup>[[5]](#references)</sup> Chúng có thể cung cấp API HTTP, giao thức tùy chỉnh hoặc các trình xử lý lệnh không an toàn.<sup>[[12]](#references)[[14]](#references)</sup>

Socket thuộc sở hữu của root và có quyền ghi cho nhóm là một ranh giới phân quyền, không phải tự thân là lỗ hổng. Hãy đối chiếu nhóm và mode của socket với tài khoản hiện tại, xác định tiến trình đang lắng nghe và xem xét dữ liệu tiến trình đó chấp nhận từ client trước khi đánh giá mức độ rủi ro. Cụ thể, một dịch vụ có đặc quyền thực thi PHP được gửi lên có thể vượt qua ranh giới thứ hai nếu dịch vụ cũng tin cậy đường dẫn `php.ini` do bên gọi chọn hoặc cho phép bên gọi thay đổi `disable_functions` hay `open_basedir`; hãy kiểm tra cấu hình thực tế và quy trình xác thực của dịch vụ. [Hướng dẫn cấu hình PHP](../../network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/README.md) giải thích các chỉ thị này. Chỉ riêng metadata của socket không chứng minh được khả năng thực thi mã.

Tìm các socket.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```

Tương tác với HTTP qua Unix socket.<sup>[[14]](#references)</sup>

```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```

Tương tác với raw socket.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```

Nếu dữ liệu socket do người dùng kiểm soát được truyền vào shell hoặc helper có quyền cao, nó có thể dẫn đến command injection.<sup>[[26]](#references)</sup> Để xem ví dụ tập trung, hãy xem [Socket Command Injection](socket-command-injection.md).

## Rà soát nftables và thay đổi quy tắc được cấp phép

Các quy tắc tường lửa cục bộ có thể giải thích vì sao một dịch vụ hiển thị cục bộ nhưng bị chặn từ xa, hoặc vì sao không thể truy cập một cổng cao từ một giao diện mạng.<sup>[[22]](#references)</sup>

Rà soát các quy tắc.<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```

Tìm các gói tin bị loại bỏ ảnh hưởng đến cổng mục tiêu.<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```

Trong môi trường lab được ủy quyền, xóa quy tắc chặn cụ thể theo handle.<sup>[[22]](#references)</sup>

```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```

Ưu tiên xóa handle cụ thể thay vì xóa sạch toàn bộ bảng. Kỹ thuật này là xác định chính xác filter gây ra hành vi đó và chỉ thay đổi rule đó.<sup>[[22]](#references)</sup>

## Quy trình nhanh

```bash
ss -lntup
ss -lnx
ip -br addr
ip route
nmap -sT -Pn --open 127.0.0.1
find /run /var/run /tmp -type s -ls 2>/dev/null
sudo nft list ruleset 2>/dev/null | head -n 80
```

Ưu tiên các dịch vụ chỉ hoạt động cục bộ, chạy với người dùng có đặc quyền cao hơn, cung cấp chức năng quản trị/gỡ lỗi hoặc tin cậy các client trên loopback/mạng container.

## References

- [1] [ss(8) — trang hướng dẫn Linux](https://man7.org/linux/man-pages/man8/ss.8.html)
- [2] [ip(8) — trang hướng dẫn Linux](https://man7.org/linux/man-pages/man8/ip.8.html)
- [3] [ip(7) — trang hướng dẫn Linux](https://man7.org/linux/man-pages/man7/ip.7.html)
- [4] [RFC 4291: Kiến trúc đánh địa chỉ IP phiên bản 6](https://www.rfc-editor.org/info/rfc4291/)
- [5] [unix(7) — trang hướng dẫn Linux](https://man7.org/linux/man-pages/man7/unix.7.html)
- [6] [Chuyển hướng (Sổ tay tham khảo Bash)](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [7] [Lệnh gọi timeout (GNU Coreutils)](https://www.gnu.org/s/coreutils/timeout)
- [8] [Các kỹ thuật quét cổng (Hướng dẫn tham khảo Nmap)](https://nmap.org/book/man-port-scanning-techniques.html)
- [9] [Phát hiện máy chủ (Hướng dẫn tham khảo Nmap)](https://nmap.org/book/man-host-discovery.html)
- [10] [Chỉ định cổng và thứ tự quét (Hướng dẫn tham khảo Nmap)](https://nmap.org/book/man-port-specification.html)
- [11] [ssh(1) — trang hướng dẫn Linux](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [12] [socat(1) — trang hướng dẫn Linux](https://www.man7.org/linux/man-pages/man1/socat.1.html)
- [13] [nc(1) — trang hướng dẫn OpenBSD](https://man.openbsd.org/nc.1)
- [14] [Sổ tay công cụ dòng lệnh curl](https://curl.se/docs/manpage.html?category=23)
- [15] [openssl-s_client — Tài liệu OpenSSL](https://docs.openssl.org/3.0/man1/openssl-s_client/)
- [16] [tcpdump(8) — trang hướng dẫn Linux](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
- [17] [RFC 7617: Lược đồ xác thực HTTP 'Basic'](https://www.rfc-editor.org/rfc/rfc7617.html)
- [18] [Lệnh gọi base64 (GNU Coreutils)](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html)
- [19] [openssl-env — Tài liệu OpenSSL](https://docs.openssl.org/master/man7/openssl-env/)
- [20] [TLS — Wiki Wireshark](https://wiki.wireshark.org/tls)
- [21] [Hướng dẫn sử dụng Wireshark](https://www.wireshark.org/docs/wsug_html/)
- [22] [Sổ tay nftables](https://netfilter.org/projects/nftables/manpage.html)
- [23] [Phân bổ địa chỉ cho mạng riêng (RFC 1918)](https://www.rfc-editor.org/rfc/rfc1918.html)
- [24] [ip-link(8) — trang hướng dẫn Linux](https://man7.org/linux/man-pages/man8/ip-link.8.html)
- [25] [Khuôn khổ ủy quyền OAuth 2.0: Cách sử dụng Bearer Token (RFC 6750)](https://www.rfc-editor.org/rfc/rfc6750.html)
- [26] [CWE-78: Không vô hiệu hóa đúng cách các ký tự đặc biệt trong lệnh hệ điều hành](https://cwe.mitre.org/data/definitions/78.html)
- [27] [Thông báo bảo mật từ maintainer aiohttp: traversal tuyến tĩnh khi bật follow_symlinks](https://github.com/aio-libs/aiohttp/security/advisories/GHSA-5h86-8mv2-jq9f)
- [28] [HTB: DevHub — token Jupyter bị lộ qua systemd và đối số tiến trình](https://0xdf.gitlab.io/2026/10/10/htb-devhub.html)
{{#include ../../banners/hacktricks-training.md}}
