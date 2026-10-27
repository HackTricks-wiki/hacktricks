# Dịch vụ mạng và giao thức macOS

{{#include ../../banners/hacktricks-training.md}}

## Dịch vụ truy cập từ xa

Đây là những dịch vụ phổ biến để truy cập từ xa vào các hệ thống macOS.<sup>[[11]](#references)</sup>\
Bạn có thể bật/tắt các dịch vụ này trong `System Settings` --> `Sharing`<sup>[[1]](#references)</sup>

- **VNC**, có tên là “Screen Sharing” (tcp:5900)
- **SSH**, có tên là “Remote Login” (tcp:22)
- **Apple Remote Desktop** (ARD), hay “Remote Management” (tcp:3283, tcp:5900)
- **AppleEvent**, có tên là “Remote Apple Event” (tcp:3031)

Kiểm tra xem dịch vụ nào đang bật bằng cách chạy:

```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\\*.88|\\*.445|\\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```

### Liệt kê cấu hình chia sẻ trên máy

Khi đã có quyền thực thi mã cục bộ trên máy Mac, hãy **kiểm tra trạng thái đã cấu hình**, không chỉ các socket đang lắng nghe. `systemsetup` và `launchctl` thường cho biết dịch vụ có được bật ở cấp quản trị hay không, còn `kickstart` và `system_profiler` giúp xác nhận cấu hình ARD/Sharing đang có hiệu lực:

```bash
system_profiler SPSharingDataType
sudo /usr/sbin/systemsetup -getremotelogin
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
sudo launchctl print-disabled system | egrep 'com.apple.screensharing|com.apple.AEServer|ssh'
```

### Pentesting ARD

Apple Remote Desktop (ARD) là phiên bản nâng cao của [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing), được thiết kế riêng cho macOS và cung cấp thêm nhiều tính năng. Một lỗ hổng đáng chú ý trong ARD nằm ở phương thức xác thực mật khẩu điều khiển màn hình: phương thức này chỉ sử dụng 8 ký tự đầu tiên của mật khẩu, khiến hệ thống dễ bị [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) bằng các công cụ như Hydra hoặc [GoRedShell](https://github.com/ahhh/GoRedShell/), do không có giới hạn tốc độ mặc định.<sup>[[2]](#references)</sup>

Có thể xác định các phiên bản dễ bị tấn công bằng script `vnc-info` của **nmap**. Các dịch vụ hỗ trợ `VNC Authentication (2)` đặc biệt dễ bị brute force attacks do mật khẩu bị cắt còn 8 ký tự.

Để bật ARD cho nhiều tác vụ quản trị như leo thang đặc quyền, truy cập GUI hoặc giám sát người dùng, hãy dùng lệnh sau:

```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```

ARD cung cấp các cấp độ kiểm soát linh hoạt, bao gồm giám sát, kiểm soát chung và toàn quyền; các phiên vẫn tồn tại ngay cả sau khi mật khẩu người dùng thay đổi. ARD cho phép gửi trực tiếp lệnh Unix và thực thi chúng dưới quyền root đối với người dùng có quyền quản trị. Lập lịch tác vụ và tìm kiếm Remote Spotlight là những tính năng đáng chú ý, hỗ trợ tìm kiếm từ xa, ít gây ảnh hưởng để tìm các tệp nhạy cảm trên nhiều máy.

Từ góc độ operator, **Monterey 12.1+ đã thay đổi quy trình bật tính năng từ xa trong các fleet được quản lý**. Nếu bạn đã kiểm soát MDM của victim, lệnh `EnableRemoteDesktop` của Apple thường là cách gọn nhất để bật chức năng remote desktop trên các hệ thống mới hơn. Nếu bạn đã có foothold trên host, `kickstart` vẫn hữu ích để kiểm tra hoặc cấu hình lại các quyền ARD từ command line.

#### Apple Screen Sharing (RFB 003.889 / security type 36) lạm dụng sao chép tệp pre-auth

Nghiên cứu gần đây về `screensharingd` cho thấy Apple Screen Sharing không phải lúc nào cũng chỉ dùng xác thực VNC cổ điển: các bản build mới hơn dùng **RFB `003.889`** và quảng bá **security type `36`**, trong đó **SRP** xác thực trước, còn **ChaCha20-Poly1305** chỉ được thiết lập sau khi `ccsrp_server_verify_session` thành công. Bài viết công khai cho biết lỗi này đã được khắc phục trong **macOS Tahoe 26.6** (**ngày 27 tháng 7 năm 2026**).<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup>

Một mẫu hữu ích cần ghi nhớ là **stale-status parser bypass**: sau khi đọc thành công độ dài 4 byte, mọi nhánh xử lý dữ liệu quá lớn hoặc lỗi đều phải trả về một lỗi mới. Trên các bản build bị ảnh hưởng, độ dài frame SRP theo big-endian **`>= 32768`** khiến đường xử lý từ chối dùng lại trạng thái thành công trước đó của `NetBufferRead` (`0`), nên caller đánh dấu phiên đã xác thực dù chưa có bước xác minh mật khẩu nào chạy và cũng chưa thiết lập mã hóa truyền tải. Vì các byte chưa đọc vẫn nằm trong bộ đệm socket dùng chung, kẻ tấn công có thể **gửi nối tiếp dữ liệu SRP sai định dạng và các thông điệp RFB post-auth trong cùng một đợt TCP** để chúng được phân tích như **lưu lượng đã xác thực dạng cleartext**.<sup>[[8]](#references)</sup>

Sau khi bypass, thông điệp **sao chép tệp** độc quyền của Apple **`0x22`** trở thành **primitive đọc/ghi tệp dưới quyền root** vì `screensharingd` chạy dưới quyền root:<sup>[[8]](#references)</sup>

```text
[u8 0x22][u8 sub][be32 L]
[be16 ver][be16 kind][be32 sid][be32 arg]
[L-12 bytes payload]
```

- `kind=1` / `StartFileSend`: đọc file tùy ý
- `kind=2` / `StartFileReceive`: ghi file tùy ý
- Các giá trị `sid` khác nhau cho phép bạn pipeline nhiều giao dịch trong một kết nối
- Trong `kind=101` (`NewItem`), đặt byte `14` / `arg[0]` thành `0x01` để chỉ định file thông thường, offset payload `+42` thành kích thước file big-endian **khác 0**, và offset payload `+0x5a` thành Unix mode mong muốn (`0600` nếu nhắm đến crontab)

Các hướng khai thác tiếp theo thú vị sau khi ghi vào các đường dẫn có thể ghi bao gồm **`/etc/sudoers.d/`**, **`/etc/zshenv`**, **`/Library/LaunchDaemons/`** và **`/var/root/.ssh/authorized_keys`**. **SIP không ngăn được auth bypass hoặc đọc file với quyền root**, nhưng chặn một số mục tiêu ghi như **`/var/at`**, vì vậy thực thi dựa trên cron chỉ hoạt động khi tắt SIP. Trên các máy chủ mặc định có bật SIP, hãy nghĩ theo hướng **"ghi file với quyền root vào các file đặc quyền được tự động sử dụng"** thay vì thực thi mã ngay lập tức.<sup>[[8]](#references)</sup>

Một lỗi SRP khác trong cùng nghiên cứu: máy chủ phải xác thực **`A mod N != 0`** (theo RFC 5054), không chỉ kiểm tra `A > 0`. Chấp nhận **`A = N`** có thể ép shared secret về 0 và làm suy yếu quá trình xác minh mật khẩu.<sup>[[8]](#references)</sup><sup>[[10]](#references)</sup>

**Ý tưởng phát hiện**

- Các phiên Security type `36` có độ dài frame SRP đầu tiên **`>= 32768`**
- Các phiên bắt đầu xử lý lưu lượng sao chép file dạng cleartext **`0x22`** trước khi có SRP proof thành công / cài đặt cipher
- Các lần thử lại ngắn liên tiếp nhắm vào **TCP/5900**, cùng nhiều giá trị `sid` sao chép file trong một đợt
- Việc tạo bất thường các file **`/etc/zshenv`**, **`/etc/sudoers.d/*`**, **`/Library/LaunchDaemons/*.plist`** hoặc **`/var/root/.ssh/authorized_keys`** sau khi Screen Sharing bị lộ

### Pentesting Remote Apple Events (RAE / EPPC)

Apple gọi tính năng này là **Remote Application Scripting** trong System Settings hiện đại. Bên dưới, tính năng này cung cấp Apple Event Manager từ xa qua **EPPC** trên **TCP/3031**, thông qua dịch vụ `com.apple.AEServer`. Palo Alto Unit 42 một lần nữa nhấn mạnh đây là một primitive **di chuyển ngang trên macOS** thực tế, vì thông tin đăng nhập hợp lệ cùng dịch vụ RAE được bật cho phép operator điều khiển các ứng dụng có thể script trên máy Mac từ xa.<sup>[[6]](#references)</sup>

Các bước kiểm tra hữu ích:

```bash
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo launchctl print-disabled system | grep AEServer
lsof -nP -iTCP:3031 -sTCP:LISTEN
```

Nếu bạn đã có quyền admin/root trên mục tiêu và muốn bật tính năng này:

```bash
sudo /usr/sbin/systemsetup -setremoteappleevents on
```

Kiểm tra kết nối cơ bản từ một máy Mac khác:

```bash
osascript -e 'tell application "Finder" of machine "eppc://user:pass@192.0.2.10" to get name of startup disk'
```

Trong thực tế, trường hợp lạm dụng không chỉ giới hạn ở Finder. Bất kỳ **ứng dụng có thể lập trình** nào chấp nhận các Apple events cần thiết đều trở thành bề mặt tấn công từ xa, khiến RAE đặc biệt đáng chú ý sau khi thông tin xác thực bị đánh cắp trên các mạng macOS nội bộ.

#### Các lỗ hổng gần đây trong Chia sẻ màn hình / ARD (2023-2025)

| Năm | CVE | Thành phần | Tác động | Đã khắc phục trong |
|------|-----|-----------|----------|----------|
|2023|CVE-2023-42940|Chia sẻ màn hình|Hiển thị phiên không chính xác có thể khiến *sai* màn hình nền hoặc cửa sổ được truyền đi, dẫn đến rò rỉ thông tin nhạy cảm|macOS Sonoma 14.2.1 (Dec 2023) <sup>[[3]](#references)</sup>|
|2024|CVE-2024-44248|Máy chủ Chia sẻ màn hình|Người dùng có quyền truy cập chia sẻ màn hình có thể xem **màn hình của người dùng khác** do sự cố quản lý trạng thái|macOS Ventura 13.7.2 / Sonoma 14.7.2 / Sequoia 15.1 (Oct-Dec 2024) <sup>[[7]](#references)</sup>|

**Mẹo tăng cường bảo mật**

* Tắt *Chia sẻ màn hình*/*Quản lý từ xa* khi không thực sự cần thiết.
* Luôn cập nhật macOS đầy đủ (Apple thường phát hành bản sửa lỗi bảo mật cho ba phiên bản chính gần nhất).
* Dùng **Mật khẩu mạnh** *và* nếu có thể, tắt tùy chọn *“VNC viewers may control screen with password”*.
* Đặt dịch vụ sau VPN thay vì để lộ TCP 5900/3283 ra Internet.
* Thêm quy tắc Application Firewall để giới hạn `ARDAgent` trong mạng con cục bộ:

  ```bash
  sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
  sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
  ```

---

## Giao thức Bonjour

Bonjour, công nghệ do Apple thiết kế, cho phép **các thiết bị trên cùng một mạng phát hiện những dịch vụ mà thiết bị khác cung cấp**. Còn được gọi là Rendezvous, **Zero Configuration** hoặc Zeroconf, công nghệ này cho phép thiết bị tham gia mạng TCP/IP, **tự động chọn một địa chỉ IP** và quảng bá các dịch vụ của mình đến những thiết bị khác trên mạng.

Zero Configuration Networking do Bonjour cung cấp đảm bảo rằng các thiết bị có thể:

- **Tự động nhận địa chỉ IP** ngay cả khi không có máy chủ DHCP.
- Thực hiện **chuyển đổi tên thành địa chỉ** mà không cần máy chủ DNS.
- **Khám phá các dịch vụ** có trên mạng.

Các thiết bị sử dụng Bonjour sẽ tự gán cho mình **một địa chỉ IP thuộc dải 169.254/16** và xác minh địa chỉ đó là duy nhất trên mạng. Máy Mac duy trì một mục trong bảng định tuyến cho subnet này; có thể xác minh bằng lệnh `netstat -rn | grep 169`.

Đối với DNS, Bonjour sử dụng **giao thức Multicast DNS (mDNS)**. mDNS hoạt động trên **cổng 5353/UDP**, dùng **các truy vấn DNS tiêu chuẩn** nhưng gửi đến **địa chỉ multicast 224.0.0.251**. Cách này đảm bảo tất cả thiết bị đang lắng nghe trên mạng đều có thể nhận và phản hồi các truy vấn, giúp cập nhật bản ghi của chúng.

Khi tham gia mạng, mỗi thiết bị tự chọn một tên, thường kết thúc bằng **.local**; tên này có thể được tạo từ hostname hoặc sinh ngẫu nhiên.

Việc khám phá dịch vụ trong mạng được thực hiện bằng **DNS Service Discovery (DNS-SD)**. Tận dụng định dạng của bản ghi DNS SRV, DNS-SD dùng **bản ghi DNS PTR** để liệt kê nhiều dịch vụ. Máy khách cần tìm một dịch vụ cụ thể sẽ yêu cầu bản ghi PTR cho `<Service>.<Domain>` và nhận về danh sách bản ghi PTR có định dạng `<Instance>.<Service>.<Domain>` nếu dịch vụ đó được nhiều host cung cấp.

Có thể dùng tiện ích `dns-sd` để **khám phá và quảng bá các dịch vụ mạng**. Sau đây là một số ví dụ sử dụng:

### Tìm kiếm dịch vụ SSH

Để tìm kiếm dịch vụ SSH trên mạng, hãy dùng lệnh sau:

```bash
dns-sd -B _ssh._tcp
```

Lệnh này bắt đầu tìm kiếm các dịch vụ \_ssh.\_tcp và xuất thông tin chi tiết như dấu thời gian, cờ, giao diện, miền, loại dịch vụ và tên phiên bản.

### Quảng bá dịch vụ HTTP

Để quảng bá dịch vụ HTTP, bạn có thể dùng:

```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```

Lệnh này đăng ký một dịch vụ HTTP có tên "Index" trên cổng 80 với đường dẫn `/index.html`.

Sau đó, để tìm kiếm các dịch vụ HTTP trên mạng:

```bash
dns-sd -B _http._tcp
```

Khi một dịch vụ khởi chạy, nó thông báo khả năng cung cấp dịch vụ của mình cho tất cả thiết bị trong subnet bằng cách multicast sự hiện diện. Các thiết bị quan tâm đến những dịch vụ này không cần gửi yêu cầu mà chỉ cần lắng nghe các thông báo đó.

Để có giao diện thân thiện hơn, ứng dụng **Discovery - DNS-SD Browser** có trên Apple App Store có thể hiển thị các dịch vụ được cung cấp trên mạng cục bộ của bạn.

Ngoài ra, bạn có thể viết các script tùy chỉnh để duyệt và khám phá dịch vụ bằng thư viện `python-zeroconf`. Script [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) minh họa cách tạo trình duyệt dịch vụ cho các dịch vụ `_http._tcp.local.`, đồng thời in ra các dịch vụ được thêm hoặc xóa:

```python
from zeroconf import ServiceBrowser, Zeroconf

class MyListener:

    def remove_service(self, zeroconf, type, name):
        print("Service %s removed" % (name,))

    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        print("Service %s added, service info: %s" % (name, info))

zeroconf = Zeroconf()
listener = MyListener()
browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
try:
    input("Press enter to exit...\n\n")
finally:
    zeroconf.close()
```

### Săn tìm Bonjour dành riêng cho macOS

Trên các mạng macOS, Bonjour thường là cách dễ nhất để tìm **các bề mặt quản trị từ xa** mà không cần tương tác trực tiếp với mục tiêu. Bản thân Apple Remote Desktop có thể phát hiện các máy khách thông qua Bonjour, vì vậy cùng dữ liệu khám phá này cũng hữu ích cho kẻ tấn công.

```bash
# Enumerate every advertised service type first
dns-sd -B _services._dns-sd._udp local

# Then look for common macOS admin surfaces
dns-sd -B _rfb._tcp local      # Screen Sharing / VNC
dns-sd -B _ssh._tcp local      # Remote Login
dns-sd -B _eppc._tcp local     # Remote Apple Events / EPPC

# Resolve a specific instance to hostname, port and TXT data
dns-sd -L "<Instance>" _rfb._tcp local
dns-sd -L "<Instance>" _eppc._tcp local
```

Để tìm hiểu thêm về các kỹ thuật mDNS spoofing, giả mạo và khám phá giữa các subnet, hãy xem trang chuyên biệt:

{{#ref}}
../../network-services-pentesting/5353-udp-multicast-dns-mdns.md
{{#endref}}

### Liệt kê Bonjour qua mạng

* **Nmap NSE** – khám phá các dịch vụ được một máy chủ quảng bá:

  ```bash
  nmap -sU -p 5353 --script=dns-service-discovery <target>
  ```

  Script `dns-service-discovery` gửi truy vấn `_services._dns-sd._udp.local`, sau đó liệt kê từng loại dịch vụ được quảng bá.

* **mdns_recon** – Công cụ Python quét toàn bộ các dải mạng để tìm các bộ phản hồi mDNS *cấu hình sai* có trả lời truy vấn unicast (hữu ích để tìm các thiết bị có thể truy cập qua các subnet/WAN):

  ```bash
  git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
  python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
  ```

  Thao tác này sẽ trả về các host cho phép truy cập SSH qua Bonjour từ bên ngoài liên kết cục bộ. 

### Các cân nhắc về bảo mật và lỗ hổng gần đây (2024-2025)

| Năm | CVE | Mức độ nghiêm trọng | Vấn đề | Đã vá trong |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Trung bình|Lỗi logic trong *mDNSResponder* cho phép một packet được tạo có chủ đích kích hoạt **denial-of-service**|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (Sep 2024) <sup>[[4]](#references)</sup>|
|2025|CVE-2025-31222|Cao|Lỗi về tính đúng đắn trong *mDNSResponder* có thể bị khai thác để **local privilege escalation**|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (May 2025) <sup>[[5]](#references)</sup>|

**Hướng dẫn giảm thiểu**

1. Giới hạn UDP 5353 trong phạm vi *link-local* – chặn hoặc giới hạn tốc độ trên các wireless controller, router và firewall trên host.
2. Tắt hoàn toàn Bonjour trên các hệ thống không cần khám phá dịch vụ:

   ```bash
   sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
   ```
3. Đối với các môi trường cần Bonjour nội bộ nhưng tuyệt đối không được để lưu lượng vượt qua ranh giới mạng, hãy sử dụng các hạn chế hồ sơ *AirPlay Receiver* (MDM) hoặc proxy mDNS.
4. Bật **System Integrity Protection (SIP)** và luôn cập nhật macOS – cả hai lỗ hổng trên đều nhanh chóng được vá, nhưng cần bật SIP để được bảo vệ đầy đủ.

### Tắt Bonjour

Nếu có lo ngại về bảo mật hoặc các lý do khác để tắt Bonjour, có thể tắt bằng lệnh sau:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```

## References

- [1] [Cẩm nang của hacker Mac](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [LockBoxx - Red Teaming macOS 206: ARD (Giao thức Apple Remote Desktop)](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [3] [NVD – CVE-2023-42940](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [4] [NVD – CVE-2024-44183](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)
- [5] [NVD – CVE-2025-31222](https://nvd.nist.gov/vuln/detail/CVE-2025-31222)
- [6] [Palo Alto Unit 42 - Di chuyển ngang trên macOS: Các kỹ thuật độc đáo và phổ biến cùng ví dụ ngoài thực tế](https://unit42.paloaltonetworks.com/unique-popular-techniques-lateral-movement-macos/)
- [7] [Apple Support - Giới thiệu về nội dung bảo mật của macOS Sonoma 14.7.2](https://support.apple.com/en-us/121840)
- [8] [RCE trước xác thực của Apple Screen Sharing](https://warez.sl0p.foo/apple-screensharing-rce/)
- [9] [Apple Support - Giới thiệu về nội dung bảo mật của macOS Tahoe 26.6](https://support.apple.com/en-us/128067)
- [10] [RFC 5054 - Sử dụng giao thức Secure Remote Password (SRP) để xác thực TLS](https://www.rfc-editor.org/rfc/rfc5054)
- [11] [Nghệ thuật phân tích malware trên Mac, Tập I: Phân tích - Patrick Wardle](https://taomm.org/)
{{#include ../../banners/hacktricks-training.md}}
