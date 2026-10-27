# Phân tích Pcap Wifi

{{#include ../../../banners/hacktricks-training.md}}

## Kiểm tra BSSID

Khi mở bản capture Wi-Fi trong Wireshark, chọn _Wireless → WLAN Traffic_ để tổng hợp các mạng không dây được ghi nhận trong bản capture; mỗi hàng đại diện cho một mạng không dây.<sup>[[1]](#references)</sup>

![Phân tích Pcap Wifi - Kiểm tra BSSID: Khi nhận được một bản capture có lưu lượng chính là Wifi và sử dụng WireShark, bạn có thể bắt đầu kiểm tra tất cả SSID trong bản capture bằng Wireless --...](<../../../images/image (106).png>)

![Phân tích Pcap Wifi - Kiểm tra BSSID: Khi nhận được một bản capture có lưu lượng chính là Wifi và sử dụng WireShark, bạn có thể bắt đầu kiểm tra tất cả SSID trong bản capture bằng Wireless --...](<../../../images/image (492).png>)

### Brute Force

Với bản capture WPA/WPA2-PSK, `aircrack-ng` cần một four-way EAPOL handshake có thể sử dụng và thử các passphrase ứng viên bằng từ điển. Dùng `-w` để chỉ định wordlist và `-b` để nhắm mục tiêu BSSID của access point:<sup>[[2]](#references)</sup>

```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```

Nếu một ứng viên khớp, Aircrack-ng sẽ khôi phục pre-shared key; sau đó có thể cấu hình password và SSID khớp trong cài đặt giải mã 802.11 của Wireshark, nếu capture và chế độ bảo mật hỗ trợ.<sup>[[2]](#references)[[5]](#references)</sup>

## Dữ liệu trong Beacon / Side Channel

Nếu nghi ngờ **dữ liệu đang bị leak trong lưu lượng beacon-side-channel**, hãy bắt đầu bằng display filter như `wlan contains "NAMEofNETWORK"` hoặc `wlan.ssid == "NAMEofNETWORK"`, rồi kiểm tra các frame khớp để tìm chuỗi đáng ngờ. Cách đầu tiên tìm kiếm rộng trên byte; cách thứ hai khớp với trường SSID.<sup>[[3]](#references)[[4]](#references)</sup>

## Tìm địa chỉ MAC không xác định trong mạng Wi-Fi

Wireshark hiển thị `wlan.ta` là địa chỉ transmitter và `wlan.addr` là địa chỉ phần cứng/MAC; display filter có thể kết hợp các trường này bằng toán tử logic:<sup>[[3]](#references)[[4]](#references)</sup>

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Nếu đã biết **các địa chỉ MAC, hãy loại chúng khỏi kết quả** bằng cách thêm các điều kiện như `&& !(wlan.addr == 5c:51:88:31:a0:3b)`.

Sau khi phát hiện các địa chỉ **MAC không xác định** đang giao tiếp trong mạng, hãy dùng filter như `wlan.addr == <MAC address> && (ftp || http || ssh || telnet)` để thu hẹp lưu lượng của chúng. Các filter FTP, HTTP, SSH và Telnet chỉ hữu ích khi Wireshark có thể phân tích payload đã giải mã tương ứng.<sup>[[3]](#references)[[5]](#references)</sup>

## Giải mã lưu lượng

Để thêm khóa giải mã 802.11 trong Wireshark, mở _Edit → Preferences → Protocols → IEEE 802.11_ rồi nhấp _Edit_ cạnh _Decryption Keys_.<sup>[[5]](#references)</sup>

![Tìm địa chỉ MAC không xác định trong mạng Wi-Fi - Giải mã lưu lượng: Sau khi phát hiện các địa chỉ MAC không xác định đang giao tiếp trong mạng, bạn có thể dùng các filter như sau:...](<../../../images/image (499).png>)

Với WPA/WPA2, Wireshark thường cần EAPOL four-way handshake và password/SSID tương ứng; cung cấp transient key có thể giúp không cần handshake. Việc giải mã WPA3 cho từng kết nối yêu cầu PMK của kết nối đó.<sup>[[5]](#references)</sup>

Để giải mã TLS ở tầng ứng dụng sau khi khôi phục lưu lượng Wi-Fi, xem [mẹo Wireshark](wireshark-tricks.md#decrypting-tls).

## References

- [1] [Hướng dẫn sử dụng Wireshark: Lưu lượng WLAN](https://www.wireshark.org/docs/wsug_html_chunked/ChWirelessWLANTraffic.html)
- [2] [Aircrack-ng](https://www.aircrack-ng.org/doku.php?id=aircrack-ng)
- [3] [Hướng dẫn sử dụng Wireshark: Tạo biểu thức Display Filter](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)
- [4] [Tham chiếu Wireshark Display Filter: Mạng LAN không dây IEEE 802.11](https://www.wireshark.org/docs/dfref/w/wlan.html)
- [5] [Hướng dẫn sử dụng Wireshark: Khóa giải mã WLAN IEEE 802.11](https://www.wireshark.org/docs/wsug_html_chunked/Ch80211Keys.html)
{{#include ../../../banners/hacktricks-training.md}}
