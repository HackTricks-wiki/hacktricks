# Mẹo Wireshark

{{#include ../../../banners/hacktricks-training.md}}

## Nâng cao kỹ năng Wireshark

### Hướng dẫn

Các hướng dẫn sau rất hữu ích để học một số mẹo cơ bản thú vị:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Thông tin đã phân tích

**Thông tin chuyên sâu**

Nhấp vào _**Analyze** --> **Expert Information**_ để xem **tổng quan** về những gì đang diễn ra trong các gói tin **được phân tích**:

![Hướng dẫn - Thông tin đã phân tích: Nhấp vào Analyze -- Expert Information để xem tổng quan về những gì đang diễn ra trong các gói tin được phân tích](<../../../images/image (256).png>)

**Địa chỉ đã phân giải**

Trong mục _**Statistics --> Resolved Addresses**_, bạn có thể tìm thấy nhiều **thông tin** được Wireshark "**phân giải**", chẳng hạn như cổng/giao thức truyền tải sang giao thức, MAC sang nhà sản xuất, v.v. Những thông tin này giúp xác định các thành phần liên quan đến giao tiếp.

![Hướng dẫn - Thông tin đã phân tích: Trong mục Statistics -- Resolved Addresses, bạn có thể tìm thấy nhiều thông tin được Wireshark " phân giải ", chẳng hạn như cổng/giao thức truyền tải sang giao thức, MAC sang...](<../../../images/image (893).png>)

**Phân cấp giao thức**

Trong mục _**Statistics --> Protocol Hierarchy**_, bạn có thể xem các **giao thức** **tham gia** vào giao tiếp cùng dữ liệu về chúng.

![Hướng dẫn - Thông tin đã phân tích: Trong mục Statistics -- Protocol Hierarchy, bạn có thể xem các giao thức tham gia vào giao tiếp cùng dữ liệu về chúng](<../../../images/image (586).png>)

**Các cuộc hội thoại**

Trong mục _**Statistics --> Conversations**_, bạn có thể xem **tóm tắt các cuộc hội thoại** trong giao tiếp cùng dữ liệu về chúng.

![Hướng dẫn - Thông tin đã phân tích: Trong mục Statistics -- Conversations, bạn có thể xem tóm tắt các cuộc hội thoại trong giao tiếp cùng dữ liệu về chúng](<../../../images/image (453).png>)

**Các endpoint**

Trong mục _**Statistics --> Endpoints**_, bạn có thể xem **tóm tắt các endpoint** trong giao tiếp cùng dữ liệu về từng endpoint.

![Hướng dẫn - Thông tin đã phân tích: Trong mục Statistics -- Endpoints, bạn có thể xem tóm tắt các endpoint trong giao tiếp cùng dữ liệu về từng endpoint](<../../../images/image (896).png>)

**Thông tin DNS**

Trong mục _**Statistics --> DNS**_, bạn có thể xem thống kê về các yêu cầu DNS được ghi lại.

![Hướng dẫn - Thông tin đã phân tích: Trong mục Statistics -- DNS, bạn có thể xem thống kê về các yêu cầu DNS được ghi lại](<../../../images/image (1063).png>)

**Biểu đồ I/O**

Trong mục _**Statistics --> I/O Graph**_, bạn có thể xem **biểu đồ giao tiếp.**

![Hướng dẫn - Thông tin đã phân tích: Trong mục Statistics -- I/O Graph, bạn có thể xem biểu đồ giao tiếp](<../../../images/image (992).png>)

### Bộ lọc

Tại đây, bạn có thể tìm bộ lọc Wireshark theo giao thức: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Trong các phiên bản Wireshark hiện tại, hãy dùng `tls.*` thay cho tên bộ lọc cũ `ssl.*`.<sup>[[1]](#references)</sup>\
Một số bộ lọc hữu ích khác:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
  - Lưu lượng HTTP và HTTPS ban đầu
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
  - Lưu lượng HTTP và HTTPS ban đầu + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
  - Lưu lượng HTTP và HTTPS ban đầu + TCP SYN + yêu cầu DNS
- `tls.handshake.extensions_server_name contains "example.com"`
  - Lọc theo SNI được gửi trong ClientHello, ngay cả khi bạn không thể giải mã payload
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
  - Nhanh chóng tách các phiên HTTPS thông thường, HTTP/2 và các phiên hỗ trợ HTTP/3
- `quic or http3`
  - Tìm lưu lượng UDP/443 hiện đại có thể bị bỏ sót nếu bạn chỉ xem các cuộc hội thoại TCP

### Tìm kiếm

Để **tìm kiếm** **nội dung** bên trong các **gói tin** của phiên, nhấn _CTRL+f_. Bạn có thể thêm các cột mới vào thanh thông tin chính (No., Time, Source, v.v.) bằng cách nhấp chuột phải rồi chọn chỉnh sửa cột.

### Theo dõi các luồng được ghép kênh

Wireshark có thể theo dõi trực tiếp các luồng `TLS`, `HTTP/2` và `QUIC`. Hộp thoại HTTP/2 và QUIC có bộ chọn kết nối và luồng con, giúp cô lập các luồng được ghép kênh dùng chung một kết nối ở tầng thấp hơn.<sup>[[4]](#references)</sup>

Khi có khóa phiên, trước tiên hãy xác định stream ID của yêu cầu, sau đó theo dõi luồng con đó thay vì toàn bộ cuộc hội thoại TCP hoặc UDP. Ví dụ `0,1` chọn stream ID 1 của HTTP/2 trên TCP stream 0; với QUIC, dùng `follow,quic,utf-8,<connection-number>,<stream-id>`. Chỉ theo dõi bộ năm giá trị có thể khiến các yêu cầu độc lập bị trộn lẫn hoặc bỏ sót kết nối QUIC sau khi di chuyển.<sup>[[6]](#references)[[7]](#references)[[9]](#references)</sup>

```bash
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -Y 'http2.headers.authority || http3.headers.authority' -T fields \
  -e tcp.stream -e http2.streamid -e quic.connection.number \
  -e quic.stream.stream_id -e http2.headers.authority \
  -e http3.headers.authority
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -q -z 'follow,http2,utf-8,0,1'
```

### Phòng lab pcap miễn phí

**Thực hành với các thử thách miễn phí tại:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Xác định Domain

Bạn có thể thêm một cột hiển thị HTTP Host header:

![Phòng lab pcap miễn phí - Xác định Domain: Bạn có thể thêm một cột hiển thị HTTP Host header](<../../../images/image (639).png>)

Và một cột hiển thị tên máy chủ từ kết nối HTTPS khởi tạo (**tls.handshake.type == 1**):

![Phòng lab pcap miễn phí - Xác định Domain: Và một cột hiển thị tên máy chủ từ kết nối HTTPS khởi tạo ( tls.handshake.type == 1 )](<../../../images/image (408) (1).png>)

Nếu phần lớn dữ liệu trong capture đã được mã hóa, việc thêm các trường này làm cột sẽ giúp tăng tốc quá trình triage đáng kể:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

Cách này cho phép bạn gom nhóm các phiên theo hostname, ALPN (`http/1.1`, `h2`, `h3`, v.v.) và fingerprint của client, ngay cả khi payload vẫn được mã hóa. Với các capture HTTP/2 và HTTP/3 đã giải mã, bạn cũng nên thêm `http2.header.value` hoặc `http3.headers.header.value` làm cột, rồi phân tích theo path, authority và các metadata đáng chú ý khác.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
  -e frame.number -e ip.src -e ip.dst \
  -e tls.handshake.extensions_server_name \
  -e tls.handshake.extensions_alpn_str \
  -e tls.handshake.ja3 -e tls.handshake.ja4
```

### ECH: đừng nhầm SNI bên ngoài với máy chủ gốc

Encrypted ClientHello (ECH) có thể đặt một tên che phủ công khai trong SNI bên ngoài hiển thị được, đồng thời mã hóa tên bên trong. Vì vậy, danh mục miền chỉ dựa trên SNI có thể quy lưu lượng ECH cho sai máy chủ gốc. Chỉ riêng extension ECH không chứng minh ECH đã hoạt động thành công: client có thể gửi extension GREASE ECH. Trên Wireshark 4.2+, hãy tìm các đề nghị ECH bên ngoài bằng bộ lọc sau và xem SNI được báo cáo là tên che phủ tiềm năng, không phải trang web được yêu cầu.<sup>[[5]](#references)[[8]](#references)</sup>

```bash
tshark -r capture.pcapng \
  -Y 'tls.handshake.type == 1 && tls.ech.client_hello_type == 0' \
  -T fields -e frame.number -e ip.dst \
  -e tls.handshake.extensions_server_name -e tls.ech.config_id
```

Nếu có các khóa phiên client tương ứng, hãy kiểm tra HTTP authority/Host đã giải mã thay vì suy đoán origin từ SNI bên ngoài. Nếu không có khóa, hãy kiểm tra bằng chứng khác về origin được ghi lại, chẳng hạn DNS dạng plaintext, nhưng đừng xem SNI bên ngoài là tên bị ẩn.<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -Y 'http.host || http2.headers.authority || http3.headers.authority' \
  -T fields -e ip.dst -e http.host \
  -e http2.headers.authority -e http3.headers.authority
```

## Nhận diện hostname cục bộ

### Từ DHCP

Trong Wireshark hiện tại, thay vì `bootp`, bạn cần tìm kiếm `DHCP`

![Nhận diện hostname cục bộ - Từ DHCP: Trong Wireshark hiện tại, thay vì bootp, bạn cần tìm kiếm DHCP](<../../../images/image (1013).png>)

### Từ NBNS

![Từ DHCP - Từ NBNS: Trong Wireshark hiện tại, thay vì bootp, bạn cần tìm kiếm DHCP](<../../../images/image (1003).png>)

## Giải mã TLS

Giải mã Wi-Fi ở tầng liên kết là quy trình riêng, không liên quan đến giải mã phiên TLS; xem [Phân tích Wi-Fi PCAP](wifi-pcap-analysis.md) để biết các yêu cầu về khóa và handshake.

### Giải mã lưu lượng https bằng private key của server

_edit > preferences > protocols > tls >_

![Giải mã TLS - Giải mã lưu lượng https bằng private key của server: Giải mã lưu lượng https bằng private key của server](<../../../images/image (1103).png>)

Nhấn _Edit_ và thêm toàn bộ dữ liệu của server cùng private key (_IP, Port, Protocol, Key file và password_)

Phương pháp này chỉ hoạt động trong một số trường hợp hạn chế. Với lưu lượng TLS 1.3 / ECDHE hiện nay, phương pháp ghi nhật ký session key bên dưới thường là lựa chọn thiết thực hơn.<sup>[[1]](#references)</sup>

### Giải mã lưu lượng https bằng symmetric session key

Cả Firefox và Chrome đều có khả năng ghi nhật ký TLS session key, có thể dùng với Wireshark để giải mã lưu lượng TLS. Điều này cho phép phân tích chuyên sâu các giao tiếp bảo mật. Hướng dẫn về cách thực hiện giải mã này có tại [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).<sup>[[3]](#references)</sup> Đây cũng là cách thông dụng để giải mã các capture TLS 1.3 và QUIC/HTTP/3 hiện đại.<sup>[[2]](#references)</sup>

Để phát hiện điều này, hãy tìm biến `SSLKEYLOGFILE` trong môi trường

Tệp chứa các khóa dùng chung sẽ có dạng như sau:

![Giải mã lưu lượng https bằng private key của server - Giải mã lưu lượng https bằng symmetric session key: Tệp chứa các khóa dùng chung sẽ có dạng như sau](<../../../images/image (820).png>)

Nếu capture ở định dạng `pcapng`, hãy kiểm tra xem nó đã chứa sẵn các bí mật giải mã được nhúng hay chưa trước khi tìm kiếm trong filesystem của host:<sup>[[1]](#references)</sup>

```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```

Để nhập nội dung này vào Wireshark, hãy vào _Chỉnh sửa > Tùy chọn > Giao thức > TLS > rồi nhập tệp vào mục Tên tệp nhật ký (Pre)-Master-Secret:

![Giải mã lưu lượng https bằng khóa riêng của máy chủ - Giải mã lưu lượng https bằng khóa phiên đối xứng: editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

## Giao tiếp ADB

Trích xuất APK từ phiên giao tiếp ADB đã gửi APK:

```python
from scapy.all import *

pcap = rdpcap("final2.pcapng")

def rm_data(data):
    splitted = data.split(b"DATA")
    if len(splitted) == 1:
        return data
    else:
        return splitted[0]+splitted[1][4:]

all_bytes = b""
for pkt in pcap:
    if Raw in pkt:
        a = pkt[Raw]
        if b"WRTE" == bytes(a)[:4]:
            all_bytes += rm_data(bytes(a)[24:])
        else:
            all_bytes += rm_data(bytes(a))
print(all_bytes)

f = open('all_bytes.data', 'w+b')
f.write(all_bytes)
f.close()
```

## References

- [1] [Wiki TLS của Wireshark](https://wiki.wireshark.org/TLS)
- [2] [Giải mã và phân tích lưu lượng HTTP/3 trong Wireshark](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)
- [3] [Giải mã lưu lượng trình duyệt TLS bằng Wireshark – Cách dễ dàng!](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)
- [4] [Theo dõi các luồng giao thức](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html)
- [5] [Tham chiếu bộ lọc hiển thị: Transport Layer Security](https://www.wireshark.org/docs/dfref/t/tls.html)
- [6] [Tham chiếu bộ lọc hiển thị: HyperText Transfer Protocol 2](https://www.wireshark.org/docs/dfref/h/http2.html)
- [7] [Tham chiếu bộ lọc hiển thị: Hypertext Transfer Protocol Version 3](https://www.wireshark.org/docs/dfref/h/http3.html)
- [8] [RFC 9849: TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [9] [Hướng dẫn sử dụng TShark](https://www.wireshark.org/docs/man-pages/tshark.html)
{{#include ../../../banners/hacktricks-training.md}}
