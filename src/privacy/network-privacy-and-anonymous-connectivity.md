# Quyền riêng tư mạng & Kết nối ẩn danh

{{#include ../banners/hacktricks-training.md}}

Quyền riêng tư mạng là một quyết định định tuyến, không phải danh tính hoàn chỉnh. Hãy chọn đường đi bằng cách xác định ai không nên biết **nguồn**, **đích**, **nội dung** và **thời điểm**.

Để xem danh mục chuẩn hóa — `Pros`, `Cons`, `Procedure` từng bước và `Detection` cho mỗi nhóm đường truy cập — hãy bắt đầu với [Danh mục kỹ thuật truy cập Internet ẩn danh](anonymous-internet-access-techniques.md). Trang này mở rộng các lựa chọn phổ biến có thể triển khai.

## Những gì mỗi bên quan sát thường có thể thấy

| Đường đi | Mạng cục bộ / ISP | Bên trung gian | Đích | Hạn chế chính | Tốc độ tương đối |
|---|---|---|---|---|---|
| HTTPS trực tiếp | Nguồn, metadata đích, thời điểm/lưu lượng | Nhà cung cấp hosting/CDN thấy kết nối | IP nguồn, dữ liệu trình duyệt/ứng dụng | Không bảo vệ quyền riêng tư của IP nguồn | Nhanh nhất |
| VPN thương mại | Nguồn kết nối với VPN; thường không thấy metadata đích | VPN thấy metadata nguồn và đích | IP egress của VPN | Một nhà cung cấp trở thành điểm tương quan | Thường nhanh |
| VPN/VPS tự lưu trữ | Nguồn kết nối với VPS | Nhật ký máy chủ/tài khoản/thanh toán/mặt phẳng điều khiển | IP egress của VPS | Dễ bị truy vết tới máy chủ/tài khoản thuê | Thường nhanh |
| Tor Browser | Nguồn kết nối với Tor/bridge; thời điểm/lưu lượng | Mỗi relay chỉ thấy một phần giới hạn | Tor exit, dữ liệu trình duyệt | Chậm hơn; có rủi ro về tài khoản/endpoint/tương quan | Trung bình/chậm |
| Tails/Whonix | Đường đi qua Tor tương tự, với ranh giới định tuyến chặt chẽ hơn | Cùng các hạn chế của Tor | Tor exit/dữ liệu ứng dụng | Lỗi vận hành và máy chủ/phần cứng vẫn là rủi ro | Trung bình/chậm |
| Wi-Fi khách công cộng + HTTPS | Địa điểm thấy thiết bị cục bộ/thời điểm và đích | ISP của địa điểm thấy metadata | IP công cộng của khách | Tương quan vật lý/cổng captive portal/thiết bị | Nhanh/thay đổi |
| Hotspot di động | Nhà mạng thấy thuê bao/thiết bị/vị trí và đích | VPN/Tor nếu được dùng | IP egress của nhà mạng, VPN hoặc Tor | Thuê bao di động và vị trí là các định danh lâu dài | Nhanh/thay đổi |
| Mixnet | Nhà cung cấp truy cập thấy việc sử dụng mixnet; thời điểm/lưu lượng | Nhiều nút trộn | Gateway/egress | Hệ sinh thái đang phát triển; tốn độ trễ và băng thông | Chậm nhất |

HTTPS bảo vệ nội dung khi truyền tải nhưng không bảo vệ toàn bộ metadata. EFF lưu ý rằng tên miền, thời gian và kích thước lưu lượng vẫn có thể hiển thị với các bên trung gian, ngay cả khi đường dẫn trang, thông tin xác thực và tin nhắn được mã hóa.<sup>[[1]](#references)</sup>

Một lớp phủ được mã hóa không tự động là mạng ẩn danh: các peer kết nối trực tiếp của Yggdrasil có thể thấy địa chỉ IP của nhau.<sup>[[20]](#references)</sup> [Chuyển tiếp ở userspace và truyền tải SOCKS](../generic-hacking/tunneling-and-port-forwarding.md#yggdrasil-userspace-overlay-with-yggstack) của nó là một lựa chọn tunneling, không phải lớp ẩn danh nguồn.<sup>[[20]](#references)[[21]](#references)</sup>

## VPN: quyền riêng tư nhanh với niềm tin tập trung

VPN hữu ích để ẩn metadata đích khỏi ISP cung cấp kết nối, bảo vệ hop đầu tiên trên mạng không đáng tin cậy, cung cấp địa chỉ egress ổn định cho đợt thực hiện, hoặc truy cập mạng riêng. VPN **không** khiến người dùng ẩn danh. VPN thấy kết nối nguồn và có thể quan sát metadata đích; tài khoản, cookie, GPS, dấu vân tay và thông tin thanh toán vẫn còn.<sup>[[1]](#references)</sup>

### Danh sách kiểm tra đánh giá nhà cung cấp

1. **Quyền sở hữu và thẩm quyền pháp lý:** xác định pháp nhân, công ty mẹ, quốc gia hoạt động, nhà thầu phụ hạ tầng và quy trình pháp lý áp dụng.
2. **Dữ liệu được thu thập:** phân biệt dữ liệu tài khoản/thanh toán, IP nguồn, dấu thời gian kết nối, băng thông, telemetry sự cố, truy vấn DNS và nhật ký đích. “Không ghi nhật ký duyệt web” không có nghĩa là “không thu thập dữ liệu”.
3. **Thời hạn lưu giữ và xóa:** tìm thời hạn cụ thể và xác định liệu bản sao lưu, hệ thống chống gian lận và bên xử lý có tuân thủ cùng lịch trình hay không.
4. **Bằng chứng:** ưu tiên các cuộc kiểm toán công khai có phạm vi, ngày thực hiện, phát hiện và biện pháp khắc phục; client mở/có thể tái lập; báo cáo minh bạch; và các sự cố được ghi nhận.
5. **Giao thức và client:** WireGuard, OpenVPN hoặc giao thức khác đã được đánh giá và còn được duy trì; cập nhật tự động; xử lý DNS và IPv6; kill switch; và kiểm tra leak trên từng nền tảng.
6. **Mô hình kinh doanh:** tìm hiểu cách dịch vụ miễn phí hoặc được trợ giá tạo nguồn thu. Chỉ xuất hiện trên app store không phải bằng chứng cho thấy dịch vụ đáng tin cậy.
7. **Phù hợp về thanh toán:** phương thức thanh toán thay thế có thể giảm tiết lộ thông tin thanh toán cho VPN nhưng không xóa IP nguồn được quan sát ở mỗi lần kết nối.

### Cấu hình và xác minh VPN

1. Cài client có chữ ký của nhà cung cấp/tổ chức từ nguồn chính thức.
2. Chọn **full tunnel**, trừ khi có tuyến được ghi nhận cần đi vòng qua VPN. Split tunneling tạo ra các đường tương quan và leak.
3. Bật chế độ fail-closed/always-on và chặn lưu lượng trong khi kết nối lại.
4. Định tuyến DNS qua tunnel và kiểm tra cả IPv4 lẫn IPv6. Chỉ tắt một giao thức nếu không thể tunnel an toàn và chấp nhận việc mất chức năng.
5. Kiểm tra chế độ ngủ/thức, chuyển mạng, đăng nhập captive portal, sự cố tunnel và chia sẻ kết nối qua hotspot. NCSC cảnh báo rằng trên một số nền tảng, các client kết nối qua hotspot có thể bỏ qua VPN trên điện thoại.<sup>[[2]](#references)</sup>
6. Dùng endpoint kiểm tra do tổ chức kiểm soát để ghi nhận IPv4, IPv6, DNS resolver và thời điểm kết nối quan sát được. Không đưa một đợt thực hiện nhạy cảm lên các trang “kiểm tra leak” ngẫu nhiên.
7. Kiểm tra lại sau khi thay đổi client, OS, mạng hoặc chính sách.

### Bỏ qua định tuyến trên mạng LAN không đáng tin cậy

VPN có thể vẫn hiển thị là “đã kết nối” trong khi một số gói tin bỏ qua tunnel, vì hệ điều hành chọn tuyến **trước khi** VPN mã hóa gói tin. TunnelCrack đã chứng minh hai cách khai thác các ngoại lệ định tuyến phổ biến: **LocalNet** khiến đích Internet có vẻ nằm trong subnet được kết nối trực tiếp, còn **ServerIP** giả mạo việc phân giải VPN gateway để một địa chỉ đích nhận ngoại lệ mạng rõ mà giao thức VPN cần. Đây là lỗi của client/định tuyến, không phải lỗ hổng của WireGuard, OpenVPN, IPsec hay TLS; payload HTTPS vẫn được mã hóa đầu cuối, nhưng bên quan sát cục bộ có thể khôi phục metadata đích/thời điểm và mọi dữ liệu giao thức dạng rõ.<sup>[[18]](#references)</sup>

TunnelVision áp dụng cùng nguyên lý trước khi mã hóa thông qua DHCP option 121. Máy chủ DHCP độc hại hoặc bị xâm nhập có thể cài đặt một tuyến không phân lớp cụ thể hơn tuyến bao quát của VPN, chọn giao diện vật lý cho một máy chủ hoặc dải tùy ý. Kênh điều khiển VPN có thể vẫn hoạt động, vì vậy kill switch chỉ được kích hoạt khi tunnel ngắt kết nối có thể không bật; một lần kiểm tra “IP leak” công khai cũng có thể bỏ sót việc bỏ qua có chọn lọc.<sup>[[19]](#references)</sup>

Kill switch dùng bộ lọc gói, chỉ cho phép DHCP và giao thức VPN đã xác thực trên giao diện vật lý, sẽ chuyển tình huống này sang fail-closed. Tuy nhiên, việc chèn tuyến có mục tiêu vẫn có thể tạo ra kênh side-channel từ chối dịch vụ có chọn lọc. Với các workload Linux có hậu quả nghiêm trọng nếu xảy ra sự cố, hãy ưu tiên [mô hình network namespace ép buộc định tuyến](advanced-network-privacy-architectures.md#enforce-the-route-per-workload) chặt chẽ hơn, trong đó namespace ứng dụng không có giao diện vật lý hoặc tuyến mặc định mạng rõ.<sup>[[19]](#references)</sup>

#### Xác minh trong lab do bạn sở hữu

Kiểm tra đúng client/OS/phiên bản trên AP, DHCP server, VPN endpoint và đích do bạn sở hữu; các tuyên bố áp dụng cho toàn bộ sản phẩm nhanh chóng lỗi thời vì cách triển khai định tuyến và bộ lọc gói khác nhau theo nền tảng. Ghi lại lưu lượng trên chính endpoint cũng như trên máy chủ kiểm tra — chỉ riêng một trang web hiển thị IP egress không chứng minh rằng mọi đích đều đi qua tunnel.<sup>[[18]](#references)[[19]](#references)</sup>

1. Kết nối VPN, ghi lại địa chỉ VPN server và lưu mọi bảng định tuyến IPv4/IPv6 cùng quy tắc định tuyến theo chính sách. Trên Windows dùng `route print`; trên macOS dùng `netstat -rn`; trên Linux dùng các lệnh bên dưới.
2. Truy vấn tuyến được chọn cho một số IP đích do bạn sở hữu. Hop/interface kế tiếp phải là tunnel, ngoại trừ endpoint truyền tải VPN đã được ghi nhận.
3. Với TunnelVision, gia hạn lease trên mạng DHCP được kiểm soát và cài đặt tuyến option 121 **chỉ cho một đích kiểm tra do bạn sở hữu**. Đạt yêu cầu khi lưu lượng vẫn được tunnel hoặc bị chặn — tuyệt đối không phát ra dưới dạng lưu lượng hướng tới đích qua giao diện vật lý.
4. Với LocalNet, gán cho client một subnet tài liệu công khai chỉ dùng trong lab, chẳng hạn `203.0.113.0/24`, rồi đặt đích kiểm tra do bạn sở hữu trong subnet đó. Xác minh rằng bật quyền truy cập LAN không khiến các đích thuộc Internet bỏ qua tunnel.
5. Với ServerIP, trước khi kết nối VPN, hãy để DNS được kiểm soát phân giải hostname VPN do bạn sở hữu thành đích kiểm tra do bạn sở hữu, trong khi gateway của lab chuyển tiếp lưu lượng VPN tới VPN endpoint thực do bạn sở hữu. Client không được miễn trừ lưu lượng ứng dụng không liên quan tới địa chỉ giả mạo.
6. Lặp lại khi bật và tắt “truy cập mạng cục bộ”, sau khi kết nối lại, ngủ/thức, chuyển mạng và sự cố tiến trình VPN. Kiểm tra riêng IPv4, IPv6 và DNS.
7. Kiểm tra bản ghi trên giao diện vật lý. Bản ghi chỉ nên có DHCP và các gói mã hóa gửi tới VPN server, không có gói gửi trực tiếp tới đích kiểm tra do bạn sở hữu. Đồng thời xác nhận rằng việc chặn lưu lượng bỏ qua không thể âm thầm chuyển sang phương án dự phòng sau lời nhắc của người dùng hoặc quá trình khôi phục kết nối.

```bash
# Run route monitoring and capture in separate terminals.
TEST_IP=203.0.113.10 # replace with the owned test endpoint
ip -4 route show table all
ip -6 route show table all
ip route get "$TEST_IP"
ip monitor route
sudo tcpdump -ni any "host $TEST_IP"
```

## Tor Browser: tăng cường tính không thể liên kết khi duyệt web

Tor tạo một circuit qua nhiều relay để thông thường không relay nào biết cả nguồn lẫn đích. Đích sẽ thấy một Tor exit thay vì IP của người dùng; mạng cục bộ thường chỉ thấy kết nối Tor.<sup>[[3]](#references)</sup> Tor được thiết kế cho các ứng dụng TCP có độ trễ thấp, nên chậm hơn và không thể đảm bảo bảo vệ trước đối thủ có khả năng tương quan lưu lượng ở cả hai đầu.<sup>[[4]](#references)</sup>

### Quy trình sử dụng Tor Browser an toàn

1. Chỉ tải Tor Browser từ Tor Project hoặc mirror chính thức, và xác minh chữ ký nếu có thể.
2. Dùng **Tor Browser**, không dùng trình duyệt thông thường trỏ đến cổng SOCKS của Tor. Trình duyệt thông thường có thể làm lộ DNS/WebRTC và các dấu vết nhận dạng.<sup>[[5]](#references)</sup>
3. Giữ nguyên kích thước, phông chữ, extension và cài đặt quyền riêng tư mặc định. Add-on bổ sung có thể khiến trình duyệt trở nên độc nhất hơn.<sup>[[6]](#references)</sup>
4. Chọn mức bảo mật **Safer** hoặc **Safest** nếu có thể chấp nhận việc một số chức năng bị lỗi.
5. Dùng bridge khi Tor bị chặn kết nối trực tiếp hoặc khi việc để lộ các IP relay thông thường trên mạng cục bộ là không thể chấp nhận. Bridge khiến việc nhận diện dễ dàng khó hơn; chúng không loại bỏ được phân tích lưu lượng.<sup>[[7]](#references)</sup>
6. Không đăng nhập vào tài khoản có thể nhận dạng bạn, cung cấp thông tin nhận dạng, hoặc mở tài liệu chủ động đã tải xuống bằng ứng dụng bên ngoài có kết nối mạng.
7. Dùng phiên/ngữ cảnh riêng cho từng danh tính. “New circuit” không đồng nghĩa với việc xóa danh tính của trình duyệt/ứng dụng; hãy dùng **New Identity** hoặc khởi động lại môi trường cô lập khi phù hợp.
8. Ưu tiên HTTPS có xác thực hoặc onion service có xác thực. Tor exit có thể quan sát lưu lượng HTTP không mã hóa.

### Tor kết hợp VPN

Kết hợp hai công cụ này không tự động an toàn hơn. Dùng VPN trước Tor có thể che giấu các kết nối trực tiếp đến Tor relay khỏi ISP, trong khi VPN biết nguồn kết nối; dùng Tor trước VPN khiến VPN có thể theo dõi ổn định hoạt động sau Tor và làm thu hẹp tập ẩn danh. Cấu hình sai có thể gây leak. Tor Project chỉ khuyến nghị các kết hợp như vậy cho threat model rõ ràng, dành cho người dùng nâng cao.<sup>[[8]](#references)</sup>

## Wi-Fi công cộng và Wi-Fi dành cho khách

HTTPS hiện đại đồng nghĩa với việc những người xung quanh thụ động thường không thể đọc nội dung web được mã hóa đúng cách, nhưng Wi-Fi dành cho khách không mang lại tính ẩn danh. Địa điểm có thể ghi lại thời điểm kết nối, định danh thiết bị, dữ liệu cổng captive portal, đích kết nối và thông tin DHCP; camera, giao dịch mua hàng, phương tiện di chuyển và quan sát trực tiếp có thể nhận dạng người dùng. Điểm phát sóng giả có tên tương tự cũng có thể thu thập thông tin đăng nhập captive portal hoặc can thiệp vào lưu lượng không mã hóa.<sup>[[9]](#references)</sup>

### Quy trình sử dụng mạng dành cho khách hợp pháp

1. Chỉ sử dụng mạng được cung cấp cho khách hoặc mạng mà chủ sở hữu đã cho phép rõ ràng. Hỏi nhân viên SSID chính xác và quy trình sử dụng portal.
2. Cập nhật thiết bị đầu cuối và travel router trước khi đến. Tắt chia sẻ tệp/máy in, khám phá thiết bị đến, tự động kết nối và dò tìm các mạng đã ghi nhớ.
3. Bật địa chỉ Wi-Fi riêng/ngẫu nhiên của hệ điều hành. Các hệ thống Apple hiện tại có thể dùng địa chỉ luân phiên trên mạng mở/yếu; tính năng ngẫu nhiên hóa trên Android hiện đại thường giữ nguyên địa chỉ theo từng SSID. Cách này chỉ giảm một định danh cục bộ.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Ưu tiên travel router do tổ chức kiểm soát hoặc thiết bị cầu nối có mức độ tin cậy thấp, đặt giữa workstation có đặc quyền và mạng dành cho khách. Cách này tập trung chính sách firewall/VPN nhưng không che giấu router khỏi địa điểm đó.<sup>[[12]](#references)</sup>
5. Chỉ hoàn tất captive portal trên thiết bị/trình duyệt được chỉ định có mức độ tin cậy thấp. Không bao giờ nhập thông tin cá nhân hoặc thông tin đăng nhập đã tái sử dụng trong ngữ cảnh được cho là ẩn danh. Đóng trình duyệt portal sau khi kết nối mạng thành công.
6. Khởi chạy VPN full-tunnel hoặc Tor trước khi thực hiện hoạt động nhạy cảm và xác nhận cơ chế fail-closed hoạt động.
7. Quên mạng sau khi sử dụng và xem lại chính sách tài khoản portal/lưu giữ dữ liệu.

{% hint style="danger" %}
Bẻ khóa Wi-Fi của hàng xóm, vượt qua portal, sử dụng thông tin đăng nhập khách bị lộ, sao chép quyền truy cập của khách khác hoặc giấu Raspberry Pi trong quán cà phê là hoạt động trái phép — không phải kỹ thuật bảo vệ quyền riêng tư. Các lựa chọn an toàn tương đương là mạng dành cho khách hợp pháp, địa điểm được khách hàng chấp thuận hoặc drop node có tài liệu ghi nhận, được đặt và thu hồi khi có sự đồng ý bằng văn bản của chủ sở hữu tài sản.
{% endhint %}

## Travel router

Travel router có thể cô lập workstation khỏi các broadcast cục bộ độc hại, thực thi firewall, cung cấp SSID nội bộ nhất quán và tự động kết nối lại VPN. Nó **không** giúp ẩn danh: mạng upstream thấy danh tính vô tuyến và thời điểm lưu lượng, còn nhà cung cấp VPN thấy nguồn của tunnel.

- Dùng firmware OpenWrt/firmware của nhà cung cấp được hỗ trợ và gỡ bỏ các dịch vụ không sử dụng.
- Quản trị qua Ethernet hoặc SSID quản lý riêng với mật khẩu độc nhất.
- Tắt quản trị từ phía WAN, UPnP, WPS, chia sẻ tệp và lưu lượng inbound không được yêu cầu.
- Chỉ dùng WAN MAC ngẫu nhiên/riêng nếu được hỗ trợ và cho phép.
- Thực thi chính sách VPN trên router, bao gồm DNS và IPv6, đồng thời chặn lưu lượng ra ngoài khi tunnel lỗi.
- Không cho rằng hotspot điện thoại sẽ chuyển lưu lượng của thiết bị tether qua VPN trên điện thoại; hãy kiểm tra.

## Mạng di động, SIM và eSIM

Mạng di động tiện lợi nhưng không ẩn danh. Nhà mạng lưu giữ định danh thuê bao/thiết bị và vị trí suy ra từ kết nối mạng; eSIM vẫn là một thuê bao di động. Trả trước không đồng nghĩa chắc chắn với việc không đăng ký — quy định khác nhau giữa các quốc gia và có thể thay đổi.<sup>[[13]](#references)</sup>

Về vận hành:

- Dùng thiết bị riêng được hỗ trợ để giảm mức độ lộ dữ liệu cá nhân, không phải để tạo một thuê bao giả.
- Nếu threat model có xét đến việc xác định vị trí đồng thời, đừng luôn mang theo thiết bị “riêng” bên cạnh điện thoại cá nhân.
- Tắt mạng di động, Wi-Fi, Bluetooth và quyền truy cập vị trí khi không sử dụng; tắt nguồn tạo ranh giới vô tuyến chắc chắn hơn các nút bật/tắt trên giao diện.
- Đưa lưu lượng nhạy cảm qua VPN/Tor đã được phê duyệt, đồng thời lưu ý rằng nhà mạng vẫn biết thuê bao/vị trí thiết bị và endpoint của tunnel.
- Xác minh quy định hiện hành về đăng ký và lưu giữ dữ liệu với cơ quan quản lý quốc gia hoặc luật sư địa phương; đừng dựa vào các danh sách trực tuyến về “các quốc gia có SIM ẩn danh”.

## Siêu dữ liệu DNS và TLS

- **DoH/DoT/DoQ** mã hóa DNS giữa client và resolver, ngăn việc đọc hoặc sửa đổi đơn giản trên mạng cục bộ, nhưng resolver vẫn thấy truy vấn và định danh truyền tải. Chúng chỉ chuyển nơi đặt niềm tin; không mang lại tính ẩn danh.<sup>[[14]](#references)</sup>
- **ODoH** thêm một proxy để resolver không cần biết IP client, với giả định proxy và target không thông đồng. Phân tích lưu lượng nằm ngoài phạm vi bảo vệ được nêu rõ.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)** có thể bảo vệ tên máy chủ bên trong quá trình bắt tay TLS khi client, DNS và server hỗ trợ. IP đích, thời điểm, dung lượng lưu lượng và endpoint vẫn hiển thị.<sup>[[16]](#references)</sup>
- Trong môi trường VPN hoặc Tor được cấu hình đúng, DNS phải đi theo tuyến được môi trường đó hỗ trợ. Thêm resolver riêng có thể tạo ra một bên quan sát mới hoặc một dấu vân tay mới.

### Quy trình xác minh DNS mã hóa/ECH

1. Xác định DNS do môi trường VPN/Tor, hệ điều hành hay ứng dụng kiểm soát. Cấu hình tại **một** lớp dự định sử dụng thay vì xếp chồng các resolver không liên quan.
2. Chọn resolver dựa trên chính sách quyền riêng tư/lưu giữ dữ liệu đã công bố và bật chế độ mã hóa nghiêm ngặt nếu nền tảng hỗ trợ. Chuyển về chế độ dự phòng theo kiểu cơ hội có thể âm thầm quay lại DNS plaintext.
3. Truy vấn một subdomain duy nhất thuộc test zone có thẩm quyền mà bạn kiểm soát; xác nhận log có thẩm quyền ghi nhận recursive resolver dự kiến.
4. Chỉ thu thập traffic của thiết bị thử nghiệm khi được phép. Xác nhận mạng truy cập không thể đọc DNS plaintext, đồng thời lưu ý rằng mạng vẫn thấy endpoint của resolver mã hóa/tunnel.
5. Thử nghiệm khi resolver mã hóa bị chặn/không truy cập được. Điều kiện đạt là hành vi fail-closed đã chọn hoặc cơ chế fallback được ghi nhận — không phải một truy vấn clear vô tình.
6. Với ECH, dùng host có bật ECH do bạn kiểm soát và kiểm tra chẩn đoán client/server để xác nhận **inner** ClientHello đã được chấp nhận. Chỉ cung cấp một bản ghi HTTPS không chứng minh ECH đã hoạt động thành công.
7. Lặp lại sau khi thay đổi mạng, dùng captive portal, cập nhật trình duyệt và kết nối lại VPN. Ghi lại thành phần nào quản lý DNS/ECH để quản trị viên sau này không tạo ra đường vòng.

## Mixnet

Mixnet như Nym hoặc Katzenpost bổ sung packet có kích thước cố định, độ trễ, sắp xếp lại và lưu lượng che phủ để chống tương quan thời điểm. Các đặc tính này phải đánh đổi bằng độ trễ và băng thông, đồng thời bằng chứng độc lập ở quy mô triển khai còn hạn chế. Hãy coi mixnet dành cho người tiêu dùng hiện nay là **lựa chọn mới nổi/có độ trễ cao**, không phải phương án thay thế Tor/VPN nhanh hơn hoặc được đảm bảo.<sup>[[17]](#references)</sup>

### Quy trình đánh giá

1. Xác định client được duy trì và ứng dụng cụ thể được hỗ trợ; đừng ép lưu lượng tùy ý của trình duyệt/hệ thống đi qua một proxy không được tài liệu hóa.
2. Đọc threat model hiện tại về các giả định đối với entry, mix node, gateway, đích và việc thông đồng.
3. Cài đặt từ nguồn chính thức có chữ ký trong một ngăn thử nghiệm riêng và chỉ sử dụng endpoint lành tính do bạn sở hữu.
4. Đo độ trễ gửi, giới hạn kích thước thông điệp, độ tin cậy, việc truyền lại và hành vi khi gateway không khả dụng.
5. Kiểm tra lưu lượng cục bộ và endpoint do bạn sở hữu để xác nhận tuyến và nguồn dự kiến. Kiểm tra xem phản hồi có dùng cùng thiết kế bảo vệ quyền riêng tư hay không.
6. Thử nghiệm khi tắt/lỗi: ứng dụng không được âm thầm chuyển sang truy cập Internet trực tiếp.
7. Đừng tắt lưu lượng che phủ, giảm độ trễ hoặc chọn tuyến cố định khác thường chỉ để tăng tốc; những thay đổi này có thể làm mất hiệu lực mô hình ẩn danh đã nêu.
8. Giữ ở trạng thái thử nghiệm cho đến khi việc triển khai cụ thể, phân tích độc lập và độ tin cậy vận hành đáp ứng được mức độ hậu quả có thể xảy ra.

## Danh sách kiểm tra trước khi dùng mạng

- [ ] Quyền cho phép bao gồm mạng truy cập, mục tiêu, ngày thực hiện và hạ tầng nguồn.
- [ ] Endpoint không chứa danh tính không liên quan hoặc phiên đồng bộ đang hoạt động.
- [ ] IPv4, IPv6, DNS và hành vi kết nối lại khớp với kế hoạch.
- [ ] Việc đưa tuyến DHCP/subnet cục bộ có kiểm soát vào không thể chuyển lưu lượng thử nghiệm sang interface vật lý.
- [ ] Đích chỉ thấy egress dự kiến.
- [ ] Đã kiểm tra captive portal và hành vi hotspot mà không dùng lưu lượng nhạy cảm.
- [ ] Đã tắt tính năng chia sẻ/khám phá cục bộ và tự động tham gia mạng.
- [ ] Đã chấp nhận bảng bên quan sát và rủi ro còn lại về tương quan lưu lượng.
- [ ] Chính sách của nhà cung cấp, thời hạn lưu giữ và liên hệ khẩn cấp còn hiệu lực.

Để tìm hiểu về relay phân chia kiến thức, workload được áp đặt tuyến, pluggable transport, onion service, I2P và trình duyệt từ xa dùng một lần, hãy tiếp tục đến [Kiến trúc quyền riêng tư mạng nâng cao](advanced-network-privacy-architectures.md).



## References

- [1] [EFF — Chọn VPN phù hợp với bạn](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Hướng dẫn bảo mật thiết bị: Mạng riêng ảo](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Các biện pháp bảo vệ quyền riêng tư và tính ẩn danh mà Tor cung cấp](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Giới thiệu ngắn về Tor](https://spec.torproject.org/intro/)
- [5] [Tor Project — Sử dụng Tor với các trình duyệt khác](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Plugin và add-on trong Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Bỏ chặn Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — Sử dụng Tor Browser với VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Mạng Wi-Fi công cộng có an toàn không?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Quyền riêng tư Wi-Fi trên thiết bị Apple](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — Triển khai ngẫu nhiên hóa MAC](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Nguyên tắc dành cho workstation truy cập đặc quyền an toàn](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Đăng ký SIM bắt buộc: quan điểm về chính sách và quy định](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — Khuyến nghị dành cho nhà vận hành dịch vụ bảo mật DNS](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — DNS qua HTTPS ẩn danh](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Threat Model](https://katzenpost.network/docs/threat_model/)
- [18] [Xue và cộng sự — Vượt qua tunnel: Làm lộ lưu lượng của VPN client bằng cách lợi dụng bảng định tuyến](https://www.usenix.org/system/files/usenixsecurity23-xue.pdf)
- [19] [Leviathan Security — TunnelVision: Cách kẻ tấn công có thể làm lộ danh tính của VPN dựa trên định tuyến, gây leak VPN toàn diện](https://www.leviathansecurity.com/blog/tunnelvision)
- [20] [Yggdrasil FAQ: Yggdrasil có ẩn danh không?](https://yggdrasil-network.github.io/faq.html#is-yggdrasil-anonymous)
- [21] [Yggstack README](https://github.com/yggdrasil-network/yggstack)
{{#include ../banners/hacktricks-training.md}}
