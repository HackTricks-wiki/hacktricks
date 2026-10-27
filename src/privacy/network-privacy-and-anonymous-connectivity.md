# Quyền riêng tư mạng & kết nối ẩn danh

{{#include ../banners/hacktricks-training.md}}

Quyền riêng tư mạng là một quyết định định tuyến, không phải danh tính hoàn chỉnh. Hãy chọn đường đi bằng cách cân nhắc ai không nên liên kết được **nguồn**, **đích**, **nội dung** và **thời điểm**.

Để xem danh mục đã chuẩn hóa — gồm `Pros`, `Cons`, `Procedure` từng bước và `Detection` cho mọi nhóm đường truy cập — hãy bắt đầu với [Danh mục kỹ thuật truy cập Internet ẩn danh](anonymous-internet-access-techniques.md). Trang này mở rộng các lựa chọn phổ biến có thể triển khai.

## Những gì mỗi bên quan sát thường có thể thấy

| Đường truy cập | Mạng cục bộ / ISP | Bên trung gian | Đích | Hạn chế chính | Tốc độ tương đối |
|---|---|---|---|---|---|
| HTTPS trực tiếp | Nguồn, metadata đích, thời điểm/lưu lượng | Nhà cung cấp dịch vụ hosting/CDN thấy kết nối | IP nguồn, dữ liệu trình duyệt/ứng dụng | Không bảo vệ quyền riêng tư của IP nguồn | Nhanh nhất |
| VPN thương mại | Nguồn kết nối đến VPN; thường không thấy metadata đích | VPN thấy nguồn và metadata đích | IP thoát của VPN | Một nhà cung cấp trở thành điểm tương quan | Thường nhanh |
| VPN/VPS tự host | Nguồn kết nối đến VPS | Nhật ký máy chủ/tài khoản/thanh toán/control plane | IP thoát của VPS | Dễ bị quy về máy chủ/tài khoản đã thuê | Thường nhanh |
| Tor Browser | Nguồn kết nối đến Tor/bridge; thời điểm/lưu lượng | Mỗi relay chỉ thấy một phần giới hạn | Tor exit, dữ liệu trình duyệt | Chậm hơn; có rủi ro về tài khoản/endpoint/tương quan | Trung bình/chậm |
| Tails/Whonix | Đường đi Tor tương tự, với ranh giới định tuyến chặt chẽ hơn | Cùng các hạn chế của Tor | Tor exit/dữ liệu ứng dụng | Sai sót vận hành và máy chủ/phần cứng vẫn là rủi ro | Trung bình/chậm |
| Wi-Fi khách công cộng + HTTPS | Địa điểm thấy thiết bị cục bộ/thời điểm và đích | ISP của địa điểm thấy metadata | IP công cộng của khách | Tương quan về vị trí thực/captive portal/thiết bị | Nhanh/thay đổi |
| Điểm phát sóng di động | Nhà mạng thấy thuê bao/thiết bị/vị trí và đích | VPN/Tor nếu có sử dụng | IP thoát của nhà mạng, VPN hoặc Tor | Thuê bao di động và vị trí là định danh lâu dài | Nhanh/thay đổi |
| Mixnet | Mạng truy cập thấy việc sử dụng mixnet; thời điểm/lưu lượng | Nhiều nút trộn | Gateway/điểm thoát | Hệ sinh thái mới phát triển; tốn độ trễ và băng thông | Chậm nhất |

HTTPS bảo vệ nội dung khi truyền tải nhưng không bảo vệ mọi metadata. EFF lưu ý rằng tên miền, thời điểm và kích thước lưu lượng vẫn có thể hiển thị với các bên trung gian, ngay cả khi đường dẫn trang, thông tin xác thực và tin nhắn đã được mã hóa.<sup>[[1]](#references)</sup>

## VPN: quyền riêng tư nhanh chóng nhưng niềm tin tập trung

VPN hữu ích để ẩn metadata đích khỏi ISP cung cấp kết nối, bảo vệ chặng đầu tiên trên mạng không đáng tin cậy, cung cấp địa chỉ thoát ổn định cho một chiến dịch, hoặc truy cập mạng riêng. VPN **không** khiến người dùng trở nên ẩn danh. VPN thấy kết nối nguồn và có thể quan sát metadata đích; tài khoản, cookie, GPS, dấu vân tay và thông tin thanh toán vẫn còn.<sup>[[1]](#references)</sup>

### Danh sách kiểm tra đánh giá nhà cung cấp

1. **Quyền sở hữu và khu vực pháp lý:** xác định pháp nhân, công ty mẹ, quốc gia hoạt động, nhà thầu phụ hạ tầng và quy trình pháp lý áp dụng.
2. **Dữ liệu được thu thập:** phân biệt dữ liệu tài khoản/thanh toán, IP nguồn, dấu thời gian kết nối, băng thông, telemetry lỗi, truy vấn DNS và nhật ký đích. “Không lưu nhật ký duyệt web” không có nghĩa là “không có dữ liệu”.
3. **Thời gian lưu giữ và xóa:** tìm hiểu thời hạn chính xác và liệu bản sao lưu, hệ thống chống gian lận và bên xử lý có tuân theo cùng lịch trình hay không.
4. **Bằng chứng:** ưu tiên các cuộc kiểm toán công khai có phạm vi, ngày thực hiện, phát hiện và biện pháp khắc phục rõ ràng; client có mã nguồn mở/có thể tái tạo; báo cáo minh bạch; và sự cố được ghi nhận.
5. **Giao thức và client:** WireGuard, OpenVPN hoặc giao thức khác được duy trì và đánh giá; tự động cập nhật; xử lý DNS và IPv6; kill switch; và kiểm tra leak trên từng nền tảng.
6. **Mô hình kinh doanh:** tìm hiểu cách dịch vụ miễn phí hoặc được trợ giá tạo doanh thu. Việc có mặt trên app store không phải bằng chứng cho thấy dịch vụ đáng tin cậy.
7. **Phương thức thanh toán phù hợp:** phương thức thanh toán thay thế có thể giảm tiết lộ thông tin thanh toán cho VPN, nhưng không xóa IP nguồn được quan sát ở mỗi lần kết nối.

### Cấu hình và xác minh VPN

1. Cài client đã được ký của nhà cung cấp/tổ chức từ nguồn chính thức.
2. Chọn **full tunnel**, trừ khi có tuyến đã được ghi nhận rõ ràng cần bỏ qua VPN. Split tunneling tạo ra các đường tương quan và leak.
3. Bật chế độ fail-closed/always-on và chặn lưu lượng khi kết nối lại.
4. Chuyển DNS qua tunnel và kiểm tra cả IPv4 lẫn IPv6. Chỉ tắt một giao thức nếu không thể tunnel an toàn và đã chấp nhận việc mất chức năng.
5. Kiểm tra chế độ ngủ/thức, chuyển mạng, đăng nhập captive portal, tunnel bị lỗi và chia sẻ kết nối hotspot. NCSC cảnh báo rằng trên một số nền tảng, các client kết nối qua tethering có thể bỏ qua VPN trên điện thoại.<sup>[[2]](#references)</sup>
6. Dùng endpoint kiểm tra do tổ chức kiểm soát để ghi nhận IPv4, IPv6, DNS resolver và thời điểm kết nối được quan sát. Không đưa một chiến dịch nhạy cảm lên các trang “kiểm tra leak” ngẫu nhiên.
7. Kiểm tra lại sau khi thay đổi client, OS, mạng hoặc chính sách.

### Bỏ qua định tuyến trên mạng LAN nguy hiểm

VPN có thể vẫn hiển thị trạng thái “đã kết nối” trong khi một số gói tin được gửi vòng qua VPN, vì hệ điều hành chọn tuyến **trước** khi VPN mã hóa gói tin. TunnelCrack đã chứng minh hai cách khai thác các ngoại lệ định tuyến phổ biến: **LocalNet** khiến một đích Internet có vẻ nằm trong subnet kết nối trực tiếp, còn **ServerIP** giả mạo kết quả phân giải VPN gateway để một địa chỉ đích kế thừa ngoại lệ mạng không mã hóa mà VPN transport cần. Đây là lỗi ở client/định tuyến, không phải lỗ hổng của WireGuard, OpenVPN, IPsec hoặc TLS; payload HTTPS vẫn được mã hóa đầu cuối, nhưng bên quan sát cục bộ có thể khôi phục metadata đích/thời điểm và mọi dữ liệu giao thức dạng cleartext.<sup>[[18]](#references)</sup>

TunnelVision áp dụng cùng nguyên lý trước mã hóa thông qua DHCP option 121. Máy chủ DHCP độc hại hoặc bị xâm nhập có thể cài một tuyến classless cụ thể hơn tuyến mặc định bắt tất cả của VPN, chọn giao diện vật lý cho một máy chủ hoặc dải tùy ý. Kênh điều khiển VPN vẫn có thể hoạt động, vì vậy kill switch chỉ được kích hoạt khi tunnel ngắt kết nối có thể không chạy, và một lần kiểm tra “IP leak” công khai có thể bỏ sót việc bỏ qua VPN có chọn lọc.<sup>[[19]](#references)</sup>

Kill switch dùng bộ lọc gói, chỉ cho phép DHCP và VPN transport đã xác thực trên giao diện vật lý, nên biến tình huống này thành fail-closed. Tuy nhiên, việc chèn tuyến có chủ đích vẫn có thể tạo ra side channel từ chối dịch vụ có chọn lọc. Với workload Linux có hậu quả nghiêm trọng, hãy ưu tiên [mẫu network namespace ép buộc tuyến mạnh hơn](advanced-network-privacy-architectures.md#enforce-the-route-per-workload), trong đó namespace của ứng dụng không có giao diện vật lý hoặc tuyến mặc định qua mạng không mã hóa.<sup>[[19]](#references)</sup>

#### Xác minh trong lab do bạn sở hữu

Kiểm tra chính xác client/OS/version trên AP, DHCP server, VPN endpoint và đích do bạn sở hữu; các tuyên bố về sản phẩm nhanh chóng lỗi thời vì việc triển khai định tuyến và bộ lọc gói khác nhau theo nền tảng. Hãy capture trên chính endpoint cũng như máy chủ kiểm tra — chỉ dùng một website kiểm tra IP thoát không chứng minh được rằng mọi đích đều đi qua tunnel.<sup>[[18]](#references)[[19]](#references)</sup>

1. Kết nối VPN, ghi lại địa chỉ VPN server và lưu mọi bảng định tuyến IPv4/IPv6 cùng các quy tắc định tuyến theo chính sách. Trên Windows dùng `route print`; trên macOS dùng `netstat -rn`; trên Linux dùng các lệnh bên dưới.
2. Truy vấn tuyến được chọn cho một số IP đích do bạn sở hữu. Hop/giao diện kế tiếp phải là tunnel, ngoại trừ endpoint VPN transport đã được ghi nhận.
3. Với TunnelVision, gia hạn lease trên mạng DHCP được kiểm soát và cài tuyến option 121 **chỉ cho một đích kiểm tra do bạn sở hữu**. Đạt yêu cầu nếu lưu lượng vẫn đi qua tunnel hoặc bị chặn — tuyệt đối không được phát ra giao diện vật lý dưới dạng lưu lượng đến đích.
4. Với LocalNet, gán cho client một subnet tài liệu công khai chỉ dùng trong lab, chẳng hạn `203.0.113.0/24`, rồi đặt đích kiểm tra do bạn sở hữu trong subnet đó. Xác minh rằng bật quyền truy cập LAN không khiến các đích thuộc Internet bỏ qua tunnel.
5. Với ServerIP, trước khi kết nối VPN, dùng DNS được kiểm soát để phân giải hostname VPN do bạn sở hữu thành đích kiểm tra do bạn sở hữu, trong khi gateway của lab chuyển tiếp VPN transport đến VPN endpoint thực do bạn sở hữu. Client không được miễn định tuyến cho lưu lượng ứng dụng không liên quan đến địa chỉ giả mạo đó.
6. Lặp lại khi bật và tắt “local network access”, sau khi kết nối lại, ngủ/thức, chuyển mạng và VPN process bị lỗi. Kiểm tra riêng IPv4, IPv6 và DNS.
7. Kiểm tra bản capture trên giao diện vật lý. Bản capture chỉ nên chứa DHCP và các gói được mã hóa gửi đến VPN server, không có gói gửi trực tiếp đến đích kiểm tra do bạn sở hữu. Đồng thời xác nhận rằng một yêu cầu bỏ qua bị từ chối không thể âm thầm chuyển sang đường khác sau lời nhắc của người dùng hoặc quá trình khôi phục kết nối.

```bash
# Run route monitoring and capture in separate terminals.
TEST_IP=203.0.113.10 # replace with the owned test endpoint
ip -4 route show table all
ip -6 route show table all
ip route get "$TEST_IP"
ip monitor route
sudo tcpdump -ni any "host $TEST_IP"
```

## Tor Browser: tính khó liên kết hoạt động web cao hơn

Tor thiết lập một mạch qua nhiều relay để thông thường không relay đơn lẻ nào biết cả nguồn lẫn đích. Đích nhìn thấy một Tor exit thay vì IP của người dùng; mạng cục bộ thường chỉ thấy kết nối Tor.<sup>[[3]](#references)</sup> Tor được thiết kế cho các ứng dụng TCP có độ trễ thấp, nên chậm hơn và không thể bảo đảm bảo vệ trước đối thủ có khả năng tương quan hai đầu.<sup>[[4]](#references)</sup>

### Quy trình sử dụng Tor Browser an toàn

1. Chỉ tải Tor Browser từ Tor Project hoặc mirror chính thức và xác minh chữ ký nếu có thể.
2. Dùng **Tor Browser**, không dùng trình duyệt thông thường trỏ đến cổng SOCKS của Tor. Trình duyệt thông thường có thể làm lộ DNS/WebRTC và trạng thái nhận dạng.<sup>[[5]](#references)</sup>
3. Giữ nguyên kích thước, phông chữ, tiện ích mở rộng và cài đặt quyền riêng tư mặc định. Các add-on bổ sung có thể khiến trình duyệt dễ bị nhận dạng hơn.<sup>[[6]](#references)</sup>
4. Chọn mức bảo mật **Safer** hoặc **Safest** nếu chấp nhận được việc một số chức năng có thể bị hỏng.
5. Dùng bridge khi Tor trực tiếp bị chặn hoặc khi IP relay thông thường tạo ra mức độ lộ diện trên mạng cục bộ không thể chấp nhận. Bridge giảm khả năng bị nhận diện dễ dàng; chúng không loại bỏ phân tích lưu lượng.<sup>[[7]](#references)</sup>
6. Không đăng nhập vào tài khoản có thể nhận dạng bạn, cung cấp thông tin nhận dạng hoặc mở tài liệu chủ động đã tải xuống bằng ứng dụng bên ngoài có kết nối mạng.
7. Dùng phiên/ngữ cảnh riêng cho từng danh tính. “New circuit” không tương đương với xóa danh tính của trình duyệt/ứng dụng; hãy dùng **New Identity** hoặc khởi động lại môi trường được cô lập nếu phù hợp.
8. Ưu tiên HTTPS có xác thực hoặc onion service có xác thực. Tor exit có thể quan sát lưu lượng HTTP không mã hóa.

### Tor kết hợp VPN

Kết hợp hai công nghệ này không tự động an toàn hơn. VPN trước Tor có thể che các kết nối trực tiếp đến Tor relay khỏi ISP, trong khi VPN biết nguồn; Tor trước VPN khiến VPN có góc nhìn ổn định về hoạt động sau Tor và có thể thu hẹp tập ẩn danh. Cấu hình sai có thể gây leak. Tor Project chỉ khuyến nghị các kết hợp này cho threat model rõ ràng, nâng cao.<sup>[[8]](#references)</sup>

## Wi-Fi công cộng và Wi-Fi dành cho khách

HTTPS hiện đại có nghĩa là những người ở gần thụ động thường không thể đọc nội dung web được mã hóa đúng cách, nhưng Wi-Fi dành cho khách không tạo ra tính ẩn danh. Địa điểm có thể ghi lại thời điểm kết nối, mã định danh thiết bị, dữ liệu captive portal, đích kết nối và thông tin DHCP; camera, giao dịch mua sắm, phương tiện di chuyển và việc quan sát trực tiếp có thể nhận dạng người dùng. Hotspot giả có tên tương tự cũng có thể thu thập thông tin đăng nhập portal hoặc thao túng lưu lượng không mã hóa.<sup>[[9]](#references)</sup>

### Quy trình sử dụng mạng dành cho khách hợp pháp

1. Chỉ sử dụng mạng dành cho khách hoặc mạng mà chủ sở hữu đã cho phép rõ ràng. Hỏi nhân viên để biết chính xác SSID và quy trình portal.
2. Cập nhật thiết bị đầu cuối và travel router trước khi đến. Tắt chia sẻ tệp/máy in, khám phá thiết bị đến, tự động kết nối và dò tìm các mạng đã ghi nhớ.
3. Bật địa chỉ Wi-Fi riêng/ngẫu nhiên của hệ điều hành. Các hệ thống Apple hiện tại có thể dùng địa chỉ luân phiên trên mạng mở/yếu; tính năng ngẫu nhiên hóa của Android hiện đại thường giữ nguyên địa chỉ theo từng SSID. Cách này chỉ giảm một mã định danh cục bộ.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Ưu tiên travel router do tổ chức kiểm soát hoặc thiết bị cầu nối có mức độ tin cậy thấp giữa máy trạm đặc quyền và mạng dành cho khách. Cách này tập trung chính sách firewall/VPN nhưng không che travel router khỏi địa điểm đó.<sup>[[12]](#references)</sup>
5. Chỉ hoàn tất captive portal bằng thiết bị/trình duyệt được chỉ định có mức độ tin cậy thấp. Không bao giờ nhập thông tin đăng nhập cá nhân hoặc thông tin được dùng lại vào ngữ cảnh được cho là ẩn danh. Đóng trình duyệt portal sau khi kết nối mạng thành công.
6. Khởi chạy VPN full-tunnel hoặc Tor trước khi thực hiện hoạt động nhạy cảm và xác nhận cơ chế fail-closed hoạt động.
7. Xóa mạng khỏi danh sách đã lưu sau khi sử dụng và xem lại chính sách tài khoản portal/lưu giữ dữ liệu.

{% hint style="danger" %}
Bẻ khóa Wi-Fi của hàng xóm, vượt qua portal, dùng thông tin đăng nhập dành cho khách bị leak, sao chép quyền truy cập của khách khác hoặc giấu Raspberry Pi trong quán cà phê là hoạt động trái phép — không phải kỹ thuật bảo vệ quyền riêng tư. Các lựa chọn an toàn tương ứng là mạng dành cho khách hợp pháp, địa điểm được khách hàng phê duyệt hoặc drop node đã được ghi chép, đặt và thu hồi với sự đồng ý bằng văn bản của chủ sở hữu tài sản.
{% endhint %}

## Travel router

Travel router có thể cô lập máy trạm khỏi các broadcast cục bộ độc hại, thực thi firewall, cung cấp SSID nội bộ nhất quán và tự động kết nối lại VPN. Nó **không** tạo ra tính ẩn danh: mạng upstream thấy danh tính vô tuyến và thời điểm lưu lượng, còn nhà cung cấp VPN thấy nguồn của tunnel.

- Dùng firmware OpenWrt/nhà cung cấp được hỗ trợ và gỡ bỏ các dịch vụ không sử dụng.
- Quản trị qua Ethernet hoặc SSID quản lý riêng có mật khẩu duy nhất.
- Tắt quản trị từ phía WAN, UPnP, WPS, chia sẻ tệp và lưu lượng inbound không được yêu cầu.
- Chỉ dùng MAC WAN ngẫu nhiên/riêng khi được hỗ trợ và cho phép.
- Thực thi chính sách VPN trên router, bao gồm DNS và IPv6, đồng thời chặn lưu lượng đi ra khi tunnel gặp sự cố.
- Không cho rằng hotspot điện thoại sẽ chuyển tiếp thiết bị tether qua VPN của điện thoại; hãy kiểm tra.

## Mạng di động, SIM và eSIM

Mạng di động tiện lợi nhưng không ẩn danh. Nhà mạng lưu mã định danh thuê bao/thiết bị và vị trí suy ra từ việc thiết bị kết nối mạng; eSIM vẫn là một thuê bao di động. Trả trước không đồng nghĩa chắc chắn với việc không cần đăng ký — yêu cầu khác nhau theo quốc gia và có thể thay đổi.<sup>[[13]](#references)</sup>

Về vận hành:

- Dùng thiết bị riêng được hỗ trợ để giảm mức độ lộ dữ liệu cá nhân, không phải để tạo ra một thuê bao hư cấu.
- Không mang theo liên tục thiết bị “riêng” bên cạnh điện thoại cá nhân nếu threat model xét đến việc xác định các thiết bị ở cùng một địa điểm.
- Tắt mạng di động, Wi-Fi, Bluetooth và quyền truy cập vị trí nếu không dùng; tắt nguồn tạo ranh giới vô tuyến mạnh hơn các nút bật/tắt trong giao diện.
- Đưa lưu lượng nhạy cảm qua đường dẫn VPN/Tor được phê duyệt, đồng thời lưu ý nhà mạng vẫn biết thuê bao/vị trí thiết bị và điểm cuối tunnel.
- Xác minh các quy định hiện hành về đăng ký và lưu giữ dữ liệu với cơ quan quản lý quốc gia hoặc luật sư địa phương; không dựa vào danh sách “quốc gia có SIM ẩn danh” trên mạng.

## Metadata DNS và TLS

- **DoH/DoT/DoQ** mã hóa DNS giữa máy khách và resolver, ngăn việc đọc hoặc sửa đổi đơn giản trên mạng cục bộ, nhưng resolver vẫn thấy truy vấn và mã định danh ở lớp truyền tải. Chúng chuyển nơi đặt niềm tin; không tạo ra tính ẩn danh.<sup>[[14]](#references)</sup>
- **ODoH** thêm proxy để resolver không cần biết IP máy khách, với giả định proxy và đích không thông đồng. Phân tích lưu lượng nằm ngoài phạm vi bảo vệ được tuyên bố.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)** có thể bảo vệ tên máy chủ bên trong quá trình bắt tay TLS khi máy khách, DNS và máy chủ đều hỗ trợ. IP đích, thời điểm, dung lượng và thiết bị đầu cuối vẫn hiển thị.<sup>[[16]](#references)</sup>
- Trong môi trường VPN hoặc Tor được cấu hình đúng, DNS cần đi theo đường dẫn được môi trường đó hỗ trợ. Thêm resolver riêng có thể tạo ra một bên quan sát mới hoặc một dấu vân tay mới.

### Quy trình xác minh DNS mã hóa/ECH

1. Quyết định DNS được kiểm soát bởi môi trường VPN/Tor, hệ điều hành hay ứng dụng. Cấu hình ở **một** lớp dự kiến thay vì xếp chồng các resolver không liên quan.
2. Chọn resolver dựa trên chính sách quyền riêng tư/lưu giữ dữ liệu đã công bố và bật chế độ mã hóa nghiêm ngặt nếu nền tảng hỗ trợ. Cơ chế dự phòng linh hoạt có thể âm thầm quay về plaintext.
3. Truy vấn một subdomain duy nhất trong vùng kiểm thử có thẩm quyền do bạn kiểm soát; xác nhận log có thẩm quyền ghi nhận recursive resolver dự kiến.
4. Chỉ capture lưu lượng của thiết bị kiểm thử khi được ủy quyền. Xác nhận mạng truy cập không thể đọc DNS plaintext, đồng thời lưu ý mạng đó vẫn thấy điểm cuối của resolver/tunnel được mã hóa.
5. Kiểm tra khi resolver mã hóa bị chặn/không thể truy cập. Điều kiện đạt là hành vi fail-closed đã chọn hoặc cơ chế dự phòng được ghi nhận — không phải một truy vấn clear vô tình.
6. Với ECH, dùng máy chủ có bật ECH do bạn kiểm soát và kiểm tra chẩn đoán của máy khách/máy chủ để xác nhận **ClientHello bên trong** đã được chấp nhận. Chỉ cung cấp bản ghi HTTPS không chứng minh ECH hoạt động thành công.
7. Kiểm tra lại sau khi thay đổi mạng, dùng captive portal, cập nhật trình duyệt và kết nối lại VPN. Ghi lại thành phần nào quản lý DNS/ECH để quản trị viên sau này không vô tình tạo ra đường vòng.

## Mixnet

Mixnet như Nym hoặc Katzenpost bổ sung gói tin có kích thước cố định, độ trễ, sắp xếp lại thứ tự và lưu lượng che phủ nhằm chống tương quan thời điểm. Các thuộc tính này làm tăng độ trễ và tiêu tốn băng thông; bằng chứng độc lập ở quy mô triển khai còn hạn chế. Hãy xem mixnet dành cho người dùng hiện nay là **lựa chọn mới nổi/độ trễ cao**, không phải giải pháp thay thế cho Tor/VPN nhanh hơn hoặc được bảo đảm.<sup>[[17]](#references)</sup>

### Quy trình đánh giá

1. Xác định client đang được duy trì và ứng dụng cụ thể được hỗ trợ; không ép lưu lượng trình duyệt/hệ thống tùy ý đi qua proxy chưa được tài liệu hóa.
2. Đọc threat model hiện hành về các giả định liên quan đến entry, mix node, gateway, đích và việc thông đồng.
3. Cài đặt từ nguồn chính thức có chữ ký trong một môi trường kiểm thử riêng và chỉ dùng endpoint an toàn do bạn sở hữu.
4. Đo độ trễ gửi, giới hạn kích thước thông điệp, độ tin cậy, truyền lại và điều gì xảy ra khi gateway không khả dụng.
5. Kiểm tra lưu lượng cục bộ và endpoint do bạn sở hữu để xác nhận đường dẫn và nguồn dự kiến. Kiểm tra xem phản hồi có dùng cùng thiết kế bảo vệ quyền riêng tư hay không.
6. Kiểm tra khi tắt/gặp sự cố: ứng dụng không được âm thầm chuyển sang truy cập Internet trực tiếp.
7. Không tắt lưu lượng che phủ, giảm độ trễ hoặc chọn các tuyến cố định bất thường chỉ để tăng tốc; những thay đổi này có thể làm mất hiệu lực mô hình ẩn danh đã nêu.
8. Giữ ở trạng thái thử nghiệm cho đến khi việc triển khai cụ thể, phân tích độc lập và độ tin cậy vận hành đáp ứng mức độ hậu quả có thể xảy ra.

## Danh sách kiểm tra trước khi kết nối mạng

- [ ] Phạm vi ủy quyền bao gồm mạng truy cập, mục tiêu, thời gian và hạ tầng nguồn.
- [ ] Thiết bị đầu cuối không chứa danh tính không liên quan hoặc phiên đồng bộ đang hoạt động.
- [ ] IPv4, IPv6, DNS và hành vi kết nối lại phù hợp với kế hoạch.
- [ ] Việc chèn route DHCP/subnet cục bộ do bạn kiểm soát không thể chuyển lưu lượng kiểm thử sang giao diện vật lý.
- [ ] Đích chỉ nhìn thấy egress dự kiến.
- [ ] Hành vi captive portal và hotspot đã được kiểm tra mà không dùng lưu lượng nhạy cảm.
- [ ] Tắt chia sẻ/khám phá cục bộ và tự động kết nối mạng.
- [ ] Bảng các bên quan sát và rủi ro tương quan lưu lượng còn lại đã được chấp nhận.
- [ ] Chính sách nhà cung cấp, thời hạn lưu giữ và liên hệ khẩn cấp còn hiệu lực.

Để tìm hiểu về relay phân tách kiến thức, workload được thực thi tuyến đường, pluggable transport, onion service, I2P và trình duyệt từ xa dùng một lần, hãy tiếp tục đến [Kiến trúc bảo vệ quyền riêng tư mạng nâng cao](advanced-network-privacy-architectures.md).



## References

- [1] [EFF — Chọn VPN phù hợp với bạn](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Hướng dẫn bảo mật thiết bị: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Các biện pháp bảo vệ quyền riêng tư và tính ẩn danh mà Tor cung cấp](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Giới thiệu ngắn về Tor](https://spec.torproject.org/intro/)
- [5] [Tor Project — Sử dụng Tor với các trình duyệt khác](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Plugin và add-on trong Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Bỏ chặn Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — Sử dụng Tor Browser với VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Mạng Wi-Fi công cộng có an toàn không?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Quyền riêng tư Wi-Fi với thiết bị Apple](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — Triển khai MAC randomization](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Các nguyên tắc dành cho máy trạm truy cập đặc quyền an toàn](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Đăng ký SIM bắt buộc: góc nhìn chính sách và quy định](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — Khuyến nghị dành cho nhà vận hành dịch vụ DNS Privacy](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Threat Model](https://katzenpost.network/docs/threat_model/)
- [18] [Xue và cộng sự — Vượt qua tunnel: Làm lộ lưu lượng VPN Client bằng cách khai thác Routing Table](https://www.usenix.org/system/files/usenixsecurity23-xue.pdf)
- [19] [Leviathan Security — TunnelVision: Cách kẻ tấn công có thể làm lộ routing-based VPN để gây VPN leak toàn diện](https://www.leviathansecurity.com/blog/tunnelvision)
{{#include ../banners/hacktricks-training.md}}
