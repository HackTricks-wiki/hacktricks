# Các kiến trúc quyền riêng tư mạng nâng cao

{{#include ../banners/hacktricks-training.md}}

Độ phức tạp chỉ hữu ích khi loại bỏ được một bên quan sát hoặc một kiểu lỗi cụ thể. Một chuỗi tunnel độc đáo, hình dạng gói tin tùy chỉnh, user agent hiếm gặp hoặc hạ tầng xoay vòng thường xuyên có thể trở thành dấu vân tay nổi bật hơn cấu hình tiêu chuẩn được hàng nghìn người sử dụng.

[Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) cung cấp schema chung `Pros`/`Cons`/`Procedure`/`Detection`. Trang này mở rộng các kiến trúc phức tạp hơn và ranh giới tin cậy.

Vì vậy, mục tiêu nâng cao là **phân tách thông tin**: không thành phần thông thường nào được đồng thời nắm danh tính người dùng, đích đến, bản rõ và lịch sử hoạt động dài hạn. Đây không phải là khả năng tàng hình; sự thông đồng, quy trình pháp lý, xâm phạm endpoint hoặc tương quan lưu lượng đầu cuối vẫn có thể tái dựng đường đi.

## Lựa chọn kiến trúc

| Mô hình | Đặc tính đạt được | Tin cậy/rủi ro mới | Trường hợp phù hợp |
|---|---|---|---|
| Tor Browser tiêu chuẩn | Dấu vân tay trình duyệt dùng chung và đường đi qua nhiều relay | Độ trễ thấp cho phép tương quan lưu lượng | Duyệt web ẩn danh nói chung |
| Tor bridge + pluggable transport | Làm cho việc chặn/phân loại Tor trực tiếp khó hơn | Bridge/transport vẫn có thể bị phát hiện; bridge biết nguồn | Mạng bị kiểm duyệt |
| Onion service | Ẩn IP của dịch vụ; tránh nút thoát; xác thực danh tính onion | Khóa onion và endpoint máy chủ trở thành tài sản trọng yếu | Xuất bản riêng tư, tiếp nhận thông tin hoặc quản trị |
| Relay ingress + egress độc lập | Thông thường không relay nào đơn lẻ thấy cả nguồn lẫn đích | Các bên vận hành có thể thông đồng; thời điểm lưu lượng đi qua cả hai | Ứng dụng được hỗ trợ, hiệu năng cao |
| Oblivious HTTP | Tách IP nguồn khỏi yêu cầu HTTP không trạng thái đã mã hóa | Cần ứng dụng, relay và gateway hỗ trợ | Telemetry, truy vấn, gửi thông tin không cần trạng thái phiên |
| Namespace workload chỉ dùng VPN | Kernel đảm bảo không có tuyến mạng rõ | VPN vẫn thấy cả hai đầu; vẫn phải tin cậy host/root | Công cụ trong hoạt động được cấp phép và egress cố định |
| Trình duyệt từ xa dùng một lần | Cô lập đích đến khỏi trình duyệt/endpoint cục bộ | Nhà cung cấp workspace thấy hoạt động và danh tính đăng nhập | Trang web/tệp không đáng tin cậy và nghiên cứu có kiểm soát |
| Dịch vụ nội bộ I2P | Tunnel vào/ra riêng biệt trên overlay; không có nút thoát chính thức | Hệ sinh thái nhỏ hơn/khác biệt; hành vi peer kéo dài | Dịch vụ chạy trên I2P, không phải giải pháp thay thế web thông thường |
| Mixnet/phân phối bất đồng bộ | Độ trễ, gom nhóm và lưu lượng che phủ chống phân tích thời điểm | Độ trễ cao, ứng dụng và độ trưởng thành hạn chế | Tin nhắn/tác vụ không cần tương tác |

## Relay phân tách thông tin

Mô hình relay do hai bên vận hành có thể vượt trội hơn một VPN đơn cho một ứng dụng giới hạn:

```text
client identity/IP
        |
 ingress relay -- sees client, not clear request/destination detail
        |
 encrypted request
        |
 egress gateway -- sees request/destination, not client IP
        |
 target service
```

Apple Private Relay là một ví dụ đã được triển khai: Apple vận hành ingress, trong khi một nhà cung cấp nội dung khác vận hành egress, vì vậy thông thường không bên nào thấy cả IP máy khách lẫn đích duyệt web.<sup>[[1]](#references)</sup> Đây là dịch vụ bảo mật Safari/DNS dành riêng cho sản phẩm, không phải mạng ẩn danh trên mọi thiết bị, và cố ý giữ lại thông tin vùng địa lý ở mức khái quát.

Oblivious HTTP (OHTTP) chuẩn hóa một mẫu ứng dụng hẹp hơn. Relay thấy máy khách và lưu lượng đã mã hóa đến gateway; gateway giải mã thông điệp HTTP nhưng chỉ thấy relay, không thấy máy khách. RFC 9458 cảnh báo rằng phương thức này cần relay/gateway sẵn sàng hỗ trợ, phù hợp nhất với các yêu cầu không có cookie/xác thực/trạng thái phiên, và không bảo đảm chống phân tích lưu lượng.<sup>[[2]](#references)</sup>

### Danh sách kiểm tra thiết kế

1. Xác định chính xác các thông điệp ứng dụng cần bảo vệ; không âm thầm proxy các phiên web đã xác thực bất kỳ.
2. Khi có thể, hãy dùng các tổ chức ingress và egress vận hành độc lập, với quản trị, thông tin xác thực, ghi nhật ký và quyền kiểm soát pháp lý riêng biệt.
3. Mã hóa yêu cầu ứng dụng gửi đến gateway để ingress không thể đọc được.
4. Loại bỏ các header chuyển tiếp bắt nguồn từ máy khách, mã định danh TLS và token ổn định theo từng người dùng ở lớp phù hợp.
5. Tránh khóa, cookie hoặc trường payload duy nhất có thể giúp gateway liên kết lại các yêu cầu dù luồng truyền tải đã được tách biệt.
6. Tổng hợp, giảm thiểu và đặt thời hạn xóa log ở cả hai phía; ghi lại rủi ro thông đồng và buộc cung cấp thông tin.
7. Chỉ đệm hoặc gom lô theo một giao thức đã được xem xét. Tự tạo cơ chế định hình lưu lượng có thể tạo ra dấu hiệu riêng mà vẫn không ngăn được việc tương quan.
8. Kiểm thử bằng các yêu cầu canary có kiểm soát và đối chiếu những gì máy khách, ingress, gateway và đích ghi lại.

Với hoạt động duyệt web tương tác thông thường, hãy dùng Tor Browser thay vì tự tạo proxy OHTTP riêng. OHTTP bảo vệ một giao dịch ứng dụng được hỗ trợ, không bảo vệ toàn bộ danh tính trình duyệt.

## Thực thi tuyến mạng cho từng workload

Kill switch chỉ dựa trên các tuyến host có thể thay đổi có thể bị lỗi khi gia hạn DHCP, sleep/wake, thay đổi IPv6 hoặc tunnel gặp sự cố. Một mẫu Linux mạnh hơn là chỉ cấp cho container hoặc network namespace một giao diện loopback và một giao diện tunnel. WireGuard ghi nhận rằng có thể tạo giao diện trong namespace vật lý, chuyển nó vào namespace workload, đồng thời giữ socket UDP đã mã hóa trong namespace ban đầu.<sup>[[3]](#references)</sup>

### Mẫu triển khai

1. Trước tiên, hãy thiết lập trên máy chủ dùng một lần/có console tại chỗ; sai sót về namespace có thể làm mất quyền truy cập từ xa.
2. Đặt giao diện Ethernet/Wi-Fi vật lý cùng DHCP/supplicant trong namespace **physical**.
3. Tạo giao diện WireGuard tại đó để socket truyền tải đã mã hóa có quyền truy cập mạng vật lý.
4. Chỉ chuyển giao diện WireGuard vào namespace **workload** và đặt nó làm tuyến mặc định duy nhất.
5. Cấp cho workload một resolver riêng theo namespace, chỉ có thể truy cập qua tunnel. Chủ động xử lý IPv6.
6. Chạy container trình duyệt/công cụ trong namespace đó, không dùng host networking, privileged capability, thư mục trình duyệt dùng chung hoặc agent thông tin xác thực cá nhân.
7. Dừng tunnel và xác minh workload không thể phân giải hoặc kết nối đến endpoint IPv4 hay IPv6 có kiểm soát.
8. Kiểm thử roaming endpoint, gia hạn DHCP, suspend/resume và xử lý captive portal bên ngoài namespace workload.
9. Ghi log hash cấu hình namespace/tunnel và địa chỉ egress được phê duyệt để phục vụ việc giải trình engagement.

Cách này **thực thi tuyến mạng**, không tạo ẩn danh trước VPN hoặc bastion của engagement. Host/root bị xâm nhập có thể kiểm tra hoặc thay đổi namespace.

## Tor bridge và pluggable transport

Bridge là các relay đầu vào Tor không công khai. Pluggable transport thay đổi lưu lượng ở hop đầu tiên để việc chặn đơn giản hoặc phân loại giao thức trở nên khó hơn. Chúng không bổ sung các lớp relay ẩn danh sau điểm vào và không đánh bại được đối tượng quan sát có khả năng tương quan thời gian trên phạm vi rộng hơn.

| Transport | Cách tiếp cận ở hop đầu tiên | Đánh đổi thực tế |
|---|---|---|
| **obfs4** | Làm lưu lượng trông ngẫu nhiên và chống thăm dò chủ động | Địa chỉ bridge đã biết vẫn có thể bị chặn |
| **Snowflake** | Dùng proxy WebRTC tình nguyện có vòng đời ngắn để kết nối đến bridge | Hiệu năng thay đổi; vẫn có các mẫu broker/STUN/WebRTC |
| **WebTunnel** | Truyền lưu lượng bridge trong một tunnel WebSocket giống HTTPS | Phụ thuộc vào web front có thể truy cập và vẫn có thể bị phân loại |

Tor Project mô tả Snowflake và WebTunnel là các transport vượt kiểm duyệt, không phải phương thức đảm bảo không thể phân biệt.<sup>[[4]](#references)</sup>

### Quy trình an toàn

1. Bắt đầu bằng kết nối trực tiếp của Tor Browser. Chỉ thêm bridge khi việc chặn hoặc khả năng bị quan sát trong mô hình đối tượng quan sát tại chỗ khiến điều đó cần thiết.
2. Dùng transport tích hợp sẵn hoặc bridge line lấy từ các kênh của Tor Project. Không tải binary transport ngẫu nhiên hoặc danh sách bridge công khai từ diễn đàn.
3. Thử lựa chọn được hỗ trợ ít phức tạp nhất nhưng vẫn kết nối ổn định; ghi lại lý do chọn.
4. Giữ Tor Browser ở cấu hình tiêu chuẩn. Bridge không khiến extension tự tạo, đăng nhập tài khoản hoặc cài đặt trình duyệt bất thường trở nên an toàn.
5. Kiểm thử kết nối lại và độ chính xác của đồng hồ. Không liên tục đổi transport theo cách gửi một chuỗi đặc trưng đến cùng một đối tượng quan sát tại chỗ.
6. Đánh giá lại nếu chính sách kiểm duyệt hoặc mạng thay đổi; việc sử dụng có thể tự nó nhạy cảm hoặc bị hạn chế tại một số địa điểm.

## Onion service làm điểm hẹn riêng tư

Onion service tạo các mạch Tor đi ra đến introduction point và rendezvous relay, nên không cần cổng inbound công khai và không làm lộ IP máy chủ qua giao thức onion. Lưu lượng từ máy khách đến dịch vụ luôn nằm trong Tor và địa chỉ onion xác thực khóa dịch vụ.<sup>[[5]](#references)</sup>

Với cổng tiếp nhận hợp pháp, kho mã riêng tư, giao diện quản trị hoặc nơi nhận bằng chứng của engagement:

1. Chạy ứng dụng trên host/VM chuyên dụng và bind vào loopback hoặc Unix socket cô lập.
2. Cài Tor từ repository chính thức và làm theo hướng dẫn thiết lập onion service v3 chính thức; không dùng hướng dẫn v2 lỗi thời.
3. Bảo vệ khóa riêng của onion service như khóa TLS/ký. Chỉ sao lưu nếu cần duy trì danh tính ổn định.
4. Thêm xác thực máy khách cho onion service đối với nhóm khép kín và gửi thông tin xác thực qua một kênh được xác thực độc lập.<sup>[[6]](#references)</sup>
5. Ngăn origin tải font, analytics, bản cập nhật hoặc webhook của bên thứ ba có thể làm lộ IP công khai hoặc tài khoản của người vận hành.
6. Thiết lập xác thực và phân quyền ngay trong ứng dụng; biết địa chỉ onion không đồng nghĩa với có quyền truy cập.
7. Vá lỗi, giới hạn tốc độ và giám sát dịch vụ mà không nhúng telemetry của bên thứ ba.
8. Từ một ngữ cảnh kiểm thử riêng, xác nhận rằng DNS, email, trang lỗi, metadata tệp và header phản hồi không tiết lộ origin.
9. Khi dùng cho red team, hãy liệt kê dịch vụ, chủ sở hữu, mục đích và thời điểm ngừng hoạt động trong ROE. Không dùng dịch vụ này để che giấu C2 ngoài phạm vi.

## Trình duyệt từ xa và workspace dùng một lần

Trình duyệt từ xa chuyển việc render và nội dung rủi ro ra khỏi endpoint cục bộ, đồng thời có thể cung cấp egress cloud dành riêng cho engagement. Nó bảo vệ thiết bị cục bộ khỏi một số nội dung và cơ chế lưu giữ; không khiến người vận hành ẩn danh trước nhà cung cấp workspace. Chẳng hạn, AWS ghi nhận việc thu thập dữ liệu portal, danh tính, chính sách, tùy chọn và log phiên, dù phiên bản trình duyệt dùng một lần bị loại bỏ khi phiên kết thúc.<sup>[[7]](#references)</sup>

Dùng một workspace do tổ chức kiểm soát cho mỗi engagement, hạn chế tải xuống/tải lên/clipboard, tắt các nhà cung cấp danh tính cá nhân, định tuyến egress cố định qua bastion được phê duyệt và hết hạn workspace sau khi xuất bằng chứng. Coi console của nhà cung cấp, IdP và quản trị viên là các đối tượng quan sát.

## I2P và overlay nội bộ

I2P xây dựng các tunnel inbound và outbound một chiều riêng biệt, không có exit ở tầng mạng chính thức; mạng này chủ yếu dành cho các dịch vụ bên trong I2P.<sup>[[8]](#references)</sup> Đây không phải cách duyệt Internet công cộng nhanh hơn có thể thay thế trực tiếp. Outproxy tạo ra một điểm cần tin cậy, còn mô hình mối đe dọa chính thức nêu rõ cần nghiên cứu thêm và không tuyên bố đảm bảo ẩn danh tuyệt đối.

Chỉ dùng I2P khi cả hai đầu đều chủ động hỗ trợ, cô lập router hoạt động lâu dài khỏi các ứng dụng cá nhân và hiểu rằng peer/mạng cục bộ có thể quan sát việc tham gia I2P. Không tăng số hop hoặc tinh chỉnh lựa chọn peer nếu không có căn cứ: cài đặt bất thường có thể làm giảm hiệu năng và thu hẹp tập ẩn danh.

## Vận hành chống tương quan

- Ưu tiên cấu hình client phổ biến, được hỗ trợ thay vì bản dựng riêng biệt.
- Tách biệt danh tính tại endpoint; không cấu trúc định tuyến nào khắc phục được việc dùng lại tài khoản, thanh toán, khôi phục hoặc nội dung.
- Với tác vụ không tương tác, ưu tiên giao thức bất đồng bộ/mixnet đã được xem xét thay vì tự thêm thời gian chờ hoặc lưu lượng giả.
- Tránh vận hành các danh tính được cho là tách biệt theo một mẫu đồng bộ từ cùng ngữ cảnh vật lý.
- Dùng cổng xuất một chiều: nội dung không đáng tin cậy đi vào renderer dùng một lần; chỉ kết quả đã được xem xét và làm sạch mới được đưa ra.
- Giữ đồng hồ chính xác để bảo đảm an toàn giao thức, nhưng loại bỏ dấu thời gian chính xác không cần thiết khỏi các hiện vật được công bố.
- Giảm thiểu thời lượng phiên và hạ tầng cũ mà không xoay vòng “fast-flux” quá nhanh, vì việc đó dễ gây chú ý và làm giảm khả năng giải trình.

## Kỹ thuật không thể dùng bên thứ ba không liên quan

Đây là các kỹ thuật của đối thủ có thật, không phải chuyện tưởng tượng hay không quan trọng. Cơ chế và cách phát hiện chúng được trình bày trong [Hạ tầng tấn công và né tránh quy kết](offensive-infrastructure-and-attribution-evasion.md), [Truy cập vật lý và không dây bí mật](covert-physical-wireless-access.md) và [các nghiên cứu tình huống APT](government-and-apt-case-studies.md). Trong một cuộc diễn tập được ủy quyền, hãy tái hiện hành vi có thể quan sát của chúng bằng các thành phần thay thế do mình sở hữu:

- mô phỏng việc luân chuyển exit residential/mobile bằng các pool relay có kiểm soát, không dùng các thị trường có sự đồng thuận không rõ ràng;
- mô phỏng open proxy, router bị xâm nhập và botnet bằng VM/router do mình sở hữu;
- mô phỏng tài khoản cloud bị đánh cắp bằng tenant diễn tập được chỉ định và danh tính nạn nhân tổng hợp;
- mô phỏng domain fronting trên reverse proxy do mình sở hữu thay vì CDN không đồng thuận;
- mô phỏng Wi-Fi của bên thứ ba bằng hai AP cô lập do phòng lab sở hữu;
- coi mã hóa tự tạo, chuỗi nhiều VPN và luân chuyển mã định danh là các giả thuyết kiểm thử, trong đó luồng mạng, tài khoản và hiện vật endpoint vẫn có thể bị phát hiện.

Với red team được ủy quyền, mọi nỗ lực làm cho lưu lượng khó nhận diện hơn phải là mục tiêu phát hiện được nêu rõ trong ROE, có bản đồ quy kết do controller nắm giữ và bao gồm cơ chế dừng/giải xung đột.

## Ma trận xác minh

| Kiểm thử | Kết quả mong đợi | Nếu thất bại nghĩa là |
|---|---|---|
| Tunnel/bridge bị dừng | Workload không có đường IPv4/IPv6/DNS trực tiếp | Thực thi tuyến mạng chưa đầy đủ |
| Kiểm tra log của đích | Chỉ xuất hiện egress/danh tính ứng dụng đã dự kiến | Header, tuyến mạng hoặc tài khoản bị leak |
| Kiểm tra log ingress | Có nguồn; không có đích/yêu cầu dạng rõ | Phân tách vùng tin cậy tại ingress thất bại |
| Kiểm tra log egress | Có relay/yêu cầu; không có danh tính nguồn | Phân tách vùng tin cậy tại egress thất bại |
| Quét origin onion từ bên ngoài | Không thể truy cập/liên kết dịch vụ origin công khai | Origin bị leak hoặc kết nối đồng thời vào nhiều mạng |
| Kết thúc phiên dùng một lần | Trạng thái instance đã biến mất; bằng chứng được phê duyệt vẫn được lưu riêng | Ranh giới lưu giữ đã thất bại |
| Thử tra cứu từ controller | Hoạt động nhanh chóng được liên kết với engagement/người vận hành | Khả năng giải trình của red team đã thất bại |

## References

- [1] [Bảo mật nền tảng Apple — Bảo mật iCloud Private Relay](https://support.apple.com/en-gb/guide/security/secad8ce3233/web)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [WireGuard — Định tuyến và Network Namespace](https://www.wireguard.com/netns/)
- [4] [Tor Project — Snowflake và pluggable transport](https://snowflake.torproject.org/) and [Arti — Pluggable Transports](https://arti.torproject.org/censorship/pluggable-transports/)
- [5] [Tor Project — Cách Onion Service hoạt động](https://community.torproject.org/onion-services/overview/)
- [6] [Tor Project — Cài đặt nâng cao và xác thực máy khách của Onion Service](https://community.torproject.org/onion-services/advanced/)
- [7] [AWS — Mã hóa dữ liệu trong Amazon WorkSpaces Secure Browser](https://docs.aws.amazon.com/workspaces-web/latest/adminguide/data-encryption.html)
- [8] [I2P — Mô hình mối đe dọa](https://www.i2p.net/en/docs/overview/threat-model/) and [Garlic Routing](https://www.i2p.net/en/docs/overview/garlic-routing/)
{{#include ../banners/hacktricks-training.md}}
