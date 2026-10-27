# Kiểm thử quyền riêng tư có thể tái lập

{{#include ../banners/hacktricks-training.md}}

Một cấu hình quyền riêng tư chưa hoàn tất khi nó kết nối được. Chỉ có thể xem là hoàn tất khi ranh giới được tuyên bố đã được kiểm thử trong quá trình sử dụng thông thường, khi xảy ra lỗi, khôi phục và tháo dỡ. Hãy kiểm thử trên cơ sở hạ tầng do bạn sở hữu hoặc được phép kiểm tra; các trang “leak test” công khai sẽ trở thành một bên quan sát khác.

## Xây dựng môi trường kiểm thử nhỏ được cấp phép

Sử dụng ba vai trò, lý tưởng nhất là trên các nhà cung cấp/mạng riêng biệt:

```text
operator endpoint ---- privacy path ---- owned web/DNS endpoint
       |                                      |
local packet/route view                 server-side logs
       |
controller/provider dashboards and payment/account records
```

Ghi lại trước mỗi bài kiểm tra:

- ID bài kiểm tra, thời gian bắt đầu/kết thúc theo UTC, người thực hiện và ủy quyền;
- phiên bản endpoint/OS/client và hash cấu hình;
- các quan sát dự kiến về IPv4, IPv6, DNS, TLS, tài khoản, thanh toán và vật lý;
- những log sẽ được kiểm tra cùng đồng hồ/múi giờ của chúng;
- quy tắc đạt/trượt và thời gian teardown.

Không bao giờ kiểm tra danh tính nhạy cảm trước. Dùng tài khoản giả lập và các giá trị canary duy nhất, vô hại do người kiểm tra sở hữu.

## Kiểm tra đường dẫn mạng

### 1. Ghi lại trạng thái cơ sở

Trước khi bật privacy path, ghi lại các tuyến đường cục bộ và resolver:

```bash
ip route
ip -6 route
resolvectl status
```

Trên macOS, dùng `route -n get default`, `netstat -rn -f inet6` và `scutil --dns`. Chỉ lưu đầu ra trong kho bằng chứng được kiểm soát; dữ liệu này có thể chứa các định danh cục bộ.

### 2. Kết nối và kiểm tra định tuyến

Bật namespace VPN/Tor/workload, sau đó kiểm tra route được chọn cho các địa chỉ công khai được kiểm soát:

```bash
ip route get 192.0.2.10
ip -6 route get 2001:db8::10
```

Thay địa chỉ trong tài liệu bằng địa chỉ máy chủ thử nghiệm. Xác nhận giao diện/bảng được chọn khớp với thiết kế.

### 3. Quan sát từ cả hai đầu

Đặt URL của endpoint do bạn sở hữu, sau đó yêu cầu một đường dẫn lành tính duy nhất:

```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl --fail --show-error --silent \
  "${PRIVACY_TEST_URL}/privacy-check/run-20260907-001"
```

Sử dụng domain thực do tester kiểm soát, TLS có xác thực và token đường dẫn không nhạy cảm. Kiểm tra log máy chủ để xem:

- địa chỉ nguồn/ASN và egress dự kiến;
- IPv4 hay IPv6;
- hành vi Host/SNI hiển thị tại endpoint;
- user agent và các header của ứng dụng;
- thời gian chính xác và việc tái sử dụng request.

Không thêm `X-Forwarded-For`, header debug duy nhất hoặc cookie chứa thông tin định danh vào request được cho là đã tách biệt.

### 4. Kiểm tra DNS bằng canary do bạn sở hữu

Cấu hình một zone thử nghiệm có authoritative DNS với log truy vấn do bạn kiểm soát. Truy vấn một nhãn ngẫu nhiên duy nhất qua phân vùng:

```bash
dig run-20260907-001.privacy-test.example A
dig run-20260907-001.privacy-test.example AAAA
```

Kiểm tra log authoritative. Log này thường ghi nhận recursive resolver, không nhất thiết là client. So sánh resolver đó với thiết kế DNS dự kiến cho VPN/Tor/ứng dụng. Không cần dùng một trang kiểm tra DNS leak công khai bất kỳ.

### 5. Kiểm tra hành vi fail-closed

Duy trì một vòng lặp yêu cầu vô hại nhắm đến endpoint do bạn sở hữu, sau đó ngắt privacy path. Workload phải thất bại thay vì chuyển sang giao diện mạng vật lý. Kiểm tra cả hai họ địa chỉ và DNS:

```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl -4 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v4"
curl -6 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v6"
dig privacy-test.example
```

Lặp lại trong các tình huống:

- tiến trình tunnel bị crash;
- chuyển từ Wi-Fi sang Ethernet hoặc hotspot;
- sleep/wake;
- gia hạn DHCP;
- trạng thái captive-portal;
- provider kết nối lại/khóa hết hạn.

Đối với namespace/container Linux, hãy dừng tunnel của nó và xác minh rằng nó không có route mặc định hoặc resolver nào khác:

```bash
ip netns exec privacy-workload ip route
ip netns exec privacy-workload ip -6 route
ip netns exec privacy-workload resolvectl status
```

Tên và lệnh khác nhau tùy theo môi trường triển khai. Đừng dán chúng vào máy chủ production từ xa nếu không có khả năng khôi phục qua console.

### 6. Kiểm tra socket và gói tin cục bộ

Khi được cấp phép, hãy kiểm tra tiến trình/giao diện nào thực sự giao tiếp:

```bash
ss -tpn
ss -upn
sudo tcpdump -ni any 'host TEST_SERVER_IP'
```

Thay `TEST_SERVER_IP` bằng địa chỉ do bạn sở hữu; tránh thu thập trên diện rộng dữ liệu của người dùng không liên quan. Giao diện vật lý chỉ nên thấy peer của tunnel/bridge, còn lưu lượng có đích đến rõ ràng chỉ nên xuất hiện ở layer được chỉ định.

## Kiểm tra Tor và onion-service

1. Trong Tor Browser, truy cập trang kiểm tra kết nối của Tor Project và xác nhận đang dùng Tor. Không xem đây là bằng chứng nhận dạng.<sup>[[1]](#references)</sup>
2. Truy cập HTTPS endpoint do bạn sở hữu bằng một canary duy nhất, rồi xác nhận endpoint thấy một Tor exit, không có cookie nhận dạng và có browser context tiêu chuẩn.
3. Chọn **New Identity**, truy cập lại bằng một canary khác và xác minh local state đã được xóa như mong đợi. IP exit có thể không đổi; đó không phải mục đích của New Identity.
4. Với onion service, chỉ truy cập bằng Tor Browser. Dùng một lượt quét bên ngoài đã được cấp phép để xác nhận host của service không có listener công khai, đồng thời xác nhận các phản hồi của ứng dụng không chứa hostname/IP công khai.
5. Kiểm tra DNS/HTTP outbound của origin, template, trang lỗi, email/webhook và tài nguyên bên thứ ba. Bất kỳ yêu cầu fetch trực tiếp nào cũng có thể làm lộ origin hoặc tài khoản operator.
6. Nếu bật client authorization, xác nhận Tor Browser sạch, không có credential không thể kết nối, còn Tor Browser có credential thì kết nối được.
7. Xoay vòng một khóa authorization thử nghiệm và xác nhận client bị thu hồi mất quyền truy cập mà không làm thay đổi danh tính onion.

## Kiểm tra browser compartment

Tạo một trang được kiểm soát, chỉ ghi lại các trường cần thiết cho kiểm tra và đặt thời hạn lưu trữ ngắn. So sánh các compartment cá nhân và riêng tư về:

- cookie/local storage/service worker và cache;
- trạng thái browser sync/login;
- ngôn ngữ, múi giờ, kích thước màn hình/cửa sổ và font;
- WebRTC/network candidate;
- permission và các sửa đổi mà extension có thể nhìn thấy;
- dữ liệu user-agent TLS/HTTP tại server.

Đừng cố làm Tor Browser “ngẫu nhiên hơn”. Điều kiện đạt là giống với anonymity set tiêu chuẩn của trình duyệt và không có trạng thái cá nhân, chứ không phải khác biệt tối đa so với browser cá nhân.

Kiểm tra copy/paste, drag/drop, mở file đã tải xuống, gợi ý từ password manager và nút identity provider. Đây là những cầu nối phổ biến giữa các compartment.

## Kiểm tra cách ly hệ điều hành

### Tails

1. Bắt đầu với một file/canary vô hại trong phiên không có Persistent Storage.
2. Tắt máy hoàn toàn, khởi động lại và xác nhận file đã biến mất.
3. Chỉ bật một danh mục persistence cần thiết, lặp lại và xác nhận trạng thái browser/application không liên quan không được lưu giữ.
4. Xác minh Unsafe Browser không thể được dùng cho hoạt động nhạy cảm sau khi đăng nhập portal, đồng thời các ứng dụng Tor kết nối lại bình thường.

### Whonix/Qubes

1. Dừng Gateway/net qube và chứng minh Workstation/app qube không thể truy cập IPv4, IPv6 hoặc DNS.
2. Chỉ thử đường dẫn clipboard/file giữa các qube đã cấu hình rõ ràng và xác nhận không có đường dẫn shared-folder/device nào khác.
3. Mở một tài liệu thử nghiệm vô hại trong disposable qube, đóng lại và xác nhận trạng thái của nó đã biến mất.
4. Kiểm tra vault qube không có NetVM và không thể được gán NetVM do thay đổi template/default.
5. Tạo snapshot/khôi phục một VM thử nghiệm và kiểm tra xem trạng thái chứa thông tin nhận dạng có bất ngờ xuất hiện lại không.

## Kiểm tra metadata liên lạc

Với mỗi messenger được chọn:

1. Tạo các participant chỉ dùng cho thử nghiệm trên thiết bị được kiểm soát.
2. Ghi lại các yêu cầu đăng ký: số điện thoại, tài khoản app store, IP, push service, username hoặc lời mời.
3. Gửi một tin nhắn vô hại trong khi kiểm tra bản xem trước thông báo, desktop được liên kết, wearable và bản sao lưu.
4. Xác minh safety/security code qua một kênh độc lập.
5. Tắt receipt/push hoặc lần lượt bật Tor/local transport, rồi quan sát thay đổi về độ tin cậy và metadata.
6. Xuất hoặc khôi phục một bản sao lưu thử nghiệm và ghi lại chính xác bản sao đó chứa profile, danh bạ và lịch sử nào.
7. Làm mất/thu hồi một thiết bị thử nghiệm và xác nhận các participant còn lại thấy thay đổi key/device như mong đợi.

Không thử nghiệm bằng cách liên hệ người không liên quan hoặc tạo lưu lượng mang tính lạm dụng.

## Kiểm tra làm sạch file

1. Hash và lưu bản gốc trong kho bằng chứng được mã hóa:

```bash
sha256sum ./original/file > ./original/file.sha256
```

2. Tạo một bản sao đã làm sạch theo quy trình dành riêng cho định dạng trong [Giao tiếp và chia sẻ bảo vệ quyền riêng tư](privacy-preserving-communications-and-sharing.md).
3. So sánh các bản kê siêu dữ liệu:

```bash
exiftool -a -u -g1 ./original/file
exiftool -a -u -g1 ./clean/file
```

4. Render/mở bản sao trong môi trường dùng một lần. Kiểm tra nội dung ẩn, tệp đính kèm, liên kết, biểu mẫu, lớp, hình thu nhỏ và dấu hiệu nhận dạng trực quan.
5. Chỉ tìm trong bản sao đã staging các chuỗi canary đã biết về tác giả/email/đường dẫn.
6. Hash đầu ra cuối cùng và nhờ người thứ hai xác minh chính xác tệp sẽ được công bố.

Việc không thấy trong đầu ra của ExifTool không chứng minh được tính ẩn danh; thông tin nội bộ của định dạng, điểm ảnh, văn xuôi và hồ sơ phân phối vẫn có thể để lộ danh tính.

## Kiểm tra quyền riêng tư thanh toán

Dùng số tiền nhỏ nhất được phép hoặc mạng thử nghiệm/sandbox chính thức:

1. Ghi lại những gì người trả tiền, người nhận/đơn vị bán hàng, bên phát hành/sàn giao dịch, mạng/nút, sổ cái công khai và kế toán/đơn vị kiểm soát dự kiến có thể thấy.
2. Tạo hóa đơn/ngữ cảnh đơn vị bán hàng thử nghiệm riêng, không dùng danh tính giả.
3. Thanh toán một lần, sau đó thu thập biên nhận, sao kê, bảng điều khiển của đơn vị bán hàng, nhật ký ví/nút và chế độ xem blockchain công khai của chính bạn, nếu có.
4. Kiểm tra xem số tiền, dấu thời gian, địa chỉ/token, tài khoản, IP/thiết bị, giao hàng và phương thức hoàn tiền có khớp với bảng quan sát viên không.
5. Với Bitcoin, kiểm tra việc tái sử dụng địa chỉ, các đầu vào được chọn, tiền thừa và việc gộp tiền về sau trong chế độ kiểm soát coin của ví.
6. Với các giao thức có shielded pool, xác minh pool/đường đi thực tế và những gì viewing key tiết lộ; đừng suy luận về quyền riêng tư chỉ từ thương hiệu ví.
7. Với e-cash/Taler, thử sao lưu/khôi phục, hoàn tiền và quy đổi với giá trị nhỏ; ghi lại hồ sơ tại ranh giới mint/sàn giao dịch/federation.
8. Thu hồi thẻ ảo/thông tin xác thực thử nghiệm và xác nhận các lần ủy quyền sau đó thất bại, đồng thời vẫn hiểu rõ cách xử lý hoàn tiền hợp lệ.
9. Đối soát và lưu giữ bằng chứng thuế/ủy quyền bắt buộc dưới dạng mã hóa.

Không bao giờ tạo giao dịch chuyển tiền vòng tròn, chia nhỏ dưới ngưỡng, giao dịch mua giả hoặc hoàn tiền đáng ngờ như một “bài kiểm tra quyền riêng tư”.

## Diễn tập trách nhiệm giải trình red-team được ủy quyền

Trước bài diễn tập, hãy thực hiện diễn tập tình huống và kiểm tra kỹ thuật:

1. Một operator khởi chạy canary lành tính từ mỗi đường dẫn nguồn đã được phê duyệt.
2. SOC mục tiêu ghi lại những gì phát hiện được mà không nhận danh tính operator nếu mục tiêu là kiểm thử mù.
3. Người điều phối bài diễn tập đối chiếu nguồn → engagement → operator từ sơ đồ đối chiếu được lưu ký và hồ sơ công việc đã ký.
4. Người điều phối gửi lệnh dừng khẩn cấp; operator và chủ sở hữu hạ tầng chứng minh khả năng tắt trong thời hạn ROE.
5. Bộ phận xử lý lạm dụng của nhà cung cấp nhận được liên hệ 24/7 và thông tin tham chiếu ủy quyền chính xác.
6. Bằng chứng thể hiện mục tiêu, thời gian, công cụ/công việc và operator mà không lưu giữ nội dung payload không cần thiết.
7. Một operator thứ hai xác minh việc thu hồi thông tin xác thực và tháo dỡ tài nguyên.

Không đạt đánh giá mức độ sẵn sàng nếu SOC có thể dễ dàng nhìn thấy hạ tầng cá nhân/tại nhà **hoặc** người điều phối không thể nhanh chóng xác định nguồn và dừng nó.

## Mẫu hồ sơ kiểm thử

```text
Test ID / date (UTC):
Authorization / owner:
Claim under test:
Expected observers:
Endpoint + versions:
Configuration hash:
Normal result:
Failure/reconnect result:
Server/provider/account evidence:
Unexpected linkage:
Pass/fail:
Remediation + retest ID:
Evidence retention/deletion date:
```

## References

- [1] [Tor Project — Kiểm tra kết nối](https://check.torproject.org/)
- [2] [WireGuard — Định tuyến và Network Namespaces](https://www.wireguard.com/netns/)
- [3] [ExifTool — Câu hỏi thường gặp và hướng dẫn về metadata](https://exiftool.org/faq.html)
- [4] [NIST SP 800-115 — Hướng dẫn kỹ thuật về kiểm thử và đánh giá an toàn thông tin](https://csrc.nist.gov/pubs/sp/800/115/final)
{{#include ../banners/hacktricks-training.md}}
