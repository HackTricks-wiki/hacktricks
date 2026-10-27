# Các nút thực địa được ủy quyền có khả năng chống bị thu giữ

{{#include ../banners/hacktricks-training.md}}

Raspberry Pi, mini-PC, travel router hoặc thiết bị di động qua mạng di động được đặt tại chỗ có thể mang lại cho red team được ủy quyền một vị trí quan sát bền vững. Đây cũng là mục tiêu có khả năng bị phát hiện, đánh cắp và truy nguồn cao. Vì vậy, mục tiêu thiết kế phù hợp là **duy trì quyền truy cập ổn định, có kiểm soát và hạn chế quyền trên nút thực địa**, chứ không phải tạo implant không thể truy dấu.

Hướng dẫn này chỉ áp dụng cho thiết bị được đặt với sự cho phép bằng văn bản của chủ sở hữu địa điểm. Quán cà phê, nhà hàng xóm, khách sạn hoặc tòa nhà dùng chung không thuộc phạm vi chỉ vì có thể kết nối vào mạng của họ. Không giấu phần cứng tại địa điểm không đồng thuận, vượt qua captive portal, dùng thông tin xác thực của người khác, can thiệp vào hoạt động giám sát hoặc cố xóa bằng chứng sau khi bị phát hiện.

{% hint style="warning" %}
Không có thiết lập “không để lại dấu vết” nào đáng tin cậy. Các bản ghi về kết nối vô tuyến, DHCP/NAT, nhà mạng, camera, giao dịch mua, thiết bị, nhà cung cấp, bộ điều khiển và đích đến có thể vẫn tồn tại sau khi thiết bị không còn. Thay vào đó, red team có trách nhiệm sẽ loại bỏ **bí mật cá nhân và không liên quan** khỏi nút, lưu giữ thông tin truy nguồn được bảo vệ ở phía bộ điều khiển và chuẩn bị để việc xử lý khi thiết bị bị thu giữ diễn ra nhanh chóng.
{% endhint %}

## Ưu và nhược điểm

**Ưu điểm:** cung cấp nguồn truy cập thực tế từ bên trong hoặc gần mục tiêu; hỗ trợ kiểm thử ổn định, tốc độ cao; xác thực NAC, egress, kiểm kê vật lý và phạm vi bao phủ của SOC; có thể tiếp tục hoạt động khi địa chỉ của operator thay đổi; có thể thu hồi quyền truy cập giới hạn từ trung tâm.

**Nhược điểm:** việc đặt thiết bị tại chỗ tạo ra bằng chứng rõ ràng; nếu bị mất, thiết bị có thể làm lộ thông tin xác thực, hồ sơ mạng và dữ liệu đã thu thập; lưu lượng điều khiển lặp lại có thể bị phát hiện; nguồn điện, portal và thay đổi vô tuyến làm giảm độ tin cậy; tunnel quá rộng có thể trở thành pivot ngoài tầm kiểm soát.

## Mô hình đe dọa và các nguyên tắc bất biến trong thiết kế

Giả định rằng người tìm thấy thiết bị có thể tháo bộ nhớ, kiểm tra firmware, sao chép mọi bí mật được lưu bằng phần mềm, quan sát hành vi mạng sau đó và giao thiết bị cho khách hàng hoặc cơ quan thực thi pháp luật. Mã hóa toàn bộ ổ đĩa chỉ bảo vệ thiết bị đang tắt theo mô hình đe dọa đã nêu; nút đang chạy nhưng đã mở khóa và các khóa được đưa vào bộ nhớ là những trường hợp khác.

| Nguyên tắc bất biến | Hệ quả thực tế |
|---|---|
| Không để lộ danh tính trực tiếp từ operator đến nút | Operator đăng nhập vào gateway của tổ chức; nút có danh tính thiết bị riêng |
| Không có dữ liệu từ máy trạm cá nhân | Không có SSH key cá nhân, hồ sơ trình duyệt, email, trình quản lý mật khẩu, ghép nối điện thoại hoặc bộ nhớ đệm cloud CLI |
| Không có bí mật chủ của bộ điều khiển | Một nút không thể đăng ký nút khác, thay đổi chính sách hoặc giải mã dữ liệu của các đợt engagement khác |
| Chỉ kết nối đi và giới hạn chặt chẽ | Mạng thực địa không chấp nhận listener quản lý; nút chỉ kết nối đến các dịch vụ rendezvous/update/time được chỉ định |
| Quyền hạn có phạm vi giới hạn và thời hạn ngắn | Mỗi thông tin xác thực chỉ áp dụng cho một thiết bị, audience, dịch vụ và thời hạn, đồng thời có thể thu hồi ngay lập tức |
| Giảm thiểu dữ liệu lưu cục bộ | Kết quả được truyền về bộ điều khiển; bộ nhớ đệm được mã hóa, giới hạn dung lượng/thời gian lưu và không có thẩm quyền quyết định |
| Trách nhiệm giải trình ở bộ điều khiển vẫn được duy trì khi thiết bị bị thu giữ | Thông tin liên kết tài sản với engagement, phê duyệt, quyền truy cập của operator và lệnh được lưu tập trung, có kiểm soát truy cập |
| Mất thiết bị đồng nghĩa với dừng hoạt động | Nếu thiết bị bị phát hiện hoặc trạng thái thay đổi không rõ nguyên nhân, phải dừng, thu hồi quyền, thông báo và bảo toàn bằng chứng—không phá hủy từ xa |

Chuẩn cơ sở IoT của NIST nhóm các năng lực nhận diện thiết bị, cấu hình, bảo vệ dữ liệu, truy cập logic, cập nhật phần mềm an toàn và nhận biết trạng thái an ninh mạng thành các năng lực cốt lõi. Tiêu chuẩn này đặc biệt xem việc nhận biết trạng thái và lưu bản ghi sự kiện ngoài thiết bị là cơ sở hỗ trợ điều tra sự cố xâm nhập.<sup>[[1]](#references)</sup>

## Kiến trúc tham chiếu

```text
operator workstation
  |  phishing-resistant MFA; named user; no field-device key
  v
organization access gateway ----> immutable audit / alerting
  |  per-engagement authorization          ^
  v                                        |
rendezvous/broker <==== outbound mTLS or WireGuard ==== field node
  |                                                     |-- approved site Wi-Fi/Ethernet
  +---- allowlisted owned test services                 +-- organization cellular fallback
```

Gateway phải biết operator có tên nào đã truy cập device có tên nào. Field node chỉ cần device credential để kết nối đến rendezvous. Nó không bao giờ biết địa chỉ nguồn hay secret xác thực của operator, và operator không bao giờ sao chép private management key vào đó. Điều này giảm mức độ liên kết cá nhân có thể khôi phục **từ dữ liệu lưu trữ trên field node** mà không làm mất khả năng quy trách nhiệm cho exercise.

Với một fleet lớn hơn, hệ thống workload identity có thể cấp danh tính X.509 có thời hạn ngắn và tự động luân chuyển key. SPIFFE khuyến nghị dùng X.509 SVID khi có thể, đồng thời mô tả rằng thời hạn ngắn và việc luân chuyển thường xuyên giúp hạn chế mức độ lộ lọt khi key bị xâm phạm.<sup>[[2]](#references)</sup> Một nhóm nhỏ có thể áp dụng các đặc tính tương tự bằng CA riêng và certificate riêng cho từng device được cấp tự động; không cần cài SPIRE chỉ để đáp ứng mô hình này.

## Step 1: authorize và đăng ký vị trí triển khai

1. Ghi lại chủ sở hữu, địa điểm, khu vực triển khai chính xác được phép, các network được phép, thời gian đánh giá, các đích/hành động được phép và thông tin liên hệ khẩn cấp.
2. Ghi lại model, serial, serial của storage, MAC có dây/không dây, IMEI modem/eSIM hoặc ICCID SIM, bộ nguồn và ảnh hiện trạng.
3. Cấp cho device một mã định danh engagement không gắn với cá nhân, ví dụ `E2026-014-DROP03`. Không đưa tên client vào hostname hoặc SSID phát quảng bá.
4. Thông báo cho người điều phối exercise và nhóm physical security/SOC nhỏ nhất cần thiết về ý nghĩa của các trạng thái “mất,” “bị di chuyển” và “bị phát hiện” trong bài kiểm thử này.
5. Thống nhất trước ai được phép thu hồi thiết bị và cách người phát hiện có thể báo tin. Nhãn an toàn có thể lược bỏ thông tin nhạy cảm về client nhưng vẫn cung cấp một kênh liên hệ có kiểm soát.
6. Đặt thời điểm hết hạn authorization tự động. Kết nối còn hoạt động sau khi hết scope không được kéo dài quyền cho phép.

## Step 2: tạo image tối thiểu có thể khôi phục

Dùng image OS được hỗ trợ, xác minh chữ ký/checksum qua kênh được vendor ghi rõ, cài security update và duy trì manifest build có thể tái tạo. Ưu tiên base chỉ đọc hoặc bất biến cùng phân vùng dữ liệu có thể ghi nhỏ nếu phần mềm cho phép.

1. Xóa account mặc định, dịch vụ demo, compiler và package không cần cho workload được authorization.
2. Tắt GUI cục bộ, Bluetooth, giao thức discovery, chia sẻ file, Wi-Fi P2P và quản trị inbound trừ khi exercise yêu cầu rõ ràng.
3. Bật secure boot và measured boot/giải phóng key dựa trên TPM nếu phần cứng thực sự hỗ trợ; không tuyên bố rằng cấu hình Raspberry Pi có measured boot cấp PC nếu chưa xác thực chính xác model.
4. Mã hóa trạng thái cục bộ có thể ghi và cấu hình kích thước tối đa cùng thời gian lưu giữ nghiêm ngặt. Mã hóa là biện pháp trì hoãn/kiềm chế, không phải bằng chứng rằng node đang chạy sẽ không tiết lộ gì.
5. Gửi log quan trọng ra khỏi device. Giới hạn journal cục bộ để tránh cạn storage, nhưng không cấu hình xóa log hoặc xóa dữ liệu chống điều tra.
6. Lưu manifest image, phiên bản package, hash cấu hình và hướng dẫn khôi phục tại controller.
7. Cài lại image cho một thiết bị dự phòng từ manifest và chạy cùng bài kiểm tra tình trạng. Thiết kế mà chỉ người tạo ra nó mới có thể khôi phục thì chưa sẵn sàng triển khai thực địa.

## Step 3: cấp identity với cơ chế tin cậy một chiều

Tạo ba identity khác nhau:

- **device identity**, chỉ được rendezvous dành cho device này chấp nhận;
- **operator identity**, được gateway của tổ chức chấp nhận và bảo vệ bằng MFA chống phishing; và
- **controller/deployment identity**, dùng để ký job hoặc cấu hình đã được phê duyệt, được lưu giữ bên ngoài cả operator lẫn field node.

Node cần có public key để xác minh job đã ký, tuyệt đối không được có signing key. Device credential bị thu thập không được dùng để xác thực vào cloud console, source repository, tài khoản thanh toán, node khác hoặc môi trường production của client.

Dùng certificate có thời hạn ngắn nếu việc tự động gia hạn đáng tin cậy. Khi cần dùng WireGuard key dài hạn vì lý do vận hành, hãy coi public key của nó là thông tin định danh để thu hồi và giới hạn nó bằng địa chỉ tunnel riêng cho từng peer, chính sách firewall và authorization của broker. Duy trì một thao tác trên controller đã được kiểm thử để gỡ peer đó ngay lập tức.

## Step 4: rendezvous outbound ổn định

Mô hình lab do tổ chức sở hữu dưới đây cung cấp khả năng quản trị ổn định qua NAT mà không để lộ dịch vụ inbound. Đây là networking WireGuard thông thường, không phải reverse shell bí mật. Dùng địa chỉ dành cho tài liệu và chỉ thay bằng endpoint do tổ chức sở hữu.

Tại rendezvous của tổ chức, gán `10.77.0.1/32`; gán `10.77.0.20/32` cho field node. Peer entry của gateway chỉ nên chấp nhận địa chỉ duy nhất của node:

```ini
# rendezvous: /etc/wireguard/wg-field.conf (relevant peer only)
[Peer]
PublicKey = <DROP03_PUBLIC_KEY>
AllowedIPs = 10.77.0.20/32
```

Nút kết nối ra ngoài tới rendezvous và chỉ duy trì ánh xạ NAT khi cần thiết:

```ini
# field node: /etc/wireguard/wg-field.conf
[Interface]
Address = 10.77.0.20/32
PrivateKey = <DROP03_PRIVATE_KEY>

[Peer]
PublicKey = <RENDEZVOUS_PUBLIC_KEY>
Endpoint = vpn.redteam.example:51820
AllowedIPs = 10.77.0.1/32
PersistentKeepalive = 25
```

WireGuard ghi nhận 25 giây là khoảng thời gian keepalive hợp lý trên nhiều cách triển khai NAT/firewall khi cần duy trì kết nối; nếu không cần thì nên tắt tính năng này.<sup>[[3]](#references)</sup> `AllowedIPs = 10.77.0.1/32` cố ý biến đây thành đường quản trị, không phải điểm chuyển tiếp default route.

Sau đó áp dụng các biện pháp kiểm soát bên ngoài WireGuard:

1. Phân giải `vpn.redteam.example` thông qua đường DNS bootstrap được phê duyệt và ghi nhận endpoint dự kiến của tổ chức trong hồ sơ triển khai.
2. Trên node, cho phép DHCP/RA đi ra, DNS/NTP cần thiết, endpoint rendezvous và đường cập nhật tối thiểu được phê duyệt. Chặn lưu lượng đến không được yêu cầu trên mọi uplink.
3. Trên rendezvous, chỉ cho phép `10.77.0.20` truy cập broker/health service cần thiết cho bài diễn tập. Không chuyển tiếp lưu lượng từ node này vào mạng máy khách một cách tổng quát.
4. Đặt quyền truy cập tương tác của operator phía sau gateway của tổ chức. Tránh để SSH từ node đi qua tunnel nếu giao diện signed pull-job đáp ứng được yêu cầu đánh giá.
5. Cấu hình service manager khởi động tunnel sau khi có mạng, khởi động lại khi lỗi với backoff có giới hạn và phát cảnh báo sau nhiều lần lỗi. Vòng lặp khởi động lại không được gây quá tải cho địa điểm hoặc che giấu lỗi gốc.
6. Xác minh thời điểm handshake gần nhất của peer, nhưng không xem việc “có handshake” là bằng chứng thiết bị không bị xâm phạm.

TURN có thể cung cấp khả năng kết nối chỉ qua relay cho một control plane WebRTC được thiết kế riêng, còn message queue có thể chịu được tình trạng dịch vụ gián đoạn. TURN công khai rõ ràng địa chỉ relay công cộng cho client nằm sau NAT; máy chủ TURN vẫn có thể quan sát lưu lượng.<sup>[[4]](#references)</sup> Hãy chọn một kiến trúc điều khiển thay vì chồng nhiều tunnel mà không nêu rõ lợi ích về bên quan sát hoặc độ tin cậy.

## Bước 5: duy trì uplink ổn định mà không dùng kết nối cá nhân

Với node tại địa điểm được ủy quyền, ưu tiên theo thứ tự sau:

1. kết nối có dây do khách hàng cung cấp hoặc VLAN kiểm thử riêng;
2. cấu hình Wi-Fi doanh nghiệp/khách được chủ sở hữu phê duyệt;
3. phương án dự phòng qua mạng di động/APN riêng do tổ chức ký hợp đồng.

Không bao giờ cấu hình sẵn điểm phát sóng từ điện thoại cá nhân, SSID ở nhà, eSIM cá nhân, tài khoản Apple/Google cá nhân hoặc cấu hình Wi-Fi xuất từ laptop dùng hằng ngày. Đây chính là những dấu vết mà việc thu giữ sẽ liên kết được.

Với mỗi uplink được phê duyệt:

- ghi lại SSID/BSSID hoặc switch/VLAN và hành vi captive portal dự kiến;
- đặt mức ưu tiên xác định trước và kiểm tra tình trạng kết nối tới endpoint do tổ chức sở hữu;
- bảo đảm chuyển đổi dự phòng chỉ thay đổi underlay; danh tính thiết bị và operator vẫn được giữ tại broker;
- bảo đảm DNS, IPv6 và lưu lượng ứng dụng không đi vòng qua rendezvous trong quá trình chuyển đổi;
- cảnh báo khi xuất hiện SSID/BSSID không xác định, thay đổi SIM, default gateway mới, thay đổi public IP/ASN hoặc nhiều uplink hoạt động đồng thời;
- kiểm thử mất nguồn, gia hạn DHCP, khởi động lại AP, thay đổi public IP, không hoạt động trong 24 giờ, mất tunnel và khôi phục từ kết nối chính sang kết nối phụ rồi quay lại trước khi triển khai.

Địa chỉ MAC riêng tư có thể giảm khả năng theo dõi thông thường giữa các mạng, nhưng thường cần MAC ổn định theo từng mạng để NAC được ủy quyền hoạt động. Ghi lại hành vi thực tế của hệ điều hành đã chọn và không xoay địa chỉ để né kiểm soát truy cập của chủ sở hữu.

## Bước 6: giới hạn công việc và dữ liệu

Node tại hiện trường an toàn không nên chấp nhận văn bản shell tùy ý từ mailbox. Hãy xác định các loại job có chữ ký như `health`, `fetch-owned-url`, `capture-approved-interface-for-60s` hoặc hành động khác được nêu rõ trong quy tắc thực hiện. Xác thực lại đích đến, thời lượng, tốc độ, kích thước đầu ra và phạm vi ngay trên node.

1. Cấp cho mỗi job một ID duy nhất, đối tượng thiết bị, thời điểm phát hành, thời điểm hết hạn, tham chiếu phạm vi và giới hạn đầu ra.
2. Ký job bằng danh tính controller/deployment.
3. Từ chối các trường không xác định, job đã hết hạn/được phát lại và job dành cho thiết bị khác.
4. Gửi kết quả trực tiếp tới collector do tổ chức sở hữu; mã hóa và đặt TTL cho mọi dữ liệu bắt buộc phải lưu tạm trên node.
5. Ghi log ID job được chấp nhận/từ chối và hash kết quả tại controller. Không đưa tham số lệnh nhạy cảm vào kênh giám sát công khai.
6. Dừng xử lý khi giấy phép hết hạn, việc xoay vòng danh tính thất bại hoặc controller đánh dấu thiết bị là bị cách ly.

## Giám sát việc phát hiện, mất thiết bị hoặc xâm phạm

Giám sát có thể báo cho controller biết trạng thái quan sát được đã thay đổi. Nó không thể chứng minh đáng tin cậy rằng “điều tra viên đã tìm thấy thiết bị”; việc cố theo dõi người ứng cứu hoặc dò quét hệ thống của họ sẽ vượt quá phạm vi đánh giá được ủy quyền.

### Thu thập trạng thái ngoài thiết bị

Gửi bản ghi tình trạng có chữ ký, dung lượng thấp tới controller theo chu kỳ vận hành ngẫu nhiên nhưng có giới hạn. Chỉ bao gồm thông tin controller cần:

- ID thiết bị, ID/bộ đếm khởi động và thời gian hoạt động đơn điệu;
- hash cấu hình/image và phiên bản phần mềm;
- số sê-ri chứng chỉ thiết bị và trạng thái gia hạn;
- loại uplink, giao diện, BSSID hoặc thông tin switch theo phạm vi được ủy quyền, hash default gateway và public IP/ASN do dịch vụ sở hữu quan sát được;
- thời gian từ lần handshake tunnel gần nhất, bộ đếm packet và độ sâu hàng đợi;
- trạng thái công tắc vỏ hoặc cảm biến can thiệp phần cứng nếu chủ sở hữu phê duyệt cảm biến đó;
- dung lượng đĩa còn lại, nhiệt độ, ước tính độ lệch đồng hồ và ID job thành công gần nhất;
- số thứ tự và chữ ký để phát hiện phát lại hoặc thiếu dữ liệu.

Lưu tập trung các bản ghi xác thực gateway, quyết định chính sách, quyền truy cập của operator, lần gửi job, hash kết quả, sự kiện kiểm toán của nhà cung cấp và cảnh báo. CISA khuyến nghị tập trung log, bảo vệ log khỏi bị xóa, thiết lập đường cơ sở cho hoạt động bình thường và chỉ định đầu mối ứng phó sự cố.<sup>[[5]](#references)</sup>

### Chỉ báo phát hiện/xâm phạm

| Tín hiệu | Các khả năng giải thích | Hành động của controller |
|---|---|---|
| Không nhận heartbeat | lỗi nguồn/mạng, thay đổi portal, hư hỏng, bị chặn có chủ ý hoặc bị tháo đi | đối chiếu trạng thái nhà cung cấp/địa điểm; không kết nối lại qua đường chưa được phê duyệt |
| Bộ đếm khởi động thay đổi bất ngờ | mất nguồn, crash, bị tháo đi hoặc bảo trì | cách ly job; đối chiếu thời gian và sự kiện tại địa điểm |
| Hash cấu hình/image thay đổi | lỗi cập nhật, lỗi lưu trữ hoặc can thiệp trái phép | dừng hoạt động; thu hồi nếu không phải bản phát hành do controller phê duyệt |
| Uplink/BSSID/gateway/ASN mới | thay AP, roaming, di chuyển thiết bị hoặc bị chặn bắt | đối chiếu danh mục đã phê duyệt; cách ly nếu có chuyển đổi không rõ nguyên nhân |
| Job/chữ ký liên tục bị từ chối | hỏng dữ liệu, phát lại hoặc controller trái phép | dừng xử lý và điều tra log gateway/controller |
| Thông tin xác thực thiết bị được dùng hai lần hoặc từ các đường kết nối không tương thích | khóa bị sao chép, dùng lại snapshot hoặc chuyển mạng | thu hồi ngay; lưu giữ bản ghi của cả hai phiên |
| Đăng nhập cục bộ, giao diện, tiến trình hoặc sự kiện đặc quyền bất ngờ | bảo trì hoặc xâm phạm | cô lập bằng chính sách broker; bảo toàn bằng chứng |
| Trạng thái công tắc vỏ thay đổi | bảo dưỡng, di chuyển hoặc bị phát hiện | thông báo đầu mối địa điểm đã chỉ định; không kích hoạt hành động phá hủy |
| Thông báo lạm dụng/truy vấn tài khoản của nhà cung cấp hoặc cảnh báo SOC | bị phát hiện, cấu hình sai hoặc lưu lượng ngoài phạm vi | dừng hoạt động và kích hoạt quy trình phối hợp/ứng phó sự cố |
| Sentinel credential bị truy cập | có người đọc bí mật mồi không có quyền, chỉ dành riêng cho node này | thu hồi danh tính thiết bị thật và bảo toàn dấu vết cảnh báo |

Sentinel credential không được cấp **bất kỳ quyền truy cập nào**, chỉ được gọi dịch vụ cảnh báo do tổ chức sở hữu và phải được nêu trong quy tắc thực hiện. Đây là bẫy phát hiện việc đọc trái phép, không phải beacon để theo dõi người tìm thấy thiết bị.

### Ngưỡng cảnh báo

Dùng quy tắc có lưu trạng thái, không dùng một cảnh báo kịch tính kiểu “bị bắt quả tang”:

- **cảnh báo:** lỡ một chu kỳ, thay đổi địa chỉ thông thường hoặc hàng đợi tăng;
- **suy giảm:** lỡ ba chu kỳ liên tiếp, gia hạn chậm, mất uplink chính hoặc khởi động lại nhiều lần;
- **cách ly:** hash/boot/uplink thay đổi không được phê duyệt, thông tin xác thực bị dùng trùng, sentinel bị sử dụng hoặc xuất hiện sự kiện đặc quyền bất ngờ;
- **xác nhận bị phát hiện/mất thiết bị:** báo cáo từ địa điểm/controller, sai lệch kiểm kê thực tế, thiết bị được một bên ngoài kế hoạch thu hồi hoặc sự việc được nhà cung cấp/SOC xác nhận và nâng cấp xử lý.

Kiểm thử việc gửi cảnh báo qua một kênh độc lập với node tại hiện trường. Tránh gửi thông tin nhạy cảm về khách hàng/thiết bị tới ứng dụng nhắn tin cá nhân hoặc tài khoản push dành cho người tiêu dùng.

## Quy trình xử lý khi nghi bị phát hiện hoặc thu giữ

1. **Dừng:** tạm ngừng job mới và phiên operator. Không gửi phép dò “kiểm tra xem có bị theo dõi không”.
2. **Cách ly:** yêu cầu broker từ chối danh tính thiết bị và các route của nó, đồng thời giữ lại log hiện có.
3. **Thu hồi:** thu hồi chứng chỉ/khóa thiết bị, queue token, thông tin xác thực cập nhật và mọi service token chỉ dùng cho một mục đích. Tạm ngưng SIM của tổ chức nếu có khả năng thiết bị đã bị mất về mặt vật lý.
4. **Bảo toàn:** chụp snapshot bản ghi controller, gateway, nhà cung cấp và cảnh báo; ghi lại thời gian đáng tin cậy, người thực hiện và cấu hình được biết gần nhất. Không xóa hoặc xóa từ xa node.
5. **Thông báo:** liên hệ controller của bài diễn tập, đầu mối sự cố của khách hàng và các đầu mối pháp lý/quyền riêng tư được xác định trong giấy phép. Nếu bên thứ ba tìm thấy thiết bị, hãy dùng quy trình thu hồi đã thống nhất trước.
6. **Đánh giá:** giả định mọi bí mật và kết quả đã lưu trên node đều bị lộ. Liệt kê chính xác từng bí mật có thể truy cập những gì và liệu nó có được sử dụng sau sự kiện đáng ngờ hay không.
7. **Khoanh vùng ảnh hưởng tiếp theo:** xoay vòng thông tin xác thực dịch vụ bị ảnh hưởng, vô hiệu hóa job đang chờ và kiểm tra log của mục tiêu/nhà cung cấp thuộc quyền sở hữu để tìm hoạt động bất thường.
8. **Thu hồi an toàn:** chỉ thu hồi thông qua người được ủy quyền; chụp ảnh/đóng gói thiết bị, ghi nhận chuỗi bàn giao và thu thập bằng chứng pháp chứng theo chỉ dẫn của khách hàng.
9. **Tiếp tục bằng danh tính mới:** không âm thầm kích hoạt lại thông tin xác thực đã bị thu giữ. Dựng lại từ manifest đã biết, khắc phục lỗi kiểm soát và xin phê duyệt rõ ràng.

Hướng dẫn ứng phó sự cố hiện hành của NIST tích hợp công tác chuẩn bị, phát hiện, ứng phó và khôi phục vào quản lý rủi ro an ninh mạng trên toàn tổ chức; hãy bảo toàn bằng chứng trước để khách hàng xác định sự việc đã xảy ra như thế nào và chọn phương án ứng phó phù hợp.<sup>[[6]](#references)</sup>

## Diễn tập thu giữ trước khi triển khai

Đưa cho một người đánh giá độc lập một thiết bị thử nghiệm đang mở khóa hoặc bản sao bộ nhớ của thiết bị, rồi yêu cầu họ liệt kê:

1. ID thiết bị/địa điểm/dự án;
2. tên operator, tài khoản cá nhân, mạng ở nhà/máy trạm và thông tin liên hệ khôi phục;
3. địa chỉ và thông tin xác thực của controller/broker;
4. cấu hình mạng khách hàng và kết quả đã lưu trong cache;
5. các thiết bị/dự án khác có thể truy cập bằng từng bí mật;
6. thông tin xác thực có giá trị hoặc dùng để thanh toán;
7. những gì controller có thể thu hồi và thời gian cần thiết;
8. hoạt động nào vẫn có thể truy ngược từ log tập trung.

Tiêu chí đạt: không có tài khoản cá nhân/khóa máy trạm; không có quyền truy cập chéo giữa các dự án hoặc quyền cấp quyền truy cập; không có thông tin xác thực thanh toán; cache được mã hóa và giới hạn dung lượng; có một thao tác thu hồi thiết bị được ghi lại; đầy đủ khả năng truy trách nhiệm ở phía controller. Xem mọi liên kết cá nhân bất ngờ hoặc khả năng di chuyển ngang là điều kiện chặn phát hành.

## Kết thúc

1. Dừng job và vô hiệu hóa route broker khi hết phạm vi.
2. Thu hồi và đối chiếu đúng danh mục thiết bị; báo cáo mọi thiết bị bị thiếu.
3. Bảo toàn log/kết quả và, nếu cần, ảnh pháp chứng theo kế hoạch lưu giữ của dự án.
4. Thu hồi danh tính thiết bị, SIM, queue, cập nhật và dịch vụ ngay cả khi đã thu hồi được phần cứng.
5. Chỉ sau khi hoàn tất bảo toàn/tiếp nhận, xóa dữ liệu hoặc hủy phương tiện lưu trữ theo quy trình xử lý dữ liệu được chủ sở hữu phê duyệt và ghi nhận việc hoàn tất. Đây là quản lý vòng đời, không phải che giấu.
6. Gỡ bỏ cấu hình NAC/DHCP tại địa điểm, route broker, DNS, vai trò cloud, quy tắc cảnh báo và đầu mối tạm thời.
7. Ghi lại hoạt động phát hiện đã quan sát, telemetry bị bỏ sót, thời gian cần để cách ly và mọi dấu vết bị lộ khi thu giữ.

## References

- [1] [NIST — IoT Device Cybersecurity Capability Catalog](https://pages.nist.gov/IoT-Device-Cybersecurity-Requirement-Catalogs/) and [NIST — Cybersecurity Event Awareness](https://pages.nist.gov/FederalProfile-8259A/technical/event/)
- [2] [SPIFFE — Concepts and short-lived workload identities](https://spiffe.io/docs/latest/spiffe/concepts/)
- [3] [WireGuard — Quick Start: Persistent Keepalive](https://www.wireguard.com/quickstart/)
- [4] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [5] [CISA — Use Logging on Business Systems](https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/use-logging-on-business-systems)
- [6] [NIST SP 800-61 Rev. 3 — Incident Response Recommendations and Considerations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
{{#include ../banners/hacktricks-training.md}}
