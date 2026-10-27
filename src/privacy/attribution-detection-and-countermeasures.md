# Quy kết, phát hiện và biện pháp đối phó

{{#include ../banners/hacktricks-training.md}}

Hạ tầng né tránh quy kết được thiết kế để các chỉ dấu riêng lẻ có thể bị loại bỏ dễ dàng. Người phòng thủ nên bảo toàn bằng chứng thô, mô hình hóa các mối quan hệ và săn tìm hành vi vẫn tồn tại khi IP, domain hoặc persona thay đổi.

## Thứ bậc bằng chứng

| Bằng chứng | Hữu ích để | Lưu ý chính |
|---|---|---|
| IP/ASN/vị trí địa lý nguồn | xác định điểm thoát hiển thị và nhà cung cấp | điểm thoát có thể là relay, NAT hoặc nạn nhân; vị trí địa lý chỉ mang tính gần đúng |
| DNS thụ động/đăng ký | lịch sử hạ tầng và đồng lưu trữ | quyền riêng tư/ẩn thông tin và shared hosting tạo ra khoảng trống |
| Dấu vân tay certificate/TLS/HTTP | nhóm các lần triển khai lặp lại | phần mềm phổ biến và hành vi bắt chước tạo ra dương tính giả |
| Thời điểm và hình dạng byte của luồng | liên kết các giai đoạn relay và beacon định kỳ | CDN/NAT và khả năng quan sát hạn chế làm giảm độ chắc chắn |
| Quy trình/danh tính trên endpoint | giải thích lý do kết nối được tạo ra | không có trên thiết bị edge/IoT; attacker có thể dùng công cụ tích hợp sẵn |
| Nhật ký kiểm tra Cloud/CDN/API | xác định tenant và bên kiểm soát hạ tầng | thời gian lưu trữ và quyền truy cập của nhà cung cấp/cơ quan pháp lý khác nhau |
| Thanh toán/tài khoản/thiết bị | liên kết hoạt động mua sắm với một cá nhân/tổ chức | cần xem xét người đứng tên hộ, hành vi xâm nhập và thiết bị dùng chung |
| Implant/cấu hình bị thu giữ | làm lộ khóa, peer, controller và liên kết bản dựng | tính toàn vẹn của quá trình thu thập và thời điểm thu giữ rất quan trọng |
| Bằng chứng con người/thực địa | liên kết sự kiện số với địa điểm/người vận hành | xâm lấn, phụ thuộc thẩm quyền pháp lý, cần xử lý nghiêm ngặt |

Không nên dựa vào bất kỳ hàng nào duy nhất để đưa ra kết luận quy kết cho một nhà nước với độ tin cậy cao. Hãy dùng các giả thuyết cạnh tranh và nêu rõ quan sát nào sẽ bác bỏ từng giả thuyết.

## Telemetry tối thiểu

1. **DNS:** client, truy vấn, loại, câu trả lời, TTL, mã phản hồi, resolver và dấu thời gian.
2. **Luồng mạng:** nguồn/đích/cổng, thời điểm bắt đầu/kết thúc, gói/byte, cờ TCP và vị trí cảm biến.
3. **TLS/HTTP:** SNI khi có thể quan sát, certificate, giao thức đã thương lượng, dấu vân tay client/server, method, authority/nhóm path, status và số byte. Bảo vệ URL đầy đủ có chứa thông tin nhạy cảm.
4. **Danh tính:** kết quả xác thực, yếu tố/certificate/thiết bị, nguồn, ứng dụng, session ID và quyết định rủi ro.
5. **Endpoint:** quy trình khởi tạo, tiến trình cha, người dùng, chữ ký/hash binary và đích đến.
6. **Thiết bị edge/thiết bị mạng:** chênh lệch cấu hình, đăng nhập quản trị, tính toàn vẹn của quy trình/tệp/firmware, giao diện và nhật ký luồng.
7. **Cloud/SaaS/CDN:** actor, tenant/project, thao tác API, nguồn, đối tượng/tài nguyên, token và kết quả.
8. **Wireless/NAC:** trạm, cờ MAC ngẫu nhiên, AP, cường độ tín hiệu, danh tính/certificate EAP, VLAN/IP được cấp và trạng thái bảo mật.

Đồng bộ đồng hồ, giữ nguyên múi giờ ban đầu, ghi lại ranh giới NAT/proxy và lưu đủ lịch sử để vượt quá thời gian tồn tại 31 ngày của một node ORB.

## Xây dựng đồ thị quy kết

Biểu diễn các quan sát dưới dạng node và cạnh có kiểu:

```text
[persona]--created-->[cloud account]--deployed-->[VPS]
    |                       |                     |
 recovery               login-from             TLS fingerprint
    |                       |                     |
[email]                [access relay]-------->[redirector]--seen-by-->[target]
```

Các nút hữu ích gồm IP, prefix, ASN, domain, tài khoản DNS, certificate/key, fingerprint tương tự JA3/JA4, HTTP grammar, hash file/config, cloud tenant, API token, email, persona, phương tiện thanh toán và thiết bị vật lý. Mỗi cạnh cần có `first_seen`, `last_seen`, sensor/source, confidence và cho biết đó là quan sát được hay suy luận.

Chỉ dựa vào mật độ đồ thị có thể gây hiểu nhầm: CDN hoặc certificate authority kết nối nhiều tác nhân không liên quan. Hãy đánh trọng số cao hơn cho các mối quan hệ hiếm do operator kiểm soát—cùng tài khoản API, SSH key, origin allowlist, response body độc nhất hoặc giao thức điều khiển—so với dịch vụ hosting phổ biến.

## Săn tìm ORB và router bị xâm nhập

### Từ một điểm thoát được quan sát

1. Xác định địa chỉ đó thuộc hosting, residential, mobile, education hay business; không loại bỏ các nguồn residential.
2. Thu thập DNS lịch sử, dịch vụ/certificate, port mở và hành vi scan/exploitation được ghi nhận trong một khoảng thời gian giới hạn.
3. Tìm các peer có chung service fingerprint hiếm, địa chỉ đích của controller, certificate material hoặc thời điểm luân phiên.
4. Phân loại các vai trò có khả năng: access, traversal, exit/staging hoặc administration.
5. Kiểm tra xem nhiều intrusion cluster không liên quan có sử dụng cùng một pool hay không; multi-tenancy làm suy yếu việc quy kết trực tiếp cho actor nhưng củng cố giả thuyết ORB.
6. Theo dõi các node mới khớp với hồ sơ vai trò sau khi IP cũ biến mất.

### Tại chủ sở hữu mạng

- Cảnh báo khi phát hiện giao diện quản lý mới bị phơi bày trên Internet và cơ chế xác thực mặc định/lỗi thời.
- Gửi các thay đổi cấu hình router/firewall/VPN và thông tin xác thực quản trị ra khỏi thiết bị.
- Lập baseline các kết nối outbound từ cơ sở hạ tầng thường khởi tạo ít session.
- Phát hiện process proxy/listener mới, tunnel, scheduled task, thay đổi firmware và DNS bất thường.
- Thay thế thiết bị đã hết vòng đời; reboot có thể xóa malware trong bộ nhớ tạm nhưng không khắc phục việc bị phơi bày.
- Giới hạn quyền quản lý vào administration plane có xác thực và các nguồn đã biết.

Mandiant khuyến nghị theo dõi cơ sở hạ tầng ORB như một thực thể luôn biến đổi, vì chặn IP tồn tại ngắn hạn không phản ánh được topology và vòng đời của nó.<sup>[[1]](#references)</sup>

## Phân tích fast-flux và dynamic DNS

Tổng hợp theo domain đã đăng ký và một sliding window. Một điểm số thực tế có thể kết hợp:

```text
score =
  2 * low_median_ttl
  + 2 * unique_answer_count
  + 2 * unique_asn_count
  + geographic_dispersion
  + nxdomain_or_answer_churn
  + first_seen_recently
  + suspicious_process_or_follow_on
```

Điều tra domain dựa trên nhiều đặc điểm độc lập, không chỉ một ngưỡng. So sánh với mô hình allow của CDN/anti-DDoS và kiểm tra việc luân phiên name server có thẩm quyền để phân biệt single flux với double flux. Với DGA, bổ sung các đợt NXDOMAIN tăng đột biến theo từng client, phân bố độ dài/ký tự, các truy vấn đồng bộ giữa các host và process tạo ra chúng. Hướng dẫn hiện hành của MITRE cũng nhấn mạnh các thay đổi với tần suất cao, TTL thấp và tương quan process/network.<sup>[[2]](#references)</sup>

## Phát hiện Domain-fronting

Khi endpoint của doanh nghiệp hoặc một điểm kiểm tra được ủy quyền có cả hai danh tính, hãy so sánh:

```text
TLS SNI / ECH state
HTTP/1 Host or HTTP/2 :authority
certificate SAN and CDN tenant/origin
initiating process and expected service
```

Tăng độ tin cậy khi SNI và authority thuộc về các tenant không liên quan, tiến trình không phải client được phê duyệt, phiên kết nối diễn ra định kỳ/kéo dài và origin bên trong hiếm gặp. SNI trống là một đặc điểm cần ghi nhận, không mặc nhiên là độc hại. ECH có thể ẩn SNI trên đường truyền, vì vậy log endpoint, DNS và nhà cung cấp/CDN trở nên quan trọng hơn. MITRE ghi nhận cả biến thể SNI không khớp và SNI trống.<sup>[[3]](#references)</sup>

## Phát hiện chuỗi resolver dead-drop

Hành vi có tín hiệu cao nằm ở chuỗi sự kiện, chứ không phải một domain bị chặn:

```text
unusual process
  -> reads one stable public object/profile/post
  -> receives small encoded-looking content
  -> decodes/parses it
  -> contacts a new domain or address within a short interval
```

Truy tìm trên toàn bộ đội thiết bị để tìm các đường dẫn đối tượng, hash phản hồi, mã định danh API và đích đến tiếp theo giống hệt nhau. Lưu lại nội dung đã truy xuất vì tác nhân có thể chỉnh sửa hoặc xóa nó. Hạn chế các API dịch vụ không cần thiết và yêu cầu ứng dụng được phê duyệt sử dụng proxy doanh nghiệp, nhưng cần tính đến công cụ dành cho nhà phát triển và hoạt động tự động hóa. MITRE liệt kê GitHub, diễn đàn, tài liệu và dịch vụ mạng xã hội/web trong các quy trình thực tế.<sup>[[4]](#references)</sup>

## Phân cụm Redirector và triển khai có thể tái sử dụng

Ngay cả khi domain và địa chỉ thay đổi, các operator thường triển khai lại cùng một hoạt động tự động hóa. Phân cụm dựa trên các tổ hợp:

- các trường chứng chỉ/tái sử dụng khóa và thời điểm cấp;
- phiên bản TLS/thứ tự cipher/extension và hành vi máy chủ;
- mã trạng thái HTTP, thứ tự header, hành vi cache, biểu tượng/nội dung và trang lỗi giống hệt nhau;
- các cặp port bất thường và chuỗi redirect;
- mẫu nhà cung cấp DNS/máy chủ tên miền và lịch TTL;
- thời điểm triển khai, thời gian hoạt động và khung giờ bảo trì;
- khả năng lộ origin phía sau hoặc các allowlist giống hệt nhau.

Một trang Nginx phổ biến là bằng chứng yếu. Một số dấu hiệu hiếm, độc lập trùng khớp cùng với tính liên tục theo thời gian có thể đủ cơ sở cho giả thuyết về một cụm hạ tầng.

## Phát hiện proxy dân cư và phiên bất khả thi

Duy trì danh tính phiên ở tầng cao hơn IP. Đánh dấu các tổ hợp như:

- một dấu vân tay phiên/thiết bị thay đổi quốc gia/ASN nhanh hơn khả năng di chuyển thực tế;
- IP dân dụng thay đổi theo từng request trong khi cookie và danh tính TLS/trình duyệt vẫn cố định;
- thiết bị được cho là ở gần có độ trễ/múi giờ/ngôn ngữ không phù hợp với điểm thoát;
- một địa chỉ luân phiên giữa các nhóm tài khoản không liên quan hoặc thể hiện hành vi proxy backconnect;
- một phiên có đặc quyền xuất hiện từ mạng dân cư mà không có chứng chỉ thiết bị của tổ chức.

Carrier NAT, công cụ hỗ trợ tiếp cận, VPN doanh nghiệp và việc đi lại có thể gây ra bất thường lành tính. Yêu cầu xác thực tăng cường hoặc điều tra thay vì chặn không thể đảo ngược chỉ dựa trên nhãn “proxy dân cư”.

## Phát hiện thiết bị không dây và thiết bị bí mật

Kết hợp RADIUS/NAC với AP và bối cảnh vật lý:

1. tìm các tổ hợp tài khoản–thiết bị–AP xuất hiện lần đầu;
2. xác định thông tin xác thực được dùng mà không có chứng chỉ EAP/trạng thái tuân thủ của thiết bị được quản lý;
3. so sánh các phiên đồng thời với sự hiện diện tại tòa nhà theo dữ liệu thẻ ra vào;
4. kiểm tra tín hiệu yếu bất thường/gần rìa vùng phủ sóng và sự di chuyển giữa các AP;
5. tìm trên các endpoint được quản lý lân cận hoạt động quét mạng không dây, bridge/NAT giao diện mới được bật, adapter ảo hoặc tunnel;
6. kiểm kê hoạt động mới trên switchport, DHCP, mạng USB và PoE;
7. tiến hành rà quét RF/vật lý được cấp phép khi bằng chứng cho thấy cần thiết.

Cách này phát hiện cả tuyến truy cập kiểu APT28 thông qua thiết bị lân cận lẫn thiết bị được cài trong một cuộc diễn tập. Không được xem MAC randomization là bằng chứng về danh tính hay hành vi sai trái.

## Phát hiện quy kết tài chính

- Lưu lại chính xác chain, token, địa chỉ, giao dịch và mã định danh block.
- Theo dõi dòng tiền qua tiền thừa, chuỗi peel, fan-out/in, mixer, bridge và khoản nạp vào dịch vụ; đồng thời ghi rõ các dấu hiệu chỉ dựa trên heuristic.
- Đối chiếu thời gian, số tiền sau khi trừ phí, sự kiện contract, thanh khoản và khoản rút trên chain đích.
- Thu thập hoặc bảo toàn hồ sơ hợp pháp từ sàn giao dịch, bridge, merchant, tài khoản, thiết bị và giao hàng.
- Kiểm tra các thực thể/địa chỉ hiện đang bị trừng phạt và các bên liên quan theo chương trình áp dụng; không dựa vào danh sách tĩnh đã cũ.
- Xem việc sử dụng giao thức bảo mật là yếu tố bối cảnh rủi ro, không phải bằng chứng về hành vi sai trái.

Các dấu hiệu cảnh báo của FATF rõ ràng phụ thuộc vào bối cảnh: mẫu bất thường, số tiền/tần suất, địa lý, nguồn tiền và dịch vụ tăng cường tính ẩn danh chỉ có ý nghĩa khi xét cùng nhau.<sup>[[5]](#references)</sup>

## Đánh lạc hướng và canary

Người bảo vệ có thể tạo tín hiệu có độ tin cậy cao mà không cần tìm cách xác định danh tính người dùng thông thường:

- thông tin xác thực hoặc tài liệu riêng biệt không bao giờ được phép rời khỏi một hệ thống;
- endpoint quản trị giả và thư mục chia sẻ mồi nhử;
- tên DNS có công cụ giám sát, chỉ được nhúng trong các hiện vật được kiểm soát;
- khóa cloud canary không có mục đích sử dụng hợp lệ;
- danh tính Wi-Fi mồi nhử mà không thiết bị được quản lý nào sở hữu.

Hãy xác định phạm vi và quản lý hoạt động đánh lạc hướng một cách cẩn trọng. Canary cần phát hiện việc sử dụng sai tài sản của chính bên phòng thủ, không thu thập lưu lượng không liên quan từ bên thứ ba.

## Thứ tự ưu tiên biện pháp đối phó

1. Gỡ bỏ router, VPN và thiết bị không còn được hỗ trợ đang kết nối Internet.
2. Yêu cầu MFA chống phishing và chứng chỉ gắn với thiết bị, bao gồm cả truy cập nội bộ/không dây.
3. Tập trung hóa log có tính bất biến ở mức phù hợp cho danh tính, endpoint, DNS, flow, proxy, cloud và thiết bị mạng.
4. Hạn chế quyền quản trị và lưu lượng outbound; kiểm kê mọi dịch vụ có thể truy cập từ bên ngoài.
5. Giám sát DNS, Certificate Transparency và cấu hình cloud để phát hiện tài sản trái phép.
6. Duy trì khả năng quan sát SaaS ở cấp tiến trình và đối tượng.
7. Diễn tập điều tra liên tầng và phối hợp với các nhà cung cấp lân cận.
8. Theo dõi cụm hạ tầng và hành vi, không chỉ các blocklist IP.

## Kỷ luật phân tích

Dùng các mức độ tin cậy:

- **Đã quan sát:** bản ghi từ sensor/nhà cung cấp trực tiếp cho thấy mối liên hệ.
- **Được hỗ trợ mạnh:** nhiều quan sát độc lập ủng hộ giả thuyết này hơn các giả thuyết khác.
- **Được đánh giá:** suy luận dựa trên các giả định và bằng chứng đã nêu.
- **Chưa rõ:** thiếu khả năng quan sát khiến không thể đưa ra kết luận.

Luôn duy trì ít nhất hai giả thuyết: hạ tầng do tác nhân vận hành so với trung gian bị xâm phạm/dùng chung; một tác nhân so với dịch vụ nhiều bên thuê; né tránh có chủ đích so với hành vi bảo mật/CDN hợp pháp. Khả năng giải thích sự không chắc chắn là một phần của quá trình phát hiện chính xác.

## References

- [1] [Google Cloud/Mandiant — Các tác nhân gián điệp liên hệ với Trung Quốc sử dụng mạng ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [2] [MITRE ATT&CK — DNS Fast Flux (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [3] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [4] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [5] [FATF — Các dấu hiệu cảnh báo đối với tài sản ảo](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [6] [CISA AA24-038A — Các tác nhân Trung Quốc xâm phạm và duy trì quyền truy cập dai dẳng](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [7] [NSA — Hướng dẫn tăng cường khả năng quan sát và bảo vệ hạ tầng truyền thông](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/3982793/guidance-urges-visibility-and-device-hardening-against-prc-affiliated-threat-ac/)
{{#include ../banners/hacktricks-training.md}}
