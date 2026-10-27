# Hạ tầng Red-Team được ủy quyền

{{#include ../banners/hacktricks-training.md}}

Với các thiết bị tại chỗ cần hoạt động lâu dài, hãy dùng thiết kế [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) và runbook xử lý khi nghi ngờ bị phát hiện.

Với một red team chuyên nghiệp, mục tiêu là **quy kết có kiểm soát**, không phải miễn trừ trách nhiệm. Mục tiêu không nên dễ dàng nhìn thấy IP mạng nhà hoặc tài khoản cá nhân của operator, trong khi người phụ trách engagement phải có khả năng xác định nguồn, dừng hoạt động, xử lý báo cáo lạm dụng, bảo toàn bằng chứng và chứng minh đã được ủy quyền.

Trang này là cấu hình triển khai cơ sở cho một engagement hợp pháp. Để tìm hiểu tradecraft của đối thủ mà hoạt động này mô phỏng—bao gồm ORB bị xâm nhập, relay dân dụng, fronting, dead drop và pivot qua mạng không dây ở gần—hãy bắt đầu với [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md) và [Government and APT Case Studies](government-and-apt-case-studies.md), sau đó tái tạo telemetry cần thiết trong [authorized labs](authorized-adversary-emulation-labs.md).

NIST định nghĩa quy tắc tham gia (ROE) là các giới hạn được thiết lập trước, cấp quyền thực hiện những hoạt động kiểm thử đã xác định.<sup>[[1]](#references)</sup> Kiến trúc quyền riêng tư không thể mở rộng phạm vi quyền đó.

## Chọn mô hình egress

| Mô hình | Phù hợp nhất cho | Mục tiêu nhìn thấy | Nhà cung cấp/người quan sát tại chỗ nhìn thấy | Trách nhiệm giải trình |
|---|---|---|---|---|
| VPN/jump host do client cung cấp | Hầu hết các đợt đánh giá | Dải địa chỉ của client | Danh tính client và quyền truy cập của operator | Cao nhất |
| Bastion của tổ chức red team | Egress có kiểm soát, có thể lặp lại | Dải địa chỉ của tổ chức | Nhà cung cấp hosting và tổ chức | Cao |
| VPS dành riêng cho engagement | Cô lập client/campaign | Địa chỉ VPS | Tài khoản hosting, thanh toán, control plane và nhật ký truy cập | Cao nếu được ghi nhận |
| VPN thương mại được phê duyệt | Nghiên cứu/quét được nhà cung cấp và ROE cho phép | Egress VPN dùng chung/dành riêng | Tài khoản VPN và kết nối nguồn | Trung bình |
| Tor Browser | Nghiên cứu web cần tránh liên kết hoạt động với đích | Tor exit | Mạng cục bộ thấy Tor/bridge; đích thấy Tor | Không phù hợp để quy kết nguồn trong allowlist |
| Drop tại chỗ được client phê duyệt | Mô phỏng nội bộ | Thiết bị/địa chỉ tại chỗ | Mạng tại cơ sở và nhà cung cấp tunnel từ xa | Cao nếu được kiểm kê |
| Wi-Fi khách được phép | Sử dụng quản trị/nghiên cứu rủi ro thấp | IP công cộng của địa điểm hoặc egress tunnel | Địa điểm, ISP, VPN/Tor | Thấp và dễ bị quan sát trực tiếp |

Với hầu hết công việc, egress cố định do client cung cấp hoặc tổ chức kiểm soát an toàn và nhanh hơn các dịch vụ ẩn danh dành cho người tiêu dùng. Cách này cũng cho phép đội phòng thủ allowlist, giám sát hoặc cố ý **không** allowlist các dải nguồn đã biết, tùy theo thiết kế bài tập.

## Phụ lục hạ tầng ROE

Ghi lại trước khi triển khai:

- pháp nhân cấp và nhận ủy quyền;
- mục tiêu chính xác và các phạm vi loại trừ rõ ràng;
- thời gian bắt đầu/kết thúc, múi giờ và kỹ thuật được phép;
- IP nguồn, tên autonomous system/nhà cung cấp, domain, redirector, hạ tầng email và mã định danh thiết bị tại chỗ;
- có cho phép phishing, C2, thu thập credential, kiểm thử không dây, truy cập vật lý, denial-of-service, persistence hoặc sử dụng dịch vụ bên thứ ba hay không;
- phê duyệt của client và nhà cung cấp, bao gồm mọi mã tham chiếu thông báo trước;
- cụm từ dừng khẩn cấp, thông tin liên hệ 24/7 của client và bộ phận xử lý lạm dụng của nhà cung cấp, cùng thời gian phản hồi tối đa;
- loại dữ liệu có thể thu thập, mã hóa, quyền truy cập, thời gian lưu giữ và xóa dữ liệu;
- yêu cầu về bằng chứng và logging, bao gồm người nắm giữ bảng ánh xạ từ hạ tầng công khai đến operator;
- tháo dỡ, hết hạn domain, thu hồi certificate, xoay vòng credential, thu hồi thiết bị và xác nhận hoàn tất cuối cùng.

Xác minh IP công khai và domain thực sự do bên ủy quyền kiểm soát hoặc được nêu rõ trong phạm vi. NIST SP 800-115 khuyến nghị xác nhận địa chỉ mục tiêu công khai thuộc quyền quản lý của tổ chức trước khi kiểm thử.<sup>[[2]](#references)</sup>

## Egress nhanh dành riêng cho engagement

### Quy trình xây dựng

1. **Tạo tài khoản/project dành cho engagement** thuộc tổ chức red team, sử dụng thông tin thanh toán và sở hữu chính xác. Tách riêng vai trò, API key, ngân sách và audit log khỏi các client khác.
2. **Kiểm tra chính sách của từng nhà cung cấp.** Nhà cung cấp cloud, VPS, CDN, domain, email và VPN có các quy định khác nhau. Ví dụ, AWS cho phép một số hoạt động đánh giá nhất định nhưng yêu cầu phê duyệt trước đối với C2 được host/mô phỏng covert, đồng thời cấm các hoạt động được liệt kê.<sup>[[3]](#references)</sup>
3. **Cấp phát địa chỉ egress cố định** và ghi vào phụ lục ROE. Tránh luân chuyển IP/tài nguyên liên tục; việc này gây phức tạp cho ứng phó sự cố và có thể vi phạm chính sách của nhà cung cấp.
4. **Gia cố hệ thống quản lý:** SSH chỉ dùng key hoặc management plane nhận biết danh tính, MFA chống phishing, mạng admin riêng, quyền tối thiểu, image đã vá, không mở cổng admin công khai và lưu trữ secret được mã hóa.
5. **Thiết lập đường truyền full-tunnel** từ endpoint của operator đến bastion. Định tuyến DNS và IPv6 có chủ đích, đồng thời áp dụng firewall deny khi tunnel bị ngắt.
6. **Giới hạn đích và cổng outbound** theo phạm vi được ủy quyền khi khả thi. Giới hạn tốc độ scanner và yêu cầu phê duyệt riêng trước khi thực hiện kỹ thuật không thể đảo ngược/phá hoại.
7. **Logging để giải trình, không phải giám sát:** xác thực operator, thay đổi cấu hình, thời điểm bắt đầu/dừng, địa chỉ nguồn, đích trong phạm vi và mã định danh công cụ/job. Tránh thu thập payload/credential trừ khi bài tập yêu cầu và kế hoạch dữ liệu có biện pháp bảo vệ.
8. **Xác thực qua endpoint có kiểm soát** do tổ chức sở hữu: IPv4/IPv6 được quan sát, đường đi DNS, reverse DNS, đồng hồ, hành vi source-port, lỗi/kết nối lại và thông tin liên hệ xử lý lạm dụng của nhà cung cấp.
9. **Chia sẻ bảng ánh xạ quy kết một cách bảo mật** với người điều phối bài tập hoặc đầu mối escrow đã thống nhất. Không công bố bảng này cho đội mục tiêu nếu bài kiểm thử có bao gồm phát hiện mù.

### Kiến trúc

```text
dedicated operator context
        |
   fail-closed tunnel
        |
engagement bastion / fixed egress ---- management + audit plane
        |
 scope allowlist / rate limits
        |
   authorized targets
```

Một VPS chỉ ẩn danh tính với đích đến. Nhà cung cấp có thể lưu hồ sơ liên hệ, thanh toán, danh tính, IP nguồn, API, thiết bị, vị trí và mức sử dụng; riêng lịch sử AWS CloudTrail mà khách hàng xem được cũng có thể tiết lộ hoạt động quản lý.<sup>[[4]](#references)</sup> Thanh toán dịch vụ hosting bằng cryptocurrency không xóa được những hồ sơ đó.

## Tên miền và chứng chỉ

- Dùng tài khoản registrar dành riêng cho từng engagement, thuộc sở hữu của tổ chức.
- Bật registrar lock, DNSSEC nếu được hỗ trợ, MFA/security keys và chỉ bật tự động gia hạn trong khoảng thời gian đã phê duyệt.
- Dùng dịch vụ bảo mật thông tin đăng ký để giảm khả năng hiển thị công khai, không dùng để khai báo sai thông tin người đăng ký. Chính sách ICANN yêu cầu registrar thu thập dữ liệu đăng ký ngay cả khi thông tin hiển thị công khai bị ẩn hoặc được proxy.<sup>[[5]](#references)</sup>
- Tránh các tên miền mạo danh trái phép bên không liên quan. Typosquatting/tên miền trông giống cần có sự chấp thuận rõ ràng của khách hàng và nhà cung cấp.
- Kiểm kê DNS, chứng chỉ, cấu hình CDN/redirector và analytics của bên thứ ba có thể làm leak thông tin về operator hoặc khách hàng.
- Khi teardown, xóa các bản ghi, thu hồi chứng chỉ/token, lưu giữ bằng chứng theo thỏa thuận và quyết định có nên giữ tên miền để phòng vệ hay không.

## Thiết bị drop node tại chỗ được ủy quyền

Chỉ được dùng Raspberry Pi hoặc thiết bị tương tự khi chủ sở hữu địa điểm/mạng và khách hàng cho phép rõ ràng vị trí lắp đặt và cách thức hoạt động cụ thể. Kế hoạch an toàn:

1. Ghi lại số serial thiết bị, MAC/chính sách private MAC, ảnh, chủ sở hữu, vị trí chính xác đã được duyệt, nguồn điện, hạn chót thu hồi và thông tin liên hệ khi thiết bị bị can thiệp.
2. Dùng image tối giản có chữ ký, secrets được mã hóa, bộ nhớ chỉ đọc hoặc có thể khôi phục, host firewall, tự động cập nhật bảo mật nếu khả thi và không dùng thông tin đăng nhập mặc định.
3. Cấu hình chỉ giao tiếp outbound đến endpoint cụ thể của engagement. Không mở listener không xác thực.
4. Allowlist các đích đến và khả năng. Packet capture, thu thập thông tin đăng nhập, giả mạo mạng không dây và lateral movement đều phải được cho phép rõ ràng.
5. Dùng xác thực hai chiều, khóa có thời hạn ngắn, remote kill, báo cáo tình trạng và giới hạn băng thông.
6. Đảm bảo việc mất hoặc bị trộm thiết bị không làm lộ thông tin đăng nhập có thể tái sử dụng hoặc dữ liệu khách hàng.
7. Lên lịch thu hồi và secure wipe/ngừng hoạt động; lấy biên bản thu hồi có chữ ký.

Không giấu thiết bị tại quán cà phê, khách sạn, văn phòng dùng chung, nhà hàng xóm hoặc địa điểm công cộng nếu không có sự cho phép bằng văn bản của chủ sở hữu/đơn vị vận hành.

## Mạng khách và travel router

Nếu kịch bản được ủy quyền yêu cầu truy cập mạng khách:

- xác minh SSID và chính sách sử dụng được chấp nhận với địa điểm/khách hàng;
- dùng travel router thuộc sở hữu tổ chức hoặc thiết bị bridge có độ tin cậy thấp để cô lập workstation có đặc quyền;
- hoàn tất captive portal bên ngoài workstation có đặc quyền;
- khởi chạy tunnel đã được phê duyệt trước khi có lưu lượng assessment;
- xác nhận các thiết bị tether thực sự sử dụng tunnel đó;
- giả định địa điểm có thể đối chiếu kết nối vô tuyến, portal, sự hiện diện tại chỗ và hồ sơ camera/thanh toán;
- không bao giờ vượt qua kiểm soát truy cập, sao chép thiết bị khác, tấn công Wi-Fi hoặc bỏ lại thiết bị.

## Tách biệt hoạt động

- Mỗi khách hàng/engagement dùng một endpoint compartment, cloud project, bộ secrets, nhóm tên miền, nhóm redirector và kho bằng chứng riêng.
- Không dùng email cá nhân, browser sync, số điện thoại, cloud drive, SSH/GPG key, danh tính ký code hoặc khoản hoàn trả thanh toán ngoài các hệ thống tổ chức đã được phê duyệt.
- Không tái sử dụng cấu hình payload đặc trưng, callback path, chứng chỉ hoặc public repository giữa các khách hàng, trừ khi thiết kế bài tập chấp nhận việc bị fingerprint.
- Đặt ngày kill và cảnh báo ngân sách cho hạ tầng. Hệ thống bị bỏ quên sẽ trở thành rủi ro cho cả khách hàng lẫn Internet.
- Lưu đủ thông tin quy kết nội bộ để điều tra sự cố. “Không có log” thường không tương thích với nghĩa vụ chuyên môn về bằng chứng và an toàn.

## Ẩn với đội phòng thủ, nhưng có thể quy trách nhiệm cho bên kiểm soát

Khi mục tiêu bài tập là đánh giá khả năng phát hiện thay vì kiểm tra allowlist, SOC mục tiêu có thể không được biết trước mà hoạt động vẫn có thể truy trách nhiệm:

1. Controller của bài tập phê duyệt mọi public source, tên miền, chứng chỉ và thiết bị tại chỗ nhưng không cung cấp danh sách đó cho SOC.
2. Controller lưu bản ánh xạ source-to-engagement/operator trong một vault mã hóa riêng, có cơ chế truy cập khẩn cấp cần hai người.
3. Mỗi operator nhận một manifest có chữ ký, ghi rõ scope, time window, source compartment và job identifier không thể thay đổi. Trong hoạt động bình thường, mục tiêu không cần xem manifest.
4. Audit event trên bastion được liên kết theo chuỗi hoặc gửi theo chế độ chỉ ghi thêm vào kho lưu trữ của controller để operator không thể âm thầm sửa thông tin quy kết sau sự cố.
5. Đầu mối xử lý lạm dụng của nhà cung cấp hoạt động 24/7, lưu một verification phrase/reference để xác nhận đã được ủy quyền mà không công khai khách hàng.
6. Mọi đường dẫn đều có kênh dừng ngoài băng tần, không phụ thuộc vào assessment C2, mạng mục tiêu hay tài khoản của một operator.
7. Trước khi kiểm thử thật, gửi canary vô hại từ mọi nguồn. Xác nhận controller có thể xác định và dừng chúng trong thời gian phản hồi ROE.
8. Sau bài tập, đối chiếu telemetry của SOC với sổ ghi nhận của controller, công bố danh sách nguồn và giải thích các trường hợp phát hiện bị bỏ sót hoặc không chính xác.

Không thêm anti-forensics, hủy log, relay bị xâm nhập hoặc danh tính thuê bao giả. Những việc đó phá vỡ khả năng kiểm thử có trách nhiệm thay vì cải thiện nó.

## Danh sách kiểm tra teardown

- [ ] Controller của bài tập xác nhận đã dừng.
- [ ] C2, tunnel, redirector, mail, VPN và scheduled job đã bị vô hiệu hóa.
- [ ] Thiết bị tại chỗ đã được thu hồi thực tế và đối soát.
- [ ] Token, API key, SSH key, chứng chỉ và thông tin đăng nhập thu thập được đã bị thu hồi/đổi.
- [ ] DNS và tài nguyên cloud đã bị xóa hoặc chuyển giao để lưu giữ phòng vệ.
- [ ] Dữ liệu khách hàng đã được hoàn trả, lưu giữ hoặc hủy theo hợp đồng.
- [ ] Hồ sơ tài chính, audit và ủy quyền bắt buộc vẫn được mã hóa và kiểm soát truy cập.
- [ ] Các vụ việc lạm dụng với nhà cung cấp đã được đóng và khách hàng nhận được các source indicator cuối cùng.
- [ ] Operator thứ hai xác minh không còn hạ tầng nào hoạt động.

## References

- [1] [NIST CSRC — Quy tắc tham gia](https://csrc.nist.gov/glossary/term/Rules_of_Engagement)
- [2] [NIST SP 800-115 — Hướng dẫn kỹ thuật về kiểm thử và đánh giá an toàn thông tin](https://csrc.nist.gov/pubs/sp/800/115/final)
- [3] [AWS — Chính sách hỗ trợ khách hàng đối với kiểm thử xâm nhập](https://aws.amazon.com/security/penetration-testing/)
- [4] [AWS — Thông báo về quyền riêng tư](https://aws.amazon.com/privacy/) and [CloudTrail Event History](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- [5] [ICANN — Chính sách dữ liệu đăng ký](https://www.icann.org/en/contracted-parties/consensus-policies/registration-data-policy)
{{#include ../banners/hacktricks-training.md}}
