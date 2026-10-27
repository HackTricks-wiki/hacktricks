# Các playbook về quyền riêng tư vận hành

{{#include ../banners/hacktricks-training.md}}

Các playbook này kết hợp những biện pháp kiểm soát trong các phần còn lại của mục này. Đây là điểm khởi đầu, không phải sự bảo đảm: hãy cập nhật mô hình mối đe dọa mỗi khi có người quan sát, tài khoản, thiết bị, địa điểm, phương thức thanh toán, tệp hoặc bên liên quan mới tham gia quy trình.

## Kiểm tra trước khi bắt đầu

1. Ghi rõ mục tiêu hợp pháp và những gì cần được giữ riêng tư **với ai**.
2. Liệt kê danh tính, thiết bị, mạng, tài khoản, phương thức thanh toán, bên liên quan, địa điểm thực tế và dữ liệu mà hoạt động sẽ tác động đến.
3. Xác định người quan sát có khả năng cao nhất và hậu quả nếu thất bại.
4. Xác nhận quyền hạn, luật hiện hành, điều khoản của nhà cung cấp và chính sách của tổ chức.
5. Quyết định những gì cần được ghi nhận nội bộ để đảm bảo an toàn, ứng phó sự cố, kế toán và kiểm toán.
6. Chọn vùng ngăn cách nhỏ nhất có thể sử dụng; thiết lập phương án khôi phục và tắt trước khi dùng.
7. Kiểm tra vùng ngăn cách với một dịch vụ có kiểm soát, bao gồm nguy cơ rò rỉ IP/DNS/IPv6, danh tính trình duyệt, metadata tài liệu, sao kê thanh toán và thông báo.

Sử dụng mô hình chi tiết trong [Threat Modeling and Identity Separation](threat-modeling-and-identity-separation.md).

## Quyền riêng tư cơ bản hằng ngày

Mục tiêu: giảm việc theo dõi thương mại, chiếm đoạt tài khoản và phơi lộ không cần thiết mà không cố gắng trở nên ẩn danh.

- Dùng OS được duy trì, có mã hóa toàn bộ ổ đĩa, cập nhật tự động, khóa màn hình và secure boot nếu có.
- Ưu tiên thiết lập trình quản lý mật khẩu, email khôi phục và MFA/khóa bảo mật chống phishing.
- Rà soát quyền ứng dụng, lịch sử vị trí, mã định danh quảng cáo, đồng bộ đám mây và kết nối tài khoản bên thứ ba.
- Dùng trình duyệt phổ biến với ít extension, tính năng chống theo dõi, HTTPS và các profile riêng cho hoạt động duyệt web cá nhân/công việc/rủi ro cao.
- Dùng alias chuyển tiếp riêng tư hoặc địa chỉ email riêng theo từng mối quan hệ; không dùng số điện thoại cá nhân nếu chỉ là tùy chọn.
- Ưu tiên nhắn tin mã hóa đầu cuối để bảo vệ nội dung, nhưng hãy nhớ rằng người tham gia, thời điểm, nhóm và endpoint vẫn là metadata.
- Chủ động xóa metadata khỏi tệp và kiểm tra bản đã xuất — không phải bản gốc — trước khi đăng.
- Dùng thẻ ảo hoặc token ví để phân tách thông tin thanh toán; đừng gọi chúng là ẩn danh.
- Sao lưu tài liệu khôi phục đã mã hóa và kiểm tra khả năng khôi phục.

## Xuất bản bằng danh tính giả danh

Mục tiêu: ngăn độc giả thông thường và nền tảng dễ dàng liên kết nội dung xuất bản với danh tính pháp lý. Cách này không chống lại được một cuộc điều tra có chủ đích và đủ năng lực.

1. Xác định nền tảng, nhà cung cấp hosting, độc giả, người liên hệ, mạng cục bộ, nhà cung cấp thanh toán hoặc quy trình pháp lý có nằm trong mô hình mối đe dọa hay không.
2. Tạo ngữ cảnh endpoint/tài khoản chuyên biệt từ một môi trường sạch. Tắt đồng bộ trình duyệt cá nhân, tài liệu đám mây, tải lên danh bạ và bản xem trước thông báo.
3. Tạo tài khoản giả danh thông qua vùng ngăn cách mạng đã chọn. Không dùng lại username, avatar, kênh khôi phục, mẫu văn bản soạn sẵn hoặc thông tin đăng nhập identity provider cá nhân.
4. Dùng Tor Browser khi việc không thể liên kết hoạt động đến đích quan trọng hơn tốc độ; không thêm extension, thay đổi kích thước/tùy chỉnh quá nhiều hoặc mở tài liệu đã tải xuống khi đang online trong phiên desktop thông thường.
5. Soạn thảo theo quy trình không nhúng tên mẫu cá nhân, tác giả bản sửa đổi, đường dẫn máy in, GPS/EXIF, thumbnail hoặc layer ẩn. Xuất một bản sao và kiểm tra bản đó bằng công cụ metadata phù hợp.
6. Kiểm tra nội dung để tìm thông tin có thể nhận diện chính người viết: ngày tháng đặc biệt, chi tiết nơi làm việc, thời tiết/múi giờ địa phương, phản chiếu, âm thanh nền, thói quen ngôn ngữ và văn bản trùng với nội dung đã xuất bản trước đây.
7. Dùng kênh trả lời riêng. Xem mọi liên hệ trực tiếp, tệp đính kèm và liên kết là nguy cơ bị liên kết hoặc phishing.
8. Nếu có tiền liên quan, dùng phương thức hợp pháp chỉ tiết lộ dữ liệu cần thiết. Giả định nền tảng và trung gian chịu quản lý có thể biết người nhận tiền ngay cả khi độc giả không biết.
9. Đăng nội dung, sau đó kiểm tra kết quả công khai từ một ngữ cảnh sạch khác. Ghi lại những gì nền tảng đã thêm hoặc biến đổi.
10. Chỉ duy trì lịch đăng đã định nếu nó không tạo ra dấu vân tay hành vi ổn định; hãy ngừng sử dụng vùng ngăn cách thay vì âm thầm tái sử dụng nó.

Đối với báo chí nghiêm túc, hoạt động xã hội, bạo lực gia đình hoặc rủi ro cấp nhà nước, hãy tìm hỗ trợ phù hợp từ một tổ chức an ninh số giàu kinh nghiệm; checklist tĩnh không thể mô hình hóa luật địa phương hoặc đối thủ đang hoạt động.

## Hoạt động red-team được ủy quyền

Mục tiêu: giữ danh tính cá nhân và mạng gia đình của người vận hành khỏi telemetry của mục tiêu, đồng thời vẫn đảm bảo ủy quyền, kiểm soát và ứng phó sự cố.

### Trước thời điểm bắt đầu

- Hoàn tất phụ lục hạ tầng ROE, mục tiêu/phạm vi loại trừ, dải địa chỉ nguồn, ngày thực hiện, quy trình dừng khẩn cấp và quyền của bên thứ ba/nhà cung cấp.
- Cấp profile operator hoặc VM chuyên dụng, secrets của đợt thực hiện, kho bằng chứng, dự án cloud, domain và ngân sách.
- Ưu tiên egress do khách hàng cung cấp hoặc bastion cố định do tổ chức kiểm soát. Kiểm tra hành vi full-tunnel IPv4/IPv6/DNS và chính sách fail-closed.
- Lưu thông tin liên kết operator với hạ tầng công khai cho người điều phối cuộc diễn tập hoặc đầu mối escrow đã thống nhất.
- Thiết lập giới hạn tốc độ, allowlist đích và quy trình phê duyệt riêng cho các hành động phá hoại, wireless, tại chỗ, phishing hoặc thu thập thông tin xác thực.
- Dùng phương thức thanh toán do tổ chức kiểm soát và ghi nhận các phê duyệt nội bộ.

### Trong quá trình thực hiện

- Bắt đầu từ endpoint và tunnel đã được phê duyệt; xác minh egress quan sát được trước khi gửi lưu lượng đánh giá.
- Không dùng tài khoản, thiết bị, số điện thoại, repository, khóa SSH/GPG và đồng bộ cloud cá nhân trong vùng ngăn cách.
- Ghi log operator/công việc, thời điểm bắt đầu/dừng, nguồn, đích trong phạm vi và thay đổi cấu hình mà không thu thập nội dung khách hàng không cần thiết.
- Dừng nếu phạm vi không rõ ràng, phát hiện hệ thống bên thứ ba ngoài dự kiến, nhận thông báo lạm dụng từ nhà cung cấp, có ảnh hưởng đến an toàn, thất lạc thiết bị hoặc mất liên lạc với người điều phối.
- Tuyệt đối không ứng biến bằng Wi-Fi của hàng xóm, thông tin xác thực đánh cắp, SIM/tài khoản chưa được phê duyệt hoặc phần cứng giấu tại địa điểm tổ chức.

### Kết thúc đợt thực hiện

- Dừng các job và C2; thu hồi thiết bị cài cắm đã được phê duyệt; thu hồi token, thông tin xác thực và certificate.
- Đối chiếu hạ tầng, domain, địa chỉ nguồn, chi phí, dữ liệu và vụ việc với nhà cung cấp theo danh mục.
- Hoàn trả/xóa/lưu giữ dữ liệu khách hàng theo hợp đồng, giữ lại lượng bằng chứng kiểm toán tối thiểu cần thiết và yêu cầu operator thứ hai xác minh việc tắt hệ thống.

Xem [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md) để biết hướng dẫn đầy đủ về triển khai và tháo dỡ.

## Mua hàng hoặc quyên góp riêng tư hợp pháp

Mục tiêu: giảm tiết lộ thông tin cho người bán hoặc công chúng, đồng thời tuân thủ nghĩa vụ với đơn vị phát hành, kế toán, thuế và lệnh trừng phạt.

1. Liệt kê ai không được biết thông tin gì: công chúng, người bán, trung gian thanh toán, người được ủy quyền trên tài khoản của cơ quan/gia đình, dịch vụ giao hàng hoặc người quan sát blockchain.
2. Kiểm tra quy định địa phương, người nhận/bên liên quan, điều khoản nhà cung cấp, giới hạn tiền mặt và yêu cầu lưu trữ hồ sơ.
3. Chọn phương thức thanh toán:
   - tiền mặt cho các khoản thanh toán hợp pháp tại địa phương được chấp nhận, không tạo hồ sơ trên mạng thanh toán;
   - thẻ ảo được quản lý/thẻ riêng cho từng người bán để tách biệt thông tin xác thực khi thanh toán trực tuyến;
   - cryptocurrency chỉ sau khi phân tích các liên kết từ việc mua, ledger, backend ví, mạng, bên liên quan và các lần chi tiêu sau đó.
4. Cung cấp thông tin bắt buộc chính xác và chỉ bỏ qua thông tin khách hàng thân thiết/tiếp thị không bắt buộc. Không dùng danh tính/địa chỉ của người khác hoặc chia nhỏ giao dịch để né ngưỡng.
5. Tách biệt ngữ cảnh tài khoản/trình duyệt dùng với người bán và tránh đăng nhập mạng xã hội, chương trình khách hàng thân thiết hoặc kênh khôi phục cá nhân không liên quan.
6. Xác nhận những gì sẽ xuất hiện trên sao kê, biên lai, thông báo, thông tin giao hàng và danh sách nhà tài trợ công khai.
7. Lưu bằng chứng biên lai/thuế/ủy quyền bắt buộc dưới dạng mã hóa; thu hồi thông tin thanh toán dùng một lần sau thời hạn hoàn tiền.

Xem [Private Digital Payments](private-digital-payments.md) và [Cryptocurrency Privacy](cryptocurrency-privacy.md).

## Du lịch và mạng không đáng tin cậy

Mục tiêu: bảo vệ dữ liệu và tài khoản trên mạng không do người dùng quản lý — không phải che giấu hoạt động trái phép.

- Cập nhật thiết bị và tải trước thông tin xác thực/bản đồ cần thiết trước chuyến đi.
- Giảm thiểu dữ liệu lưu trên thiết bị; dùng mã hóa toàn bộ ổ đĩa, phương thức mở khóa mạnh, kế hoạch khôi phục từ xa và quy trình tắt nguồn khi qua biên giới/trước rủi ro vật lý phù hợp với tư vấn pháp lý.
- Xác minh SSID/captive portal của địa điểm. Khi phù hợp, ưu tiên hotspot cá nhân nhưng nhớ rằng hồ sơ thuê bao và vị trí di động vẫn được lưu.
- Dùng VPN full/forced đã được phê duyệt cho dữ liệu của tổ chức; xác minh các thiết bị tethering cũng dùng VPN và kiểm tra hành vi IPv6/DNS.
- Dùng travel router để cách ly client và áp dụng chính sách nhất quán, không phải như một sự bảo đảm ẩn danh.
- Xem sạc USB công cộng, máy tính mượn, máy in công cộng và hệ thống dùng chung trong phòng họp là các mối đe dọa riêng biệt.
- Giả định sự hiện diện thực tế, mã định danh vô tuyến, đăng nhập portal, camera và hồ sơ thanh toán/vị trí có thể liên kết chuyến ghé thăm.

Thông tin so sánh và thiết lập có trong [Network Privacy and Anonymous Connectivity](network-privacy-and-anonymous-connectivity.md).

## Ứng phó khi thất bại hoặc bị lộ

Khi một vùng ngăn cách bị leak hoặc có thể bị liên kết:

1. Dừng hoạt động nếu tiếp tục sẽ làm tăng thiệt hại; nếu phù hợp, dùng quy trình dừng khẩn cấp của đợt thực hiện.
2. Bảo toàn bằng chứng cần thiết mà không phát tán dữ liệu nhạy cảm. Ghi lại thời gian chính xác, dấu hiệu quan sát được và tài sản bị ảnh hưởng.
3. Thông báo cho chủ sở hữu/điều phối viên/đầu mối an ninh phù hợp. Đừng che giấu sự cố để bảo vệ câu chuyện về quyền riêng tư.
4. Thu hồi phiên đăng nhập, token, thông tin thanh toán và quyền truy cập hạ tầng; xoay vòng secrets từ một endpoint đã biết là sạch.
5. Xác định những liên kết nào đã bị lộ: endpoint, tài khoản khôi phục, mạng, thanh toán, metadata, nội dung, hành vi, bên liên quan hoặc sự hiện diện thực tế.
6. Coi toàn bộ vùng ngăn cách bị ảnh hưởng là đã bị lộ. Đừng chỉ đổi username hoặc IP thoát.
7. Thực hiện nghĩa vụ thông báo về vi phạm, nhà cung cấp, khách hàng, tài chính và pháp lý.
8. Chỉ dựng lại sau khi thay đổi quy trình gây ra liên kết; ghi lại biện pháp kiểm soát và kiểm tra biện pháp đó.

## Kiểm toán định kỳ

- [ ] Mô hình mối đe dọa và các giả định pháp lý/nhà cung cấp được rà soát theo lịch có ghi ngày.
- [ ] Thiết bị, tài khoản, alias, domain, đường dẫn mạng và thông tin thanh toán được kiểm kê.
- [ ] Các phương án khôi phục không vô tình đi qua những vùng ngăn cách khác.
- [ ] Đã kiểm tra hành vi full-tunnel, DNS, IPv6 và fail-closed.
- [ ] Tệp công khai và profile đã được kiểm tra để tìm metadata/nội dung trùng lặp.
- [ ] Các giả định về node/backend ví và giao thức crypto vẫn còn phù hợp.
- [ ] Log và biên lai được tối giản, mã hóa, giới hạn quyền truy cập và nằm trong thời hạn lưu giữ.
- [ ] Các vùng ngăn cách cũ và hạ tầng phục vụ đợt thực hiện đã được loại bỏ hoàn toàn.
{{#include ../banners/hacktricks-training.md}}
