# Mô hình hóa mối đe dọa & Tách biệt danh tính

{{#include ../banners/hacktricks-training.md}}

Lỗi ẩn danh phổ biến nhất không phải do cryptography bị phá vỡ. Đó là **liên kết**: một định danh, kiểu thời gian, thiết bị, tài khoản, khoản thanh toán, tệp hoặc thói quen của con người kết nối hai bối cảnh vốn cần được giữ tách biệt.

## Xây dựng mô hình mối đe dọa về quyền riêng tư

Kế hoạch bảo mật gồm sáu câu hỏi của EFF là nền tảng vững chắc: cần bảo vệ điều gì, trước ai, hậu quả và khả năng xảy ra sự cố, nguồn lực hiện có và những đồng minh có thể giúp đỡ.<sup>[[1]](#references)</sup> Biến kế hoạch đó thành hành động bằng một bảng nhỏ:

| Tài sản/hành động | Bên quan sát | Dữ liệu có thể quan sát | Cách liên kết | Biện pháp kiểm soát | Rủi ro còn lại |
|---|---|---|---|---|---|
| Nghiên cứu về một khách hàng | ISP | Metadata về đích đến/thời điểm | Hồ sơ thuê bao tại nhà | Tor Browser | Việc dùng Tor vẫn hiển thị; tương quan đầu cuối |
| Tài khoản dùng biệt danh | Nền tảng | IP, trình duyệt, dữ liệu khôi phục | Dùng lại số điện thoại/email/ảnh | Bối cảnh riêng và bí danh | Có thể liên kết qua cách viết/đồ thị xã hội |
| Mua hàng trực tuyến | Người bán | Tài khoản, giao hàng, thẻ được token hóa | Địa chỉ và lịch sử tài khoản | Thanh toán với tư cách khách, điền ít trường thông tin, thẻ ảo | Tổ chức phát hành và nhà mạng vẫn lưu hồ sơ |
| Lưu lượng red-team | Mục tiêu/khách hàng | IP nguồn và hành vi | Hồ sơ nhà cung cấp/hoạt động | Egress riêng được ủy quyền | Cố ý có thể quy kết khi leo thang |

Xem lại bảng mỗi khi địa điểm, nhà cung cấp, thiết bị, bên liên quan hoặc hậu quả thay đổi.

## Vẽ đồ thị liên kết

Coi mỗi danh tính là một nút riêng. Thêm một cạnh cho mỗi thuộc tính được dùng chung:

- email hoặc địa chỉ khôi phục;
- số điện thoại hoặc dữ liệu tải lên từ danh bạ;
- tên người dùng, ảnh đại diện, ảnh, tiểu sử hoặc văn phong viết/lập trình;
- mật khẩu, tài khoản đồng bộ passkey hoặc câu hỏi khôi phục;
- thiết bị, ID quảng cáo, hồ sơ trình duyệt, cookie, font hoặc tiện ích mở rộng;
- địa chỉ IP, múi giờ, ngôn ngữ, lịch trình hoặc trạng thái trực tuyến đồng thời;
- thẻ ngân hàng, tài khoản sàn giao dịch, cụm ví, địa chỉ giao hàng hoặc chương trình khách hàng thân thiết;
- trường thông tin tác giả trong tài liệu, vị trí EXIF, dấu máy in hoặc chủ sở hữu tệp chia sẻ trên cloud;
- đồng nghiệp, tư cách thành viên nhóm và đồ thị xã hội.

Một cạnh không đồng nghĩa với thất bại chắc chắn, nhưng cho bạn biết bên quan sát nào có thể liên kết các danh tính. EFF đặc biệt cảnh báo rằng số điện thoại, địa chỉ email và ảnh được dùng lại có thể liên kết các hồ sơ.<sup>[[2]](#references)</sup>

## Tạo một ngăn cách ly theo từng bước

1. **Đặt tên cho bối cảnh và xác định các liên kết bị cấm.** Ví dụ: `client-red-2026`, không liên kết với email cá nhân, hồ sơ trình duyệt tại nhà, phương thức thanh toán cá nhân và các khách hàng không liên quan.
2. **Chọn ranh giới cách ly.** Theo mức độ cách ly tăng dần: hồ sơ trình duyệt riêng → tài khoản OS riêng → VM/qube riêng → thiết bị chuyên dụng. Tab riêng hoặc cửa sổ riêng tư không phải là ranh giới bảo mật.
3. **Tạo định danh mới bên trong ranh giới đó.** Dùng email/bí danh, tên người dùng, kho hoặc bộ sưu tập trong password manager và khóa xác thực dành riêng cho bối cảnh. Đừng thêm kênh khôi phục cá nhân nếu cần tránh để nhà cung cấp liên kết danh tính.
4. **Chọn một chính sách mạng.** Quyết định bối cảnh luôn dùng VPN của khách hàng, VPS phục vụ hoạt động, VPN đáng tin cậy hay Tor. Khi có thể, hãy thực thi định tuyến fail-closed.
5. **Chọn chính sách thanh toán.** Phương thức thanh toán phải phù hợp với mô hình bên quan sát; thẻ ảo có thể che PAN khỏi người bán nhưng vẫn xác định khách hàng với tổ chức phát hành.
6. **Đặt quy tắc truyền dữ liệu.** Ưu tiên truyền dữ liệu có chủ đích và giới hạn phạm vi. Coi clipboard, thư mục dùng chung, thiết bị USB, đồng bộ cloud, máy in và ảnh chụp màn hình là những cầu nối tiềm năng.
7. **Ghi lại ngày tạo và ngày dọn bỏ.** Xác định bằng chứng nào cần được lưu giữ để phục vụ hợp đồng/thuế/tuân thủ và dữ liệu tạm thời nào cần hết hạn.
8. **Kiểm tra liên kết trước khi sử dụng.** Kiểm tra cài đặt tài khoản, trường khôi phục, hồ sơ công khai, IP/DNS, trạng thái trình duyệt, metadata tệp và dashboard của nhà cung cấp.

{% hint style="warning" %}
Đừng bịa thông tin danh tính khi dịch vụ hoặc luật yêu cầu xác minh danh tính chính xác. Ngăn cách quyền riêng tư nhằm giảm thiểu và tách biệt dữ liệu, không phải gian lận danh tính hay né tránh thẩm định khách hàng.
{% endhint %}

## Nền tảng cho endpoint và tài khoản

- Dùng phần cứng còn được hỗ trợ và nhanh chóng cài đặt các bản cập nhật OS, trình duyệt, wallet và firmware.
- Bật mã hóa thiết bị và dùng mật mã thiết bị mạnh. Mã hóa dữ liệu lưu trữ giúp bảo vệ khi thiết bị đã tắt nguồn bị mất hoặc bị thu giữ, nhưng không có tác dụng khi malware hoặc phiên đã mở khóa có thể đọc dữ liệu.<sup>[[3]](#references)</sup>
- Dùng mật khẩu duy nhất, được tạo ngẫu nhiên trong password manager.
- Ưu tiên phương thức xác thực chống phishing như WebAuthn/passkey hoặc khóa bảo mật phần cứng nếu mô hình mối đe dọa cho phép dùng mô hình khôi phục/đồng bộ của chúng. NIST lưu ý OTP được nhập thủ công không chống phishing vì kẻ mạo danh có thể chuyển tiếp mã đó.<sup>[[4]](#references)</sup>
- Giữ mã khôi phục ngoại tuyến và tách biệt khỏi endpoint. Xem xét liệu tài khoản đồng bộ passkey có liên kết những danh tính cần được giữ tách biệt hay không.
- Tắt các quyền không cần thiết về vị trí, danh bạ, microphone, camera, Bluetooth, ID quảng cáo và chạy nền.
- Không dùng chung đồng bộ cloud cá nhân, đồng bộ trình duyệt, tài khoản password manager hoặc cửa hàng ứng dụng trong bối cảnh cần mức độ tách biệt cao.

## Quyền riêng tư trên trình duyệt

Fingerprinting trình duyệt sử dụng cấu hình, thiết bị, môi trường và hành vi có thể quan sát được để nhận diện hoặc liên kết người dùng. Xóa cookie hoặc đổi địa chỉ IP không thể đánh bại cách này một cách đáng tin cậy, và W3C cho rằng việc loại bỏ hoàn toàn bằng các phương tiện kỹ thuật được triển khai rộng rãi là khó khả thi.<sup>[[5]](#references)</sup>

Để có quyền riêng tư thông thường:

1. Dùng trình duyệt được duy trì cập nhật, có chế độ chỉ HTTPS và khả năng bảo vệ chống theo dõi mạnh.
2. Chặn theo dõi của bên thứ ba và phân vùng trạng thái khi được hỗ trợ.
3. Dùng các hồ sơ trình duyệt riêng cho những bối cảnh thực sự tách biệt.
4. Tắt các quyền không cần thiết và xóa dữ liệu trang web theo lịch xác định.
5. Tránh đăng nhập vào tài khoản chứa nhiều thông tin định danh khi thực hiện nghiên cứu nhạy cảm không liên quan.

Để ẩn danh trên web, hãy dùng **Tor Browser với cấu hình tiêu chuẩn**. Đừng chuyển tiếp lưu lượng của trình duyệt thông thường qua Tor: Tor Project cảnh báo rằng trình duyệt thông thường có thể làm lộ dữ liệu qua DNS/WebRTC, trạng thái lưu trữ lâu dài, font, plugin và khác biệt về fingerprint.<sup>[[6]](#references)</sup> Tránh dùng tiện ích mở rộng bổ sung, kích thước cửa sổ khác thường, font tùy chỉnh và các tùy chọn khiến trình duyệt trở nên khác biệt.<sup>[[7]](#references)</sup>

## Liên lạc và metadata

Metadata bao gồm người gửi, người nhận, thời gian, vị trí và các thông tin ngữ cảnh khác, ngay cả khi nội dung tin nhắn được mã hóa.<sup>[[8]](#references)</sup>

- Khi khả thi, hãy ưu tiên các công cụ mã hóa đầu cuối có metadata phía máy chủ được tối thiểu hóa và giao thức/ứng dụng khách mã nguồn mở.
- Xác minh danh tính các liên hệ nhạy cảm qua một kênh độc lập hoặc gặp trực tiếp. Mã an toàn Signal được thiết kế để phục vụ việc kiểm tra này.<sup>[[9]](#references)</sup>
- Tên người dùng Signal cho phép bắt đầu liên lạc mà không cần chia sẻ số điện thoại, nhưng vẫn cần số điện thoại để đăng ký; hãy chủ động cấu hình khả năng hiển thị/tìm kiếm bằng số điện thoại.<sup>[[9]](#references)</sup>
- Tin nhắn tự biến mất giúp giảm số bản sao được lưu giữ; người nhận vẫn có thể chụp ảnh, sao chép, chuyển tiếp hoặc lưu trữ nội dung.
- Email thường để lộ metadata định tuyến. Ngay cả nhà cung cấp chú trọng quyền riêng tư cũng không thể mã hóa đầu cuối một tin nhắn nếu bên kia dùng email thông thường, trừ khi cả hai bên dùng phương thức E2EE tương thích. Ví dụ, Proton ghi rõ rằng thư thông thường gửi đến nhà cung cấp khác sử dụng TLS và vẫn có thể được nhà cung cấp nhận đọc.<sup>[[10]](#references)</sup>
- Tách riêng sổ địa chỉ và không tải danh bạ cá nhân lên tài khoản dùng biệt danh.

## Tệp, ảnh và quyền tác giả

Tails cảnh báo rằng ảnh có thể chứa dữ liệu máy ảnh và vị trí, còn tài liệu văn phòng có thể chứa trường thông tin tác giả và thời gian tạo.<sup>[[11]](#references)</sup>

Trước khi chia sẻ:

```bash
# Inspect recursively; do not assume the extension tells the whole story
exiftool -a -u -g1 path/to/file

# Create a cleaned copy. Verify the copy before publishing.
exiftool -all= -o cleaned-file path/to/file
```

Sau đó mở lại bản đã làm sạch trong một trình xem biệt lập và kiểm tra:

- thuộc tính tài liệu, bình luận, nội dung đã theo dõi thay đổi, trang tính/trang chiếu ẩn, hình thu nhỏ và tệp đính kèm;
- EXIF/XMP/IPTC, GPS, dấu thời gian, tên thiết bị/phần mềm và ID duy nhất;
- hình phản chiếu, địa danh, nội dung màn hình, giọng nói, khuôn mặt và âm thanh nền hiển thị hoặc nghe được;
- tên tệp, đường dẫn trong kho lưu trữ, chủ sở hữu liên kết chia sẻ trên cloud, chứng chỉ ký và lịch sử phiên bản.

Việc khử dữ liệu có thể làm hỏng bằng chứng hoặc tính xác thực. Hãy giữ bản gốc được mã hóa nếu cần bảo toàn chuỗi quản lý chứng cứ hoặc xác minh sau này. Phong cách viết và phong cách lập trình cũng có thể liên kết tác giả; xóa metadata không làm thay đổi phong cách của con người.

## Các kiểu lỗi thường gặp

- Đăng nhập vào tài khoản cá nhân qua một kết nối “ẩn danh”.
- Dùng lại số điện thoại khôi phục, avatar, tên người dùng, khóa công khai, ví hoặc địa chỉ quyên góp.
- Vận hành đồng thời hai danh tính trong những bối cảnh có thể liên kết với nhau.
- Sao chép văn bản/tệp qua clipboard cloud cá nhân hoặc thư mục dùng chung.
- Cài các extension Tor Browser khác biệt hoặc thay đổi nhiều thiết lập mặc định.
- Tin vào tuyên bố “không ghi log” mà không hiểu những gì được ghi lại, trong bao lâu và bởi những nhà thầu phụ nào.
- Cho rằng điện thoại phụ là ẩn danh khi nó di chuyển cùng điện thoại cá nhân. EFF lưu ý rằng vị trí di động và việc di chuyển cùng nhau có thể liên kết các thiết bị.<sup>[[3]](#references)</sup>
- Coi mã hóa là xóa dữ liệu; thiết bị đầu cuối và người nhận có thể vẫn giữ bản rõ.

## Danh sách kiểm tra xác minh

- [ ] Bối cảnh không có địa chỉ khôi phục cá nhân, số điện thoại, tài khoản đồng bộ hoặc nội dung đa phương tiện được dùng lại, trừ khi đã chủ động chấp nhận.
- [ ] Đường truyền mạng dự kiến đang hoạt động và hệ thống ngắt an toàn khi có lỗi.
- [ ] Múi giờ, ngôn ngữ, extension và quyền của trình duyệt/thiết bị phù hợp với kế hoạch.
- [ ] Không có tài khoản cá nhân nào đang mở trong môi trường biệt lập.
- [ ] Các tệp đã được kiểm tra và khử dữ liệu; bản gốc được xử lý riêng.
- [ ] Danh tính của các liên hệ đã được xác thực qua kênh thứ hai.
- [ ] Đã hiểu rõ metadata mà nhà cung cấp có thể thấy và thời hạn lưu giữ.
- [ ] Đã ghi lại quy trình dọn dẹp, lưu giữ bằng chứng và khôi phục tài khoản.

## References

- [1] [EFF Surveillance Self-Defense — Kế hoạch bảo mật của bạn](https://ssd.eff.org/module/your-security-plan)
- [2] [EFF Surveillance Self-Defense — Bảo vệ bản thân trên mạng xã hội](https://ssd.eff.org/module/protecting-yourself-social-networks)
- [3] [EFF Surveillance Self-Defense — Tham gia biểu tình](https://ssd.eff.org/module/attending-protest)
- [4] [NIST SP 800-63B-4 — Xác thực và quản lý phương thức xác thực](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [5] [W3C — Giảm thiểu việc lấy dấu vân tay trình duyệt trong các đặc tả web](https://www.w3.org/TR/fingerprinting-guidance/)
- [6] [Tor Project — Sử dụng Tor với các trình duyệt khác](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [7] [Tor Project — Plugin và tiện ích bổ sung trong Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [8] [EFF Surveillance Self-Defense — Vì sao metadata liên lạc lại quan trọng](https://ssd.eff.org/module/why-metadata-matters)
- [9] [Signal — Quyền riêng tư số điện thoại và tên người dùng: Tìm hiểu sâu hơn](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [10] [Proton — Nội dung nào trong Proton Mail được mã hóa?](https://proton.me/support/what-is-encrypted-within-protonmail)
- [11] [Tails — Cảnh báo: Tails an toàn nhưng không phải phép màu](https://tails.net/doc/about/warnings/index.en.html)
{{#include ../banners/hacktricks-training.md}}
