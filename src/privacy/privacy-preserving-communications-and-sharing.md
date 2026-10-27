# Liên lạc và chia sẻ bảo vệ quyền riêng tư

{{#include ../banners/hacktricks-training.md}}

Mã hóa đầu cuối bảo vệ nội dung. Nó không tự động che giấu tài khoản, số điện thoại, đồ thị liên hệ, địa chỉ IP, push token, phần xem trước thông báo, thời điểm, metadata tệp hay hành vi của người nhận. Hãy chọn công cụ dựa trên metadata mà nó loại bỏ và các bên quan sát mà nó đưa vào.

## So sánh các mô hình liên lạc

| Công cụ/mô hình | Đặc tính hữu ích | Các bên quan sát và giới hạn còn lại |
|---|---|---|
| Signal | E2EE trưởng thành; username có thể bắt đầu liên lạc mà không cần chia sẻ số điện thoại; sealed sender giảm metadata mà dịch vụ có thể thấy | Cần số điện thoại để đăng ký; dịch vụ, nhà cung cấp push, danh bạ và thiết bị đầu cuối vẫn lưu lại một số dấu vết |
| SimpleX | Không có mã định danh người dùng toàn cục; hàng đợi riêng cho từng liên hệ; tùy chọn truyền tải qua Tor | Thời điểm/truyền tải qua relay, dịch vụ push, lời mời và thiết bị đầu cuối; hệ sinh thái mới hơn/nhỏ hơn |
| Briar | Đồng bộ trực tiếp; dùng Tor khi có mạng; dùng Bluetooth/Wi-Fi khi ngoại tuyến; không có nơi lưu trữ tin nhắn tập trung | Danh bạ và thiết bị đầu cuối; bên quan sát vô tuyến cục bộ; tập trung vào Android; cả hai bên phải cùng khả dụng hoặc dùng Mailbox |
| OnionShare | Trực tiếp chia sẻ tệp/nhận tệp/trò chuyện/trang web qua dịch vụ onion tạm thời; không có nhà cung cấp lưu trữ | Máy tính của người gửi là dịch vụ; người có liên kết biết cách truy cập; thời điểm và thiết bị đầu cuối vẫn bị lộ |
| Tệp mã hóa bằng `age` | Mã hóa đơn giản bằng khóa người nhận, độc lập với phương thức truyền tải | Phương thức truyền tải biết người gửi/người nhận/thời điểm/kích thước; tên tệp/metadata lưu trữ và thiết bị đầu cuối vẫn bị lộ |
| Email thông thường + TLS | Mã hóa kênh giữa các máy chủ | Cả hai nhà cung cấp email thường có thể đọc nội dung và lưu metadata định tuyến/tài khoản |

## Signal: liên hệ riêng tư mà không tiết lộ số điện thoại

Username Signal có thể bắt đầu cuộc trò chuyện mà không tiết lộ số điện thoại của người dùng cho liên hệ mới, nhưng vẫn cần số điện thoại để đăng ký.<sup>[[1]](#references)</sup> Sealed sender là biện pháp bảo vệ metadata bổ sung, không chống được mọi kiểu tương quan IP/thời điểm.<sup>[[2]](#references)</sup>

### Quy trình

1. Cài Signal từ cửa hàng ứng dụng/dự án chính thức và cập nhật hệ điều hành trước.
2. Đăng ký bằng số điện thoại mà bạn có quyền sử dụng hợp pháp. Không dùng dịch vụ kích hoạt SMS thuê, số điện thoại của người khác hoặc tài khoản nhà cung cấp có được bằng danh tính giả.
3. Trong **Settings → Privacy → Phone Number**, thiết lập ai có thể thấy số điện thoại và ai có thể tìm tài khoản bằng số điện thoại, phù hợp với mô hình đe dọa.
4. Tạo username để người liên hệ mới có thể tìm thấy bạn. Chia sẻ chính xác liên kết/mã QR qua một kênh đã xác thực; username có thể thay đổi và không phải tên hồ sơ.
5. Tắt quyền tải lên danh bạ/quyền truy cập danh bạ nếu sự tiện lợi không đáng để đánh đổi việc liên kết danh tính; nếu nền tảng hỗ trợ, hãy thêm liên hệ thủ công.
6. Mở thông tin liên hệ và so sánh safety number/mã QR qua kênh thứ hai hoặc gặp trực tiếp trước khi gửi nội dung nhạy cảm.
7. Kiểm tra thiết bị đã liên kết, registration lock/PIN, phần xem trước thông báo, bảo mật màn hình, chuyển tiếp cuộc gọi, cài đặt mặc định cho tin nhắn tự biến mất và cách sao lưu.
8. Gửi tin nhắn và gọi thử không chứa thông tin nhạy cảm. Kiểm tra dấu vết trên màn hình khóa, máy tính, thiết bị đeo và thông báo trên đám mây ở cả hai phía.
9. Xem safety number thay đổi hoặc thiết bị liên kết bất ngờ là sự kiện cần điều tra, không phải cảnh báo có thể tự động bỏ qua.

Đừng kết hợp ảnh hồ sơ, tiểu sử, tư cách thành viên nhóm hoặc lịch trình mang tính giả danh với một bối cảnh Signal có thể nhận diện bạn.

## SimpleX: kết nối riêng cho từng liên hệ mà không có mã định danh toàn cục

SimpleX định tuyến tin nhắn qua các hàng đợi một chiều và không gán mã định danh người dùng trên toàn mạng. Chính sách của dự án vẫn nêu rõ các phiên truyền tải, dữ liệu tạm thời trên máy chủ, sự đánh đổi khi dùng thông báo push và trách nhiệm của người dùng đối với thiết bị đầu cuối.<sup>[[3]](#references)</sup>

### Quy trình

1. Tải ứng dụng được duy trì từ cửa hàng/dự án chính thức và xác minh nhà phát hành. Dùng hồ sơ hệ điều hành/ứng dụng riêng khi cần tránh trộn lẫn danh tính.
2. Tạo hồ sơ **cục bộ** với tên hiển thị và ảnh phù hợp với từng bối cảnh. Gỡ ứng dụng mà không sao lưu có thể làm mất hồ sơ và các kết nối.
3. Khi mở ứng dụng lần đầu, hãy chủ động chọn chế độ thông báo. Push tức thời trên thiết bị di động có thể làm lộ thêm metadata cho hạ tầng Apple/Google.
4. Tạo liên kết mời dùng một lần cho một liên hệ. Chuyển liên kết qua kênh đã xác thực; bất kỳ ai có được lời mời còn hiệu lực đều có thể thử sử dụng.
5. Sau khi kết nối, mở thông tin liên hệ và so sánh mã bảo mật trực tiếp hoặc qua một kênh độc lập đã xác minh.<sup>[[4]](#references)</sup>
6. Dùng hồ sơ riêng tư cho từng nhóm nếu được hỗ trợ, thay vì tái sử dụng cùng một hồ sơ trong các nhóm không liên quan.
7. Cấu hình phương thức truyền tải Tor mà ứng dụng hỗ trợ nếu không muốn mạng/máy chủ cục bộ thấy IP trực tiếp. Xác nhận kết nối sau khi thay đổi; đừng ép dùng proxy hệ thống không được hỗ trợ.
8. Kiểm tra biên nhận gửi/nhận, bản xem trước liên kết, cuộc gọi, tải xuống tự động và xuất/sao lưu cơ sở dữ liệu. Mỗi tính năng đều làm thay đổi metadata hoặc mức độ lộ thông tin từ thiết bị đầu cuối.
9. Thử khôi phục trên một thiết bị dự phòng biệt lập, không chạy bản sao hồ sơ đang hoạt động trùng lặp; dự án cảnh báo việc chạy các bản sao đồng thời có thể làm gián đoạn cuộc trò chuyện.

Không có mã định danh toàn cục không ngăn được liên hệ nhận diện người dùng qua nội dung, việc tái sử dụng hồ sơ, cách gửi lời mời, thời điểm hoặc đồ thị xã hội.

## Briar: nhắn tin trực tiếp, chống gián đoạn

Briar đồng bộ trực tiếp giữa các thiết bị, qua Tor khi có mạng và qua Bluetooth/Wi-Fi khi kết nối cục bộ bị gián đoạn. Mô hình đe dọa chính thức chỉ giả định có sự giám sát hạn chế của đối phương đối với sóng vô tuyến tầm ngắn, vì vậy kết nối không dây cục bộ không phải là vô hình.<sup>[[5]](#references)</sup>

### Quy trình

1. Cài đặt từ bản phân phối Briar chính thức và xác minh nguồn gói. Dùng thiết bị Android được hỗ trợ với các bản cập nhật bảo mật mới nhất.
2. Tạo tài khoản cục bộ với biệt danh riêng cho từng bối cảnh và mật khẩu mạnh. Không có cách đặt lại mật khẩu; hãy thử khôi phục thông tin bí mật dùng để mở khóa.
3. Nếu có thể, hãy thêm liên hệ trực tiếp bằng cách quét mã QR của nhau. Cách này xác thực liên hệ và tránh gửi liên kết qua kênh có thể bị tương quan.
4. Trong cài đặt kết nối, chỉ bật các phương thức truyền tải cần thiết: Tor/Internet, Wi-Fi và/hoặc Bluetooth. Tắt các kết nối vô tuyến cục bộ khi không cần.
5. Để gửi tin nhắn không đồng bộ, hãy cân nhắc chạy Briar Mailbox trên một thiết bị riêng luôn bật nguồn; quản lý và bảo vệ thiết bị này về mặt vật lý như máy chủ tin nhắn.
6. Gửi tin nhắn thử không nhạy cảm khi có Internet, sau đó thử phương thức dự phòng đã lên kế hoạch bằng cách tắt Internet tại địa điểm bạn được phép thực hiện.
7. Kiểm tra bản sao lưu Android, phần xem trước thông báo, ảnh chụp màn hình và nội dung đã xuất. Bộ nhớ cục bộ được mã hóa vẫn có thể bị lộ khi thiết bị đầu cuối được mở khóa/bị xâm nhập.
8. Xóa liên hệ/thiết bị bị mất và ngừng sử dụng toàn bộ bối cảnh nếu quyền kiểm soát thiết bị về mặt vật lý hoặc mật khẩu tài khoản bị xâm phạm.

## OnionShare: truyền tệp trực tiếp, tạm thời

OnionShare chạy một dịch vụ onion trên máy tính của người gửi/người nhận; tệp không được tải lên nhà cung cấp lưu trữ và lưu lượng được mã hóa đầu cuối bên trong Tor.<sup>[[6]](#references)</sup> Toàn bộ URL onion là một thông tin cho phép truy cập và phải được bảo vệ.

### Quy trình chia sẻ tệp qua GUI

1. Cài OnionShare từ bản phân phối chính thức có chữ ký và cài Tor Browser ở phía người nhận.
2. Đặt **bản sao đã được làm sạch** của tệp trong một thư mục tạm riêng. Đừng trỏ OnionShare đến thư mục nhà cá nhân.
3. Mở **Share Files**, chỉ thêm các tệp đã chuẩn bị, giữ bật bảo vệ khóa riêng/quyền truy cập và bật **Stop sharing after files have been sent** khi chia sẻ cho một người nhận.
4. Bắt đầu chia sẻ và gửi toàn bộ URL onion qua một kênh E2EE đã xác thực. Đừng dán URL vào email, hệ thống theo dõi lỗi hoặc cuộc trò chuyện công khai.
5. Người nhận mở URL trong Tor Browser, xác minh tên/kích thước tệp dự kiến với người gửi rồi tải xuống.
6. Để bảo đảm tính toàn vẹn khi tệp là ranh giới bảo mật, hai bên so sánh mã băm SHA-256 đã thống nhất trước hoặc được gửi riêng.
7. Xác nhận OnionShare đã dừng sau khi tải xuống; nếu chưa, hãy tự dừng và đóng ứng dụng.
8. Xóa bản sao tạm theo chính sách lưu giữ và kiểm tra cài đặt lịch sử/nhật ký của OnionShare để tránh vô tình tiết lộ tên tệp.

### Quy trình CLI

CLI chính thức nhận tệp dưới dạng đối số vị trí và dừng sau khi hoàn tất lần chia sẻ đầu tiên theo mặc định. Trên máy đã cài CLI/Tor chính thức:

```bash
# Inspect the installed version and options first
onionshare-cli --help

# Share one sanitized file; stop after one hour even if unused
onionshare-cli --auto-stop-timer 3600 ./staging/report-clean.pdf
```

Gửi URL đầy đủ thu được một cách an toàn. Không thêm `--public`, `--no-autostop-sharing`, ghi log tên tệp chi tiết hoặc persistence, trừ khi threat model yêu cầu rõ ràng các mức lộ thông tin đó.<sup>[[7]](#references)</sup>

Coi tài liệu nhận được là không đáng tin cậy. Mở chúng trong VM dùng một lần/công cụ kết xuất kiểu Dangerzone thay vì trên máy chủ lưu danh tính.

## Mã hóa riêng một tệp bằng `age`

Mã hóa độc lập với phương thức truyền tải hữu ích khi nhà cung cấp dịch vụ lưu trữ/email có thể nhìn thấy đối tượng. Cách này không che giấu người gửi, người nhận, kích thước, thời điểm hoặc tên tệp, trừ khi các thông tin đó được xử lý riêng.

### Thiết lập người nhận

```bash
# Creates a secret identity file; protect its permissions and backup
age-keygen -o recipient-identity.txt

# Derive a public recipient file safe to share
age-keygen -y recipient-identity.txt > recipient-public.txt
```

Xác minh chuỗi người nhận công khai qua một kênh thứ hai. Sau đó, người gửi chạy:

```bash
age -R recipient-public.txt -o package.tar.age package.tar
```

Người nhận giải mã ra một đường dẫn mới:

```bash
age --decrypt -i recipient-identity.txt -o package-restored.tar package.tar.age
```

CLI chính thức cảnh báo rằng `-o` sẽ ghi đè đầu ra hiện có, vì vậy hãy dùng thư mục mới và xác minh digest/nội dung trước khi di chuyển tệp.<sup>[[8]](#references)</sup> Không bao giờ gửi tệp định danh cùng ciphertext.

## Quy trình khử metadata có thể tái lập

Việc loại bỏ metadata phụ thuộc vào định dạng. Hãy giữ lại bản gốc đã mã hóa khi tính xác thực, pháp y hoặc chuỗi bảo quản chứng cứ là quan trọng; thao tác trên một bản sao.

### Ví dụ JPEG

```bash
mkdir -p ./clean

# Inventory embedded metadata
exiftool -a -u -g1 ./original/photo.jpg

# Write a new JPEG while retaining color-profile/color-space information
exiftool -all= --icc_profile:all -tagsfromfile @ -colorspacetags \
  -o ./clean/photo.jpg ./original/photo.jpg

# Re-inspect the output
exiftool -a -u -g1 ./clean/photo.jpg
```

Điều này tuân theo hướng dẫn an toàn hơn của ExifTool về JPEG: xóa bừa mọi thẻ cũng có thể làm mất thông tin màu.<sup>[[9]](#references)</sup> Sau đó, kiểm tra trực quan các pixel để tìm khuôn mặt, hình phản chiếu, màn hình, địa danh và các kiểu hư hại/nhiễu độc nhất.

### Quy trình Office/PDF

1. Giữ bản gốc có thể chỉnh sửa được mã hóa và tách biệt khỏi môi trường xuất bản.
2. Xóa nhận xét, nội dung chỉnh sửa được theo dõi, slide/trang tính ẩn, tệp nhúng, mẫu cá nhân và thuộc tính tài liệu trong ứng dụng soạn thảo.
3. Xuất một PDF mới từ hồ sơ sạch chuyên dụng; không “in” ra máy in đám mây.
4. Kiểm tra bằng cả công cụ nhận biết định dạng và trình kết xuất trực quan dùng một lần:

```bash
exiftool -a -u -g1 ./clean/report.pdf
pdfinfo ./clean/report.pdf
```

5. Tìm trong đầu ra đã render các tên, đường dẫn, địa chỉ email và nội dung revision. Rasterization có thể loại bỏ các cấu trúc chủ động nhưng làm giảm khả năng truy cập/tìm kiếm, đồng thời không xóa nội dung hiển thị hoặc văn phong.
6. Hash artifact cuối cùng và chỉ chuyển bản sao đó qua compartment xuất bản.

## Privacy Pass: ủy quyền ẩn danh cho nhà thiết kế dịch vụ

Privacy Pass tách biệt việc **phát hành** token khỏi việc **đổi** token. Một origin có thể biết client sở hữu token được issuer phê duyệt mà không biết tương tác phát hành cụ thể của client. Việc tái sử dụng token, metadata duy nhất, thời điểm hoặc thông đồng có thể làm lộ lại khả năng liên kết.<sup>[[10]](#references)</sup>

Mẫu triển khai an toàn:

1. Xác định tuyên bố mà token chứng minh (ví dụ: đủ điều kiện rate-limit), không phải một danh tính toàn cục bị ẩn.
2. Dùng kiến trúc và giao thức phát hành đã chuẩn hóa; không tự triển khai mật mã chữ ký mù.
3. Tách biệt quản trị issuer/attester và origin khi thuộc tính mong muốn đòi hỏi điều đó.
4. Giảm thiểu metadata token công khai/riêng tư và bảo đảm các tập ẩn danh đủ lớn.
5. Nếu được hỗ trợ, phát hành theo lô trước khi sử dụng để thời điểm phát hành không dễ dàng khớp với thời điểm đổi token.
6. Chỉ đổi mỗi token một lần, xác thực challenge gắn với origin và xóa trạng thái token đã hết hạn.
7. Không để cookie, ghi log IP và tài khoản ứng dụng âm thầm vô hiệu hóa thuộc tính bảo mật quyền riêng tư của token.
8. Kiểm tra xem log của issuer và origin có thể liên kết một sự kiện phát hành và đổi token được kiểm soát bằng thời điểm, metadata hoặc lỗi duy nhất hay không.

Privacy Pass là một tính năng ứng dụng, không phải thứ người dùng có thể tự thêm vào một tài khoản bất kỳ.

## Danh sách kiểm tra xác minh liên lạc

- [ ] Danh tính liên hệ/lời mời/khóa đã được xác thực độc lập.
- [ ] Đã hiểu rõ mức độ lộ số điện thoại, tên người dùng, hồ sơ, nhóm và dữ liệu tải lên từ danh bạ.
- [ ] Đã liệt kê các bên có thể quan sát IP trực tiếp, relay, Tor, nhà cung cấp push và radio cục bộ.
- [ ] Đã kiểm tra bản xem trước thông báo, thiết bị đeo, máy tính để bàn được liên kết và bản sao lưu.
- [ ] File đã được làm sạch, mã hóa nếu cần và mở trong môi trường dùng một lần.
- [ ] Có thể khôi phục mà không liên kết các danh tính không liên quan.
- [ ] Log, lịch sử và dịch vụ chia sẻ tạm thời có quy tắc ngừng hoạt động/lưu giữ.

## References

- [1] [Signal — Quyền riêng tư số điện thoại và tên người dùng](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [2] [Signal — Sealed Sender](https://signal.org/blog/sealed-sender/)
- [3] [SimpleX — Chính sách quyền riêng tư và Điều kiện sử dụng](https://simplex.chat/privacy/) and [Protocol design](https://simplex.chat/docs/simplex.html)
- [4] [SimpleX — Hướng dẫn về quyền riêng tư và bảo mật](https://simplex.chat/docs/guide/privacy-security.html)
- [5] [Briar — Cách hoạt động](https://briarproject.org/how-it-works/) and [Quick Start](https://briarproject.org/quick-start/)
- [6] [OnionShare — Thiết kế bảo mật](https://docs.onionshare.org/2.6/en/security.html)
- [7] [OnionShare 2.6.3 — Cách sử dụng nâng cao và CLI](https://docs.onionshare.org/2.6.3/en/advanced.html)
- [8] [`age` — CLI chính thức và cách sử dụng](https://github.com/FiloSottile/age)
- [9] [FAQ ExifTool — Xóa metadata an toàn](https://exiftool.org/faq.html#Q32)
- [10] [RFC 9576 — Kiến trúc Privacy Pass](https://www.rfc-editor.org/rfc/rfc9576.html), [RFC 9577 — HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html), and [RFC 9578 — Issuance Protocols](https://www.rfc-editor.org/rfc/rfc9578.html)
{{#include ../banners/hacktricks-training.md}}
