# Tấn công side-channel qua biên nhận gửi trong ứng dụng nhắn tin E2EE

{{#include ../banners/hacktricks-training.md}}

Biên nhận gửi là bắt buộc trong các ứng dụng nhắn tin end-to-end encrypted (E2EE) hiện đại vì client cần biết khi nào ciphertext được giải mã để có thể loại bỏ trạng thái ratchet và khóa tạm thời. Server chuyển tiếp các blob không thể đọc được, nên thiết bị người nhận sẽ gửi xác nhận (dấu tích kép) sau khi giải mã thành công. Đo thời gian khứ hồi (RTT) giữa hành động do attacker kích hoạt và biên nhận gửi tương ứng sẽ làm lộ một kênh thời gian có độ phân giải cao, leak trạng thái thiết bị và sự hiện diện trực tuyến, đồng thời có thể bị lợi dụng để DoS bí mật. Các triển khai đa thiết bị kiểu "client-fanout" khuếch đại mức độ leak vì mọi thiết bị đã đăng ký đều giải mã gói thăm dò và gửi biên nhận riêng.<sup>[[1]](#references)</sup>

## Nguồn biên nhận gửi và tín hiệu hiển thị cho người dùng

Chọn các loại tin nhắn luôn tạo biên nhận gửi nhưng không tạo dấu hiệu trên UI của nạn nhân. Bảng dưới đây tóm tắt hành vi đã được xác nhận qua thực nghiệm:<sup>[[1]](#references)</sup>

| Messenger | Hành động | Biên nhận gửi | Thông báo cho nạn nhân | Ghi chú |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Tin nhắn văn bản | ● | ● | Luôn gây chú ý → chỉ hữu ích để khởi tạo trạng thái. |
| | Reaction | ● | ◐ (chỉ khi reaction tin nhắn của nạn nhân) | Tự reaction và gỡ reaction không hiển thị. |
| | Chỉnh sửa | ● | Push im lặng tùy nền tảng | Cửa sổ chỉnh sửa ≈20 phút; vẫn được xác nhận sau khi hết hạn. |
| | Xóa với mọi người | ● | ○ | UI cho phép khoảng 60 giờ, nhưng các packet gửi muộn hơn vẫn được xác nhận. |
| **Signal** | Tin nhắn văn bản | ● | ● | Có cùng hạn chế như WhatsApp. |
| | Reaction | ● | ◐ | Tự reaction không hiển thị với nạn nhân. |
| | Chỉnh sửa/Xóa | ● | ○ | Server áp dụng cửa sổ khoảng 48 giờ, cho phép tối đa 10 lần chỉnh sửa, nhưng các packet gửi muộn vẫn được xác nhận. |
| **Threema** | Tin nhắn văn bản | ● | ● | Biên nhận của nhiều thiết bị được tổng hợp, nên mỗi gói thăm dò chỉ hiển thị một RTT. |

Chú giải: ● = luôn luôn, ◐ = có điều kiện, ○ = không bao giờ. Hành vi UI tùy nền tảng được ghi chú ngay trong bảng. Tắt biên nhận đã đọc nếu cần, nhưng không thể tắt biên nhận gửi trong WhatsApp hoặc Signal.<sup>[[1]](#references)</sup>

## Mục tiêu và mô hình của attacker

* **G1 – Nhận dạng thiết bị:** Đếm số biên nhận đến theo từng gói thăm dò, phân cụm RTT để suy luận OS/client (Android, iOS hay desktop), và theo dõi các lần chuyển trạng thái trực tuyến/ngoại tuyến.
* **G2 – Giám sát hành vi:** Xem chuỗi RTT tần suất cao (≈1 Hz là ổn định) như một chuỗi thời gian và suy luận trạng thái bật/tắt màn hình, app ở foreground/background, giờ đi làm hay giờ làm việc, v.v.
* **G3 – Làm cạn tài nguyên:** Giữ cho radio/CPU của mọi thiết bị nạn nhân luôn hoạt động bằng cách gửi các gói thăm dò im lặng không ngừng, làm hao pin/dữ liệu và giảm chất lượng cuộc gọi video.<sup>[[1]](#references)</sup>

Có thể mô tả bề mặt lạm dụng bằng hai tác nhân đe dọa:<sup>[[1]](#references)</sup>

1. **Người quen đáng ngờ:** Đã có cuộc trò chuyện với nạn nhân và lạm dụng tính năng tự reaction, gỡ reaction hoặc chỉnh sửa/xóa liên tục dựa trên ID tin nhắn có sẵn.
2. **Người lạ đáng ngờ:** Đăng ký tài khoản dùng một lần và gửi reaction tham chiếu đến các ID tin nhắn chưa từng tồn tại trong cuộc trò chuyện cục bộ; WhatsApp và Signal vẫn giải mã và xác nhận các reaction đó dù UI loại bỏ thay đổi trạng thái, nên không cần có cuộc trò chuyện trước đó.

## Công cụ truy cập giao thức thô

Dùng các client cung cấp đủ quyền truy cập vào giao thức E2EE bên dưới để tạo packet được hỗ trợ ngoài các giới hạn của UI và ghi lại timestamp chính xác; cần kiểm tra từng triển khai để biết có thể dùng ID tin nhắn tùy ý hay không:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, API đa thiết bị WhatsApp Web) có tài liệu về cách gửi và nhận biên nhận gửi; [Cobalt](https://github.com/Auties00/Cobalt) (API Web và mobile không chính thức bằng Java/Kotlin) có tài liệu về các thao tác tin nhắn như reaction, chỉnh sửa và xóa. Dùng các API được tài liệu hóa thay vì mặc định rằng mọi frame nội bộ đều được công khai.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) cung cấp các giao diện CLI, JSON-RPC và D-Bus, còn [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) là thư viện Java để giao tiếp với Signal.<sup>[[5]](#references)[[7]](#references)</sup> Cú pháp `signal-cli` hiện tại dùng `sendReaction RECIPIENT --target-author --target-timestamp`; giữ `receive` hoặc `daemon` chạy để tiếp tục xử lý các bản cập nhật giao thức.<sup>[[6]](#references)</sup> Ví dụ bật/tắt tự reaction:
  ```bash
  signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
      --target-timestamp 1712345678901 --emoji "👍"
  signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
      --target-timestamp 1712345678901 --remove
  ```
* **Threema:** Các phép đo trong bài báo Careless Whisper cho thấy biên nhận gửi được đồng bộ giữa các thiết bị, nên chỉ một biên nhận cho mỗi tin nhắn bị lộ ngay cả khi thiết lập nhiều thiết bị.<sup>[[1]](#references)</sup>
* **PoC dùng ngay:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) đi kèm các backend WhatsApp/Signal, mặc định dùng các probe xóa im lặng và phân loại `active` với `standby` bằng ngưỡng trung vị trượt (`RTT < 0.9 * median`).<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) là một CLI nhẹ hơn, ưu tiên WhatsApp, có `--delay`, `--concurrent`, bộ xuất CSV/Prometheus và đầu ra tương thích với Grafana.<sup>[[9]](#references)</sup> Hãy xem cả hai là công cụ hỗ trợ trinh sát, không phải tài liệu tham khảo về giao thức; điều quan trọng cần rút ra là cần rất ít mã khi đã có quyền truy cập trực tiếp vào client.

Khi không có công cụ tùy chỉnh, client chính thức hoặc công cụ dành cho nhà phát triển của trình duyệt vẫn có thể kích hoạt các hành động im lặng và làm lộ thời điểm của lưu lượng đã mã hóa; API thô loại bỏ độ trễ giao diện và cho phép thực hiện các thao tác không hợp lệ.<sup>[[1]](#references)</sup>

## Đồng phạm rùng rợn: vòng lặp lấy mẫu im lặng

1. Chọn bất kỳ tin nhắn cũ nào do bạn gửi trong cuộc trò chuyện để nạn nhân không bao giờ thấy các bong bóng "reaction" thay đổi.
2. Luân phiên giữa một emoji hiển thị và payload reaction rỗng (được mã hóa thành `""` trong protobuf của WhatsApp hoặc dùng `--remove` trong signal-cli). Mỗi lần truyền đều tạo ra một ack từ thiết bị dù giao diện của nạn nhân không thay đổi.
3. Ghi lại thời điểm gửi và thời điểm nhận từng biên nhận gửi. Vòng lặp 1 Hz như sau sẽ tạo ra các dấu vết RTT theo từng thiết bị vô thời hạn:
   ```python
   while True:
       send_reaction(msg_id, "👍")
       log_receipts()
       send_reaction(msg_id, "")  # removal
       log_receipts()
       time.sleep(0.5)
   ```
4. Vì WhatsApp/Signal chấp nhận các cập nhật reaction không giới hạn, kẻ tấn công không bao giờ cần đăng nội dung chat mới hay lo về thời hạn chỉnh sửa.<sup>[[1]](#references)</sup>

## Người lạ bí ẩn: dò quét các số điện thoại bất kỳ

1. Đăng ký tài khoản WhatsApp/Signal mới và lấy public identity keys của số điện thoại mục tiêu (việc này tự động diễn ra trong quá trình thiết lập phiên).
2. Tạo một packet reaction tham chiếu đến `message_id` ngẫu nhiên mà cả hai bên chưa từng thấy; bài báo cho biết cả WhatsApp lẫn Signal đều chấp nhận các reaction như vậy và vẫn tạo delivery receipts.<sup>[[1]](#references)</sup>
3. Gửi packet dù không có thread nào. Thiết bị của nạn nhân giải mã packet, không khớp được với tin nhắn gốc, loại bỏ thay đổi trạng thái, nhưng vẫn xác nhận ciphertext nhận được và gửi device receipts lại cho kẻ tấn công.
4. Lặp lại liên tục để tạo chuỗi RTT mà không cần có cuộc trò chuyện trước đó hoặc thông báo hiển thị.<sup>[[1]](#references)</sup>

Nếu trước tiên cần xác định số nào đã đăng ký hoặc muốn tạo sẵn danh sách thiết bị trên quy mô lớn, hãy kết hợp kỹ thuật này với [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) thay vì tự đoán các dải E.164 ngẫu nhiên.

Nghiên cứu contact-discovery đã công bố cho thấy điều này quan trọng như thế nào trong thực tế: với bảng tiền tố điện thoại chính xác và nguồn lực vừa phải, các nhà nghiên cứu có thể truy vấn khoảng `10%` số điện thoại di động tại Mỹ trên WhatsApp và `100%` trên Signal trước khi chuyển sang dò quét có mục tiêu.<sup>[[11]](#references)</sup> Trong thực tế, lọc trước các tài khoản đang hoạt động giúp tập trung ngân sách silent-probe vào những số thực sự giải mã được packet.

Các bản WhatsApp gần đây cũng có tùy chọn `Settings -> Privacy -> Advanced -> Block unknown account messages`.<sup>[[10]](#references)</sup> Hãy xem đây là giới hạn thông lượng: tài liệu về tracker cho biết WhatsApp chặn lượng lớn tin nhắn từ tài khoản không xác định nhưng không công bố ngưỡng, nên tính năng này không ngăn chặn hoàn toàn các probe reaction.<sup>[[8]](#references)</sup>

## Tái sử dụng thao tác chỉnh sửa và xóa làm tín hiệu kích hoạt ngầm

* **Xóa lặp lại:** Sau khi một tin nhắn đã được xóa cho mọi người, các packet xóa tiếp theo tham chiếu cùng `message_id` không gây thay đổi nào trên UI, nhưng mọi thiết bị vẫn giải mã và xác nhận chúng.
* **Thao tác ngoài thời hạn:** WhatsApp áp dụng thời hạn khoảng 60 giờ để xóa / khoảng 20 phút để chỉnh sửa trên UI; Signal áp dụng thời hạn khoảng 48 giờ. Các protocol message được tạo bên ngoài những thời hạn này sẽ bị thiết bị nạn nhân âm thầm bỏ qua nhưng vẫn gửi receipts, vì vậy kẻ tấn công có thể dò quét vô thời hạn sau khi cuộc trò chuyện kết thúc.
* **Payload không hợp lệ:** Bài báo cho biết các tin nhắn không hợp lệ vẫn có thể được xác nhận; hành vi chính xác với nội dung bị lỗi định dạng hoặc ID đã bị xóa tùy thuộc vào cách triển khai, vì vậy hãy kiểm tra trước khi dựa vào đó.<sup>[[1]](#references)</sup>

## Khuếch đại đa thiết bị và fingerprinting

* Trên WhatsApp và Signal, mỗi thiết bị được liên kết (điện thoại, ứng dụng desktop, trình duyệt đồng hành) giải mã probe độc lập và gửi ack riêng. Đếm số receipts cho mỗi probe sẽ cho biết chính xác số lượng thiết bị.<sup>[[1]](#references)</sup>
* Nếu thiết bị ngoại tuyến, receipt của thiết bị đó sẽ được xếp hàng và gửi khi kết nối lại. Do đó, các khoảng trống làm lộ chu kỳ online/offline, thậm chí cả lịch trình đi lại (ví dụ: desktop receipts ngừng xuất hiện khi người dùng di chuyển).
* Phân bố RTT khác nhau tùy nền tảng và môi trường vì hệ điều hành, model, client và điều kiện mạng ảnh hưởng đến thời gian. Phân cụm RTT (ví dụ: dùng k-means trên các đặc trưng median/variance) để gán nhãn “điện thoại Android”, “điện thoại iOS”, “desktop Electron”, v.v.
* Vì người gửi phải lấy danh sách key của người nhận trước khi mã hóa, kẻ tấn công cũng có thể theo dõi thời điểm thiết bị mới được ghép nối; số lượng thiết bị tăng đột ngột hoặc xuất hiện cụm RTT mới là dấu hiệu rõ ràng.<sup>[[1]](#references)</sup>

## Nhịp lấy mẫu, xếp hàng và receipts chồng lấn

* **Khả năng chịu burst của WhatsApp:** Các phép đo đã công bố cho biết WhatsApp chấp nhận các burst silent-reaction nhanh đến mức mỗi `50 ms` có một probe mà không thấy server-side queueing rõ rệt. Điều này hữu ích cho các burst hiệu chuẩn ngắn, đếm thiết bị nhanh hoặc nhanh chóng tăng cường độ của một cuộc tấn công drain.
* **Xếp hàng dài hạn trên Signal:** Signal chịu được các burst ngắn nhưng bắt đầu xếp hàng khi lưu lượng nhiều probe mỗi giây được duy trì liên tục. Để giám sát dài hạn, hãy giữ nhịp khoảng `1 Hz` (hoặc thấp hơn) để mỗi receipt vẫn phản ánh trạng thái thiết bị hiện tại thay vì xử lý backlog.
* **Hiện tượng khi kết nối lại:** Khi thiết bị kết nối lại, một số client gom nhóm hoặc nhanh chóng gửi hàng loạt receipts bị trì hoãn. Hãy xem các burst receipt đó là dấu mốc chuyển trạng thái thay vì các mẫu RTT độc lập, nếu không bộ phân loại `active` và `idle` của bạn sẽ overfit với nhiễu do kết nối lại.<sup>[[1]](#references)</sup>

## Suy luận hành vi từ dấu vết RTT

1. Lấy mẫu ở tần suất ≥1 Hz để ghi nhận ảnh hưởng của việc lập lịch hệ điều hành. Với WhatsApp trên iOS, RTT <1 giây tương quan chặt với trạng thái màn hình bật/ứng dụng ở foreground; RTT >1 giây tương quan với trạng thái màn hình tắt/ứng dụng bị giới hạn ở background.
2. Xây dựng các bộ phân loại đơn giản (dựa trên ngưỡng hoặc k-means hai cụm) để gán nhãn mỗi RTT là “active” hoặc “idle”. Gom các nhãn thành chuỗi để suy ra giờ đi ngủ, giờ đi lại, giờ làm việc hoặc thời điểm ứng dụng đồng hành trên desktop hoạt động.
3. Dùng các probe đồng thời hướng đến mọi thiết bị để xem khi nào người dùng chuyển từ mobile sang desktop, khi nào thiết bị đồng hành offline và liệu ứng dụng có bị giới hạn tốc độ do push hay persistent socket.
4. Trong mạng thực tế, tránh dùng một ngưỡng `1 s` cố định. Khởi tạo từng thiết bị bằng một khoảng thời gian làm nóng ngắn và duy trì baseline cuốn chiếu (ví dụ: PoC device-activity-tracker dùng `threshold = 0.9 * median RTT`) để độ trôi của Wi-Fi/di động không làm hỏng bộ phân loại.<sup>[[1]](#references)[[8]](#references)</sup>

## Suy luận vị trí từ delivery RTT

Có thể tận dụng cùng một primitive đo thời gian để suy luận vị trí của người nhận, chứ không chỉ biết họ có đang hoạt động hay không. Nghiên cứu `Hope of Delivery` cho thấy việc huấn luyện trên các phân bố RTT tại những vị trí đã biết của người nhận cho phép kẻ tấn công phân loại vị trí của nạn nhân chỉ từ delivery confirmations:<sup>[[2]](#references)</sup>

* Tạo baseline cho cùng một mục tiêu khi họ ở một số địa điểm đã biết (nhà, văn phòng, khuôn viên trường, quốc gia A so với quốc gia B, v.v.).
* Với mỗi địa điểm, thu thập nhiều RTT của tin nhắn thông thường và trích xuất các đặc trưng đơn giản như median, variance hoặc các nhóm percentile.
* Trong cuộc tấn công thực tế, so sánh chuỗi probe mới với các cụm đã huấn luyện. Bài báo cho biết thường có thể phân biệt cả những địa điểm trong cùng một thành phố, với độ chính xác `>80%` trong kịch bản gồm 3 địa điểm.
* Cách này hiệu quả nhất khi kẻ tấn công kiểm soát môi trường gửi và thực hiện probe trong điều kiện mạng tương tự, vì đường truyền được đo bao gồm mạng truy cập của người nhận, độ trễ đánh thức thiết bị và hạ tầng messenger.<sup>[[2]](#references)</sup>

Không giống các cuộc tấn công silent reaction/edit/delete ở trên, suy luận vị trí không cần ID tin nhắn không hợp lệ hay packet thay đổi trạng thái một cách kín đáo. Chỉ cần tin nhắn thông thường với delivery confirmations bình thường, nên đánh đổi là mức độ kín đáo thấp hơn nhưng có thể áp dụng rộng hơn trên nhiều messenger.

## Làm cạn kiệt tài nguyên một cách kín đáo

Vì mọi silent probe đều phải được giải mã và xác nhận, việc liên tục gửi reaction toggles, edit không hợp lệ hoặc packet delete-for-everyone sẽ tạo ra một cuộc tấn công DoS ở tầng ứng dụng:<sup>[[1]](#references)</sup>

* Buộc radio/modem truyền/nhận mỗi giây → gây hao pin đáng kể, đặc biệt trên điện thoại đang rảnh.
* Tạo lưu lượng lên/xuống tiêu tốn gói dữ liệu di động và có thể cạnh tranh tài nguyên với các tính năng nhạy cảm với độ trễ như cuộc gọi video.<sup>[[1]](#references)</sup>
* Payload không hợp lệ lớn làm tăng khối lượng xử lý, nhưng bài báo cho biết bản thân hoạt động mã hóa chỉ chiếm phần không đáng kể trong mức tiêu thụ pin.<sup>[[1]](#references)</sup>
* Trên WhatsApp, reaction không hợp lệ có thể chấp nhận nhiều dữ liệu hơn rất nhiều so với những gì một emoji thông thường gợi ý: các phép đo đã công bố cho thấy server-side chấp nhận tối đa khoảng `1 MB` cho mỗi reaction.
* Reaction quá lớn không còn tạo delivery receipts đáng tin cậy khi phần thân vượt quá khoảng `30 bytes`, nhưng vẫn được chuyển tiếp và xử lý trước khi bị loại bỏ. Hãy giữ phần thân reaction thật nhỏ khi cần ACK; chỉ làm chúng lớn hơn khi mục tiêu đơn thuần là drain hoặc vận chuyển dữ liệu ngầm một chiều.
* Các phép đo công khai đạt khoảng `3.7 MB/s` (`~13.3 GB/h`) lưu lượng trên thiết bị nạn nhân ở chế độ này.

## References

- [1] [Lời thì thầm bất cẩn: Khai thác các xác nhận gửi âm thầm để giám sát người dùng trên các ứng dụng nhắn tin tức thời di động](https://arxiv.org/html/2411.11194v4)
- [2] [Hy vọng được gửi đi: Trích xuất vị trí người dùng từ các ứng dụng nhắn tin tức thời di động](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [trang man signal-cli](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [Cách chặn lượng lớn tin nhắn không xác định | Trung tâm trợ giúp WhatsApp](https://faq.whatsapp.com/3379690015658337)
- [11] [Tất cả các số đều là của Mỹ: Lạm dụng quy mô lớn tính năng Contact Discovery trên các ứng dụng nhắn tin di động](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)
{{#include ../banners/hacktricks-training.md}}
