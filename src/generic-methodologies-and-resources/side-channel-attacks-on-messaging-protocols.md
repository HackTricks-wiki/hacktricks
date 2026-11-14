# Tấn công Side-Channel qua Biên nhận gửi trong các ứng dụng nhắn tin E2EE

{{#include ../banners/hacktricks-training.md}}

Biên nhận gửi là bắt buộc trong các ứng dụng nhắn tin end-to-end encrypted (E2EE) hiện đại vì client cần biết khi nào ciphertext đã được giải mã để có thể loại bỏ trạng thái ratchet và khóa tạm thời. Server chuyển tiếp các blob không thể đọc được, vì vậy thiết bị người nhận gửi xác nhận (dấu tích kép) sau khi giải mã thành công. Đo thời gian khứ hồi (RTT) giữa một hành động do attacker kích hoạt và biên nhận gửi tương ứng sẽ làm lộ một kênh timing có độ phân giải cao, tiết lộ trạng thái thiết bị và sự hiện diện trực tuyến, đồng thời có thể bị lợi dụng để DoS bí mật. Các triển khai đa thiết bị kiểu "client-fanout" khuếch đại lượng thông tin bị lộ vì mọi thiết bị đã đăng ký đều giải mã probe và gửi biên nhận riêng.<sup>[[1]](#references)</sup>

## Nguồn biên nhận gửi và tín hiệu hiển thị với người dùng

Chọn các loại tin nhắn luôn tạo biên nhận gửi nhưng không hiển thị dấu vết UI trên thiết bị nạn nhân. Bảng dưới đây tóm tắt hành vi đã được xác nhận thực nghiệm:<sup>[[1]](#references)</sup>

| Messenger | Hành động | Biên nhận gửi | Thông báo cho nạn nhân | Ghi chú |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Tin nhắn văn bản | ● | ● | Luôn gây chú ý → chỉ hữu ích để khởi tạo trạng thái. |
| | Reaction | ● | ◐ (chỉ khi reaction tin nhắn của nạn nhân) | Tự reaction và gỡ reaction vẫn im lặng. |
| | Chỉnh sửa | ● | Silent push tùy nền tảng | Cửa sổ chỉnh sửa ≈20 phút; vẫn được xác nhận sau khi hết hạn. |
| | Xóa với mọi người | ● | ○ | UI cho phép khoảng 60 giờ, nhưng các packet gửi sau đó vẫn được xác nhận. |
| **Signal** | Tin nhắn văn bản | ● | ● | Hạn chế tương tự WhatsApp. |
| | Reaction | ● | ◐ | Tự reaction không hiển thị với nạn nhân. |
| | Chỉnh sửa/Xóa | ● | ○ | Server áp dụng giới hạn khoảng 48 giờ, cho phép tối đa 10 lần chỉnh sửa, nhưng các packet gửi muộn vẫn được xác nhận. |
| **Threema** | Tin nhắn văn bản | ● | ● | Biên nhận trên nhiều thiết bị được gộp lại, nên mỗi probe chỉ hiển thị một RTT. |

Chú giải: ● = luôn luôn, ◐ = tùy điều kiện, ○ = không bao giờ. Hành vi UI tùy nền tảng được ghi chú ngay trong bảng. Có thể tắt biên nhận đã đọc nếu cần, nhưng không thể tắt biên nhận gửi trên WhatsApp hoặc Signal.<sup>[[1]](#references)</sup>

## Mục tiêu và mô hình của attacker

* **G1 – Fingerprinting thiết bị:** Đếm số biên nhận đến được cho mỗi probe, phân nhóm RTT để suy đoán OS/client (Android, iOS hay desktop), và theo dõi các lần chuyển trạng thái trực tuyến/ngoại tuyến.
* **G2 – Giám sát hành vi:** Xem chuỗi RTT tần suất cao (≈1 Hz là ổn định) như một chuỗi thời gian và suy luận màn hình bật/tắt, ứng dụng ở foreground/background, giờ đi làm hay làm việc, v.v.
* **G3 – Cạn kiệt tài nguyên:** Giữ radio/CPU của mọi thiết bị nạn nhân luôn hoạt động bằng cách gửi probe im lặng không ngừng, làm hao pin/dữ liệu và giảm chất lượng cuộc gọi video.<sup>[[1]](#references)</sup>

Hai tác nhân đe dọa là đủ để mô tả bề mặt lạm dụng:<sup>[[1]](#references)</sup>

1. **Kẻ đồng hành đáng ngờ:** đã có chung cuộc trò chuyện với nạn nhân và lạm dụng tính năng tự reaction, gỡ reaction hoặc chỉnh sửa/xóa lặp đi lặp lại gắn với các ID tin nhắn hiện có.
2. **Người lạ đáng ngờ:** đăng ký tài khoản dùng một lần và gửi reaction tham chiếu đến các ID tin nhắn chưa từng tồn tại trong cuộc trò chuyện cục bộ; WhatsApp và Signal vẫn giải mã và xác nhận chúng dù UI loại bỏ thay đổi trạng thái, nên không cần có cuộc trò chuyện trước đó.

## Công cụ truy cập protocol thô

Dùng các client có thể hiển thị đủ thông tin về protocol E2EE bên dưới để tạo packet được hỗ trợ ngoài các giới hạn của UI và ghi lại timestamp chính xác; cần kiểm tra từng triển khai khi dùng ID tin nhắn tùy ý:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, API đa thiết bị WhatsApp Web) có tài liệu về việc gửi và nhận biên nhận gửi; [Cobalt](https://github.com/Auties00/Cobalt) (API Web và mobile không chính thức cho Java/Kotlin) có tài liệu về các thao tác với tin nhắn như reaction, chỉnh sửa và xóa. Hãy dùng các API được tài liệu hóa thay vì cho rằng mọi frame nội bộ đều được cung cấp.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) cung cấp giao diện CLI, JSON-RPC và D-Bus, còn [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) là thư viện Java để giao tiếp với Signal.<sup>[[5]](#references)[[7]](#references)</sup> Cú pháp `signal-cli` hiện tại dùng `sendReaction RECIPIENT --target-author --target-timestamp`; hãy duy trì `receive` hoặc `daemon` để tiếp tục xử lý các cập nhật protocol.<sup>[[6]](#references)</sup> Ví dụ bật/tắt tự reaction:
  ```bash
  signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
      --target-timestamp 1712345678901 --emoji "👍"
  signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
      --target-timestamp 1712345678901 --remove
  ```
* **Threema:** Các phép đo trong bài báo Careless Whisper cho thấy biên nhận đã giao được đồng bộ giữa các thiết bị, nên chỉ một biên nhận cho mỗi tin nhắn bị lộ, ngay cả khi thiết lập nhiều thiết bị.<sup>[[1]](#references)</sup>
* **PoC dùng ngay:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) có sẵn backend WhatsApp/Signal, mặc định dùng các probe xóa im lặng và phân loại `active` vs `standby` bằng ngưỡng trung vị trượt (`RTT < 0.9 * median`).<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) là CLI nhẹ hơn, ưu tiên WhatsApp, có `--delay`, `--concurrent`, bộ xuất CSV/Prometheus và đầu ra tương thích với Grafana.<sup>[[9]](#references)</sup> Hãy xem cả hai là công cụ hỗ trợ trinh sát, không phải tài liệu tham khảo về protocol; điều quan trọng là chỉ cần rất ít code khi đã có quyền truy cập client thô.

Khi không có công cụ tùy chỉnh, client chính thức hoặc công cụ dành cho nhà phát triển của trình duyệt vẫn có thể kích hoạt các hành động im lặng và làm lộ thời điểm lưu lượng đã mã hóa; raw API loại bỏ độ trễ của UI và cho phép thực hiện các thao tác không hợp lệ.<sup>[[1]](#references)</sup>

## Companion rùng rợn: vòng lặp lấy mẫu im lặng

1. Chọn bất kỳ tin nhắn cũ nào do bạn gửi trong cuộc trò chuyện để nạn nhân không bao giờ thấy các bong bóng "reaction" thay đổi.
2. Luân phiên giữa một emoji hiển thị được và một payload reaction rỗng (mã hóa thành `""` trong protobuf của WhatsApp hoặc dùng `--remove` trong signal-cli). Mỗi lần gửi đều tạo ra device ack dù UI của nạn nhân không có gì thay đổi.
3. Ghi lại thời điểm gửi và thời điểm nhận từng biên nhận đã giao. Vòng lặp 1 Hz như sau sẽ tạo ra các dấu vết RTT theo từng thiết bị vô thời hạn:
   ```python
   while True:
       send_reaction(msg_id, "👍")
       log_receipts()
       send_reaction(msg_id, "")  # removal
       log_receipts()
       time.sleep(0.5)
   ```
4. Vì WhatsApp/Signal chấp nhận các cập nhật reaction không giới hạn, kẻ tấn công không cần đăng nội dung chat mới hoặc lo về thời hạn chỉnh sửa.<sup>[[1]](#references)</sup>

## Người lạ bí ẩn: thăm dò các số điện thoại bất kỳ

1. Đăng ký tài khoản WhatsApp/Signal mới và lấy public identity keys của số điện thoại mục tiêu (việc này tự động diễn ra trong quá trình thiết lập phiên).
2. Tạo một gói reaction tham chiếu đến `message_id` ngẫu nhiên mà cả hai bên chưa từng thấy; bài báo cho biết WhatsApp và Signal đều chấp nhận các reaction như vậy và vẫn tạo delivery receipts.<sup>[[1]](#references)</sup>
3. Gửi gói tin dù chưa có thread nào tồn tại. Thiết bị của nạn nhân giải mã gói tin, không tìm thấy tin nhắn gốc tương ứng, loại bỏ thay đổi trạng thái nhưng vẫn xác nhận ciphertext nhận được, gửi device receipts về cho kẻ tấn công.
4. Lặp lại liên tục để tạo chuỗi RTT mà không cần có cuộc trò chuyện trước đó hoặc hiển thị thông báo.<sup>[[1]](#references)</sup>

Nếu trước tiên cần tìm những số nào đã đăng ký hoặc muốn thu thập trước danh sách thiết bị trên quy mô lớn, hãy kết hợp kỹ thuật này với [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) thay vì tự đoán các dải E.164 ngẫu nhiên.

Các nghiên cứu contact-discovery đã cho thấy tầm quan trọng thực tế của việc này: với bảng tiền tố số điện thoại chính xác và nguồn lực vừa phải, các nhà nghiên cứu có thể truy vấn khoảng `10%` số di động ở Mỹ trên WhatsApp và `100%` trên Signal trước khi chuyển sang thăm dò mục tiêu cụ thể.<sup>[[11]](#references)</sup> Trên thực tế, lọc trước các tài khoản đang hoạt động giúp tập trung ngân sách silent-probe vào những số thực sự giải mã được gói tin.

Các bản WhatsApp gần đây cũng có tùy chọn `Settings -> Privacy -> Advanced -> Block unknown account messages`.<sup>[[10]](#references)</sup> Hãy xem đây là giới hạn thông lượng: tài liệu của tracker cho biết WhatsApp chặn lượng lớn tin nhắn từ tài khoản lạ nhưng không tiết lộ ngưỡng, do đó tùy chọn này không ngăn chặn hoàn toàn các reaction thăm dò.<sup>[[8]](#references)</sup>

## Tái sử dụng thao tác chỉnh sửa và xóa làm trigger bí mật

* **Xóa lặp lại:** Sau khi một tin nhắn đã được xóa cho tất cả mọi người, các gói delete tiếp theo tham chiếu cùng `message_id` không làm thay đổi giao diện, nhưng mọi thiết bị vẫn giải mã và xác nhận chúng.
* **Thao tác ngoài thời hạn:** WhatsApp áp dụng thời hạn khoảng 60 giờ để xóa / 20 phút để chỉnh sửa trên giao diện; Signal áp dụng khoảng 48 giờ. Các tin nhắn giao thức được tạo bên ngoài những thời hạn này sẽ bị thiết bị nạn nhân âm thầm bỏ qua, nhưng receipts vẫn được truyền đi, cho phép kẻ tấn công thăm dò vô thời hạn sau khi cuộc trò chuyện kết thúc.
* **Payload không hợp lệ:** Bài báo cho biết tin nhắn không hợp lệ vẫn có thể được xác nhận; hành vi cụ thể với nội dung sai định dạng hoặc ID đã bị xóa phụ thuộc vào cách triển khai, vì vậy hãy kiểm thử trước khi dựa vào điều này.<sup>[[1]](#references)</sup>

## Khuếch đại và fingerprinting đa thiết bị

* Trên WhatsApp và Signal, mỗi thiết bị được liên kết (điện thoại, ứng dụng desktop, trình duyệt đồng hành) giải mã probe độc lập và trả về ack riêng. Đếm receipts cho mỗi probe sẽ tiết lộ chính xác số lượng thiết bị.<sup>[[1]](#references)</sup>
* Nếu một thiết bị đang offline, receipt của thiết bị đó sẽ được xếp hàng và gửi đi khi thiết bị kết nối lại. Do đó, các khoảng trống sẽ leak chu kỳ online/offline, thậm chí cả lịch trình đi lại (ví dụ: receipts từ desktop ngừng xuất hiện khi người dùng đang di chuyển).
* Phân bố RTT khác nhau tùy nền tảng và môi trường vì OS, model, client và điều kiện mạng ảnh hưởng đến thời gian phản hồi. Phân cụm RTT (ví dụ: dùng k-means trên các đặc trưng median/variance) để gán nhãn như “thiết bị Android”, “thiết bị iOS”, “desktop Electron”, v.v.
* Vì người gửi phải lấy danh sách key của người nhận trước khi mã hóa, kẻ tấn công cũng có thể theo dõi thời điểm thiết bị mới được ghép nối; số thiết bị tăng đột ngột hoặc xuất hiện cụm RTT mới là dấu hiệu rõ ràng.<sup>[[1]](#references)</sup>

**Fingerprint từ receipts được xếp hàng:** Gửi một vài probe với các message ID riêng biệt trong khi thiết bị mục tiêu offline. Khi thiết bị kết nối lại, đối chiếu các ID trong delivery receipts được trả về và kiểm tra xem chúng được gửi riêng hay gộp vào một receipt, cũng như thứ tự các ID được giữ nguyên hay đảo ngược khi gộp. Trong các client được kiểm thử, WhatsApp trên Android/iOS trả về delivery receipts riêng lẻ, trong khi Web, Windows và macOS gộp chúng; macOS đảo thứ tự các ID được gộp. Signal Desktop gộp receipts, khác với các client di động. Cách này có thể phân loại client khi kết nối lại ngay cả khi các phân bố RTT chồng lấn. Đừng nhầm delivery receipts với read receipts, vì quy tắc gộp của chúng khác nhau.<sup>[[1]](#references)</sup>

Để xem một probe WhatsApp riêng biệt đọc **server-side prekey refills** mà không gửi tin nhắn, hãy xem [Prekey Bundle Depletion and Refill Side Channel](whatsapp-prekey-bundle-side-channel.md).

## Tần suất lấy mẫu, xếp hàng và receipts được gộp

* **Khả năng chịu burst của WhatsApp:** Các phép đo đã công bố cho biết WhatsApp chấp nhận các burst silent-reaction nhanh tới mức một probe mỗi `50 ms` mà không có dấu hiệu xếp hàng rõ ràng ở phía máy chủ. Điều này hữu ích cho các burst hiệu chỉnh ngắn, đếm thiết bị nhanh hoặc tăng tốc một cuộc tấn công drain.
* **Xếp hàng dài hạn trên Signal:** Signal chịu được các burst ngắn nhưng bắt đầu xếp hàng khi lưu lượng nhiều probe mỗi giây được duy trì. Để giám sát dài hạn, hãy giữ nhịp khoảng `1 Hz` (hoặc thấp hơn) để mỗi receipt vẫn phản ánh trạng thái thiết bị hiện tại thay vì lượng tin đang chờ được gửi.
* **Hiện tượng khi kết nối lại:** Khi một thiết bị online trở lại, một số client sẽ gộp nhiều receipts bị trì hoãn thành lô hoặc gửi chúng đi nhanh liên tiếp. Hãy xem các burst receipt đó là dấu mốc chuyển trạng thái thay vì các mẫu RTT độc lập, nếu không bộ phân loại `/` của bạn cho `active` và `idle` sẽ khớp quá mức với nhiễu khi kết nối lại.<sup>[[1]](#references)</sup>

## Suy luận hành vi từ các dấu vết RTT

1. Lấy mẫu ở tần suất ≥1 Hz để ghi nhận ảnh hưởng của lịch trình OS. Với WhatsApp trên iOS, RTT <1 giây tương quan mạnh với trạng thái màn hình bật/ứng dụng ở foreground; RTT >1 giây tương quan với trạng thái màn hình tắt/ứng dụng ở background bị hạn chế.
2. Tạo các bộ phân loại đơn giản (dựa trên ngưỡng hoặc k-means hai cụm) để gán nhãn mỗi RTT là "active" hoặc "idle". Gộp các nhãn thành chuỗi để suy ra giờ đi ngủ, thời gian đi lại, giờ làm việc hoặc thời điểm companion trên desktop hoạt động.
3. Thăm dò đồng thời mọi thiết bị để xác định thời điểm người dùng chuyển từ di động sang desktop, khi companion offline và liệu ứng dụng bị giới hạn tốc độ bởi push hay socket liên tục.
4. Trên mạng thực tế, tránh dùng một ngưỡng `1 s` cố định. Khởi tạo mỗi thiết bị bằng một khoảng thời gian làm nóng ngắn và duy trì baseline cuốn chiếu (ví dụ: PoC device-activity-tracker dùng `threshold = 0.9 * median RTT`) để tránh việc dao động Wi-Fi/di động làm hỏng bộ phân loại.<sup>[[1]](#references)[[8]](#references)</sup>

## Suy luận vị trí từ delivery RTT

Cùng một phương pháp đo thời gian này có thể được dùng để suy luận vị trí của người nhận, không chỉ xác định họ có đang hoạt động hay không. Nghiên cứu `Hope of Delivery` cho thấy việc huấn luyện trên các phân bố RTT tại những vị trí đã biết của người nhận giúp kẻ tấn công phân loại vị trí của nạn nhân chỉ dựa vào xác nhận gửi tin:<sup>[[2]](#references)</sup>

* Tạo baseline cho cùng một mục tiêu khi họ ở một số địa điểm đã biết (nhà, văn phòng, khuôn viên trường, quốc gia A so với quốc gia B, v.v.).
* Với mỗi địa điểm, thu thập nhiều RTT của tin nhắn thông thường và trích xuất các đặc trưng đơn giản như median, variance hoặc nhóm percentile.
* Trong cuộc tấn công thực tế, so sánh chuỗi probe mới với các cụm đã huấn luyện. Bài báo cho biết thường có thể phân biệt ngay cả các địa điểm trong cùng một thành phố, với độ chính xác `>80%` trong trường hợp 3 địa điểm.
* Cách này hiệu quả nhất khi kẻ tấn công kiểm soát môi trường gửi và thăm dò trong điều kiện mạng tương tự, vì đường truyền được đo bao gồm mạng truy cập của người nhận, độ trễ đánh thức và hạ tầng messenger.<sup>[[2]](#references)</sup>

Khác với các cuộc tấn công reaction/edit/delete im lặng ở trên, suy luận vị trí không cần message ID không hợp lệ hoặc các gói tin thay đổi trạng thái một cách kín đáo. Tin nhắn thông thường với xác nhận gửi bình thường là đủ, vì vậy sự đánh đổi là giảm tính ẩn mình nhưng có thể áp dụng rộng hơn trên các messenger.

## Làm cạn kiệt tài nguyên một cách kín đáo

Vì mọi probe im lặng đều phải được giải mã và xác nhận, việc liên tục gửi các gói reaction toggle, edit không hợp lệ hoặc delete-for-everyone sẽ tạo thành một cuộc tấn công DoS ở tầng ứng dụng:<sup>[[1]](#references)</sup>

* Buộc radio/modem truyền/nhận mỗi giây → làm hao pin đáng kể, đặc biệt trên các thiết bị đang idle.
* Tạo lưu lượng gửi lên/tải xuống, tiêu tốn gói dữ liệu di động và có thể ảnh hưởng đến các tính năng nhạy cảm với độ trễ như cuộc gọi video.<sup>[[1]](#references)</sup>
* Payload không hợp lệ cỡ lớn làm tăng khối lượng xử lý, nhưng bài báo cho biết bản thân việc mã hóa chỉ chiếm phần chi phí pin không đáng kể.<sup>[[1]](#references)</sup>
* Trên WhatsApp, reaction không hợp lệ chấp nhận lượng dữ liệu lớn hơn nhiều so với những gì một emoji thông thường gợi ý: các phép đo đã công bố cho thấy phía máy chủ chấp nhận tối đa khoảng `1 MB` cho mỗi reaction.
* Reaction quá lớn không còn tạo delivery receipts đáng tin cậy khi nội dung vượt quá khoảng `30 bytes`, nhưng vẫn được chuyển tiếp và xử lý trước khi bị loại bỏ. Hãy giữ nội dung reaction nhỏ khi cần ACK; chỉ làm chúng lớn hơn khi mục tiêu là drain thuần túy hoặc truyền dữ liệu bí mật một chiều.
* Các phép đo công khai đạt khoảng `3.7 MB/s` (`~13.3 GB/h`) lưu lượng đến thiết bị nạn nhân ở chế độ này.



## References

- [1] [Careless Whisper: Khai thác Silent Delivery Receipts để theo dõi người dùng trên các ứng dụng nhắn tin tức thời di động](https://arxiv.org/html/2411.11194v4)
- [2] [Hope of Delivery: Trích xuất vị trí người dùng từ các ứng dụng nhắn tin tức thời di động](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [Trang man của signal-cli](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [Cách chặn lượng lớn tin nhắn lạ | Trung tâm trợ giúp WhatsApp](https://faq.whatsapp.com/3379690015658337)
- [11] [Tất cả các số đều ở Mỹ: Lạm dụng contact discovery trên quy mô lớn trong các ứng dụng nhắn tin di động](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)
{{#include ../banners/hacktricks-training.md}}
