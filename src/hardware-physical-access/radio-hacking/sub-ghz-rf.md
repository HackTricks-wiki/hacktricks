# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Cửa garage

Remote điều khiển cửa garage sử dụng các dải tần sub-GHz khác nhau tùy theo khu vực và sản phẩm. Có thể gặp các tần số như 300, 310, 315, 390 và 433.92 MHz, nhưng không có dải tần cửa garage phổ quát nào là “300–190 MHz”. Hãy xác định nhãn của thiết bị mục tiêu, khu vực pháp lý và tín hiệu quan sát được trước khi phát.<sup>[[1]](#references)</sup>

## Cửa xe hơi

Nhiều remote chìa khóa xe hơi sử dụng **315 MHz hoặc 433.92 MHz**; quy định theo khu vực và thiết kế xe ảnh hưởng đến lựa chọn này. Chỉ riêng tần số không khiến 433 MHz có tầm xa hơn 315 MHz: công suất phát, hiệu suất ăng-ten, điều chế, độ nhạy của bộ thu, khả năng truyền sóng và quy định địa phương đều có ảnh hưởng. Châu Âu thường dùng 433.92 MHz, còn 315 MHz phổ biến ở Bắc Mỹ và Nhật Bản.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

Trong hệ thống mã cố định được minh họa, gửi mỗi mã một lần thay vì năm lần giúp giảm thời gian ước tính xuống còn sáu phút:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

Bỏ khoảng chờ 2 ms giữa các tín hiệu giúp rút thời gian của ví dụ này xuống còn khoảng ba phút.

Sử dụng chuỗi De Bruijn để chồng lấp các chuỗi bit ứng viên giúp rút ngắn cuộc tấn công minh họa xuống còn khoảng tám giây, nếu bộ thu chấp nhận chuỗi liên tục mà không yêu cầu preamble hoặc đặt lại khung dữ liệu.<sup>[[3]](#references)</sup>

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

OpenSesame triển khai cuộc tấn công này nhằm vào các hệ thống mã cố định tương thích.<sup>[[5]](#references)</sup>

Yêu cầu **preamble sẽ vô hiệu hóa** tối ưu hóa bằng **chuỗi De Bruijn**, còn **rolling code sẽ ngăn chặn cuộc tấn công này** (với giả định mã đủ dài để không thể brute-force).

## Tấn công Sub-GHz

Để tấn công các tín hiệu này bằng Flipper Zero, hãy xem:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Bảo vệ bằng Rolling Code

Bộ mở cửa garage tự động thường dùng remote không dây để mở và đóng cửa. Remote **gửi tín hiệu tần số vô tuyến (RF)** đến bộ mở cửa garage, thiết bị này kích hoạt mô-tơ để mở hoặc đóng cửa.

Kẻ khác có thể dùng thiết bị gọi là code grabber để chặn tín hiệu RF và ghi lại để sử dụng sau. Đây được gọi là **replay attack**. Để ngăn kiểu tấn công này, nhiều bộ mở cửa garage hiện đại sử dụng phương thức mã hóa an toàn hơn gọi là hệ thống **rolling code**.

**Tín hiệu RF thường được truyền bằng rolling code**, nghĩa là mã thay đổi sau mỗi lần sử dụng. Điều này khiến việc **chặn** tín hiệu rồi **dùng** tín hiệu đó để xâm nhập **trái phép** vào garage trở nên **khó khăn** hơn.

Trong hệ thống rolling code, remote và bộ mở cửa garage có một **thuật toán dùng chung** để **tạo mã mới** mỗi lần sử dụng remote. Bộ mở cửa garage chỉ phản hồi với **mã chính xác**, khiến việc xâm nhập trái phép vào garage chỉ bằng cách ghi lại mã trở nên khó khăn hơn nhiều.

### **Tấn công Missing Link**

Về cơ bản, bạn nghe tín hiệu khi nhấn nút và **ghi lại tín hiệu trong lúc remote nằm ngoài vùng phủ sóng** của thiết bị (chẳng hạn như xe hoặc garage). Sau đó, bạn đến gần thiết bị và **dùng mã đã ghi để mở thiết bị**.<sup>[[2]](#references)</sup>

### Tấn công gây nhiễu Full Link

> [!CAUTION]
> Gây nhiễu RF có chủ đích là bất hợp pháp ở nhiều khu vực pháp lý và có thể làm gián đoạn các hệ thống liên quan đến an toàn. Chỉ thử nghiệm gây nhiễu trong phòng thí nghiệm có che chắn, được cấp phép và tuân thủ các quy định vô tuyến hiện hành.<sup>[[6]](#references)</sup>

Kẻ tấn công có thể **gây nhiễu tín hiệu gần xe hoặc bộ thu** để bộ thu không giải mã được mã, đồng thời ghi lại riêng tín hiệu bị chặn, ngừng gây nhiễu rồi phát lại tín hiệu đã ghi.<sup>[[2]](#references)</sup>

Đến một lúc nào đó, nạn nhân sẽ dùng **chìa khóa để khóa xe**, nhưng khi ấy cuộc tấn công đã **ghi lại đủ mã “đóng cửa”** để có thể phát lại nhằm mở cửa (có thể cần **đổi tần số**, vì một số xe dùng cùng mã để mở và đóng nhưng nghe hai lệnh ở các tần số khác nhau).

> [!WARNING]
> **Gây nhiễu có hiệu quả**, nhưng dễ bị phát hiện: nếu **người khóa xe thử cửa** để chắc chắn xe đã khóa, họ sẽ nhận ra xe vẫn mở. Ngoài ra, nếu biết về kiểu tấn công này, họ thậm chí có thể nhận thấy cửa không phát ra **âm thanh** khóa hoặc **đèn xe** không nhấp nháy khi họ bấm nút “lock”.

### **Tấn công Code Grabbing (còn gọi là ‘RollJam’)**

Đây là kỹ thuật **gây nhiễu kín đáo hơn**. Kẻ tấn công gây nhiễu tín hiệu để khi nạn nhân thử khóa cửa, thao tác đó không thành công, nhưng kẻ tấn công sẽ **ghi lại mã này**. Sau đó, nạn nhân sẽ **thử khóa xe lần nữa** bằng cách bấm nút và xe sẽ **ghi nhận mã thứ hai này**.<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>\
Ngay sau đó, **kẻ tấn công có thể gửi mã thứ nhất** để **khóa xe** (nạn nhân sẽ nghĩ rằng lần bấm thứ hai đã khóa xe). Sau đó, kẻ tấn công có thể **gửi mã thứ hai đã đánh cắp để mở** xe (với giả định rằng mã **“đóng xe” cũng có thể dùng để mở xe**). Có thể cần đổi tần số (vì một số xe dùng cùng mã để mở và đóng nhưng nghe hai lệnh ở các tần số khác nhau).

Một cách triển khai RollJam khai thác băng thông bộ thu: thiết bị gây nhiễu phát gần tần số sóng mang của remote để làm giảm độ nhạy của bộ thu có băng thông rộng hơn trên xe, trong khi bộ thu có băng thông hẹp hơn của kẻ tấn công vẫn được chỉnh đúng tần số của remote và có thể ghi lại tín hiệu. Độ lệch tần số và băng thông cụ thể phụ thuộc vào phần cứng mục tiêu.<sup>[[2]](#references)</sup>

> [!WARNING]
> Các triển khai khác được mô tả trong tài liệu kỹ thuật cho thấy **rolling code chỉ là một phần** của tổng mã được gửi. Ví dụ, mã được gửi là **khóa 24 bit**, trong đó **12 bit đầu là rolling code**, **8 bit tiếp theo là lệnh** (chẳng hạn khóa hoặc mở khóa), còn 4 bit cuối là **checksum**. Các xe sử dụng kiểu này cũng dễ bị tấn công, vì kẻ tấn công chỉ cần thay phần rolling code để có thể **dùng bất kỳ rolling code nào trên cả hai tần số**.

> [!CAUTION]
> Lưu ý rằng nếu nạn nhân gửi mã thứ ba trong lúc kẻ tấn công đang gửi mã thứ nhất, mã thứ nhất và thứ hai sẽ mất hiệu lực.

### Tấn công gây nhiễu khiến chuông báo động kêu

Khi thử nghiệm trên một hệ thống rolling code lắp thêm cho xe, **gửi cùng một mã hai lần** đã ngay lập tức **kích hoạt chuông báo động** và thiết bị chống khởi động, tạo ra cơ hội **từ chối dịch vụ** đặc biệt. Trớ trêu thay, cách **tắt chuông báo động** và thiết bị chống khởi động lại là **bấm** remote, cho phép kẻ tấn công **liên tục thực hiện DoS attack**. Hoặc kết hợp cuộc tấn công này với cuộc tấn công **trước đó để thu thêm mã**, vì nạn nhân có thể muốn dừng cuộc tấn công càng sớm càng tốt.<sup>[[2]](#references)</sup>

## References

- [1] [Tài liệu Flipper Zero - tần số Sub-GHz theo khu vực](https://docs.flipper.net/zero/sub-ghz/frequencies)
- [2] [Vượt qua hệ thống Rolling Code - Andrew Mohawk](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Samy Kamkar - DEF CON 23: Lái xe như thể bạn đã hack nó (OpenSesame)](https://samy.pl/defcon2015/)
- [4] [Cách hack xe hơi - tái tạo RollJam bằng YARD Stick One / RTL-SDR](https://hackaday.io/project/164566-how-to-hack-a-car/details)
- [5] [Mã nguồn OpenSesame](https://github.com/samyk/opensesame)
- [6] [Khuyến cáo thực thi của FCC - thực thi quy định về thiết bị gây nhiễu](https://www.fcc.gov/document/jammer-enforcement)
{{#include ../../banners/hacktricks-training.md}}
