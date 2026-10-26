# Bỏ qua KYC bằng AI

{{#include ../banners/hacktricks-training.md}}

Các mô hình tạo sinh có thể được dùng để **bỏ qua quy trình KYC, xác minh độ tuổi và kiểm tra tính sống sinh trắc học trên trình duyệt**. Điểm yếu thường **không nằm ở lớp truyền tải hay nhà cung cấp dịch vụ kiểm tra tính sống trên cloud**, mà ở **ranh giới tin cậy của camera**: trình duyệt máy tính để bàn thường tin mọi thiết bị mà `getUserMedia()` cung cấp dưới dạng webcam.<sup>[[1]](#references)</sup>

## Chuỗi tấn công thực tế

1. **Tạo nội dung đa phương tiện đáp ứng thử thách** bằng mô hình video-to-video, sử dụng một diễn viên nguồn và ảnh tham chiếu của nạn nhân.<sup>[[1]](#references)</sup>
2. **Chèn luồng giả trước khi ký hoặc tải lên**, chẳng hạn thông qua camera ảo Linux được tạo bằng `v4l2loopback` và cấp dữ liệu từ OBS hoặc FFmpeg.<sup>[[3]](#references)</sup>
3. Để trình duyệt và SDK của nhà cung cấp (WebRTC, AWS, v.v.) **thu thập, ký và tải lên các khung hình do kẻ tấn công kiểm soát như thể chúng đến từ webcam thật**.<sup>[[2]](#references)</sup>

Điều này quan trọng trong quá trình đánh giá vì các đoạn WebSocket đã ký hoặc định dạng khung hình riêng của SDK có thể khiến **việc can thiệp ở lớp mạng** không khả thi, trong khi **chèn ở lớp camera** vẫn hoạt động.<sup>[[1]](#references)</sup>

## Các hướng kiểm thử có giá trị cao

- **Chấp nhận webcam ảo**: nếu quy trình hoạt động trên trình duyệt máy tính để bàn, hãy kiểm tra xem OBS, `v4l2loopback` hoặc camera ảo của nhà cung cấp có được chấp nhận như thiết bị ngoại vi thông thường hay không.<sup>[[1]](#references)</sup>
- **Chuyển hướng API camera trên thiết bị di động**: quy trình gốc vẫn có thể dễ bị tấn công khi công cụ đo đạc lúc chạy như Frida hook các API camera và thay thế bộ đệm cảm biến bằng khung hình từ tệp MP4 hoặc camera ảo được hỗ trợ bởi trình giả lập. Việc này đòi hỏi quyền kiểm soát môi trường thực thi của client và cần được đánh giá cùng với các tín hiệu root/jailbreak và tính toàn vẹn của ứng dụng.<sup>[[1]](#references)</sup>
- **Nới lỏng ràng buộc**: các trang yêu cầu `deviceId`, `frameRate`, `width`, `height` hoặc `facingMode` chính xác đôi khi có thể bị vượt qua bằng cách monkeypatch `navigator.mediaDevices.getUserMedia` và thay các ràng buộc nghiêm ngặt bằng các khoảng rộng hơn.<sup>[[4]](#references)</sup>
- **Tạo video chất lượng thấp rồi hậu xử lý**: kiểm tra xem video tạo sinh chi phí thấp có thể được nâng độ phân giải hoặc nội suy khung hình bằng FFmpeg đủ để đáp ứng các ràng buộc ghi hình hay không.<sup>[[1]](#references)</sup>
- **Thử thách chủ động dễ đoán**: nên ghi lại và phát lại các chuỗi lặp lại gồm chuyển động đầu hoặc chớp sáng thông qua quy trình tạo sinh.
- **Phát hiện phát lại yếu**: các thay đổi đơn giản trong cảnh, chẳng hạn dịch chuyển vùng cắt hoặc vị trí, thay đổi lớp phủ hoặc chuyển động nhẹ, có thể đã đủ nếu logic chống phát lại chỉ kiểm tra sơ sài mức độ giống nhau giữa các khung hình.<sup>[[1]](#references)</sup>

## Khác biệt về độ tin cậy giữa thiết bị di động và máy tính để bàn

Ứng dụng di động gốc có thể tăng chi phí tấn công bằng cách sử dụng:<sup>[[1]](#references)</sup>

- **tín hiệu nguồn gốc hoặc chứng thực được hỗ trợ bởi phần cứng**, bao gồm bằng chứng được hỗ trợ bởi Secure Element nếu nền tảng và ngăn xếp ghi hình thực sự cung cấp tín hiệu đó;
- tín hiệu **toàn vẹn thực thi** như **Play Integrity** hoặc **App Attest**;<sup>[[5]](#references)[[6]](#references)</sup>
- **tương quan chuyển động** giữa video và dữ liệu đo từ gia tốc kế hoặc con quay hồi chuyển.

Các quy trình web trên máy tính để bàn thường không có chuỗi tin cậy camera tương đương, nên nhìn chung là con đường dễ bị tấn công nhất.<sup>[[1]](#references)</sup>

## Ghi chú khi rà soát biện pháp phòng thủ

Khi rà soát một tích hợp KYC hoặc kiểm tra tính sống, hãy xác minh xem tích hợp đó có:<sup>[[1]](#references)</sup>

- cho phép **dự phòng bằng trình duyệt máy tính để bàn** trong quy trình vốn chỉ được mô hình hóa mối đe dọa cho hình thức ghi hình trên thiết bị di động;
- chủ yếu dựa vào **kiểm tra tính sống bằng thuật toán** mà không có quy trình chuyển cho con người xử lý đủ mạnh đối với các phiên đáng ngờ;
- sử dụng **thử thách ổn định hoặc dễ đoán**, có thể được ghi trước và đưa vào quy trình tạo sinh;
- phát hiện **việc monkeypatch `getUserMedia`**, camera ảo, dữ liệu đo phần cứng trình duyệt không nhất quán hoặc thiếu chứng thực thiết bị.<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - KYC: Bỏ qua xác minh độ tuổi bằng các mô hình video tạo sinh](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Kiểm tra tính sống khuôn mặt](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)
- [5] [Nhà phát triển Android — Play Integrity API](https://developer.android.com/google/play/integrity)
- [6] [Nhà phát triển Apple — App Attest](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity)
{{#include ../banners/hacktricks-training.md}}
