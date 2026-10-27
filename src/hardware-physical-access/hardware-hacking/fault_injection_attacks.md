# Fault Injection Attacks

{{#include ../../banners/hacktricks-training.md}}

Fault injection—thường được gọi là **glitching** trong lĩnh vực bảo mật phần cứng—cố ý gây nhiễu thiết bị khi thiết bị đang hoạt động để khiến thiết bị thực hiện phép tính sai. Lỗi hữu ích có thể bỏ qua một chỉ thị, làm hỏng dữ liệu, vượt qua bước kiểm tra bảo mật hoặc tạo ra đầu ra mật mã sai lệch, từ đó có thể suy ra thông tin bí mật.<sup>[[1]](#references)</sup>

Các kỹ thuật phổ biến thao túng điện áp nguồn hoặc xung nhịp, đưa nhiễu điện từ vào thiết bị hoặc sử dụng kích thích quang học hay laser.<sup>[[1]](#references)</sup> Mức độ chính xác và xâm lấn của các kỹ thuật này khác nhau, nhưng thử nghiệm thành công thường cần một tín hiệu kích hoạt có thể lặp lại và việc quét có hệ thống các thông số về thời điểm, độ rộng xung và cường độ. Hãy bắt đầu với trạng thái cơ sở ổn định, ghi nhận riêng các lần khởi động lại và đầu ra sai định dạng, đồng thời chỉ thay đổi một thông số mỗi lần.<sup>[[2]](#references)</sup>

## References

- [1] [Hayashi và cộng sự - Phương pháp Fault Injection không xâm lấn, không cần tín hiệu kích hoạt, dựa trên nhiễu điện từ có chủ đích](https://csrc.nist.gov/csrc/media/events/non-invasive-attack-testing-workshop/documents/04_hayashi.pdf)
- [2] [Tài liệu ChipWhisperer - Tổng quan và so sánh phần cứng thu thập](https://chipwhisperer.readthedocs.io/en/latest/Capture/overview.html)
{{#include ../../banners/hacktricks-training.md}}
