# FZ - Hồng ngoại

{{#include ../../../banners/hacktricks-training.md}}

## Giới thiệu <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Để biết thêm thông tin về cách hồng ngoại hoạt động, hãy xem:


{{#ref}}
../infrared.md
{{#endref}}

## Bộ thu tín hiệu IR trong Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper Zero sử dụng bộ thu IR giải điều chế để thu tín hiệu từ các remote IR phổ biến. Một số điện thoại, bao gồm một số mẫu Xiaomi, có bộ phát IR, nhưng hầu hết không thể thu và giải mã tín hiệu từ remote điều khiển.<sup>[[1]](#references)</sup>

**Bộ thu hồng ngoại của Flipper khá nhạy**. Bạn thậm chí có thể **bắt tín hiệu** khi đang ở **khoảng giữa** remote và TV. Không cần chĩa remote thẳng vào cổng IR của Flipper. Điều này rất hữu ích khi ai đó đứng gần TV và chuyển kênh, còn bạn và Flipper ở cách đó một khoảng.

Việc giải mã protocol được thực hiện bằng phần mềm. Các protocol được nhận diện có thể được lưu dưới dạng lệnh đã giải mã; những protocol không được hỗ trợ có thể được thu và phát lại dưới dạng dữ liệu thời gian thô, trong giới hạn tần số sóng mang và thời gian của phần cứng.<sup>[[1]](#references)</sup>

## Thao tác

### Remote đa năng

Chế độ remote đa năng của Flipper Zero lần lượt gửi các lệnh đã biết từ cơ sở dữ liệu hồng ngoại cho những TV, thiết bị âm thanh, máy chiếu và máy điều hòa được hỗ trợ. Chế độ này không đảm bảo điều khiển được mọi thiết bị và chỉ nên được sử dụng với thiết bị thuộc sở hữu của bạn hoặc khi bạn được phép kiểm thử.<sup>[[1]](#references)</sup>

Chỉ cần nhấn nút nguồn trong chế độ Universal Remote, Flipper sẽ **lần lượt gửi lệnh "Power Off"** của tất cả TV mà nó biết: Sony, Samsung, Panasonic... và các hãng khác. Khi TV nhận được tín hiệu, nó sẽ phản hồi và tắt.

Quá trình brute-force này mất thời gian. Từ điển càng lớn thì càng mất nhiều thời gian để hoàn tất. Không thể biết chính xác TV đã nhận diện tín hiệu nào vì TV không gửi phản hồi.

### Học remote mới

Flipper Zero có thể **thu tín hiệu hồng ngoại**. Nếu nhận diện được protocol và lệnh, thiết bị sẽ lưu bản biểu diễn đã giải mã; nếu không, thiết bị có thể lưu dữ liệu thời gian thô để phát lại sau.<sup>[[1]](#references)</sup>

## References

- [1] [Chiếm quyền điều khiển TV bằng cổng hồng ngoại của Flipper Zero](https://blog.flipperzero.one/infrared/)
{{#include ../../../banners/hacktricks-training.md}}
