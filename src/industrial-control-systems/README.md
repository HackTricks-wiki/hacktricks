# Hacking hệ thống điều khiển công nghiệp

{{#include ../banners/hacktricks-training.md}}

## Giới thiệu về phần này

Phần này giới thiệu các thành phần, kiến trúc, giao thức và phương pháp đánh giá bảo mật của hệ thống điều khiển công nghiệp (ICS). ICS thuộc lĩnh vực công nghệ vận hành (OT) rộng hơn: các hệ thống và thiết bị có thể lập trình, dùng để giám sát hoặc gây ra những thay đổi trong quy trình vật lý. Các ví dụ phổ biến gồm hệ thống điều khiển giám sát và thu thập dữ liệu (SCADA), hệ thống điều khiển phân tán (DCS) và bộ điều khiển logic khả trình (PLC).<sup>[[1]](#references)</sup>

Công tác bảo mật trong những môi trường này phải tính đến các yêu cầu khác với IT thông thường, bao gồm an toàn quy trình, độ tin cậy, tính sẵn sàng, hoạt động tất định và vòng đời thiết bị. Một biện pháp kiểm soát bảo mật hợp lệ về mặt kỹ thuật vẫn có thể không phù hợp nếu làm gián đoạn quy trình vật lý. Vì vậy, việc kiểm thử và khắc phục cần được phối hợp với chủ sở hữu hệ thống và nhân sự vận hành.<sup>[[1]](#references)</sup>

Sự cố xâm nhập hoặc gián đoạn ngoài ý muốn có thể khiến hoạt động sản xuất ngừng lại, làm hỏng thiết bị, phát tán vật liệu nguy hiểm, gây hại cho môi trường, hoặc gây thương tích và tử vong. Tác động vật lý tiềm tàng này là lý do cần hiểu rõ quy trình được kiểm soát và các giới hạn vận hành an toàn trước khi tiến hành kiểm thử chủ động.<sup>[[1]](#references)</sup>

Nhiều hệ thống OT vẫn sử dụng hệ điều hành, ứng dụng và giao thức cũ vì thiết bị có tuổi thọ sử dụng dài, còn mọi thay đổi đều cần được kiểm thử về vận hành và an toàn. Một số giao thức được thiết kế mà không có cơ chế xác thực hoặc mã hóa hiện đại; việc vá lỗi cũng có thể bị hạn chế bởi hỗ trợ của nhà cung cấp hoặc lịch bảo trì. Khi không thể nâng cấp trực tiếp, hãy bù đắp bằng phân đoạn mạng, kiểm soát truy cập và giám sát.<sup>[[1]](#references)</sup>

## Ưu tiên đánh giá

Bắt đầu bằng việc tìm hiểu quy trình được kiểm soát, ranh giới hệ thống, cấu trúc mạng, tài sản, luồng dữ liệu, mối quan hệ tin cậy và các kết nối bên ngoài. Cùng một loại thiết bị có thể đảm nhiệm các chức năng khác nhau ở những cơ sở khác nhau, vì vậy không nên cho rằng kiến trúc hoặc mô hình tác động của một hệ thống có thể áp dụng cho hệ thống khác.<sup>[[1]](#references)</sup>

Khi có thể, hãy ưu tiên phát hiện thụ động và tài liệu kỹ thuật hiện có. Mọi hoạt động quét chủ động hoặc khai thác cần tuân theo kế hoạch kiểm thử đã được phê duyệt, trong đó xác định các giới hạn an toàn, khung thời gian bảo trì, quy trình khôi phục và điều kiện dừng. Cần đánh giá các phát hiện dựa trên cả tác động an ninh mạng lẫn ảnh hưởng tiềm tàng đến quy trình vật lý.<sup>[[1]](#references)</sup>

Cùng kiến thức về kiến trúc này cũng hỗ trợ các hoạt động phòng thủ như kiểm kê tài sản, phân đoạn mạng, giám sát, ứng phó sự cố và quản lý lỗ hổng dựa trên rủi ro.<sup>[[1]](#references)</sup>

## Các điểm truy cập giao thức

- [Kiểm thử Modbus](../network-services-pentesting/pentesting-modbus.md) đề cập đến Modbus TCP, các biến thể nối tiếp, mã chức năng và quyền truy cập thanh ghi.
- [Kiểm thử OPC UA](../network-services-pentesting/4840-pentesting-opc-ua.md) đề cập đến dịch vụ trao đổi dữ liệu công nghiệp.
- [Kiểm thử BACnet](../network-services-pentesting/47808-udp-bacnet.md) đề cập đến các mạng điều khiển tự động hóa tòa nhà.

## References

- [1] [NIST SP 800-82 Rev. 3 - Hướng dẫn bảo mật công nghệ vận hành (OT)](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
{{#include ../banners/hacktricks-training.md}}
