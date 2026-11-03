# Tấn công hệ thống điều khiển công nghiệp

{{#include ../banners/hacktricks-training.md}}

## Giới thiệu về phần này

Phần này giới thiệu các thành phần, kiến trúc, giao thức và phương pháp đánh giá bảo mật của hệ thống điều khiển công nghiệp (ICS). ICS thuộc lĩnh vực công nghệ vận hành (OT) rộng hơn: các hệ thống và thiết bị lập trình được dùng để giám sát hoặc tạo ra thay đổi trong các quy trình vật lý. Các ví dụ phổ biến gồm hệ thống điều khiển giám sát và thu thập dữ liệu (SCADA), hệ thống điều khiển phân tán (DCS) và bộ điều khiển logic khả trình (PLC).<sup>[[1]](#references)</sup>

Công tác bảo mật trong các môi trường này cần tính đến những yêu cầu khác với IT thông thường, bao gồm an toàn quy trình, độ tin cậy, tính sẵn sàng, khả năng vận hành xác định và vòng đời thiết bị. Một biện pháp kiểm soát bảo mật hợp lệ về mặt kỹ thuật vẫn có thể không phù hợp nếu làm gián đoạn quy trình vật lý, vì vậy cần phối hợp việc kiểm thử và khắc phục với chủ sở hữu hệ thống và nhân viên vận hành.<sup>[[1]](#references)</sup>

Việc bị xâm nhập hoặc gián đoạn ngoài ý muốn có thể làm ngừng sản xuất, gây hư hỏng thiết bị, rò rỉ vật liệu nguy hiểm, gây hại cho môi trường, hoặc dẫn đến thương tích và thiệt mạng. Khả năng gây tác động vật lý này là lý do cần tìm hiểu quy trình được kiểm soát và các giới hạn vận hành an toàn trước khi tiến hành kiểm thử chủ động.<sup>[[1]](#references)</sup>

Nhiều hệ thống OT vẫn sử dụng hệ điều hành, ứng dụng và giao thức cũ vì thiết bị có tuổi thọ dài và mọi thay đổi đều cần được kiểm thử về vận hành và an toàn. Một số giao thức được thiết kế mà không có cơ chế xác thực hoặc mã hóa hiện đại, còn việc vá lỗi có thể bị hạn chế bởi hỗ trợ của nhà cung cấp hoặc lịch bảo trì; khi không thể nâng cấp trực tiếp, hãy bù đắp bằng phân đoạn mạng, kiểm soát truy cập và giám sát.<sup>[[1]](#references)</sup>

## Ưu tiên đánh giá

Hãy bắt đầu bằng việc tìm hiểu quy trình được kiểm soát, ranh giới hệ thống, cấu trúc liên kết mạng, tài sản, luồng dữ liệu, quan hệ tin cậy và các kết nối bên ngoài. Các loại thiết bị tương tự có thể đảm nhiệm những chức năng khác nhau tại các cơ sở khác nhau, vì vậy đừng cho rằng kiến trúc hoặc mô hình tác động của một hệ thống có thể áp dụng cho hệ thống khác.<sup>[[1]](#references)</sup>

Ưu tiên khám phá thụ động và sử dụng tài liệu kỹ thuật hiện có khi có thể. Mọi hoạt động quét chủ động hoặc khai thác đều cần tuân theo kế hoạch kiểm thử đã được phê duyệt, trong đó xác định các giới hạn an toàn, thời gian bảo trì, quy trình khôi phục và điều kiện dừng. Cần đánh giá các phát hiện dựa trên cả tác động an ninh mạng lẫn ảnh hưởng tiềm tàng đến quy trình vật lý.<sup>[[1]](#references)</sup>

Cùng kiến thức về kiến trúc này cũng hỗ trợ các hoạt động phòng thủ như kiểm kê tài sản, phân đoạn mạng, giám sát, ứng phó sự cố và quản lý lỗ hổng dựa trên rủi ro.<sup>[[1]](#references)</sup>

## Lạm dụng bộ điều khiển làm lạnh giám sát

Bộ quản lý hệ thống làm lạnh điều phối các bộ điều khiển máy nén và tủ lạnh nhưng không trực tiếp làm lạnh các tủ. Vì vậy, quyền truy cập vào giao diện quản lý có thể cho phép kiểm soát nhiều thiết bị cấp dưới thông qua việc phân phối cấu hình thông thường. Điều này khác với việc thay đổi một bộ điều nhiệt hoặc điều khiển trực tiếp máy nén.<sup>[[3]](#references)[[4]](#references)</sup>

### Đăng nhập bằng mã bảo trì tạo từ ngày

Trên các bộ quản lý hệ thống Danfoss bị ảnh hưởng, một phương thức đăng nhập XML thay thế chấp nhận mã được tạo từ ngày của bộ điều khiển thay vì mật khẩu tài khoản.<sup>[[2]](#references)[[3]](#references)</sup> Trên SM800 và SC255, Synacktiv lần theo các thuộc tính `eds_only` và `quantum_only` qua `xml_load_file` và `check_authorize` đến `check_code_of_day`. Khuyến cáo của họ cũng cho thấy `read_date_time` trên `xml.cgi` tiết lộ ngày của bộ điều khiển mà không cần xác thực.<sup>[[2]](#references)</sup> Claroty phát hiện một đường dẫn `getauth` tương ứng trên AK-SM 800A, nhưng đã ẩn các thuộc tính kích hoạt; không nên cho rằng tên thuộc tính của các mẫu cũ sẽ hoạt động trên nền tảng này.<sup>[[3]](#references)</sup>

Synacktiv mô tả truy vấn ngày không cần xác thực như sau:<sup>[[2]](#references)</sup>

```bash
curl -k -d '<cmd action="read_date_time"/>' https://<controller>/xml.cgi
```

Mã không có secret riêng cho từng thiết bị: khôi phục thuật toán từ [firmware](../hardware-physical-access/firmware-analysis/) có thể tạo ra credential hợp lệ theo ngày cho các thiết bị dùng cùng phiên bản triển khai bị ảnh hưởng.<sup>[[2]](#references)[[3]](#references)</sup> Trước tiên, hãy xác nhận model và firmware. Chỉ riêng phản hồi về ngày tháng không chứng minh rằng có thể đăng nhập bằng phương thức thay thế hoặc đã có được session.

### Cấu hình hàng loạt và lạm dụng bộ gia nhiệt xả đá

Sau khi có quyền quản trị, hãy xác định các bộ điều khiển tủ được ánh xạ với system manager và xem chức năng phân phối cấu hình có thể cập nhật tất cả cùng lúc hay không. Thay đổi setpoint của tủ thường chỉ làm tủ ấm lên đến nhiệt độ phòng. Để làm tủ nóng hơn nhiệt độ môi trường, bộ điều khiển liên quan là bộ gia nhiệt xả đá bằng điện của dàn bay hơi: quá trình xả đá sẽ dừng làm lạnh và bật bộ gia nhiệt cho đến khi cảm biến hoặc bộ hẹn giờ kết thúc chu kỳ. Thay vào đó, có thể giữ bộ gia nhiệt hoạt động bằng cách thay đổi phương thức xả đá, lịch chạy, nhiệt độ kết thúc và giới hạn thời gian. System manager có thể phân phối những thay đổi đó cho nhiều tủ và tắt các cảnh báo liên quan, biến một lần xâm phạm hệ thống giám sát thành thay đổi quy trình trên toàn cửa hàng.<sup>[[4]](#references)</sup>

Đây là mối nguy đối với quy trình vật lý, không phải PoC an toàn để thử trên hệ thống đang hoạt động. Nếu có, các công tắc ngắt nhiệt có thể giới hạn hoạt động của bộ gia nhiệt, nhưng chạy liên tục vẫn có thể làm quá nhiệt một mối nối điện vốn đã yếu. Chỉ xác minh cấu hình và tác động trong phòng lab được phê duyệt hoặc theo kế hoạch an toàn quy trình của đơn vị vận hành.<sup>[[4]](#references)</sup>

## Các điểm truy cập giao thức

- [Kiểm thử Modbus](../network-services-pentesting/pentesting-modbus.md) đề cập đến Modbus TCP, các biến thể serial, function code và quyền truy cập register.
- [Kiểm thử OPC UA](../network-services-pentesting/4840-pentesting-opc-ua.md) đề cập đến dịch vụ trao đổi dữ liệu công nghiệp.
- [Kiểm thử BACnet](../network-services-pentesting/47808-udp-bacnet.md) đề cập đến các mạng điều khiển tự động hóa tòa nhà.

## References

- [1] [NIST SP 800-82 Rev. 3 - Hướng dẫn bảo mật Operational Technology (OT)](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
- [2] [Synacktiv - Bypass xác thực trên Danfoss System-Managers SM800 và SC255](https://www.synacktiv.com/sites/default/files/2023-10/synacktiv-danfoss-sm800-sc255-sc355-auth-bypass.pdf)
- [3] [Claroty Team82 - Đóng băng bộ điều khiển, rã đông thực phẩm](https://claroty.com/team82/research/freeze-the-controller-defrost-the-food-uncovering-vulnerabilities-in-danfoss-refrigeration-controllers)
- [4] [Pen Test Partners - Không cần đến một quốc gia để làm ấm tủ lạnh](https://pentestpartners.com/security-blog/you-dont-need-a-nation-state-to-warm-up-a-fridge)
{{#include ../banners/hacktricks-training.md}}
