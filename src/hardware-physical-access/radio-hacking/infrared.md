# Hồng ngoại

{{#include ../../banners/hacktricks-training.md}}

## Cách hoạt động của hồng ngoại <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Ánh sáng hồng ngoại không nhìn thấy được bằng mắt người**. Bước sóng IR nằm trong khoảng **0.7 đến 1000 micron**. Điều khiển từ xa trong gia đình sử dụng tín hiệu IR để truyền dữ liệu và hoạt động trong dải bước sóng 0.75..1.4 micron. Bộ vi điều khiển bên trong điều khiển từ xa làm cho đèn LED hồng ngoại nhấp nháy ở một tần số cụ thể, chuyển tín hiệu số thành tín hiệu IR.

Để nhận tín hiệu IR, người ta sử dụng **bộ thu quang**. Bộ thu **chuyển ánh sáng IR thành các xung điện áp**, vốn đã là **tín hiệu số**. Thông thường, bên trong bộ thu có **bộ lọc ánh sáng tối**, chỉ cho **bước sóng mong muốn đi qua** và loại bỏ nhiễu.<sup>[[1]](#references)</sup>

### Các loại giao thức IR <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

Các giao thức IR khác nhau ở 3 yếu tố:<sup>[[1]](#references)</sup>

- mã hóa bit
- cấu trúc dữ liệu
- tần số sóng mang — thường nằm trong khoảng 36..38 kHz

#### Các cách mã hóa bit <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Mã hóa theo khoảng cách xung**

Các bit được mã hóa bằng cách điều chế thời lượng khoảng nghỉ giữa các xung. Độ rộng của xung luôn không đổi.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Mã hóa theo độ rộng xung**

Các bit được mã hóa bằng cách điều chế độ rộng xung. Độ dài khoảng nghỉ sau chuỗi xung luôn không đổi.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Mã hóa pha**

Cách này còn được gọi là mã hóa Manchester. Giá trị logic được xác định bởi cực tính của chuyển tiếp giữa chuỗi xung và khoảng nghỉ. "Từ khoảng nghỉ sang chuỗi xung" biểu thị logic "0", còn "từ chuỗi xung sang khoảng nghỉ" biểu thị logic "1".

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Kết hợp các cách trên và những cách khác ít phổ biến hơn**

> [!TIP]
> Có những giao thức IR **hướng đến khả năng trở thành chuẩn chung** cho nhiều loại thiết bị. Nổi tiếng nhất là RC5 và NEC. Đáng tiếc, **nổi tiếng nhất không có nghĩa là phổ biến nhất**. Trong môi trường của tôi, tôi chỉ gặp hai điều khiển từ xa NEC và không gặp chiếc nào dùng RC5.
>
> Các nhà sản xuất thích sử dụng giao thức IR độc quyền của riêng họ, ngay cả trong cùng một nhóm thiết bị (ví dụ: TV box). Vì vậy, điều khiển từ xa của các công ty khác nhau, và đôi khi là các mẫu khác nhau của cùng một công ty, không thể điều khiển các thiết bị cùng loại khác.

### Khám phá tín hiệu IR

Cách đáng tin cậy nhất để xem tín hiệu IR từ điều khiển từ xa trông như thế nào là sử dụng máy hiện sóng. Thiết bị này không giải điều chế hay đảo tín hiệu nhận được mà chỉ hiển thị tín hiệu "nguyên trạng". Điều này hữu ích cho việc kiểm tra và gỡ lỗi. Tôi sẽ minh họa tín hiệu dự kiến bằng giao thức IR NEC.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Thông thường, ở đầu gói đã mã hóa sẽ có phần mở đầu. Nhờ đó, bộ thu có thể xác định mức khuếch đại và mức nền. Cũng có những giao thức không có phần mở đầu, chẳng hạn như Sharp.

Sau đó, dữ liệu được truyền đi. Cấu trúc, phần mở đầu và phương thức mã hóa bit phụ thuộc vào giao thức cụ thể.

**Giao thức IR NEC** gồm một lệnh ngắn và một mã lặp được gửi trong lúc nhấn nút. Cả lệnh và mã lặp đều có cùng phần mở đầu.

Ngoài phần mở đầu, **lệnh** NEC còn gồm một byte địa chỉ và một byte số lệnh, cho biết thiết bị cần thực hiện thao tác nào. Các byte địa chỉ và số lệnh được lặp lại với giá trị đảo ngược để kiểm tra tính toàn vẹn của quá trình truyền. Cuối lệnh có thêm một bit dừng.

**Mã lặp** có một bit "1" sau phần mở đầu, đây là bit dừng.

Để biểu diễn **logic "0" và "1"**, NEC sử dụng mã hóa theo khoảng cách xung: trước tiên, một chuỗi xung được truyền đi, sau đó là một khoảng nghỉ; độ dài khoảng nghỉ xác định giá trị của bit.

### Máy điều hòa

Không giống các loại điều khiển từ xa khác, **điều khiển máy điều hòa không chỉ truyền mã của nút vừa nhấn**. Khi nhấn nút, chúng còn **truyền toàn bộ thông tin** để đảm bảo **máy điều hòa và điều khiển từ xa được đồng bộ**.\
Điều này giúp tránh tình trạng máy được đặt ở 20ºC rồi tăng lên 21ºC bằng một điều khiển từ xa, sau đó một điều khiển khác vẫn đang đặt ở 20ºC được dùng để tăng nhiệt độ tiếp, khiến nhiệt độ chỉ "tăng" lên 21ºC (thay vì lên 22ºC như khi nghĩ rằng máy đang ở 21ºC).<sup>[[1]](#references)</sup>

---

## Nghiên cứu tấn công & phòng thủ <a href="#attacks" id="attacks"></a>

Bạn có thể tấn công hồng ngoại bằng Flipper Zero:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Chiếm quyền Smart-TV / Set-top Box (EvilScreen)

Nghiên cứu học thuật gần đây (EvilScreen, 2022) cho thấy **có thể lợi dụng điều khiển từ xa đa kênh kết hợp hồng ngoại với Bluetooth hoặc Wi-Fi để chiếm quyền hoàn toàn các smart-TV hiện đại**. Cuộc tấn công kết hợp các service code IR có đặc quyền cao với các gói Bluetooth đã xác thực, vượt qua cơ chế cô lập kênh và cho phép khởi chạy ứng dụng tùy ý, kích hoạt micro hoặc khôi phục cài đặt gốc mà không cần truy cập vật lý. Tám mẫu TV phổ biến từ các nhà sản xuất khác nhau — trong đó có một mẫu Samsung tuyên bố tuân thủ ISO/IEC 27001 — được xác nhận là có lỗ hổng. Biện pháp giảm thiểu cần có bản vá firmware từ nhà sản xuất hoặc tắt hoàn toàn các bộ thu IR không sử dụng.<sup>[[2]](#references)</sup>

### Rò rỉ dữ liệu qua khe hở vật lý bằng đèn LED IR (nhóm aIR-Jumper)

Camera an ninh thường có **đèn LED IR nhìn đêm**. Nguyên mẫu aIR-Jumper cho thấy malware kiểm soát các đèn LED này có thể **rò rỉ bí mật qua cửa sổ** đến camera bên ngoài với tốc độ lên tới **20 bit/s trên mỗi camera giám sát**, ở khoảng cách hàng chục mét. Theo chiều ngược lại, các nhà nghiên cứu đã chứng minh khả năng xâm nhập với tốc độ hơn **100 bit/s**, ở khoảng cách từ hàng trăm mét đến hàng kilomet.<sup>[[3]](#references)</sup> Vì ánh sáng nằm ngoài quang phổ nhìn thấy được nên người vận hành có thể không nhận ra. Các biện pháp đối phó gồm:

* Che chắn vật lý hoặc tháo bỏ đèn LED IR tại các khu vực nhạy cảm
* Giám sát chu kỳ hoạt động của đèn LED và tính toàn vẹn firmware của camera
* Lắp bộ lọc chặn IR trên cửa sổ và camera giám sát

Kẻ tấn công cũng có thể dùng máy chiếu IR công suất lớn để **xâm nhập**, truyền lệnh vào mạng bằng cách chiếu dữ liệu ngược vào các camera không an toàn.

### Brute-force tầm xa & giao thức mở rộng với Flipper Zero 1.0

Firmware 1.0 (tháng 9 năm 2024) mở rộng thư viện điều khiển từ xa đa năng và bổ sung khả năng tải động các tệp dữ liệu hồng ngoại từ microSD.<sup>[[4]](#references)</sup> Các chức năng học và điều khiển từ xa đa năng có thể phát lại hoặc thử các lệnh đã biết trên TV và máy điều hòa ở gần. Phạm vi phụ thuộc nhiều vào bộ phát, hệ quang học, ánh sáng môi trường và bộ thu; phần cứng IR bên ngoài có thể mở rộng phạm vi, nhưng không nên mặc định một khoảng cách cố định.

---

## Công cụ & ví dụ thực tế <a href="#tooling" id="tooling"></a>

### Phần cứng

* **Flipper Zero** – bộ thu phát di động có các chế độ học lệnh, phát lại và brute-force từ điển (xem ở trên).
* **Arduino / ESP32** + đèn LED IR / bộ thu TSOP38xx – thiết bị phân tích/phát tín hiệu DIY giá rẻ. Có thể kết hợp với thư viện `Arduino-IRremote` (v4.x hỗ trợ hơn 40 giao thức).
* **Bộ phân tích logic** (Saleae/FX2) – ghi lại thời gian tín hiệu thô khi chưa biết giao thức.
* **Điện thoại thông minh có IR blaster** (ví dụ: Xiaomi) – hữu ích để kiểm tra nhanh tại hiện trường nhưng phạm vi hạn chế.

### Phần mềm

* **`Arduino-IRremote`** – thư viện C++ được duy trì thường xuyên:<sup>[[5]](#references)</sup>
  ```cpp
  #include <IRremote.hpp>
  void setup(){ IrSender.begin(3); }
  void loop(){
    IrSender.sendNEC(0x00, 0x10, 0); // address, command, repeats
    delay(5000);
  }
  ```
* **IRscrutinizer / AnalysIR** – Các bộ giải mã GUI nhập bản ghi thô, tự động nhận diện giao thức và tạo mã Pronto/Arduino.
* **LIRC / ir-keytable (Linux)** – nhận và phát IR từ dòng lệnh:
  ```bash
  sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
  irsend SEND_ONCE samsung KEY_POWER
  ```

---

## Biện pháp phòng thủ <a href="#defense" id="defense"></a>

* Tắt hoặc che các bộ thu IR trên thiết bị được triển khai ở nơi công cộng khi không cần dùng.
* Yêu cầu *ghép nối* hoặc kiểm tra mật mã giữa smart-TV và điều khiển từ xa; cô lập các mã “dịch vụ” có đặc quyền.
* Triển khai bộ lọc IR-cut hoặc thiết bị phát hiện sóng liên tục quanh các khu vực mật để phá vỡ các kênh bí mật quang học.
* Giám sát tính toàn vẹn firmware của camera/thiết bị IoT có đèn LED IR điều khiển được.

## References

- [1] [Bài đăng blog về hồng ngoại của Flipper Zero](https://blog.flipperzero.one/infrared/)
- [2] [Tấn công EvilScreen: Chiếm quyền điều khiển smart TV bằng cách mô phỏng điều khiển từ xa đa kênh (arXiv:2210.03014)](https://arxiv.org/abs/2210.03014)
- [3] [aIR-Jumper: Trích xuất/đưa dữ liệu bí mật qua air gap bằng camera an ninh và hồng ngoại (IR) (arXiv:1709.05742)](https://arxiv.org/abs/1709.05742)
- [4] [Blog Flipper Zero - Phát hành Firmware 1.0](https://blog.flipper.net/released-firmware-1/)
- [5] [Arduino-IRremote - tài liệu về cách sử dụng và giao thức](https://github.com/Arduino-IRremote/Arduino-IRremote)
{{#include ../../banners/hacktricks-training.md}}
