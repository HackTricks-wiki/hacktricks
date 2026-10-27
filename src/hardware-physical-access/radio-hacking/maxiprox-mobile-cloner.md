# Xây dựng thiết bị clone thẻ HID MaxiProx 125 kHz di động

{{#include ../../banners/hacktricks-training.md}}

## Mục tiêu
Chuyển đổi đầu đọc tầm xa HID MaxiProx 5375 dùng nguồn điện lưới, hoạt động ở tần số 125 kHz, thành thiết bị clone thẻ dùng pin, có thể mang đi hiện trường và âm thầm thu thập thẻ proximity trong các đợt đánh giá an ninh vật lý.

Quy trình chuyển đổi này dựa trên loạt nghiên cứu “Let’s Clone a Cloner – Part 3: Putting It All Together” của TrustedSec, kết hợp các yếu tố cơ khí, điện và RF để tạo ra thiết bị có thể bỏ vào ba lô và sử dụng ngay tại hiện trường.<sup>[[1]](#references)</sup>

> [!warning]
> Thao tác với thiết bị dùng điện lưới và pin dự phòng Lithium-ion có thể nguy hiểm. Hãy kiểm tra mọi kết nối **trước khi** cấp điện cho mạch, đồng thời giữ nguyên vị trí ăng-ten, cáp đồng trục và mặt phẳng nối đất như thiết kế ban đầu để tránh làm lệch tần số cộng hưởng của đầu đọc.

## Danh mục vật tư (BOM)

* Đầu đọc HID MaxiProx 5375 (hoặc bất kỳ đầu đọc tầm xa HID Prox® 12 V nào)
* ESP RFID Tool v2.2 (thiết bị dò/ghi log Wiegand dùng ESP32)
* Module kích hoạt USB-PD (Power-Delivery) có thể thương lượng 12 V @ ≥3 A
* Pin dự phòng USB-C 100 W (có cấu hình đầu ra 12 V PD)
* Dây đấu nối lõi đồng 26 AWG, cách điện silicone – đỏ/trắng
* Công tắc gạt SPST lắp trên bảng điều khiển (dùng làm công tắc ngắt còi)
* Nắp bảo vệ công tắc NKK AT4072 / nắp chống kích hoạt nhầm
* Mỏ hàn, dây hút thiếc và bơm hút thiếc
* Dụng cụ cầm tay phù hợp với ABS: cưa lọng, dao rọc, giũa phẳng và giũa bán nguyệt
* Mũi khoan 1/16″ (1.5 mm) và 1/8″ (3 mm)
* Băng keo hai mặt 3 M VHB và dây rút

## 1. Phân hệ nguồn

1. Tháo hàn và gỡ bo mạch buck-converter gốc dùng để tạo nguồn 5 V cho PCB logic.
2. Lắp module kích hoạt USB-PD cạnh ESP RFID Tool và đưa cổng USB-C của module ra bên ngoài vỏ.
3. Module PD thương lượng nguồn 12 V từ pin dự phòng và cấp trực tiếp cho MaxiProx (đầu đọc vốn yêu cầu 10–14 V). Một đường nguồn 5 V phụ được lấy từ bo mạch ESP để cấp điện cho các phụ kiện.
4. Đặt pin 100 W sát khít với trụ đỡ bên trong để **không có** dây nguồn nào vắt qua ăng-ten ferrite, nhờ đó duy trì hiệu suất RF.

## 2. Công tắc ngắt còi – Vận hành im lặng

1. Xác định hai điểm hàn của loa trên bo mạch logic MaxiProx.
2. Dùng dây hút thiếc làm sạch *cả hai* điểm hàn, sau đó chỉ hàn lại điểm **âm**.
3. Hàn dây 26 AWG (trắng = âm, đỏ = dương) vào các điểm hàn của còi và luồn dây qua một khe mới cắt đến công tắc SPST lắp trên bảng điều khiển.
4. Khi công tắc mở, mạch còi bị ngắt và đầu đọc hoạt động hoàn toàn im lặng – phù hợp để bí mật thu thập thẻ.
5. Lắp nắp an toàn có lò xo NKK AT4072 lên công tắc gạt. Cẩn thận mở rộng lỗ bằng cưa lọng/giũa cho đến khi nắp bật khớp vào thân công tắc. Nắp bảo vệ ngăn công tắc vô tình bật bên trong ba lô.

## 3. Vỏ thiết bị và gia công cơ khí

• Dùng kìm cắt sát, sau đó dùng dao và giũa để *loại bỏ* phần “lồi” ABS bên trong, giúp pin USB-C cỡ lớn nằm phẳng trên trụ đỡ.
• Tạo hai rãnh song song trên thành vỏ để luồn cáp USB-C; cách này cố định pin và loại bỏ tình trạng xê dịch/rung.
• Tạo một lỗ chữ nhật cho nút **nguồn** của pin:
  1. Dán một khuôn giấy lên vị trí cần cắt.
  2. Khoan lỗ dẫn hướng 1/16″ ở cả bốn góc.
  3. Mở rộng bằng mũi khoan 1/8″.
  4. Nối các lỗ bằng cưa lọng; dùng giũa hoàn thiện các cạnh.  
  ✱  *Không dùng* Dremel quay – mũi khoan tốc độ cao làm chảy lớp ABS dày và để lại cạnh xấu.

## 4. Lắp ráp hoàn thiện

1. Lắp lại bo mạch logic MaxiProx và hàn lại dây SMA vào điểm nối đất trên PCB của đầu đọc.
2. Dùng băng keo 3 M VHB để lắp ESP RFID Tool và module kích hoạt USB-PD.
3. Bó gọn toàn bộ dây bằng dây rút, giữ dây nguồn **cách xa** vòng ăng-ten.
4. Siết vít vỏ cho đến khi pin bị nén nhẹ; lực ma sát bên trong giúp pin không xê dịch khi thiết bị giật lùi sau mỗi lần đọc thẻ.

## 5. Kiểm tra tầm đọc và khả năng chắn sóng

* Với thẻ thử nghiệm **Pupa** 125 kHz, thiết bị clone di động đọc ổn định ở khoảng cách **≈ 8 cm** trong không gian thoáng – giống hệt khi dùng nguồn điện lưới.<sup>[[1]](#references)</sup>
* Đặt đầu đọc trong hộp đựng tiền bằng kim loại thành mỏng (mô phỏng bàn ở sảnh ngân hàng) làm giảm tầm đọc xuống ≤ 2 cm, xác nhận rằng các vỏ kim loại lớn có tác dụng chắn RF hiệu quả.<sup>[[1]](#references)</sup>

## Quy trình sử dụng

1. Sạc pin USB-C, kết nối pin và bật công tắc nguồn chính.
2. (Tùy chọn) Mở nắp bảo vệ còi và bật phản hồi âm thanh khi kiểm tra trên bàn; khóa nắp lại trước khi sử dụng bí mật tại hiện trường.
3. Đi ngang qua người đang mang thẻ mục tiêu – MaxiProx sẽ kích hoạt thẻ và ESP RFID Tool sẽ ghi lại luồng Wiegand.
4. Trích xuất thông tin xác thực đã ghi qua Wi-Fi hoặc USB-UART rồi replay/clone khi cần.

## Khắc phục sự cố

| Triệu chứng | Nguyên nhân có thể | Cách khắc phục |
|---------|--------------|------|
| Đầu đọc khởi động lại khi đưa thẻ đến gần | Module kích hoạt PD thương lượng 9 V thay vì 12 V | Kiểm tra jumper trên module / thử cáp USB-C công suất cao hơn |
| Không có tầm đọc | Pin hoặc dây nằm *trên* ăng-ten | Đi lại dây và giữ khoảng cách 2 cm quanh vòng ferrite |
| Còi vẫn kêu | Công tắc được mắc vào dây dương thay vì dây âm | Chuyển công tắc ngắt sang ngắt đường **âm** của loa |

## References

- [1] [Clone một thiết bị clone – Phần 3 (TrustedSec)](https://trustedsec.com/blog/lets-clone-a-cloner-part-3-putting-it-all-together)
{{#include ../../banners/hacktricks-training.md}}