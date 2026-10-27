# Số sê-ri macOS

{{#include ../../../banners/hacktricks-training.md}}

## Thông tin cơ bản

Đừng mặc định rằng mọi máy Mac đều có số sê-ri 12 ký tự có thể giải mã. Định dạng cũ của Apple mã hóa thông tin sản xuất và cấu hình, nhưng Apple bắt đầu giới thiệu số sê-ri ngẫu nhiên trên các sản phẩm mới vào năm 2021. Định dạng ngẫu nhiên không tiết lộ thông tin sản xuất hoặc cấu hình.<sup>[[1]](#references)</sup>

### Định dạng cũ gồm 12 ký tự

Với nhiều thiết bị được sản xuất từ năm 2010 cho đến khi chuyển sang định dạng ngẫu nhiên, định dạng 12 ký tự vẫn có thể cung cấp các manh mối hữu ích để kiểm kê:<sup>[[3]](#references)</sup>

- Ký tự 1–3 xác định địa điểm sản xuất.
- Ký tự 4–5 mã hóa nửa năm và tuần sản xuất.
- Ký tự 6–8 phân biệt các thiết bị được sản xuất tại cùng địa điểm và thời điểm.
- Ký tự 9–12 xác định mã kiểu máy hoặc cấu hình.

Ví dụ: `C02L13ECF8J2` tuân theo cấu trúc cũ này. Các bảng tra cứu nhà máy do cộng đồng duy trì ghi nhận những tiền tố như `FC`, `F`, `XA`, `XB`, `QP` và `G8` cho các địa điểm tại Hoa Kỳ; `RN` cho Mexico; `CK` cho Cork; `VM` cho một địa điểm của Foxconn tại Cộng hòa Séc; `SG` hoặc `E` cho Singapore; `MB` cho Malaysia; `PT` hoặc `CY` cho Hàn Quốc; và `EE`, `QT` hoặc `UV` cho Đài Loan. Nhiều tiền tố, bao gồm `FK`, `F1`, `F2`, `W8`, `DL`, `DM`, `DN`, `YM`, `7J`, `1C`, `4H`, `WQ`, `F7`, `C0`, `C3` và `C7`, được cho là liên quan đến các cơ sở ở Trung Quốc; `RM` được cho là liên quan đến thiết bị tân trang.<sup>[[3]](#references)</sup>

Mã ngày ở ký tự thứ tư chạy từ `C` (nửa đầu năm 2010) đến `Z` (nửa cuối năm 2019), sau đó chuỗi này được sử dụng lại. Với ký tự thứ năm, các chữ số `1`–`9` đại diện cho tuần 1–9, còn các chữ cái `C`–`Y`, ngoại trừ nguyên âm và `S`, đại diện cho tuần 10–27; cộng thêm 26 nếu ký tự thứ tư biểu thị nửa cuối năm.<sup>[[3]](#references)</sup>

Các bảng tra cứu này hữu ích khi phân loại sơ bộ thiết bị cũ, nhưng không phải bằng chứng xác thực về nguồn gốc, tuổi đời hoặc tính chính hãng. Hãy xác nhận kết quả bằng dữ liệu kiểm kê của Apple.

Để nhận diện đáng tin cậy, hãy lấy số sê-ri từ thiết bị và dùng công cụ tra cứu phạm vi bảo hành hoặc thông số kỹ thuật của Apple, thay vì suy đoán kiểu máy từ vị trí các ký tự.<sup>[[2]](#references)</sup>

### Lấy số sê-ri

Giao diện đồ họa hiển thị số sê-ri trong **menu Apple > Giới thiệu về máy Mac này**.<sup>[[2]](#references)</sup> Từ shell, một trong hai lệnh sau sẽ đọc số sê-ri của nền tảng:

```bash
system_profiler SPHardwareDataType | awk -F ': ' '/Serial Number/ {print $2}'
ioreg -rd1 -c IOPlatformExpertDevice | awk -F '"' '/IOPlatformSerialNumber/ {print $4}'
```

Hãy xem số sê-ri là mã định danh, không phải thông tin xác thực: xác minh thiết bị qua quy trình kiểm kê Apple hoặc MDM phù hợp trước khi quyết định đăng ký hoặc quyền sở hữu.

## References

- [1] [MacRumors - Apple bắt đầu chuyển sang số sê-ri ngẫu nhiên](https://www.macrumors.com/2021/05/05/purple-iphone-12-randomized-serial-number/)
- [2] [Apple Support - Tìm tên kiểu máy và số sê-ri của máy Mac](https://support.apple.com/en-us/102767)
- [3] [Beetstech - Giải mã ý nghĩa của số sê-ri Apple](https://beetstech.com/blog/decode-meaning-behind-apple-serial-number)
{{#include ../../../banners/hacktricks-training.md}}
