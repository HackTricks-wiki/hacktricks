# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Giới thiệu <a href="#id-9wrzi" id="id-9wrzi"></a>

Để tìm hiểu về RFID và NFC, hãy xem trang sau:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Các thẻ NFC được hỗ trợ <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> Ngoài thẻ NFC, Flipper Zero còn hỗ trợ **các loại thẻ tần số cao khác**, chẳng hạn như một số thẻ **Mifare** Classic, Ultralight và **NTAG**.

Danh sách khả năng bên dưới mô tả firmware được tài liệu gốc đề cập và không nên được xem là ma trận hỗ trợ đầy đủ hiện tại. Firmware Flipper đã bổ sung giao thức và thay đổi cách hoạt động của NFC theo thời gian; hãy kiểm tra tài liệu chính thức hiện tại dành cho firmware đã cài đặt.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Thẻ ngân hàng (EMV)** — chỉ đọc UID, SAK và ATQA mà không lưu.
- **Thẻ không xác định** — đọc UID, SAK và ATQA, đồng thời giả lập UID.

Đối với **các loại thẻ NFC B, F và V**, firmware được mô tả có thể đọc UID mà không lưu.

### Thẻ NFC loại A <a href="#uvusf" id="uvusf"></a>

#### Thẻ ngân hàng (EMV) <a href="#kzmrp" id="kzmrp"></a>

Firmware được mô tả có thể đọc UID, SAK, ATQA và dữ liệu ứng dụng khả dụng từ thẻ ngân hàng **mà không lưu dữ liệu**.

Với các thẻ ngân hàng này, firmware hiển thị dữ liệu mà không lưu hoặc giả lập thẻ.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Thẻ không xác định <a href="#id-37eo8" id="id-37eo8"></a>

Khi Flipper Zero **không thể xác định loại thẻ NFC**, chỉ có thể **đọc và lưu** **UID, SAK và ATQA**.

Với thẻ NFC không xác định, chế độ này chỉ có thể giả lập UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### Thẻ NFC loại B, F và V <a href="#wyg51" id="wyg51"></a>

Trong firmware được tài liệu gốc mô tả, thẻ NFC loại B, F và V chỉ có thể được đọc và hiển thị mã định danh mà không lưu lại.<sup>[[1]](#references)</sup>

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## Thao tác

Để xem phần giới thiệu về NFC, [**hãy đọc trang này**](../pentesting-rfid.md#high-frequency-rfid-tags-1356-mhz-1).

### Đọc

Flipper Zero có thể đọc thẻ NFC nhưng không triển khai mọi giao thức cấp cao được xây dựng trên ISO 14443. Vì vậy, thiết bị có thể lấy được UID, SAK và ATQA ở mức thấp nhưng không xác định được giao thức ứng dụng. Với các hệ thống kiểm soát truy cập cơ bản chỉ xác thực bằng UID, công cụ có thể đọc, nhập thủ công và giả lập mã định danh đó; các hệ thống dùng xác thực mật mã cần nhiều hơn một UID được sao chép.<sup>[[1]](#references)</sup>

#### Đọc UID so với đọc dữ liệu bên trong <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

Trong Flipper, việc đọc thẻ 13.56 MHz có thể chia thành hai phần:<sup>[[1]](#references)</sup>

- **Đọc mức thấp** — chỉ đọc UID, SAK và ATQA. Flipper cố gắng đoán giao thức cấp cao dựa trên dữ liệu đọc từ thẻ. Không thể chắc chắn 100% vì đây chỉ là suy đoán dựa trên một số yếu tố.
- **Đọc mức cao** — đọc dữ liệu từ bộ nhớ thẻ bằng một giao thức cấp cao cụ thể. Ví dụ: đọc dữ liệu trên Mifare Ultralight, đọc các sector của Mifare Classic hoặc đọc thuộc tính của thẻ PayPass/Apple Pay.

### Đọc cụ thể

Nếu Flipper Zero không thể xác định loại thẻ từ dữ liệu mức thấp, trong `Extra Actions`, bạn có thể chọn `Read Specific Card Type` và **tự chỉ định loại thẻ muốn đọc**.

#### Thẻ ngân hàng EMV (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Các phiên bản firmware Flipper cũ hơn và thẻ EMV tương thích có thể để lộ nhiều dữ liệu hơn UID, có khả năng bao gồm PAN, ngày hết hạn, tên chủ thẻ hoặc nhật ký giao dịch nếu thẻ cung cấp các bản ghi đó. Tính khả dụng tùy thuộc vào thẻ, ứng dụng và firmware. CVV của dải từ được in trên thẻ không thể được truy xuất theo cách này; việc đọc các bản ghi này cũng không sao chép được khả năng giao dịch mật mã cần thiết để thanh toán không tiếp xúc.<sup>[[1]](#references)</sup>

## References

- [1] [Tìm hiểu sâu về giao thức RFID với Flipper Zero](https://blog.flipperzero.one/rfid/)
- [2] [Tài liệu Flipper Zero - NFC](https://docs.flipper.net/zero/nfc)
{{#include ../../../banners/hacktricks-training.md}}
