# Radio Hacking

{{#include ../../banners/hacktricks-training.md}}

Kiểm thử bảo mật vô tuyến xem xét cách thiết bị truyền, nhận và diễn giải tín hiệu không dây. Software-defined radio (SDR) có thể giúp xác định vị trí tín hiệu, ghi lại các mẫu in-phase/quadrature (I/Q), và kiểm thử giải điều chế, giải mã mà không cần gắn bó với phần cứng dành riêng cho từng giao thức.<sup>[[1]](#references)</sup>

Quy trình thực tế là xác định băng tần và độ rộng kênh, ghi lại một số thao tác đã biết của thiết bị, so sánh các tín hiệu thu được, rồi xác định kiểu điều chế và cấu trúc gói tin. Chỉ kiểm thử phát lại hoặc truyền tín hiệu trong môi trường cách ly, trên các tần số và thiết bị mà bạn được phép sử dụng. Các trang trong phần này đề cập đến RFID, NFC, vô tuyến dưới 1 GHz, hồng ngoại, BLE và các công cụ liên quan.<sup>[[1]](#references)</sup>

## Find the relevant interface

- Với thẻ ra vào hoặc chìa khóa tiếp xúc, hãy bắt đầu với [RFID/NFC tag types and attacks](pentesting-rfid.md), [Proxmark3 workflows](proxmark-3.md) hoặc [iButton and 1-Wire keys](ibutton.md). [Flipper Zero guide](flipper-zero/README.md) liên kết đến các thao tác dành riêng cho từng giao diện.
- Với tín hiệu điều khiển từ xa, hãy dùng [sub-GHz RF and rolling codes](sub-ghz-rf.md) hoặc [infrared protocols and attacks](infrared.md).
- Với các thiết bị và cảm biến ở gần, hãy dùng [BLE advertising, GATT, and mesh testing](pentesting-ble-bluetooth-low-energy.md) hoặc [LPWAN/LoRaWAN security](low-power-wide-area-network.md).
- Với tín hiệu RF đã ghi lại hoặc chưa rõ nguồn gốc, hãy dùng [SigDigger signal analysis](../hardware-hacking/radio.md#sigdigger) hoặc [FISSURE framework](fissure-the-rf-framework.md).
- Với đường xuống của thiết bị đầu cuối vệ tinh, xem [VSAT forward-link signal injection](vsat-forward-link-injection.md).



## References

- [1] [Great Scott Gadgets - Radio được định nghĩa bằng phần mềm với HackRF](https://greatscottgadgets.com/sdr/1/)
{{#include ../../banners/hacktricks-training.md}}
