# MediaTek XFlash Carbonara Bypass Hash

{{#include ../../banners/hacktricks-training.md}}

## Tóm tắt

"Carbonara" lợi dụng đường tải xuống XFlash của MediaTek để chạy một Download Agent stage 2 (DA2) đã chỉnh sửa, bất chấp các bước kiểm tra tính toàn vẹn của DA1. DA1 lưu SHA-256 dự kiến của DA2 trong RAM và so sánh trước khi chuyển nhánh. Trên nhiều loader, host hoàn toàn kiểm soát địa chỉ/kích thước nạp DA2, tạo ra một thao tác ghi bộ nhớ không được kiểm tra, có thể ghi đè hash trong bộ nhớ này và chuyển hướng thực thi đến payload tùy ý (trong ngữ cảnh trước hệ điều hành, với DA xử lý việc vô hiệu hóa cache).<sup>[[1]](#references)[[2]](#references)</sup>

## Ranh giới tin cậy trong XFlash (DA1 → DA2)

- **DA1** được BootROM/Preloader ký/nạp. Khi bật Download Agent Authorization (DAA), chỉ DA1 đã ký mới được chạy.
- **DA2** được gửi qua USB. DA1 nhận **kích thước**, **địa chỉ nạp** và **SHA-256**, rồi tính hash của DA2 nhận được và so sánh với **hash dự kiến được nhúng trong DA1** (được sao chép vào RAM).
- **Điểm yếu:** Trên các loader chưa được vá, DA1 không xác thực địa chỉ/kích thước nạp DA2 và giữ hash dự kiến ở vùng bộ nhớ có thể ghi, cho phép host can thiệp vào bước kiểm tra này.<sup>[[1]](#references)[[2]](#references)</sup>

## Quy trình Carbonara (thủ thuật "two BOOT_TO")

1. **`BOOT_TO` lần đầu:** Đi vào quy trình staging DA1→DA2 (DA1 cấp phát, chuẩn bị DRAM và để lộ bộ đệm hash dự kiến trong RAM).
2. **Ghi đè ô hash:** Gửi một payload nhỏ quét bộ nhớ DA1 để tìm hash DA2 dự kiến đã lưu, rồi ghi đè bằng SHA-256 của DA2 đã chỉnh sửa. Cách này tận dụng thao tác nạp do người dùng kiểm soát để đưa payload đến vị trí chứa hash.
3. **`BOOT_TO` lần hai + digest:** Kích hoạt một `BOOT_TO` khác với metadata DA2 đã sửa, rồi gửi digest thô 32 byte khớp với DA2 đã chỉnh sửa. DA1 tính lại SHA-256 trên DA2 nhận được, so sánh với hash dự kiến vừa được sửa và chuyển nhánh thành công vào mã của attacker.

Trên các loader bị ảnh hưởng, địa chỉ và kích thước không được kiểm tra có thể cung cấp cho attacker primitive ghi bộ nhớ trước hệ điều hành tại vị trí do attacker chọn, vượt ra ngoài ô hash. Tùy thuộc vào memory map của SoC và các bước xác minh tiếp theo, điều này có thể hỗ trợ implant khởi động sớm, công cụ hỗ trợ bypass secure boot hoặc payload kiểu rootkit. Việc thực thi mã DA không tự động tạo ra persistence hay hoàn tất bypass secure boot; vẫn cần một cơ chế persistence riêng và chuỗi xác minh tương thích.<sup>[[1]](#references)[[2]](#references)</sup>

## Mẫu PoC tối thiểu (kiểu mtkclient)

```python
if self.xsend(self.Cmd.BOOT_TO):
    payload = bytes.fromhex("a4de2200000000002000000000000000")
    if self.xsend(payload) and self.status() == 0:
        import hashlib
        da_hash = hashlib.sha256(self.daconfig.da2).digest()
        if self.xsend(da_hash):
            self.status()
            self.info("All good!")
```

- `payload` 16 byte tái tạo blob được quan sát trong quy trình làm việc với công cụ trả phí và được triển khai công khai sử dụng để vá buffer expected-hash. Đây là payload dành riêng cho loader, không phải bản vá hash-slot dùng được trên mọi SoC hoặc DA.<sup>[[1]](#references)[[2]](#references)</sup>
- `sha256(...).digest()` gửi raw bytes (không phải hex) để DA1 so sánh với buffer đã vá.
- Trên loader dễ bị tấn công và khớp với exploit, DA2 có thể là image do attacker tạo, còn metadata load đã chọn sẽ kiểm soát vị trí của nó trong bộ nhớ. Hãy xác thực tổ hợp DA/SoC trước khi truyền, vì địa chỉ không chính xác có thể khiến thiết bị bị treo hoặc hư hỏng.<sup>[[3]](#references)</sup>

## Bức tranh về các bản vá (loader đã được tăng cường bảo mật)

- **Biện pháp giảm thiểu đã quan sát**: Các DA đã được tăng cường bảo mật mà nhóm nghiên cứu kiểm tra buộc địa chỉ load của DA2 là `0x40000000` và bỏ qua địa chỉ do host cung cấp, ngăn việc ghi vào vùng hash DA1 được quan sát gần `0x200000`. Hãy xem cả hai địa chỉ là thông số riêng của từng triển khai, không phải hằng số kiến trúc.
- **Phát hiện DA đã vá**: mtkclient/penumbra quét DA1 để tìm các mẫu cho thấy địa chỉ đã được tăng cường bảo mật; nếu phát hiện, Carbonara sẽ bị bỏ qua. DA cũ để lộ các hash slot có thể ghi (thường ở các offset như `0x22dea4` trong V5 DA1) và vẫn có thể bị khai thác.
- **V5 so với V6**: Một số loader V6 (XML) vẫn chấp nhận địa chỉ do người dùng cung cấp; các binary V6 mới hơn thường áp dụng địa chỉ cố định và miễn nhiễm với Carbonara, trừ khi bị downgrade.<sup>[[2]](#references)[[3]](#references)</sup>

## Lưu ý sau Carbonara (heapb8)

MediaTek đã vá Carbonara; một lỗ hổng mới hơn, **heapb8**, nhắm vào trình xử lý tải file USB của DA2 trên các loader V6 đã vá, cho phép thực thi mã ngay cả khi `boot_to` đã được tăng cường bảo mật. Lỗ hổng này khai thác heap overflow trong quá trình truyền file theo từng chunk để chiếm quyền điều khiển luồng thực thi của DA2. Exploit được công khai trong Penumbra/mtk-payloads và cho thấy các bản sửa lỗi Carbonara không khắc phục toàn bộ bề mặt tấn công DA.<sup>[[4]](#references)</sup>

## Lưu ý khi phân loại và tăng cường bảo mật

- Các thiết bị không kiểm tra địa chỉ/kích thước DA2 và để DA1 giữ hash dự kiến ở trạng thái có thể ghi thì dễ bị tấn công. Nếu Preloader/DA ở giai đoạn sau áp dụng giới hạn địa chỉ hoặc giữ hash ở trạng thái bất biến, Carbonara sẽ được giảm thiểu.
- Bật DAA và đảm bảo DA1/Preloader xác thực các tham số BOOT_TO (giới hạn + tính xác thực của DA2) sẽ khắc phục primitive này. Chỉ chặn việc vá hash mà không giới hạn vùng load vẫn để lại nguy cơ ghi tùy ý.

## References

- [1] [Carbonara: Exploit MediaTek mà không ai cung cấp](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [2] [Tài liệu về exploit Carbonara](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [3] [Mã nguồn Carbonara của Penumbra](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [4] [heapb8: khai thác Download Agent V6 đã được vá](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)
{{#include ../../banners/hacktricks-training.md}}
