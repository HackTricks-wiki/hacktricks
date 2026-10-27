# Pháp y bản sao lưu iOS (điều tra tập trung vào ứng dụng nhắn tin)

{{#include ../../banners/hacktricks-training.md}}

Trang này mô tả các bước thực tế để tái dựng và phân tích bản sao lưu iOS nhằm tìm dấu hiệu phát tán exploit 0-click qua tệp đính kèm trong ứng dụng nhắn tin. Nội dung tập trung vào việc chuyển cấu trúc bản sao lưu đã được Apple băm thành các đường dẫn dễ đọc, sau đó liệt kê và quét tệp đính kèm trên các ứng dụng phổ biến.

Mục tiêu:
- Tái tạo đường dẫn dễ đọc từ Manifest.db
- Liệt kê cơ sở dữ liệu nhắn tin (iMessage, WhatsApp, Signal, Telegram, Viber)
- Xác định đường dẫn tệp đính kèm, trích xuất đối tượng nhúng nếu được hỗ trợ (PDF/Images/Fonts) và đưa chúng vào các bộ phát hiện cấu trúc


## Tái dựng bản sao lưu iOS

Bản sao lưu được lưu trong MobileSync sử dụng tên tệp đã băm, không thể đọc được. Cơ sở dữ liệu SQLite Manifest.db ánh xạ từng đối tượng được lưu trữ tới đường dẫn logic của nó.<sup>[[1]](#references)[[2]](#references)</sup>

Quy trình tổng quan:
1) Mở Manifest.db và đọc các bản ghi tệp (domain, relativePath, flags, fileID/hash)
2) Tái tạo cấu trúc thư mục ban đầu dựa trên domain + relativePath
3) Sao chép hoặc tạo hardlink cho từng đối tượng được lưu trữ tới đường dẫn đã tái tạo

Quy trình ví dụ với công cụ triển khai toàn bộ quy trình này (ElegantBouncer):<sup>[[1]](#references)[[2]](#references)</sup>

```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```

Ghi chú:
- Giải mã các bản sao lưu được mã hóa trước khi chuyển chúng cho công cụ tái tạo; ElegantBouncer yêu cầu bản sao lưu đã giải mã.<sup>[[2]](#references)[[3]](#references)</sup>
- Nếu có thể, hãy giữ nguyên dấu thời gian/ACL để bảo toàn giá trị chứng cứ

### Thu thập và giải mã bản sao lưu (USB / Finder / libimobiledevice)

- Trong Finder/Apple Devices/iTunes, bật "Encrypt local backup" rồi tạo bản sao lưu mới; các bản sao lưu được mã hóa có thể chứa mật khẩu đã lưu và dữ liệu Health mà bản sao lưu không mã hóa bỏ qua.<sup>[[8]](#references)</sup>
- Đa nền tảng: libimobiledevice 1.4.0 bao gồm các bản sửa lỗi cho `idevicebackup2`.<sup>[[4]](#references)</sup> Bật mã hóa theo cách tương tác, sau đó buộc tạo bản sao lưu đầy đủ bằng thứ tự lệnh được tài liệu hướng dẫn, với thư mục đích ở cuối.<sup>[[6]](#references)</sup>

```bash
# Pair, then enable encrypted backups (prompts for the password); keep the target directory last
$ idevicepair pair
$ idevicebackup2 -i encryption on ~/backups/iphone17

# Create a full encrypted backup over USB
$ idevicebackup2 backup --full ~/backups/iphone17
```

### Phân loại ban đầu dựa trên IOC với MVT

Mobile Verification Toolkit của Amnesty có thể trích xuất khóa từ các bản sao lưu iTunes/Finder đã mã hóa và giải mã chúng, sau đó quét bản sao lưu đã giải mã bằng tệp IOC STIX2.<sup>[[3]](#references)</sup>

```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt to a separate destination
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree with a STIX2 indicator file
$ mvt-ios check-backup -i indicators.stix2.json -o /tmp/mvt-results /tmp/dec-backup
```

Với `-o`, kết quả JSON được ghi vào `/tmp/mvt-results/`; các kết quả khớp IOC có hậu tố `_detected` và có thể được đối chiếu với các đường dẫn tệp đính kèm được khôi phục bên dưới.<sup>[[3]](#references)</sup>

### Phân tích hiện vật tổng quát (iLEAPP)

Để xem dòng thời gian/siêu dữ liệu ngoài phần nhắn tin, hãy chạy iLEAPP trên thư mục sao lưu thô; kiểu đầu vào `itunes` chấp nhận bản sao lưu iTunes/Finder và các bản phát hành hiện tại hỗ trợ iOS/iPadOS 11 đến các phiên bản hiện hành.<sup>[[7]](#references)</sup>

```bash
$ mkdir -p /tmp/ileapp-report
$ python3 ileapp.py -t itunes -i /tmp/dec-backup -o /tmp/ileapp-report
```


## Liệt kê tệp đính kèm trong ứng dụng nhắn tin

Sau khi tái dựng, hãy liệt kê tệp đính kèm của các ứng dụng phổ biến. Schema chính xác thay đổi tùy ứng dụng/phiên bản, nhưng cách thực hiện tương tự: truy vấn cơ sở dữ liệu nhắn tin, join tin nhắn với tệp đính kèm và xác định đường dẫn trên ổ đĩa.<sup>[[1]](#references)[[2]](#references)</sup>

### iMessage (sms.db)
Các bảng chính: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ).<sup>[[2]](#references)</sup>

Ví dụ truy vấn:

```sql
-- List attachments with basic message linkage
SELECT
  m.ROWID            AS message_rowid,
  a.ROWID            AS attachment_rowid,
  a.filename         AS attachment_path,
  m.handle_id,
  m.date,
  m.is_from_me
FROM message m
JOIN message_attachment_join maj ON maj.message_id = m.ROWID
JOIN attachment a ON a.ROWID = maj.attachment_id
ORDER BY m.date DESC;

-- Include chat names via chat_message_join
SELECT
  c.display_name,
  a.filename AS attachment_path,
  m.date
FROM chat c
JOIN chat_message_join cmj ON cmj.chat_id = c.ROWID
JOIN message m ON m.ROWID = cmj.message_id
JOIN message_attachment_join maj ON maj.message_id = m.ROWID
JOIN attachment a ON a.ROWID = maj.attachment_id
ORDER BY m.date DESC;
```

Đường dẫn tệp đính kèm có thể là đường dẫn tuyệt đối hoặc tương đối với cây được tái tạo bên dưới Library/SMS/Attachments.<sup>[[2]](#references)</sup>

### WhatsApp (ChatStorage.sqlite)
Liên kết phổ biến: bảng message ↔ bảng media/attachment (tên gọi thay đổi tùy phiên bản). Truy vấn các hàng media để lấy đường dẫn trên đĩa. Belkasoft xác định `ZMEDIALOCALPATH` trong `ZWAMEDIAITEM` là vị trí tệp media; cách triển khai hiện tại của ElegantBouncer kết nối `ZWAMEDIAITEM.ZMESSAGE` với `ZWAMESSAGE.Z_PK` và thêm `Message/` vào trước khi phân giải đường dẫn bắt đầu bằng `Media/`.<sup>[[9]](#references)[[10]](#references)</sup>

```sql
SELECT
  m.Z_PK                 AS message_pk,
  mi.ZMEDIALOCALPATH     AS media_path,
  datetime(m.ZMESSAGEDATE + 978307200, 'unixepoch') AS message_date,
  CASE m.ZISFROMME WHEN 1 THEN 'outgoing' ELSE 'incoming' END AS direction
FROM ZWAMEDIAITEM mi
JOIN ZWAMESSAGE m ON mi.ZMESSAGE = m.Z_PK
WHERE mi.ZMEDIALOCALPATH IS NOT NULL
ORDER BY m.ZMESSAGEDATE DESC;
```

Với đường dẫn tái dựng của ElegantBouncer đó, đường dẫn media bắt đầu bằng `Media/` sẽ được phân giải bên dưới `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/`; hướng dẫn của Belkasoft lại ghi đường dẫn `Messages/Media/`, vì vậy hãy kiểm tra backup trước khi mặc định một trong hai cách viết.<sup>[[9]](#references)[[10]](#references)</sup>

### Signal / Telegram / Viber
- Signal: DB tin nhắn được mã hóa; tuy nhiên, các tệp đính kèm được lưu trong bộ nhớ đệm trên đĩa (và ảnh thu nhỏ) thường có thể quét được.<sup>[[2]](#references)</sup>
- Telegram: kiểm tra các thư mục media/cache của ứng dụng; Telegram đã ghi nhận lỗi dọn dẹp cache trong ứng dụng iOS 11.2 trên iOS 18.0.1, được đánh dấu là đã sửa trong phiên bản 11.3, vì vậy hãy kiểm tra các tệp còn sót lại.<sup>[[2]](#references)[[5]](#references)</sup>
- Viber: Viber.sqlite chứa các bảng tin nhắn/tệp đính kèm với tham chiếu đến tệp trên đĩa.<sup>[[2]](#references)</sup>

Mẹo: ngay cả khi metadata được mã hóa, việc quét các thư mục media/cache vẫn có thể phát hiện các đối tượng độc hại.<sup>[[2]](#references)</sup>


## Quét tệp đính kèm để tìm lỗi khai thác cấu trúc

Khi đã có đường dẫn tệp đính kèm, hãy đưa chúng vào các công cụ phát hiện cấu trúc để kiểm tra các bất biến của định dạng tệp thay vì chữ ký. Ví dụ với ElegantBouncer:<sup>[[1]](#references)[[2]](#references)</sup>

```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```

Các phát hiện được bao quát bởi các quy tắc cấu trúc bao gồm:<sup>[[1]](#references)[[2]](#references)</sup>
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): trạng thái từ điển JBIG2 bất khả thi
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): cấu trúc bảng Huffman quá lớn
- TrueType TRIANGULATION (CVE‑2023‑41990): opcode bytecode không được tài liệu hóa
- DNG/TIFF CVE‑2025‑43300: không khớp giữa metadata và thành phần luồng dữ liệu


## Xác thực, lưu ý và dương tính giả

- Chuyển đổi thời gian: iMessage lưu ngày tháng theo epoch/đơn vị của Apple trên một số phiên bản; hãy chuyển đổi phù hợp khi báo cáo.<sup>[[2]](#references)</sup>
- Thay đổi schema: schema SQLite của ứng dụng thay đổi theo thời gian; hãy xác nhận tên bảng/cột theo bản dựng của thiết bị
- Trích xuất đệ quy: PDF có thể nhúng luồng JBIG2 và font; hãy dùng trình phân tích cú pháp có thể trích xuất và quét các đối tượng bên trong
- Dương tính giả: heuristic cấu trúc được thiết kế thận trọng nhưng vẫn có thể gắn cờ các tệp media hiếm gặp, bị lỗi định dạng nhưng vô hại.<sup>[[1]](#references)[[2]](#references)</sup>


## References

- [1] [ELEGANTBOUNCER: Khi bạn không thể lấy mẫu nhưng vẫn cần phát hiện mối đe dọa](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [2] [Dự án ElegantBouncer (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [3] [Quy trình MVT kiểm tra bản sao lưu iOS](https://docs.mvt.re/en/latest/ios/backup/check/)
- [4] [Ghi chú phát hành libimobiledevice 1.4.0](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)
- [5] [Bản cập nhật 11.2 làm hỏng việc dọn dẹp cache trên iOS 18.0.1 (Trình theo dõi lỗi Telegram)](https://bugs.telegram.org/c/44361)
- [6] [Hướng dẫn sử dụng idevicebackup2](https://github.com/libimobiledevice/libimobiledevice/blob/master/docs/idevicebackup2.1)
- [7] [Dự án iLEAPP (GitHub)](https://github.com/abrignoni/iLEAPP)
- [8] [Giới thiệu về bản sao lưu được mã hóa trên iPhone, iPad hoặc iPod touch (Apple Support)](https://support.apple.com/en-ie/108353)
- [9] [Phân tích pháp chứng WhatsApp trên iOS bằng Belkasoft X](https://belkasoft.com/ios-whatsapp-forensics-with-belkasoft-x)
- [10] [Trình quét WhatsApp và trình phân giải đường dẫn ElegantBouncer](https://github.com/msuiche/elegant-bouncer/blob/main/src/messaging.rs)
{{#include ../../banners/hacktricks-training.md}}
