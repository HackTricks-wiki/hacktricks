# Pháp y bộ nhớ đệm Discord (Disk Cache Chromium)

{{#include ../../../banners/hacktricks-training.md}}

Trang này tóm tắt cách phân loại sơ bộ các hiện vật trong bộ nhớ đệm của Discord Desktop để tìm media được lưu cục bộ, webhook endpoint và tương quan hoạt động. Discord Desktop sử dụng Electron, và Electron lưu dữ liệu phiên như disk cache trong `sessionData`.<sup>[[3]](#references)[[4]](#references)</sup>

## Tìm ở đâu (Windows/macOS/Linux)

- Windows: `%AppData%\discord\Cache\Cache_Data`
- macOS: `~/Library/Application Support/discord/Cache/Cache_Data`
- Linux: `~/.config/discord/Cache/Cache_Data`

Đây là các đường dẫn mặc định mà parser được tham chiếu sử dụng; Electron cho phép ứng dụng ghi đè `sessionData`, vì vậy hãy xác nhận đường dẫn profile thực tế trong quá trình thu thập dữ liệu.<sup>[[2]](#references)[[4]](#references)</sup>

Cấu trúc `index` + `data_#` + `f_######` khớp với backend disk-cache blockfile của Chromium; đừng gắn nhãn là Simple Cache nếu chưa xác minh backend, vì Chromium ghi nhận các triển khai cache khác nhau.<sup>[[5]](#references)</sup>

Các cấu trúc chính trên đĩa bên trong `Cache_Data`:
- `index`: Chỉ mục cache Blockfile dùng để định vị các mục.
- `data_#`: Các tệp block có kích thước cố định, có thể chứa metadata cache, HTTP header và dữ liệu phản hồi.
- `f_######`: Các tệp riêng biệt dùng cho dữ liệu lớn hơn giới hạn của block-file; những tệp này chứa dữ liệu đã lưu mà không có header block-file.

Việc xóa tin nhắn, kênh hoặc máy chủ không đảm bảo các byte đã được lưu cục bộ trong cache cũng bị xóa, nhưng Chromium có thể loại bỏ hoặc tạo lại các tệp cache bất cứ lúc nào. Hãy xem các hiện vật còn sót lại là bằng chứng có thể tận dụng, và chỉ dùng thời gian sửa đổi tệp như dấu hiệu gần đúng về thời điểm ghi cục bộ, cần được đối chiếu với dữ liệu đo từ xa khác.<sup>[[5]](#references)[[6]](#references)</sup>

## Có thể khôi phục những gì

Tùy vào dữ liệu đã được tải xuống và chưa bị loại bỏ, quá trình phân loại sơ bộ có thể khôi phục tệp đính kèm, media, URL và hash tệp trong cache; riêng cache không chứng minh được một mục đã bị exfiltrate.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

- Tệp đính kèm và thumbnail được tham chiếu bằng URL CDN của Discord.
- Hình ảnh, GIF và video (ví dụ: `.jpg`, `.png`, `.gif`, `.webp`, `.mp4` và `.webm`).
- URL webhook như `https://discord.com/api/webhooks/...`.<sup>[[2]](#references)[[7]](#references)</sup>
- API call của Discord như `https://discord.com/api/vX/...`.<sup>[[2]](#references)</sup>
- SHA-256 hash của media đã khôi phục để so sánh với các tập dữ liệu hoặc nguồn thông tin tình báo đã biết.<sup>[[1]](#references)[[2]](#references)</sup>

## Phân loại sơ bộ nhanh (thủ công)

- Grep cache để tìm các hiện vật có tín hiệu mạnh. Những mẫu này mô phỏng biểu thức URL của parser được tham chiếu, chỉ dùng làm bộ lọc phân loại sơ bộ chứ không phải chỉ dấu đầy đủ.<sup>[[2]](#references)</sup>
  - Webhook endpoint:
    - Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
    - Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
  - URL tệp đính kèm/CDN:
    - strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discordapp\.com/attachments/"
  - API call của Discord:
    - strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Sắp xếp các mục trong cache theo thời gian sửa đổi để dựng trình tự gần đúng; mtime là tín hiệu từ hệ thống tệp và tự nó không xác định được thời điểm một đối tượng Discord được tải xuống hoặc gửi đi.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
  - Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Phân tích mục f_* (HTTP body + header)

Trong cấu trúc blockfile, các tệp `f_######` là các luồng dữ liệu riêng biệt và không đảm bảo bắt đầu bằng một HTTP response hoàn chỉnh. Nếu tệp được thu thập có chứa HTTP header đã tuần tự hóa, theo sau là `\r\n\r\n`, hãy tách tại dấu phân cách đầu tiên rồi kiểm tra:<sup>[[2]](#references)[[5]](#references)</sup>
- Content-Type: Dùng để suy luận loại media
- Content-Location hoặc X-Original-URL: URL từ xa ban đầu để xem trước/đối chiếu
- Content-Encoding: Có thể là gzip/deflate/br (Brotli).

Sau đó có thể trích xuất media bằng cách tách header khỏi body và tùy chọn giải nén theo `Content-Encoding`; parser được tham chiếu xử lý Brotli, gzip và deflate. Nhận diện bằng magic byte hữu ích khi không có `Content-Type`, nhưng đây vẫn chỉ là phương pháp heuristic.<sup>[[2]](#references)</sup>

## DFIR tự động: Discord Forensic Suite (CLI/GUI)

- Repo: [Discord Forensic Suite](https://github.com/jwdfir/discord_cache_parser).<sup>[[1]](#references)</sup>
- Chức năng: Quét đệ quy thư mục cache của Discord, tìm URL webhook/API/tệp đính kèm, phân tích body `f_*`, tùy chọn trích xuất media và xuất báo cáo HTML, CSV cùng timeline theo trình tự thời gian (không bắt buộc) có SHA-256 hash.<sup>[[1]](#references)[[2]](#references)</sup>

Ví dụ sử dụng CLI:

```powershell
# Acquire a copy of the cache for offline parsing, then run on Windows:
python discord_forensic_suite_cli `
  --cache "$env:APPDATA\discord\Cache\Cache_Data" `
  --outdir "C:\IR\discord-cache" `
  --output discord_cache_report `
  --format both `
  --timeline `
  --extra `
  --carve `
  --verbose
```

CLI định nghĩa các tùy chọn và tên đầu ra sau:<sup>[[2]](#references)</sup>
- --cache: Đường dẫn đến thư mục Discord Cache_Data
- --format html|csv|both
- --timeline: Tạo timeline CSV theo thứ tự (dựa trên thời gian sửa đổi)
- --extra: Quét thêm Code Cache và GPUCache cùng cấp
- --carve: Trích xuất media từ byte cache thô bằng các signature media đã nhận diện (ảnh/video)
- Output: `<output>.html`, `<output>.csv`, tùy chọn `<output>_timeline.csv` và thư mục `<output>_media` chứa các tệp đã trích xuất hoặc carve.

## Mẹo cho chuyên viên phân tích

- Đối chiếu thời gian sửa đổi (mtime) của các tệp `f_*` và `data_*` với khoảng thời gian hoạt động của người dùng hoặc attacker và dữ liệu đo từ xa độc lập; mtime không phải dấu thời gian sự kiện mang tính kết luận.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Hash media khôi phục được (SHA-256) và so sánh với các bộ dữ liệu đã biết là độc hại hoặc dùng cho exfiltration.<sup>[[1]](#references)[[2]](#references)</sup>
- Xem các URL webhook đã trích xuất như thông tin xác thực. Không gọi chúng chỉ để kiểm tra xem chúng còn hoạt động hay không; hãy bảo quản an toàn, phối hợp thu hồi hoặc xoay vòng và dùng dữ liệu đo từ xa mạng liên quan để retro-hunting.<sup>[[7]](#references)</sup>
- Xóa ở phía server không đảm bảo byte được lưu trong cache cục bộ đã bị xóa. Nếu có thể thu thập, hãy lấy toàn bộ thư mục `Cache` và các cache cùng cấp liên quan (`Code Cache`, `GPUCache`) trước khi chúng bị xóa hoặc cache được tạo lại.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Bộ công cụ pháp chứng Discord (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [2] [CLI của Bộ công cụ pháp chứng Discord](https://raw.githubusercontent.com/jwdfir/discord_cache_parser/refs/heads/main/discord_forensic_suite_cli)
- [3] [Cách Discord nâng cấp liền mạch hàng triệu người dùng lên kiến trúc 64-bit](https://discord.com/blog/how-discord-seamlessly-upgraded-millions-of-users-to-64-bit-architecture)
- [4] [app | Electron](https://www.electronjs.org/docs/latest/api/app)
- [5] [Disk Cache](https://www.chromium.org/developers/design-documents/network-stack/disk-cache/)
- [6] [Discord làm C2 và bằng chứng cache còn sót lại](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [7] [Discord Webhooks – Thực thi Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)
{{#include ../../../banners/hacktricks-training.md}}
