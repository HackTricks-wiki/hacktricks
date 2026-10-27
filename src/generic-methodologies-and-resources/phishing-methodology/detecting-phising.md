# Phát hiện Phishing

{{#include ../../banners/hacktricks-training.md}}

## Giới thiệu

Để phát hiện một cuộc tấn công phishing, điều quan trọng là **hiểu các kỹ thuật phishing đang được sử dụng hiện nay**. Bạn có thể tìm thấy thông tin này trên trang cha của bài viết này. Vì vậy, nếu bạn chưa biết những kỹ thuật nào đang được sử dụng ngày nay, tôi khuyên bạn nên truy cập trang cha và đọc ít nhất phần đó.

Bài viết này dựa trên ý tưởng rằng **kẻ tấn công sẽ cố gắng bằng cách nào đó bắt chước hoặc sử dụng tên miền của nạn nhân**. Nếu tên miền của bạn là `example.com` và vì lý do nào đó bạn bị phishing bằng một tên miền hoàn toàn khác như `youwonthelottery.com`, thì các kỹ thuật này sẽ không phát hiện được.

## Biến thể tên miền

Việc **phát hiện** những cuộc tấn công **phishing** sử dụng tên miền **tương tự** trong email khá **dễ dàng**.\
Chỉ cần **tạo danh sách những tên miền phishing có khả năng được kẻ tấn công sử dụng cao nhất**, rồi **kiểm tra** xem chúng đã được **đăng ký** hay chưa, hoặc kiểm tra xem có **IP** nào đang sử dụng chúng không.

### Tìm các tên miền đáng ngờ

Bạn có thể dùng bất kỳ công cụ nào sau đây cho mục đích này. Cả hai đều phân giải các tên miền ứng viên để kiểm tra xem chúng có đang được sử dụng hay không.<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Mẹo: Nếu tạo danh sách tên miền ứng viên, hãy đưa danh sách đó vào cả log DNS resolver để phát hiện **các truy vấn NXDOMAIN từ bên trong tổ chức** (người dùng cố truy cập một tên miền gõ sai trước khi kẻ tấn công thực sự đăng ký nó). Hãy sinkhole hoặc chặn trước các tên miền này nếu chính sách cho phép.

### Bitflipping

**Để xem giải thích ngắn gọn, hãy truy cập trang cha; để đọc nghiên cứu gốc về bitsquatting trên Windows.com, xem [bài viết của Remy Hax](https://remyhax.xyz/posts/bitsquatting-windows/) và [báo cáo của BleepingComputer](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)**.<sup>[[1]](#references)[[2]](#references)</sup>

Ví dụ, thay đổi 1 bit trong tên miền microsoft.com có thể biến nó thành _windnws.com._\
**Kẻ tấn công có thể đăng ký càng nhiều tên miền bit-flipping liên quan đến nạn nhân càng tốt để chuyển hướng người dùng hợp pháp đến hạ tầng của chúng**.<sup>[[1]](#references)[[2]](#references)</sup>

**Cũng cần giám sát tất cả các tên miền bit-flipping có thể có.**

Nếu bạn cũng cần xem xét các tên miền giả mạo bằng homoglyph/IDN (ví dụ: trộn ký tự Latin/Cyrillic), hãy xem:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Kiểm tra cơ bản

Sau khi có danh sách tên miền đáng ngờ tiềm năng, bạn nên **kiểm tra** chúng (chủ yếu là các cổng HTTP và HTTPS) để **xem chúng có đang sử dụng biểu mẫu đăng nhập tương tự** biểu mẫu của một tên miền thuộc nạn nhân hay không.\
Bạn cũng có thể kiểm tra cổng 3333 để xem cổng này có đang mở và chạy một instance `gophish` hay không.\
Việc biết **tuổi của từng tên miền đáng ngờ được phát hiện** cũng rất hữu ích; tên miền càng mới thì rủi ro càng cao.\
Bạn cũng có thể chụp **ảnh màn hình** trang web đáng ngờ qua HTTP và/hoặc HTTPS để xem trang đó có đáng ngờ không, rồi trong trường hợp đó **truy cập để kiểm tra kỹ hơn**.

### Kiểm tra nâng cao

Nếu muốn tiến thêm một bước, tôi khuyên bạn nên **giám sát các tên miền đáng ngờ đó và định kỳ tìm thêm tên miền mới** (mỗi ngày chăng? việc này chỉ mất vài giây/phút). Bạn cũng nên **kiểm tra** các **cổng** đang mở của những IP liên quan, **tìm các instance `gophish` hoặc công cụ tương tự** (đúng vậy, kẻ tấn công cũng mắc lỗi), đồng thời **giám sát các trang web HTTP và HTTPS của những tên miền và tên miền phụ đáng ngờ** để xem chúng có sao chép biểu mẫu đăng nhập từ các trang web của nạn nhân hay không.\
Để **tự động hóa việc này**, tôi khuyên bạn nên lập danh sách các biểu mẫu đăng nhập trên những tên miền của nạn nhân, crawl các trang web đáng ngờ, rồi so sánh từng biểu mẫu đăng nhập tìm thấy trên các tên miền đáng ngờ với từng biểu mẫu đăng nhập trên tên miền của nạn nhân bằng công cụ như `ssdeep`.\
Nếu đã xác định được các biểu mẫu đăng nhập trên những tên miền đáng ngờ, bạn có thể thử **gửi thông tin đăng nhập rác** và **kiểm tra xem chúng có chuyển hướng bạn đến tên miền của nạn nhân hay không**.

---

### Truy tìm bằng favicon và dấu vân tay web (Shodan/Censys)

Nhiều phishing kit sử dụng lại favicon của thương hiệu mà chúng giả mạo. Shodan băm dữ liệu favicon được mã hóa base64 bằng MurmurHash3, trong khi Censys cung cấp các trường hash favicon riêng.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> Bạn có thể tạo hash tương thích với Shodan rồi pivot dựa trên hash đó:

Ví dụ Python (mmh3):

```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```

- Truy vấn Shodan: `http.favicon.hash:309020573`
- Dùng công cụ: tham khảo các công cụ cộng đồng như favfreak để tính hash và tạo Shodan dork.<sup>[[16]](#references)</sup>

Lưu ý
- Favicon được dùng lại; hãy xem các kết quả trùng khớp là manh mối và xác thực nội dung cũng như chứng chỉ trước khi hành động.
- Kết hợp với heuristic về độ tuổi domain và từ khóa để tăng độ chính xác.

### Săn tìm telemetry URL (urlscan.io)

`urlscan.io` lưu trữ ảnh chụp màn hình, DOM, request và metadata TLS lịch sử của các URL đã gửi. Bạn có thể săn tìm hành vi lạm dụng thương hiệu và các bản sao:<sup>[[8]](#references)</sup>

Ví dụ truy vấn (UI hoặc API):
- Tìm các domain giả mạo, loại trừ domain hợp pháp của bạn: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Tìm các site hotlink tài nguyên của bạn: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Giới hạn kết quả gần đây: thêm `AND date:>now-7d`

Ví dụ API:

```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
  -H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```

Từ JSON, pivot dựa trên:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` để phát hiện chứng chỉ rất mới của các domain nhái
- Các giá trị `task.source` như `certstream-suspicious` để liên kết kết quả với hoạt động giám sát CT

### Tuổi domain qua RDAP (có thể viết script)

RDAP trả về các sự kiện đăng ký ở định dạng máy có thể đọc được. Hữu ích để phát hiện **domain mới đăng ký (NRDs)**.<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
  jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```

Làm phong phú pipeline bằng cách gắn thẻ các domain theo nhóm tuổi đăng ký (ví dụ: <7 ngày, <30 ngày) và ưu tiên phân loại tương ứng.

### Dấu vân tay TLS/JAx để phát hiện hạ tầng AiTM

Phishing đánh cắp thông tin xác thực có thể dùng reverse proxy **Adversary-in-the-Middle (AiTM)** (ví dụ: Evilginx) để đánh cắp session token.<sup>[[11]](#references)</sup> Bạn có thể bổ sung các cơ chế phát hiện ở phía mạng:

- Ghi lại dấu vân tay TLS/HTTP (JA3/JA4/JA4S/JA4H) tại điểm lưu lượng ra. Một số bản dựng Evilginx được ghi nhận có giá trị JA4 phía client/server ổn định. Chỉ cảnh báo dựa trên dấu vân tay đã biết là độc hại như một tín hiệu yếu; luôn xác minh bằng nội dung và thông tin tình báo về domain.<sup>[[12]](#references)</sup>
- Chủ động ghi lại metadata chứng chỉ TLS (issuer, số lượng SAN, việc sử dụng wildcard, thời hạn hiệu lực) của các host giả mạo được phát hiện qua CT hoặc urlscan, rồi đối chiếu với tuổi DNS và vị trí địa lý.

> Lưu ý: Hãy xem dấu vân tay là thông tin bổ sung, không phải cơ sở duy nhất để chặn; framework liên tục thay đổi và có thể ngẫu nhiên hóa hoặc làm rối dấu vân tay.

### Tên domain sử dụng từ khóa

Trang cha cũng đề cập đến một kỹ thuật biến thể tên domain, trong đó **tên domain của nạn nhân được đặt bên trong một domain dài hơn** (ví dụ: paypal-financial.com cho paypal.com).

#### Certificate Transparency

Log Certificate Transparency (CT) công khai danh tính chứng chỉ, vì vậy tìm kiếm từ khóa thương hiệu trong tên Subject hoặc SAN có thể giúp phát hiện domain giả mạo (ví dụ: chứng chỉ cho `paypal-financial.com` có từ khóa `paypal`). Khi cần, hãy lọc kết quả theo ngày cấp và CA, đồng thời xác minh các domain tiềm năng vì kết quả khớp từ khóa có thể là false positive.<sup>[[13]](#references)</sup>

Bài viết gốc của Patrik Hudak về [săn tìm domain phishing](https://0xpatrik.com/phishing-domains/) minh họa quy trình này trên Censys, bao gồm các bộ lọc theo ngày cấp chứng chỉ và issuer, chẳng hạn như Let's Encrypt.<sup>[[13]](#references)</sup>

![Kết quả tìm kiếm chứng chỉ Censys được dùng để nhận diện các domain giả mạo](<../../images/image (1115).png>)

Bạn cũng có thể dùng dịch vụ miễn phí [**crt.sh**](https://crt.sh) để tìm kiếm từ khóa và lọc kết quả theo ngày và CA.<sup>[[13]](#references)</sup>

![Tìm kiếm từ khóa trên crt.sh để tìm danh tính chứng chỉ đáng ngờ](<../../images/image (519).png>)

Trường Matching Identities có thể giúp so sánh danh tính của domain thật với các domain đáng ngờ, nhưng hãy xem các kết quả khớp là đầu mối chứ không phải bằng chứng.<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) truyền phát các cập nhật CT gần như theo thời gian thực, còn [*phishing_catcher*](https://github.com/x0rz/phishing_catcher) lấy dữ liệu từ luồng đó để chấm điểm các tên chứng chỉ đáng ngờ.<sup>[[14]](#references)[[15]](#references)</sup>

Mẹo thực tế: khi phân loại kết quả CT, hãy ưu tiên NRD, registrar không đáng tin cậy/không rõ danh tính, WHOIS dùng dịch vụ bảo vệ quyền riêng tư và chứng chỉ có thời điểm `NotBefore` rất gần đây. Duy trì allowlist các domain/thương hiệu thuộc sở hữu của bạn để giảm nhiễu.

#### **Domain mới**

Một lựa chọn khác là thu thập các domain mới đăng ký theo TLD (ví dụ: qua [Whoxy](https://www.whoxy.com/newly-registered-domains/)) rồi lọc theo từ khóa thương hiệu. Cách này bỏ sót phishing được lưu trữ trên subdomain nếu từ khóa không xuất hiện trong domain đã đăng ký.<sup>[[13]](#references)</sup>

Heuristic bổ sung: hãy tăng mức độ cảnh giác khi cảnh báo về một số **TLD có phần mở rộng giống tên tệp** (ví dụ: `.zip`, `.mov`). Những TLD này thường bị nhầm với tên tệp trong các nội dung dụ nhấp; hãy kết hợp tín hiệu TLD với từ khóa thương hiệu và tuổi NRD để tăng độ chính xác.

## References

- [1] [Remy Hax – Bit-squatting Windows.com](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [Chiếm quyền lưu lượng truy cập đến windows.com của Microsoft bằng cách lật bit](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [Phân tích chuyên sâu: http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [Tài liệu mmh3](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Tập dữ liệu thuộc tính web của nền tảng](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – Tài liệu tham khảo Search API](https://urlscan.io/docs/search/)
- [9] [Trợ giúp về Registration Data Access Protocol](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083: Phản hồi JSON cho Registration Data Access Protocol](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [Chiến thuật token: Cách ngăn chặn, phát hiện và ứng phó với hành vi đánh cắp cloud token](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [APNIC Blog – Dấu vân tay mạng JA4+](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – Tìm kiếm phishing: Công cụ và kỹ thuật](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – Giới thiệu CertStream](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
