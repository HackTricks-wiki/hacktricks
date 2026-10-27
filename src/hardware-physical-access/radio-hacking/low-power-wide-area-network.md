# Mạng diện rộng công suất thấp

{{#include ../../banners/hacktricks-training.md}}

## Giới thiệu

**Mạng diện rộng công suất thấp** (LPWAN) là một nhóm công nghệ mạng không dây, công suất thấp, diện rộng, được thiết kế để **liên lạc đường dài** với tốc độ bit thấp.
Tùy thuộc vào thông số vô tuyến, ăng-ten, khu vực quản lý, địa hình và chu kỳ hoạt động, các triển khai LPWAN có thể đánh đổi thông lượng để đạt vùng phủ sóng nhiều kilomet và thời lượng pin nhiều năm. Hãy xem các con số về phạm vi và thời lượng pin do nhà cung cấp công bố là mục tiêu thiết kế, không phải cam kết.<sup>[[3]](#references)</sup>

Long Range (**LoRa**) hiện là lớp vật lý LPWAN được triển khai rộng rãi nhất, còn đặc tả lớp MAC mở của nó là **LoRaWAN**.

---

## LPWAN, LoRa và LoRaWAN

* LoRa – Lớp vật lý Chirp Spread Spectrum (CSS) do Semtech phát triển (độc quyền nhưng có tài liệu công khai).
* LoRaWAN – Lớp MAC/Network mở do LoRa-Alliance duy trì. Các phiên bản 1.0.x và 1.1 thường được triển khai thực tế.
* Kiến trúc điển hình: *thiết bị đầu cuối → gateway (packet-forwarder) → network-server → application-server*.<sup>[[3]](#references)</sup>

> Trong LoRaWAN 1.1, **mô hình bảo mật** sử dụng các khóa gốc AES-128 riêng biệt cho ứng dụng và mạng để tạo các khóa phiên theo vai trò trong quá trình OTAA. Các triển khai 1.0.x cũ hơn thường dùng một AppKey để tạo khóa phiên mạng và ứng dụng, trong khi ABP cấp phát trực tiếp các khóa phiên. Khả năng có được từ một khóa bị leak phụ thuộc vào phiên bản LoRaWAN và khóa nào bị lộ.<sup>[[3]](#references)</sup>

---

## Tóm tắt bề mặt tấn công

| Layer | Điểm yếu | Tác động thực tế |
|-------|----------|------------------|
| PHY | Gây nhiễu phản ứng / có chọn lọc | Mất gói cục bộ; hiệu quả phụ thuộc vào link budget, thời điểm, băng thông và các ràng buộc pháp lý |
| MAC | Phát lại join và data-frame khi trạng thái nonce/counter bị sử dụng lại | Làm mất đồng bộ thiết bị, giả mạo hoặc chèn dữ liệu nếu server/thiết bị vi phạm cơ chế chống phát lại |
| Network-Server | Packet-forwarder không an toàn, bộ lọc MQTT/UDP yếu, firmware gateway lỗi thời | RCE trên gateway → pivot vào mạng OT/IT |
| Application | AppKey được hard-code hoặc dễ đoán | Brute-force/giải mã lưu lượng, giả mạo cảm biến |

---

## Các lỗ hổng trong những triển khai tiêu biểu

* **CVE-2024-29862** – Các phiên bản ChirpStack Gateway Bridge trước 4.0.11 và MQTT Forwarder trước 4.2.1 có thể kết nối tới MQTT broker do kẻ tấn công kiểm soát vì việc xác thực chứng chỉ máy chủ TLS đã bị vô hiệu hóa. Điều này có thể làm lộ thông tin xác thực và lưu lượng gateway; hãy nâng cấp lên các bản đã khắc phục.<sup>[[4]](#references)</sup>
* **Dragino LG01 firmware 4.3.4** – CVE-2022-45227 mô tả việc liệt kê thư mục `/lib/` không cần xác thực, trong đó có tệp sao lưu có thể tải xuống; CVE-2022-45228 là CSRF mức độ nghiêm trọng thấp trong trang đăng xuất. Các hồ sơ này không xác nhận tác động được cho là có trên LG308, việc ghi đè cấu hình, quy mô triển khai hoặc tình trạng bản vá năm 2025.<sup>[[6]](#references)[[7]](#references)</sup>
* Phiên bản trước của trang này mô tả một vấn đề được cho là có trong Semtech UDP packet-forwarder: **uplink được tạo thủ công dài hơn 255 byte gây tràn stack và RCE trên các gateway tham chiếu SX130x**, được cho là trình bày tại “LoRa Exploitation Reloaded” ở Black Hat Europe 2023 và có bản vá riêng vào tháng 10 năm 2023. Các chi tiết cụ thể đó được giữ lại ở đây như một hướng nghiên cứu, nhưng không thể xác minh bằng advisory, bài trình bày hoặc bản vá công khai tương ứng. Không xem đây là lỗ hổng đã được xác nhận nếu chưa có sản phẩm/phiên bản bị ảnh hưởng và nguồn sơ cấp có thể kiểm chứng.

---

## Các kỹ thuật tấn công thực tế

### 1. Sniff & Decrypt lưu lượng

```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
    --freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```

Các lệnh này giữ nguyên quy trình ban đầu dưới dạng **cú pháp minh họa**; bố cục repository và các flag khác nhau tùy dự án/phiên bản. Thu thập thụ động không làm lộ AppKey mạnh. Đoán offline chỉ hữu ích khi khóa gốc đủ yếu để tìm ra và một trao đổi join đã thu được cung cấp giá trị có thể dùng để xác thực các ứng viên.<sup>[[2]](#references)[[3]](#references)</sup>

### 2. Kiểm tra cơ chế chống replay OTAA và trạng thái nonce

1. Trong mạng thử nghiệm được cấp phép, thu thập một **JoinRequest** hợp lệ.
2. Phát lại cùng yêu cầu đó và xác nhận network server từ chối `DevNonce` đã được sử dụng.
3. Khởi động lại hoặc reset thiết bị thử nghiệm rồi lặp lại kiểm tra để phát hiện trạng thái nonce bị mất. Server tuân thủ tiêu chuẩn phải theo dõi các nonce đã dùng; chỉ phát lại JoinRequest không làm lộ các session key mới được dẫn xuất hoặc giúp bên phát lại kiểm soát một phiên.<sup>[[3]](#references)</sup><sup>[[5]](#references)</sup>

### 3. Hạ cấp Adaptive Data-Rate (ADR)

Kẻ tấn công có thể xác thực các lệnh MAC ở lớp mạng—ví dụ, sau khi xâm nhập network session key tương ứng hoặc network server—có thể tìm cách ép dùng các tham số data-rate kém hiệu quả và tăng airtime. Một thiết bị phát không xác thực ở gần không thể gửi lệnh ADR hợp lệ chỉ bằng cách biết địa chỉ thiết bị.<sup>[[3]](#references)</sup>

### 4. Jamming phản ứng

Thiết bị gây jamming phản ứng có thể phát tín hiệu sau khi phát hiện preamble LoRa và làm gián đoạn có chọn lọc các frame. Trang trước đó tuyên bố cấu hình HackRF/GNU Radio gây mất kết nối hoàn toàn ở **2 km với công suất không quá 200 mW**, nhưng không đưa ra nguồn đo đạc hỗ trợ; chỉ nên xem các con số đó là mục tiêu để tái hiện, không phải kết quả kỳ vọng. Công suất phát, thời điểm, băng thông, spreading factor bị ảnh hưởng và phạm vi phụ thuộc vào môi trường. Chỉ thử nghiệm trong môi trường được cấp phép, có kiểm soát RF và tuân thủ quy định phổ tần tại địa phương.

---

## Công cụ offensive (2025)

| Công cụ | Mục đích | Ghi chú |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | Tạo/phân tích/tấn công frame LoRaWAN, trình phân tích dùng DB, công cụ brute-force | Docker image; hỗ trợ đầu vào Semtech UDP<sup>[[1]](#references)</sup> |
| **LoRaPWN** | Tiện ích Python của Trend Micro để brute-force OTAA, tạo downlink, giải mã payload | Tiện ích nghiên cứu công khai; xác minh phần cứng và phiên bản giao thức được hỗ trợ<sup>[[2]](#references)</sup> |
| **LoRAttack** | Framework nghiên cứu để thu thập LoRaWAN đa kênh, phân tích phiên, dẫn xuất key và kiểm tra replay | Được mô tả trong luận văn thạc sĩ năm 2024; hãy tải và xác minh bản triển khai chính xác trước khi dựa vào các flag ví dụ<sup>[[8]](#references)</sup> |
| **gr-lora / gr-lora_sdr** | Các khối out-of-tree của GNU Radio để thu LoRa baseband hoặc nghiên cứu transceiver | Các dự án khác nhau về khả năng tương thích với GNU Radio và bộ tính năng<sup>[[9]](#references)</sup> |

---

## Khuyến nghị phòng thủ (checklist cho pentester)

1. Ưu tiên **OTAA** và xác minh thiết bị, server lưu bền vững trạng thái nonce cần thiết; theo dõi các lần join trùng lặp bị từ chối.
2. Ưu tiên **LoRaWAN 1.1** nếu được hỗ trợ để các chức năng mạng dùng session key riêng biệt và xử lý nonce được cập nhật.<sup>[[3]](#references)</sup>
3. Lưu bộ đếm frame trong bộ nhớ không mất dữ liệu (**ABP**) hoặc chuyển sang OTAA.
4. Triển khai **secure element** phù hợp (ví dụ: ATECC608A trong thiết kế được hỗ trợ) để giảm nguy cơ lộ khóa gốc trong vùng lưu trữ firmware thông thường.
5. Không để lộ các UDP listener của packet-forwarder đã cấu hình (thường là cổng 1700) ra mạng không tin cậy; xác thực/mã hóa kết nối backhaul của gateway hoặc giới hạn bằng VPN.
6. Duy trì firmware gateway được nhà cung cấp hỗ trợ và đối chiếu chính xác model/phiên bản với các khuyến cáo bảo mật liên quan.
7. Triển khai **phát hiện bất thường lưu lượng** (ví dụ: trình phân tích LAF) – cảnh báo khi bộ đếm reset, join trùng lặp, ADR thay đổi đột ngột.<sup>[[1]](#references)</sup>



## References

- [1] [LoRaWAN Auditing Framework (LAF)](https://github.com/IOActive/laf)
- [2] [Tổng quan về Trend Micro LoRaPWN](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)
- [3] [LoRa Alliance - Đặc tả LoRaWAN L2 1.1](https://resources.lora-alliance.org/technical-specifications/lorawan-specification-v1-1)
- [4] [NVD - CVE-2024-29862](https://nvd.nist.gov/vuln/detail/CVE-2024-29862)
- [5] [LoRa Alliance - Tham số khu vực LoRaWAN 1.1 và đồng bộ hóa join](https://resources.lora-alliance.org/technical-specifications/lorawan-backend-interfaces-v1-1)
- [6] [NVD - CVE-2022-45227](https://nvd.nist.gov/vuln/detail/CVE-2022-45227)
- [7] [NVD - CVE-2022-45228](https://nvd.nist.gov/vuln/detail/CVE-2022-45228)
- [8] [Danh mục luận văn CTU - Phân tích bảo mật giao thức LPWAN bằng công nghệ SDR](https://fit.cvut.cz/en/faculty/people/5076-ing-jiri-dostal-ph-d/theses)
- [9] [Transceiver GNU Radio `gr-lora_sdr` của EPFL](https://github.com/tapparelj/gr-lora_sdr)
{{#include ../../banners/hacktricks-training.md}}
