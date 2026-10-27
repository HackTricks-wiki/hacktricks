# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**Tìm hiểu về macOS MDM tại:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)<sup>[[1]](#references)</sup>
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)<sup>[[2]](#references)</sup>

## Basics

### **Tổng quan về MDM (Mobile Device Management)**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) được sử dụng để quản lý nhiều thiết bị đầu cuối của người dùng như điện thoại thông minh, laptop và máy tính bảng. Đặc biệt đối với các nền tảng của Apple (iOS, macOS, tvOS), MDM bao gồm một tập hợp các tính năng, API và phương thức chuyên biệt. MDM hoạt động dựa trên một MDM server tương thích, có thể là sản phẩm thương mại hoặc mã nguồn mở, và phải hỗ trợ [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Các điểm chính gồm:

- Kiểm soát thiết bị tập trung.
- Phụ thuộc vào MDM server tuân thủ MDM protocol.
- MDM server có khả năng gửi nhiều lệnh đến thiết bị, chẳng hạn như xóa dữ liệu từ xa hoặc cài đặt cấu hình.

### **Kiến thức cơ bản về DEP (Device Enrollment Program)**

[Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP) do Apple cung cấp giúp đơn giản hóa việc tích hợp Mobile Device Management (MDM) bằng cách hỗ trợ cấu hình zero-touch cho các thiết bị iOS, macOS và tvOS. DEP tự động hóa quy trình đăng ký, giúp thiết bị có thể hoạt động ngay khi mở hộp mà người dùng hoặc quản trị viên hầu như không cần can thiệp. Các điểm chính gồm:

- Cho phép thiết bị tự đăng ký với MDM server được xác định trước khi kích hoạt lần đầu.
- Chủ yếu hữu ích cho thiết bị mới, nhưng cũng áp dụng được cho thiết bị đang được cấu hình lại.
- Giúp đơn giản hóa quá trình thiết lập để thiết bị nhanh chóng sẵn sàng phục vụ tổ chức.

### **Lưu ý về bảo mật**

Điều quan trọng cần lưu ý là quy trình đăng ký dễ dàng do DEP cung cấp tuy hữu ích nhưng cũng có thể gây ra rủi ro bảo mật. Nếu không có biện pháp bảo vệ phù hợp cho quy trình đăng ký MDM, kẻ tấn công có thể lợi dụng quy trình đơn giản hóa này để đăng ký thiết bị của chúng vào MDM server của tổ chức, giả làm thiết bị thuộc công ty.<sup>[[2]](#references)</sup>

> [!CAUTION]
> **Cảnh báo bảo mật**: Quy trình đăng ký DEP đơn giản hóa có thể cho phép đăng ký thiết bị trái phép vào MDM server của tổ chức nếu không có biện pháp bảo vệ phù hợp.

### Kiến thức cơ bản: SCEP (Simple Certificate Enrolment Protocol) là gì?

- Một protocol tương đối cũ, ra đời trước khi TLS và HTTPS được sử dụng rộng rãi.
- Cung cấp cho client một cách thức chuẩn hóa để gửi **Certificate Signing Request** (CSR) nhằm được cấp certificate. Client sẽ yêu cầu server cấp cho mình một certificate đã ký.

### Configuration Profile (còn gọi là mobileconfig) là gì?

- Cách chính thức của Apple để **thiết lập/áp dụng cấu hình hệ thống**.
- Định dạng tệp có thể chứa nhiều payload.
- Dựa trên property list (loại XML).
- “có thể được ký và mã hóa để xác thực nguồn gốc, đảm bảo tính toàn vẹn và bảo vệ nội dung.” Basics — Trang 70, iOS Security Guide, tháng 1 năm 2018.

## Protocols

### MDM

- Kết hợp APNs (**server của Apple**) + RESTful API (**server của nhà cung cấp MDM**)
- **Giao tiếp** diễn ra giữa một **thiết bị** và server liên kết với một sản phẩm **quản lý** **thiết bị**
- MDM gửi **lệnh** đến thiết bị dưới dạng **từ điển được mã hóa bằng plist**
- Tất cả đều qua **HTTPS**. MDM server có thể được pin và thường là như vậy.
- Apple cấp cho nhà cung cấp MDM một **APNs certificate** để xác thực

### DEP

- **3 API**: 1 cho reseller, 1 cho nhà cung cấp MDM, 1 cho danh tính thiết bị (không được tài liệu hóa):
  - API [DEP "cloud service"](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf) được sử dụng bởi MDM server để liên kết DEP profile với các thiết bị cụ thể.
  - [DEP API được Apple Authorized Reseller sử dụng](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) để đăng ký thiết bị, kiểm tra trạng thái đăng ký và trạng thái giao dịch.
  - DEP API riêng tư, không được tài liệu hóa. Apple Devices sử dụng API này để yêu cầu DEP profile. Trên macOS, binary `cloudconfigurationd` chịu trách nhiệm giao tiếp qua API này.
- Hiện đại hơn và dựa trên **JSON** (so với plist)
- Apple cấp **OAuth token** cho nhà cung cấp MDM

**DEP "cloud service" API**

- RESTful
- đồng bộ bản ghi thiết bị từ Apple sang MDM server
- đồng bộ “DEP profile” từ MDM server lên Apple (sau đó Apple gửi đến thiết bị)
- DEP “profile” chứa:
  - URL của MDM server của nhà cung cấp
  - Certificate đáng tin cậy bổ sung cho URL server (tùy chọn pinning)
  - Cài đặt bổ sung (ví dụ: các màn hình cần bỏ qua trong Setup Assistant)

## Serial Number

Các thiết bị Apple được sản xuất sau năm 2010 thường có serial number gồm **12 ký tự chữ và số**. **Ba chữ số đầu tiên biểu thị địa điểm sản xuất**, **hai chữ số tiếp theo** cho biết **năm** và **tuần** sản xuất, **ba chữ số kế tiếp** là **mã định danh duy nhất**, còn **bốn chữ số cuối** biểu thị **model number**.


{{#ref}}
macos-serial-number.md
{{#endref}}

## Các bước đăng ký và quản lý

1. Tạo bản ghi thiết bị (Reseller, Apple): Tạo bản ghi cho thiết bị mới
2. Gán bản ghi thiết bị (Khách hàng): Gán thiết bị cho một MDM server
3. Đồng bộ bản ghi thiết bị (Nhà cung cấp MDM): MDM đồng bộ bản ghi thiết bị và đẩy DEP profile lên Apple
4. DEP check-in (Thiết bị): Thiết bị nhận DEP profile
5. Truy xuất profile (Thiết bị)
6. Cài đặt profile (Thiết bị) a. bao gồm các payload MDM, SCEP và root CA
7. Phát hành lệnh MDM (Thiết bị)

![Serial Number - Các bước đăng ký và quản lý: 7. Phát hành lệnh MDM (Thiết bị)](<../../../images/image (694).png>)

Tệp `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` export các function có thể được xem là những **“bước” cấp cao** của quy trình đăng ký.

### Bước 4: DEP check-in - Lấy Activation Record

Phần này của quy trình diễn ra khi **người dùng khởi động Mac lần đầu tiên** (hoặc sau khi xóa sạch thiết bị)

![Các bước đăng ký và quản lý - Bước 4: DEP check-in - Lấy Activation Record: Phần này của quy trình diễn ra khi người dùng khởi động Mac lần đầu tiên (hoặc sau khi xóa sạch thiết bị...](<../../../images/image (1044).png>)

hoặc khi chạy `sudo profiles show -type enrollment`

- Xác định **thiết bị có bật DEP hay không**
- Activation Record là tên nội bộ của **DEP “profile”**
- Bắt đầu ngay khi thiết bị kết nối Internet
- Được điều khiển bởi **`CPFetchActivationRecord`**
- Được triển khai bởi **`cloudconfigurationd`** qua XPC. **"Setup Assistant**" (khi thiết bị được khởi động lần đầu) hoặc lệnh **`profiles`** sẽ **liên hệ daemon này** để lấy activation record.
  - LaunchDaemon (luôn chạy với quyền root)

Quy trình lấy Activation Record gồm một số bước do **`MCTeslaConfigurationFetcher`** thực hiện. Quy trình này sử dụng phương thức mã hóa có tên **Absinthe**<sup>[[1]](#references)</sup>

1. Truy xuất **certificate**
   1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Khởi tạo** trạng thái từ certificate (**`NACInit`**)
   1. Sử dụng nhiều dữ liệu riêng cho thiết bị (ví dụ: **Serial Number qua `IOKit`**)
3. Truy xuất **session key**
   1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Thiết lập session (**`NACKeyEstablishment`**)
5. Gửi request
   1. POST đến [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile), gửi dữ liệu `{ "action": "RequestProfileConfiguration", "sn": "" }`
   2. JSON payload được mã hóa bằng Absinthe (**`NACSign`**)
   3. Tất cả request đều qua HTTPS, sử dụng root certificate tích hợp sẵn

![Các bước đăng ký và quản lý - Bước 4: DEP check-in - Lấy Activation Record: 3. Tất cả request đều qua HTTPS, sử dụng root certificate tích hợp sẵn](<../../../images/image (566) (1).png>)

Phản hồi là một JSON dictionary chứa một số dữ liệu quan trọng, chẳng hạn:

- **url**: URL của host thuộc nhà cung cấp MDM chứa activation profile
- **anchor-certs**: Mảng DER certificate được dùng làm anchor đáng tin cậy

### **Bước 5: Truy xuất Profile**

![Bước 4: DEP check-in - Lấy Activation Record - Bước 5: Truy xuất Profile: Bước 5: Truy xuất Profile](<../../../images/image (444).png>)

- Request được gửi đến **url được cung cấp trong DEP profile**.
- **Anchor certificate** được dùng để **đánh giá độ tin cậy** nếu được cung cấp.
  - Nhắc lại: thuộc tính **anchor_certs** của DEP profile
- **Request là một .plist đơn giản** chứa thông tin nhận dạng thiết bị
  - Ví dụ: **UDID, phiên bản OS**.
- Được ký bằng CMS, mã hóa DER
- Được ký bằng **device identity certificate (từ APNS)**
- **Certificate chain** bao gồm **Apple iPhone Device CA** đã hết hạn

![Bước 4: DEP check-in - Lấy Activation Record - Bước 5: Truy xuất Profile: Được ký bằng device identity certificate (từ APNS)](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Bước 6: Cài đặt Profile

- Sau khi truy xuất, **profile được lưu trên hệ thống**
- Bước này tự động bắt đầu (nếu đang ở trong **setup assistant**)
- Được điều khiển bởi **`CPInstallActivationProfile`**
- Được triển khai bởi mdmclient qua XPC
  - LaunchDaemon (chạy với quyền root) hoặc LaunchAgent (chạy với quyền người dùng), tùy ngữ cảnh
- Configuration profile có nhiều payload cần cài đặt
- Framework có kiến trúc dựa trên plugin để cài đặt profile
- Mỗi loại payload được liên kết với một plugin
  - Có thể là XPC (trong framework) hoặc Cocoa truyền thống (trong ManagedClient.app)
- Ví dụ:
  - Certificate Payload sử dụng CertificateService.xpc

Thông thường, **activation profile** do nhà cung cấp MDM cung cấp sẽ **bao gồm các payload sau**:

- `com.apple.mdm`: để **đăng ký** thiết bị vào MDM
- `com.apple.security.scep`: để cung cấp an toàn **client certificate** cho thiết bị.
- `com.apple.security.pem`: để **cài đặt certificate CA đáng tin cậy** vào System Keychain của thiết bị.
- Cài đặt MDM payload tương đương với **MDM check-in trong tài liệu**
- Payload **chứa các thuộc tính chính**:
- - MDM Check-In URL (**`CheckInURL`**)
  - MDM Command Polling URL (**`ServerURL`**) + APNs topic để kích hoạt
- Để cài đặt MDM payload, request được gửi đến **`CheckInURL`**
- Được triển khai trong **`mdmclient`**
- MDM payload có thể phụ thuộc vào các payload khác
- Cho phép **pin request vào các certificate cụ thể**:
  - Thuộc tính: **`CheckInURLPinningCertificateUUIDs`**
  - Thuộc tính: **`ServerURLPinningCertificateUUIDs`**
  - Được gửi qua PEM payload
- Cho phép gán cho thiết bị một identity certificate:
  - Thuộc tính: IdentityCertificateUUID
  - Được gửi qua SCEP payload

### **Bước 7: Chờ lệnh MDM**

- Sau khi hoàn tất MDM check-in, nhà cung cấp có thể **gửi push notification bằng APNs**
- Khi nhận được, notification được xử lý bởi **`mdmclient`**
- Để truy vấn lệnh MDM, request được gửi đến ServerURL
- Sử dụng MDM payload đã cài đặt trước đó:
  - **`ServerURLPinningCertificateUUIDs`** để pin request
  - **`IdentityCertificateUUID`** để làm TLS client certificate

## Attacks

### Đăng ký thiết bị vào tổ chức khác

Serial number được gán có thể giúp xác định luồng đăng ký của tổ chức, nhưng **không** đảm bảo thiết bị sẽ được đăng ký MDM. Server có thể yêu cầu người dùng xác thực qua `configuration_web_url` trước khi trả về enrollment profile. Hãy kiểm tra xem có luồng đăng ký thay thế nào bỏ qua bước xác thực này hay không, thay vì mặc định rằng mọi serial được gán đều có thể tham gia đội thiết bị.<sup>[[3]](#references)</sup>

Để thực hiện quy trình đăng ký trái phép, hãy dùng trang được liên kết bên dưới. Để tìm hiểu về kiểm soát MDM và phân phối package sau khi xâm nhập, xem [macOS Red Teaming](../).


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}



## References

- [1] [Tìm hiểu sâu về macOS MDM (và cách hệ thống này có thể bị xâm phạm)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — "MDM Me Maybe?" (nghiên cứu bảo mật về đăng ký DEP/MDM)](https://duo.com/labs/research/mdm-me-maybe)
- [3] [Apple — Xác thực qua web view](https://developer.apple.com/documentation/devicemanagement/authenticating-through-web-views)
{{#include ../../../banners/hacktricks-training.md}}
