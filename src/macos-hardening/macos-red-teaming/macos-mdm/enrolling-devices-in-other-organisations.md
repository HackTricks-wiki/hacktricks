# Đăng ký thiết bị vào tổ chức khác

{{#include ../../../banners/hacktricks-training.md}}

## Giới thiệu

Apple Automated Device Enrollment (trước đây là DEP) bắt đầu bằng việc xác định thiết bị được gán cho một tổ chức. Nghiên cứu năm 2018 được tóm tắt ở đây cho thấy chỉ cần biết số serial được gán là đã đủ để lấy một số hồ sơ đăng ký của tổ chức, vì các tổ chức đó không yêu cầu xác thực bổ sung phù hợp. Đây là phát hiện mang tính lịch sử, không phải khẳng định rằng hiện nay có thể tham gia mọi MDM chỉ bằng số serial. Hồ sơ có thể chứa chứng chỉ, ứng dụng, mật khẩu Wi-Fi, cài đặt VPN và các cấu hình nhạy cảm khác.<sup>[[1]](#references)[[2]](#references)</sup>

**Sau đây là bản tóm tắt nghiên cứu [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Hãy xem nghiên cứu để biết thêm chi tiết kỹ thuật!**<sup>[[1]](#references)</sup>

## Tổng quan về DEP và phân tích binary MDM

Nghiên cứu phân tích các binary liên quan đến DEP và MDM trên các phiên bản macOS hiện hành vào thời điểm đó. Tên và nhiệm vụ của các thành phần có thể thay đổi giữa các bản phát hành:

- **`mdmclient`**: Giao tiếp với máy chủ MDM và kích hoạt quá trình check-in DEP trên các phiên bản macOS trước 10.13.4.
- **`profiles`**: Quản lý Configuration Profiles và kích hoạt quá trình check-in DEP trên macOS phiên bản 10.13.4 trở lên.
- **`cloudconfigurationd`**: Quản lý giao tiếp với DEP API và truy xuất Device Enrollment profiles.

Quá trình check-in DEP sử dụng các hàm `CPFetchActivationRecord` và `CPGetActivationRecord` từ private Configuration Profiles framework để lấy Activation Record; `CPFetchActivationRecord` phối hợp với `cloudconfigurationd` thông qua XPC.<sup>[[1]](#references)</sup>

## Reverse engineering giao thức Tesla và lược đồ Absinthe

Trong quá trình check-in DEP, `cloudconfigurationd` gửi một payload JSON được mã hóa và ký đến _iprofiles.apple.com/macProfile_. Payload chứa số serial của thiết bị và hành động "RequestProfileConfiguration". Lược đồ mã hóa này được gọi nội bộ là "Absinthe". Việc giải mã lược đồ này phức tạp và đòi hỏi nhiều bước, dẫn đến việc tìm kiếm các phương pháp thay thế để chèn số serial tùy ý vào yêu cầu Activation Record.<sup>[[1]](#references)</sup>

## Proxy yêu cầu DEP

Các nỗ lực chặn và sửa đổi yêu cầu DEP đến _iprofiles.apple.com_ bằng những công cụ như Charles Proxy gặp trở ngại do payload được mã hóa và các biện pháp bảo mật SSL/TLS. Tuy nhiên, bật cấu hình `MCCloudConfigAcceptAnyHTTPSCertificate` cho phép bỏ qua bước xác thực chứng chỉ máy chủ, dù bản chất được mã hóa của payload vẫn khiến không thể sửa đổi số serial nếu không có khóa giải mã.<sup>[[1]](#references)</sup>

## Instrument binary hệ thống tương tác với DEP

Để instrument các binary hệ thống như `cloudconfigurationd`, cần tắt System Integrity Protection (SIP) trên macOS. Khi SIP đã tắt, có thể dùng các công cụ như LLDB để attach vào tiến trình hệ thống và có khả năng sửa đổi số serial được sử dụng trong các tương tác với DEP API. Phương pháp này được ưu tiên vì tránh được sự phức tạp liên quan đến entitlements và code signing.<sup>[[1]](#references)</sup>

**Khai thác bằng cách instrument binary:**
Việc sửa đổi payload yêu cầu DEP trước khi JSON serialization trong `cloudconfigurationd` đã cho thấy hiệu quả. Quy trình gồm:

1. Attach LLDB vào `cloudconfigurationd`.
2. Tìm vị trí hệ thống lấy số serial.
3. Chèn một số serial tùy ý vào bộ nhớ trước khi payload được mã hóa và gửi đi.

Phương pháp này cho phép các nhà nghiên cứu truy xuất DEP profiles ứng với những số serial được cung cấp và đã được gán. Nó không khiến một số serial tùy ý chưa được gán trở nên hợp lệ.<sup>[[1]](#references)</sup>

### Tự động hóa việc instrument bằng Python

Quá trình khai thác được tự động hóa bằng Python cùng LLDB API, giúp có thể lập trình để chèn số serial tùy ý và truy xuất các DEP profiles tương ứng.<sup>[[1]](#references)</sup>

## Nhìn lại năm 2025: Đăng ký trái phép từ VM

Nghiên cứu tại Black Hat Asia 2025 cho thấy vấn đề ranh giới tin cậy ban đầu vẫn có thể ảnh hưởng đến **lớp MDM**: thay vì vá `cloudconfigurationd` bằng LLDB, các nhà nghiên cứu chạy macOS trong QEMU/KVM với OpenCore và cung cấp danh tính cần kiểm tra thông qua SMBIOS của VM. Sau đó, enrollment stack nguyên bản của macOS thực hiện quá trình trao đổi được mã hóa với Apple. Vì vậy, có thể kiểm tra các serial bị leak công khai và các ứng viên có vẻ hợp lệ mà không cần sở hữu chiếc Mac vật lý tương ứng; tuy nhiên, để tìm thấy thông tin phù hợp thì serial vẫn phải được gán cho một tổ chức, đồng thời quy trình đăng ký của tổ chức đó phải có xác thực chưa đủ chặt chẽ.<sup>[[3]](#references)</sup>

Đối với thiết bị lab được cấp quyền, các giá trị `PlatformInfo` liên quan trong OpenCore bao gồm model sản phẩm và serial (trong triển khai thực tế, ROM và UUID cũng cần nhất quán với nhau):<sup>[[3]](#references)</sup>

```xml
<key>SystemProductName</key>
<string>iMacPro1,1</string>
<key>SystemSerialNumber</key>
<string>AUTHORIZED_TEST_SERIAL</string>
```

Cùng nghiên cứu đó đã xác định trạng thái `CheckProfilesFetchRateLimit` trong tệp riêng tư `/var/db/ConfigurationProfiles/Settings/.profilesDEPTimerCheck`. Vì cơ chế kiểm tra được duy trì trên client, việc sửa các giá trị thời gian đã lưu sẽ vô hiệu hóa cơ chế này. Các đường dẫn này không được tài liệu hóa và phụ thuộc vào phiên bản, nhưng hữu ích làm điểm khởi đầu cho việc phân tích ngược khi đánh giá một bản dựng macOS hiện tại:<sup>[[3]](#references)</sup>

```bash
sudo plutil -p /var/db/ConfigurationProfiles/Settings/.profilesDEPTimerCheck 2>/dev/null
sudo plutil -p /var/db/ConfigurationProfiles/Settings/.cloudConfigRecordFound 2>/dev/null
```

Artifact thứ hai có thể tiết lộ bản ghi kích hoạt được lưu trong cache, bao gồm việc quy trình sử dụng `ConfigurationURL` trực tiếp hay `ConfigurationWebURL` có xác thực. Kiểm tra cả quy trình được quảng bá lẫn mọi endpoint đăng ký cũ dành riêng cho MDM: chỉ bật SSO trên luồng web chính sẽ không bảo vệ endpoint trực tiếp song song. Để xem trình tự giao thức đầy đủ, hãy tham khảo [tổng quan về macOS MDM](README.md).<sup>[[3]](#references)</sup>

### Săn tìm bí mật sau khi đăng ký

Đăng ký rogue chỉ là điểm khởi đầu. Sau khi đăng ký, hãy kiểm tra mọi profile được gửi xuống, chính sách bootstrap, cấu hình kho package, script cài đặt agent và mục tự phục vụ. Nghiên cứu năm 2025 đã tìm thấy các ví dụ về thông tin xác thực Wi-Fi, mật khẩu quản trị viên cục bộ dùng chung, URL lưu trữ đám mây có chữ ký, URL webhook, dữ liệu kích hoạt security agent và thông tin xác thực MDM/API. Thông tin xác thực API của tenant trong script được gửi xuống có thể biến một endpoint rogue thành quyền kiểm soát các thiết bị được quản lý khác, vì vậy hãy tìm kiếm cả trên hệ thống tệp đang hoạt động lẫn nội dung chính sách đã tải xuống/được lưu trong cache.<sup>[[3]](#references)</sup>

Các mục tiêu cần kiểm tra bao gồm:<sup>[[3]](#references)</sup>

- Payload `.mobileconfig` đã cài đặt và cơ sở dữ liệu Configuration Profiles.
- Script và package PreStage/bootstrap tạo tài khoản hoặc cài đặt agent EDR/VPN.
- URL kho package Munki hoặc các kho package khác, đặc biệt là chuỗi truy vấn chứa chữ ký dạng bearer/SAS.
- Danh mục tự phục vụ và các policy API phía sau, bao gồm cả các route cũ có thể không áp dụng chính sách SSO đăng ký.
- Lịch sử shell và đầu ra chính sách được lưu trong cache có chứa `password`, `token`, `secret`, `Authorization`, hostname webhook và endpoint API của nhà cung cấp.

### Củng cố ranh giới tin cậy

Coi số serial là thuộc tính kiểm kê/định tuyến, **không phải** bằng chứng về quyền sở hữu thiết bị. Yêu cầu người dùng xác thực khi đăng ký và sử dụng dịch vụ tự phục vụ, tạo mật khẩu quản trị viên cục bộ riêng cho từng thiết bị, và tuyệt đối không nhúng thông tin xác thực API của tenant hoặc bí mật hạ tầng có thể tái sử dụng vào profile hay script. Nếu bắt buộc phải dùng bootstrap token, hãy đặt thời hạn ngắn và giới hạn token chỉ cho hành động và thiết bị duy nhất đang được cấp phát.<sup>[[3]](#references)</sup>

Trên các máy Mac Apple silicon chạy macOS 14 trở lên, Managed Device Attestation có thể liên kết danh tính với Secure Enclave bằng mật mã. Attestation có gốc tin cậy từ Apple này có thể mang theo nonce mới cùng số serial, UDID, phiên bản OS, trạng thái SIP và trạng thái secure boot; sau đó ACME có thể cấp danh tính client gắn với phần cứng. Dùng danh tính đó để bảo vệ kênh MDM và kiểm soát quyền truy cập vào các chứng chỉ có giá trị cao, VPN cùng các tài nguyên khác, đồng thời vẫn duy trì xác thực người dùng riêng vì device attestation chứng minh danh tính thiết bị chứ không phải người vận hành.<sup>[[4]](#references)</sup>

## Tác động tiềm ẩn của các lỗ hổng DEP và MDM

Nghiên cứu nhấn mạnh các mối lo ngại đáng kể về bảo mật:

1. **Rò rỉ thông tin**: Bằng cách cung cấp số serial đã đăng ký DEP, có thể truy xuất thông tin nhạy cảm của tổ chức chứa trong profile DEP.<sup>[[1]](#references)</sup>



## References

- [1] [Duo Labs — MDM Me Maybe: Bảo mật chương trình đăng ký thiết bị](https://duo.com/labs/research/mdm-me-maybe)
- [2] [Triển khai nền tảng Apple — Đăng ký thiết bị tự động](https://support.apple.com/guide/deployment/automated-device-enrollment-and-mdm-dep73069dd57/web)
- [3] [Black Hat Asia 2025 — Hội chứng kẻ mạo danh: Hack Apple MDM bằng cách đăng ký thiết bị rogue](https://i.blackhat.com/Asia-25/Asia-25-Molnar-Impostor-Syndrome-Hacking-Apple-MDMs.pdf)
- [4] [Bảo mật nền tảng Apple — Managed Device Attestation](https://support.apple.com/guide/security/managed-device-attestation-sec8a37b4cb2/web)
{{#include ../../../banners/hacktricks-training.md}}
