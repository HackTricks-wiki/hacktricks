# macOS System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## System Extensions / Endpoint Security Framework

Không giống Kernel Extensions, **System Extensions chạy trong user space** thay vì kernel space, giúp giảm nguy cơ hệ thống bị crash do extension gặp lỗi.

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Có ba loại system extension: **DriverKit** Extensions, **Network** Extensions và **Endpoint Security** Extensions.

### **DriverKit Extensions**

DriverKit là giải pháp thay thế cho kernel extensions, **cung cấp hỗ trợ phần cứng**. DriverKit cho phép các device driver (chẳng hạn driver USB, Serial, NIC và HID) chạy trong user space thay vì kernel space. Framework DriverKit bao gồm **các phiên bản user space của một số lớp I/O Kit**, còn kernel chuyển tiếp các sự kiện I/O Kit thông thường đến user space, tạo ra môi trường an toàn hơn để chạy các driver này.<sup>[[2]](#references)</sup>

### **Network Extensions**

Network Extensions cho phép tùy chỉnh các hành vi mạng. Có một số loại Network Extensions:

- **App Proxy**: Dùng để tạo VPN client triển khai VPN protocol tùy chỉnh, hướng theo luồng. Nghĩa là, client xử lý lưu lượng mạng dựa trên các kết nối (hoặc luồng) thay vì từng packet riêng lẻ.
- **Packet Tunnel**: Dùng để tạo VPN client triển khai VPN protocol tùy chỉnh, hướng theo packet. Nghĩa là, client xử lý lưu lượng mạng dựa trên từng packet riêng lẻ.
- **Filter Data**: Dùng để lọc các "luồng" mạng. Có thể giám sát hoặc chỉnh sửa dữ liệu mạng ở cấp luồng.
- **Filter Packet**: Dùng để lọc từng packet mạng. Có thể giám sát hoặc chỉnh sửa dữ liệu mạng ở cấp packet.
- **DNS Proxy**: Dùng để tạo DNS provider tùy chỉnh. Có thể dùng để giám sát hoặc chỉnh sửa các yêu cầu và phản hồi DNS.<sup>[[2]](#references)</sup>

## Endpoint Security Framework

Endpoint Security là framework do Apple cung cấp trong macOS, bao gồm một tập hợp API phục vụ bảo mật hệ thống. Framework này dành cho **các nhà cung cấp giải pháp bảo mật và developer xây dựng sản phẩm có thể giám sát và kiểm soát hoạt động của hệ thống** để xác định và bảo vệ khỏi hoạt động độc hại.

Framework này cung cấp **tập hợp API để giám sát và kiểm soát hoạt động của hệ thống**, chẳng hạn như việc thực thi process, sự kiện hệ thống tệp, sự kiện mạng và kernel.

Phần cốt lõi của framework được triển khai trong kernel, dưới dạng Kernel Extension (KEXT) tại **`/System/Library/Extensions/EndpointSecurity.kext`**.<sup>[[2]](#references)</sup> KEXT này gồm một số thành phần chính:

- **EndpointSecurityDriver**: Hoạt động như "điểm truy cập" cho kernel extension. Đây là điểm tương tác chính giữa OS và Endpoint Security framework.
- **EndpointSecurityEventManager**: Thành phần này chịu trách nhiệm triển khai kernel hook. Kernel hook cho phép framework giám sát các sự kiện hệ thống bằng cách chặn các system call.
- **EndpointSecurityClientManager**: Thành phần này quản lý việc giao tiếp với các client trong user space, theo dõi những client đang kết nối và cần nhận thông báo sự kiện.
- **EndpointSecurityMessageManager**: Thành phần này gửi thông điệp và thông báo sự kiện đến các client trong user space.

Các sự kiện mà Endpoint Security framework có thể giám sát được phân loại như sau:

- Sự kiện tệp
- Sự kiện process
- Sự kiện socket
- Sự kiện kernel (chẳng hạn như tải/gỡ tải kernel extension hoặc mở thiết bị I/O Kit)

### Kiến trúc Endpoint Security Framework

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

**Giao tiếp trong user space** với Endpoint Security framework diễn ra thông qua lớp IOUserClient. Tùy thuộc vào loại caller, framework sử dụng một trong hai subclass:

- **EndpointSecurityDriverClient**: Cần entitlement `com.apple.private.endpoint-security.manager`, chỉ được cấp cho system process `endpointsecurityd`.
- **EndpointSecurityExternalClient**: Cần entitlement `com.apple.developer.endpoint-security.client`. Thường được phần mềm bảo mật của bên thứ ba sử dụng khi cần tương tác với Endpoint Security framework.<sup>[[1]](#references)</sup>

Endpoint Security Extensions:**`libEndpointSecurity.dylib`** là thư viện C mà system extensions dùng để giao tiếp với kernel. Thư viện này sử dụng I/O Kit (`IOKit`) để giao tiếp với Endpoint Security KEXT.<sup>[[2]](#references)</sup>

**`endpointsecurityd`** là system daemon quan trọng, chịu trách nhiệm quản lý và khởi chạy các endpoint security system extension, đặc biệt trong quá trình khởi động sớm. **Chỉ system extension** được đánh dấu **`NSEndpointSecurityEarlyBoot`** trong tệp `Info.plist` mới được xử lý trong giai đoạn khởi động sớm này.<sup>[[2]](#references)</sup>

Một system daemon khác là **`sysextd`**, có nhiệm vụ **xác thực system extension** và chuyển chúng đến đúng vị trí trong hệ thống. Sau đó, daemon này yêu cầu daemon phù hợp tải extension. **`SystemExtensions.framework`** chịu trách nhiệm kích hoạt và vô hiệu hóa system extension.<sup>[[2]](#references)</sup>

## Bypassing ESF

Các công cụ bảo mật sử dụng ESF để phát hiện red teamer, vì vậy mọi thông tin về cách né tránh cơ chế này đều đáng quan tâm.

### CVE-2021-30965

Vấn đề là ứng dụng bảo mật cần có **quyền Full Disk Access**. Vì vậy, nếu attacker có thể gỡ bỏ quyền đó, họ có thể ngăn phần mềm chạy:<sup>[[3]](#references)</sup>

```bash
tccutil reset All
```

Để biết **thêm thông tin** về bypass này và các bypass liên quan, hãy xem bài nói chuyện [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)<sup>[[3]](#references)</sup>

Cuối cùng, vấn đề này được khắc phục bằng cách cấp quyền mới **`kTCCServiceEndpointSecurityClient`** cho ứng dụng bảo mật do **`tccd`** quản lý, để `tccutil` không xóa các quyền của ứng dụng, khiến ứng dụng không thể chạy.<sup>[[3]](#references)</sup>

## References

- [1] [OBTS v3.0: "Bảo mật điểm cuối & Sự thiếu an toàn" - Scott Knight](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [2] [Knight.sc - Các thành phần bên trong của System Extension](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)
- [3] [#OBTS v5.0: "Gót chân Achilles của EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)
{{#include ../../../banners/hacktricks-training.md}}
