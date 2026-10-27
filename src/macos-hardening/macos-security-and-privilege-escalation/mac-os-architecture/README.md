# Kernel macOS và System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## Kernel XNU

**Lõi của macOS là XNU**, viết tắt của “X is Not Unix”. Đây là kernel lai kết hợp Mach, các thành phần BSD và framework driver C++ I/O Kit. Apple công bố mã nguồn XNU, bao gồm các subsystem `osfmk`, `bsd` và `iokit`. <sup>[[1]](#references)</sup><sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

Từ góc nhìn của nhà nghiên cứu bảo mật hoặc nhà phát triển Unix, **macOS** có thể trông khá **giống** một hệ thống **FreeBSD** với GUI tinh tế và nhiều ứng dụng tùy chỉnh. Hầu hết ứng dụng được phát triển cho BSD sẽ biên dịch và chạy trên macOS mà không cần chỉnh sửa, vì macOS có đầy đủ các công cụ dòng lệnh quen thuộc với người dùng Unix. Tuy nhiên, do kernel XNU tích hợp Mach, macOS có một số khác biệt đáng kể so với hệ thống kiểu Unix truyền thống. Những khác biệt này có thể gây ra vấn đề tiềm ẩn hoặc đem lại lợi thế riêng.

Các bản phát hành XNU mã nguồn mở có tại kho phân phối chính thức của Apple. <sup>[[1]](#references)</sup>

### Mach

Mach là một **microkernel** được thiết kế để **tương thích với UNIX**. Một trong những nguyên tắc thiết kế then chốt là **giảm thiểu** lượng **code** chạy trong không gian **kernel**, thay vào đó cho phép nhiều chức năng kernel điển hình như hệ thống tệp, mạng và I/O **chạy dưới dạng tác vụ ở cấp người dùng**.

Trong XNU, Mach **chịu trách nhiệm cho nhiều hoạt động cấp thấp quan trọng** mà kernel thường xử lý, chẳng hạn như lập lịch bộ xử lý, đa nhiệm và quản lý bộ nhớ ảo.

### BSD

**Kernel** XNU cũng **tích hợp** một lượng đáng kể code bắt nguồn từ dự án **FreeBSD**. Code này **chạy như một phần của kernel cùng với Mach**, trong cùng không gian địa chỉ. Tuy nhiên, code FreeBSD trong XNU có thể khác đáng kể so với code FreeBSD gốc vì cần chỉnh sửa để đảm bảo tương thích với Mach. FreeBSD đóng góp vào nhiều hoạt động kernel, bao gồm:

- Quản lý tiến trình
- Xử lý signal
- Các cơ chế bảo mật cơ bản, bao gồm quản lý user và group
- Cơ sở hạ tầng system call
- TCP/IP stack và socket
- Firewall và lọc gói tin

Việc hiểu tương tác giữa BSD và Mach có thể phức tạp do hai bên có khung khái niệm khác nhau. Chẳng hạn, BSD dùng tiến trình làm đơn vị thực thi cơ bản, còn Mach hoạt động dựa trên thread. Trong XNU, sự khác biệt này được dung hòa bằng cách **liên kết mỗi tiến trình BSD với một Mach task** chứa chính xác một Mach thread. Khi gọi system call fork() của BSD, code BSD bên trong kernel dùng các hàm Mach để tạo task và cấu trúc thread.

Ngoài ra, **Mach và BSD duy trì các mô hình bảo mật khác nhau**: mô hình bảo mật của Mach dựa trên quyền port, còn mô hình của BSD bao gồm thông tin xác thực và quyền sở hữu của tiến trình. Khác biệt tại ranh giới giữa hai mô hình này từng tạo ra các cơ hội leo thang đặc quyền cục bộ. Không gian người dùng tương tác với các lớp này thông qua Mach trap và system call BSD. Những thành phần này tạo nên kiến trúc lai của kernel macOS.<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

### I/O Kit - Driver

I/O Kit là framework driver thiết bị hướng đối tượng, mã nguồn mở của XNU. Trước đây, kernel extension dùng framework này để tải động code driver dạng mô-đun vào kernel; các phiên bản macOS hiện đại ngày càng chuyển những driver được hỗ trợ sang extension ở không gian người dùng DriverKit. I/O Kit cũng cung cấp các giao diện user-client để tiến trình người dùng giao tiếp với driver. Trang chuyên biệt trình bày registry, mô hình matching, user client và attack surface của framework:<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup>


{{#ref}}
macos-iokit.md
{{#endref}}

### Bộ đồng xử lý và phần cứng bảo mật chuyên dụng

Apple silicon và máy Mac có chip T2 bao gồm **Secure Enclave**, với Boot ROM và AES engine riêng, hỗ trợ tạo và lưu trữ khóa an toàn, xử lý sinh trắc học và hệ thống phân cấp khóa được các tính năng bảo vệ dữ liệu sử dụng. Nền tảng Apple cũng dùng các bộ đồng xử lý khác để chuyển những tác vụ nhạy cảm với độ trễ ra khỏi các lõi CPU chính và cô lập các chức năng quan trọng về bảo mật. Nhiệm vụ và giao diện của chúng thay đổi tùy model và phiên bản OS, vì vậy hãy xem chi tiết firmware cấp thấp và mailbox là đặc thù của từng bản triển khai, trừ khi đã xác nhận trên đúng mục tiêu. <sup>[[2]](#references)</sup>

Khi đánh giá bảo mật, điều quan trọng cần nhớ là attack surface của macOS không chỉ giới hạn ở các tiến trình người dùng thông thường và kernel XNU. Driver, parser firmware, giao diện bộ nhớ dùng chung và user client của I/O Kit hoặc DriverKit có thể trung gian cho việc truy cập phần cứng chuyên dụng. Hãy xác minh thành phần, thế hệ phần cứng và ranh giới tin cậy trước khi kết luận về tác động của một exploit.

Danh sách kiểm tra dưới đây giữ lại các manh mối cấp thấp hữu ích, đồng thời tránh giả định rằng mọi mục đều áp dụng giống nhau cho mọi máy Mac. Apple mô tả Secure Enclave và ranh giới bảo mật phần cứng; Asahi Linux và `m1n1` cung cấp tài liệu tham khảo về reverse engineering cho thiết bị Apple silicon và giao tiếp với bộ đồng xử lý. <sup>[[2]](#references)</sup><sup>[[7]](#references)</sup><sup>[[8]](#references)</sup>

| Thành phần | Kiến trúc và các hướng khảo sát attack surface cần xác thực trên mục tiêu | Tác động tiềm tàng khi bị xâm phạm |
| --- | --- | --- |
| **Secure Enclave Processor (SEP)** | Bộ xử lý ARM chuyên dụng với microkernel, Boot ROM và chuỗi secure boot riêng. SEP thường được mô tả là hoạt động qua ranh giới secure-world; việc sử dụng exception level cụ thể tùy SoC. Kiểm tra bản cập nhật firmware SEP, driver trong macOS giao tiếp qua mailbox và các broker ở không gian người dùng như `seputil` và `securityd`. | Lộ vật liệu khóa dài hạn, bypass chính sách sinh trắc học hoặc làm suy yếu cơ chế bảo vệ của FileVault và Apple Pay. |
| **System Management Controller (SMC)** | Firmware độc quyền trên bộ điều khiển nằm ngoài mô hình ARM exception level thông thường của application processor. macOS truy cập các dịch vụ của SMC qua driver nền tảng và I/O Kit. Kiểm tra đầu vào USB-C power delivery, quản lý quạt/pin, giao diện cảm biến và đường dẫn cập nhật firmware. | Vượt giới hạn nhiệt, thao túng nguồn điện, giả mạo dữ liệu cảm biến, từ chối dịch vụ hoặc duy trì hiện diện qua firmware/NVRAM. |
| **Chip bảo mật T1/T2** | Các SoC Apple riêng chạy bridgeOS, với môi trường thực thi ARM và đường dẫn secure boot riêng. Chúng giao tiếp với macOS qua các kênh thiết bị thường được mô tả là tương tự PCIe/USB và được trung gian bởi driver I/O Kit. Kiểm tra đường dẫn DFU/restore, IPC liền kề `tccd`, pipeline media được bridge và dịch vụ input. | Làm suy yếu secure boot, lộ khóa SSD, lạm dụng cơ chế khóa camera/micro hoặc giả lập đầu vào HID. |
| **Display Coprocessor (DCP)** | Theo tài liệu reverse engineering, firmware màn hình chạy trong môi trường cô lập, với buffer descriptor dùng chung, giao diện dịch vụ DCP và cơ chế bảo vệ DART IOMMU. Tìm các giao diện liên quan đến `DCPAVService` và parser ảnh firmware; không giả định exception level cụ thể nếu chưa xác nhận trên SoC. | Chèn khung hình tùy ý, làm lộ framebuffer hoặc gây từ chối dịch vụ pipeline màn hình. |
| **Apple Neural Engine (ANE)** | Cụm ML chuyên dụng, không phải lõi ARM đa dụng. macOS truy cập ANE qua Core ML, dịch vụ compiler như `ANECompilerService`, model `.ane` đã biên dịch, giao diện I/O Kit và trình tải firmware. | Làm lộ model hoặc dữ liệu âm thanh/hình ảnh đã xử lý, can thiệp suy luận hoặc leo thang qua lỗi parser/driver. |
| **AGX GPU** | Firmware chạy trên các lõi GPU tùy chỉnh với scheduler riêng. Ứng dụng EL0 gửi lệnh Metal và buffer dùng chung qua các giao diện được kernel xác thực, bao gồm thành phần driver/firmware AGX như `com.apple.AGXFirmware`. | Làm lộ bộ nhớ qua DMA, thoát sandbox qua driver GPU hoặc xâm phạm firmware để duy trì hiện diện. |
| **Apple Video Encoder / media engine** | Theo các mô tả reverse-engineering, firmware media chạy trong môi trường thực thi cô lập tương tự EL1. Bitstream codec, bộ tham số, buffer do người dùng kiểm soát, VideoToolbox và các họ driver như `AppleAVE2` là những bề mặt parser có giá trị cao. | Làm lộ khung hình chưa nén, bypass DRM hoặc thực thi code có quyền truy cập các DMA engine. |
| **Image Signal Processor (ISP)** | Firmware xử lý camera an toàn gắn với cụm media engine, trong khi driver camera macOS chạy trên application processor. Camera HAL, descriptor khung hình thô, hàng đợi cấu hình ISP, giao diện I/O Kit và bản cập nhật firmware tạo nên phạm vi đánh giá. | Âm thầm ghi hình thô từ camera, bypass đèn báo quyền riêng tư, tạo hình ảnh giả hoặc xâm phạm driver/firmware. |
| **AMX matrix unit** | Các matrix unit kiểu đồng xử lý được truy cập qua lệnh đặc thù kiến trúc, có thể được code ở user và kernel đã tạo sử dụng. Kiểm tra cơ chế ảo hóa trạng thái AMX của kernel, chuyển đổi ngữ cảnh, `thread_set_state` và việc tạo code ở không gian người dùng. | Rò rỉ thanh ghi tile giữa các tiến trình, nhận dạng workload hoặc leo thang do hỏng trạng thái kernel. |

Các bộ đồng xử lý này tham gia vào chuỗi tin cậy của nền tảng. Apple mô tả các quy trình secure boot riêng cho chip T2 và Secure Enclave, cơ chế cấp quyền cho bản cập nhật phần mềm do Apple ký và bảo vệ tính toàn vẹn firmware của bộ đồng xử lý. Các thành phần được reverse-engineer có thể còn dùng giao thức driver hoặc mailbox đã xác thực; hãy xác minh mọi khẳng định về handshake challenge-response trên đúng phần cứng và firmware, thay vì giả định có một cơ chế chung áp dụng ở mọi nơi. <sup>[[2]](#references)</sup><sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### IPC - Giao tiếp liên tiến trình

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/
{{#endref}}

## Kernel Extension trên macOS

macOS **hạn chế nghiêm ngặt việc tải Kernel Extension** (.kext) do mức đặc quyền cao mà code này được cấp khi chạy. Trên thực tế, theo mặc định, việc này gần như bất khả thi (trừ khi tìm được bypass).

Trang sau cũng hướng dẫn cách khôi phục `.kext` mà macOS tải bên trong **kernelcache**:

{{#ref}}
macos-kernel-extensions.md
{{#endref}}

### System Extensions trên macOS

macOS cung cấp system extension và DriverKit để nhiều thành phần bảo mật, mạng và driver có thể chạy trong không gian người dùng thay vì bên trong kernel. Apple khuyến nghị sử dụng các cơ chế này bất cứ khi nào chúng đáp ứng được chức năng cần thiết. <sup>[[3]](#references)</sup>

{{#ref}}
macos-system-extensions.md
{{#endref}}


### Cryptex và Rapid Security Response

**Cryptex** (extension được niêm phong bằng mật mã) là ảnh đĩa được niêm phong, cho phép Apple phân phối và mount riêng một số nội dung hệ điều hành đã chọn, tách khỏi system volume được niêm phong. Rapid Security Response đã sử dụng cơ chế này để phân phối các bản vá quan trọng giữa những lần cập nhật phần mềm đầy đủ trên các phiên bản OS được hỗ trợ. Cấu trúc cryptex, cách tích hợp vào quá trình khởi động và khả năng cung cấp response cụ thể tùy phiên bản; hãy xác thực trên mục tiêu thay vì dựa vào một cấu trúc cũ duy nhất. <sup>[[4]](#references)</sup><sup>[[9]](#references)</sup>

Các chi tiết triển khai quan trọng được ghi nhận trên hệ điều hành Apple hỗ trợ RSR bao gồm:

- Framework, shared library và ứng dụng đủ điều kiện nhận Rapid Security Response được chuyển vào các ảnh đĩa cryptex đã tối ưu hóa và niêm phong bằng mật mã trên volume Preboot.
- RSR có thể vá ảnh nền cryptex mà không cần niêm phong lại toàn bộ system volume.
- Nội dung cryptex được khởi tạo sau kernel; thông tin về filesystem seal, phép đo và trust cache được thể hiện trong một Image4 ticket riêng.
- Khi chạy, nội dung cryptex đã được xác thực được mount hoặc graft vào namespace của hệ điều hành để ứng dụng phân giải thành các phiên bản do cryptex cung cấp. Các mô tả kỹ thuật về quá trình khởi động cũng theo dõi việc xác thực manifest và root hash trước khi toàn bộ dịch vụ hệ thống khả dụng.
- Trong quá trình cài đặt RSR, thiết bị yêu cầu manifest Cryptex1 Image4 gắn với thiết bị từ dịch vụ ký của Apple; boot ticket hiện có của application processor không bị thay thế.
- Trên macOS, một số nội dung ứng dụng đã vá, chẳng hạn như thành phần Safari, có thể được kích hoạt sau khi khởi chạy lại ứng dụng thay vì sau khi khởi động lại toàn bộ máy.
- Apple có thể gỡ bỏ một response có vấn đề; trên các phiên bản được hỗ trợ, người dùng có thể gỡ và áp dụng lại RSR sau đó.
- Các mô tả kỹ thuật về những bản RSR đầu tiên gọi thành phần rollback là **antipatch**; thành phần này hoàn nguyên nội dung cryptex về trạng thái thể hiện trong OS nền.
- Bản tải xuống RSR thường nhỏ hơn bản cập nhật OS đầy đủ và trước đây có các điều kiện cài đặt ít hạn chế hơn, chẳng hạn ngưỡng pin thấp hơn; các chính sách này có thể thay đổi.


## References

- [1] [Apple Open Source - XNU](https://github.com/apple-oss-distributions/xnu)
- [2] [Bảo mật nền tảng Apple - Tổng quan về bảo mật phần cứng](https://support.apple.com/guide/security/hardware-security-overview-secf020d1074/web)
- [3] [Apple Developer - System Extensions](https://developer.apple.com/documentation/systemextensions)
- [4] [Apple Support - Rapid Security Responses](https://support.apple.com/en-us/102657)
- [5] [Cẩm nang hacker Mac](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/)
- [6] [Nghệ thuật phân tích malware trên Mac, Tập 1](https://taomm.org/)
- [7] [Asahi Linux - Tài liệu về nền tảng Apple silicon](https://asahilinux.org/docs/)
- [8] [Asahi Linux - Công cụ thử nghiệm Apple silicon `m1n1`](https://github.com/AsahiLinux/m1n1)
- [9] [Bảo mật nền tảng Apple - Rapid Security Response trong hệ điều hành Apple](https://support.apple.com/guide/security/sec87fc038c2/web)
- [10] [Bảo mật nền tảng Apple - Cập nhật phần mềm an toàn](https://support.apple.com/guide/security/secure-software-updates-secf683e0b36/web)
- [11] [Bảo mật nền tảng Apple - Tính toàn vẹn của hệ điều hành](https://support.apple.com/guide/security/sec8b776536b/web)
{{#include ../../../banners/hacktricks-training.md}}
