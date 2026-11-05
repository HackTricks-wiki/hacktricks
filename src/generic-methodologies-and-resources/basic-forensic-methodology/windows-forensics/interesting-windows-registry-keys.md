# Các khóa Registry Windows đáng chú ý

{{#include ../../../banners/hacktricks-training.md}}

Các hive Windows Registry là một trong những cách nhanh nhất để chuyển từ câu hỏi _chuyện gì đã xảy ra?_ sang _người dùng nào, khi nào và từ đâu?_. Khi phân tích trực tiếp, hãy ưu tiên `CurrentControlSet`; khi phân tích hive ngoại tuyến, trước tiên hãy xác định `ControlSet00x` nào đang hoạt động thay vì mặc định dùng `ControlSet001`.

### Thông tin phiên bản Windows và chủ sở hữu

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: phiên bản/build Windows, thời gian cài đặt, chủ sở hữu đã đăng ký, tên sản phẩm và các metadata build khác.
- `SYSTEM\Select`: ánh xạ `Current`, `Default` và `LastKnownGood` tới các giá trị `ControlSet00x` thực tế được hệ thống sử dụng.

### Tên máy tính

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: hostname hiện tại.

### Cài đặt múi giờ

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: múi giờ đã cấu hình và các giá trị liên quan đến DST.

### Theo dõi thời gian truy cập

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` cho biết dấu thời gian truy cập gần nhất của NTFS có được cập nhật hay không.
- Để bật tính năng này, dùng: `fsutil behavior set disablelastaccess 0`

### Chi tiết tắt máy

- `SYSTEM\CurrentControlSet\Control\Windows`: thời gian tắt máy gần nhất.
- Các hệ thống cũ hơn cũng có thể lưu bộ đếm tắt máy tại `SYSTEM\CurrentControlSet\Control\Watchdog\Display`.

### Cấu hình mạng

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: IP của giao diện, lease DHCP, gateway và dữ liệu DNS.<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: tên/SSID của cấu hình mạng cùng thời điểm kết nối đầu tiên và gần nhất.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` và `...\Unmanaged\{GUID}`: dữ liệu đối chiếu cấu hình như địa chỉ MAC của gateway và hậu tố DNS.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: các thư mục chia sẻ cục bộ được máy chủ công bố.

### Truy cập từ xa và lịch sử chia sẻ mạng

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: danh sách MRU RDP đi ra (`MRU0`..`MRU9`).<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: lịch sử RDP đi ra theo từng máy chủ. Các khóa con thường lưu `UsernameHint`; thời gian `LastWrite` của khóa là một điểm pivot hữu ích.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: ổ đĩa mạng được ánh xạ, share UNC và điểm gắn phương tiện di động gắn với một người dùng cụ thể.

### Chương trình tự khởi động và cơ chế duy trì lịch chạy

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` và `...\Tasks\{GUID}`: metadata của scheduled task. Nếu task có ở đây nhưng thiếu giá trị `SD` trong `Tree\<TaskName>`, hãy nghi ngờ hành vi can thiệp task kiểu Tarrask ẩn và đối chiếu với `C:\Windows\System32\Tasks\<TaskName>`.

### Tìm kiếm, đường dẫn đã nhập và MRU

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: các từ khóa tìm kiếm trong File Explorer.<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: các đường dẫn Explorer được nhập thủ công.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: 26 lệnh `Win + R` gần nhất. `MRUList` lưu thứ tự của chúng.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: tài liệu và thư mục được mở gần đây.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: các tệp Office gần đây.

### Theo dõi hoạt động người dùng

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: lịch sử thực thi do GUI khởi chạy. Tên giá trị được mã hóa ROT13; dữ liệu nhị phân chứa bộ đếm lần chạy và thời gian chạy gần nhất.<sup>[[1]](#references)</sup>
- Hãy xem `UserAssist` là bằng chứng hỗ trợ có giá trị, không phải kết luận độc lập: nó chủ yếu theo dõi ứng dụng hoặc tệp `.lnk` được khởi chạy qua Explorer và có thể bỏ sót việc thực thi qua command line hoặc service. Trên Windows 10 trở lên, một số mục không nhất thiết có nghĩa là tiến trình đã chạy hoàn tất.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` và `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: dấu vết thực thi trên Windows 10/11 hiện đại, có thông tin SID và thời gian thực thi gần nhất. Các khóa này đặc biệt hữu ích với binary được thực thi cục bộ, nhưng mục cũ có thể nhanh chóng bị xóa và dữ liệu về việc thực thi từ network share/phương tiện di động kém tin cậy hơn.
- Để xem các artifact thực thi rộng hơn như Prefetch, Amcache, ShimCache và SRUM, tham khảo [Windows forensics overview](./#programs-executed).

### Shellbags

- Shellbags được lưu trong cả `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` và `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`.<sup>[[1]](#references)</sup>
- Các mục trong `NTUSER.DAT` đặc biệt hữu ích để xác định hoạt động duyệt UNC/mạng, trong khi `UsrClass.dat` là nơi Windows Vista trở lên thường lưu shellbags của thư mục cục bộ/phương tiện di động.
- Chúng có thể cho biết thư mục từng tồn tại, được truy cập và các tùy chọn hiển thị thư mục, ngay cả sau khi thư mục bị xóa. Việc truy cập tệp lưu trữ bằng các công cụ tương tự Explorer cũng có thể để lại dấu vết shellbag.<sup>[[1]](#references)</sup>
- Không phải shellbag nào cũng chứng minh việc truy cập thư mục thành công, vì vậy hãy đối chiếu với LNK, Jump Lists, dấu thời gian hoặc ánh xạ volume.
- Dùng **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** hoặc **SBECmd** để phân tích chúng.

### Thông tin USB

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: danh mục chính của thiết bị lưu trữ USB (nhà cung cấp, sản phẩm, phiên bản, số sê-ri/instance thiết bị).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: danh mục USB rộng hơn, bao gồm các thiết bị không phải thiết bị lưu trữ.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: trên các bản build Windows 10/11 gần đây, đây là nơi có giá trị cao để tìm dấu thời gian vòng đời theo từng thiết bị như thời điểm cài đặt, cài đặt lần đầu, kết nối gần nhất và tháo thiết bị gần nhất.<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`: ánh xạ volume và mã định danh thiết bị tới ký tự ổ đĩa / volume GUID. Chỉ ánh xạ gần nhất cho một ký tự ổ đĩa có thể còn tồn tại.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: điểm pivot hữu ích để tìm số sê-ri volume và metadata phương tiện trước đó.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: lịch sử tương tác với ký tự ổ đĩa và share theo từng người dùng.<sup>[[2]](#references)</sup>
- Điện thoại và máy tính bảng hiện đại kết nối qua MTP/PTP có thể **không** xuất hiện trong `USBSTOR`. Hãy kiểm tra cả `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` và `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`.<sup>[[2]](#references)</sup>
- Để liên kết thiết bị với người dùng, hãy pivot từ mã định danh thiết bị hoặc volume sang các artifact theo từng người dùng như shellbags, LNK, Jump Lists, `RecentDocs` và `MountPoints2`.<sup>[[2]](#references)</sup>



## References

- [1] [Windows Registry Forensics Cheat Sheet 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [USB Device Forensics on Windows 10 and 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
