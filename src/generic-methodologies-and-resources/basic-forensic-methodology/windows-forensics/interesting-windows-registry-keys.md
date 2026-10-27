# Các khóa Registry Windows đáng chú ý

{{#include ../../../banners/hacktricks-training.md}}

Các hive Windows Registry là một trong những cách nhanh nhất để chuyển từ câu hỏi _điều gì đã xảy ra?_ sang _người dùng nào, khi nào và từ đâu?_. Khi phân tích hệ thống đang chạy, hãy ưu tiên `CurrentControlSet`; khi phân tích hive offline, trước tiên hãy xác định `ControlSet00x` nào đang hoạt động thay vì mặc định dùng `ControlSet001`.

### Thông tin phiên bản Windows và chủ sở hữu

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: phiên bản/build Windows, thời điểm cài đặt, chủ sở hữu đã đăng ký, tên sản phẩm và các metadata build khác.
- `SYSTEM\Select`: ánh xạ `Current`, `Default` và `LastKnownGood` sang giá trị `ControlSet00x` thực tế mà hệ thống sử dụng.

### Tên máy tính

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: hostname hiện tại.

### Cài đặt múi giờ

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: múi giờ được cấu hình và các giá trị liên quan đến DST.

### Theo dõi thời gian truy cập

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` cho biết liệu timestamp truy cập gần nhất của NTFS có được cập nhật hay không.
- Để bật tính năng này, dùng: `fsutil behavior set disablelastaccess 0`

### Chi tiết tắt máy

- `SYSTEM\CurrentControlSet\Control\Windows`: thời điểm tắt máy gần nhất.
- Các hệ thống cũ hơn cũng có thể lưu bộ đếm tắt máy trong `SYSTEM\CurrentControlSet\Control\Watchdog\Display`.

### Cấu hình mạng

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: IP của interface, DHCP lease, gateway và dữ liệu DNS.<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: tên/SSID của network profile cùng thời điểm kết nối lần đầu và gần nhất.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` và `...\Unmanaged\{GUID}`: dữ liệu đối chiếu profile, chẳng hạn địa chỉ MAC của gateway và DNS suffix.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: các thư mục chia sẻ cục bộ do máy host công bố.

### Truy cập từ xa và lịch sử network share

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: danh sách MRU RDP đi ra (`MRU0`..`MRU9`).<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: lịch sử RDP đi ra theo từng host. Các subkey thường lưu `UsernameHint`; thời gian `LastWrite` của key là một điểm pivot hữu ích.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: ổ đĩa mạng đã ánh xạ, UNC share và điểm mount của thiết bị lưu trữ rời gắn với một người dùng cụ thể.

### Chương trình tự khởi động và persistence theo lịch

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` và `...\Tasks\{GUID}`: metadata của scheduled task. Nếu có task ở đây nhưng thiếu giá trị `SD` trong `Tree\<TaskName>`, hãy nghi ngờ hành vi can thiệp task ẩn kiểu Tarrask và đối chiếu với `C:\Windows\System32\Tasks\<TaskName>`.

### Tìm kiếm, đường dẫn đã nhập và MRU

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: các cụm từ đã tìm trong File Explorer.<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: các đường dẫn Explorer được nhập thủ công.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: 26 lệnh `Win + R` gần nhất. `MRUList` giữ nguyên thứ tự của chúng.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: tài liệu và thư mục được mở gần đây.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: các tệp Office gần đây.

### Theo dõi hoạt động người dùng

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: lịch sử thực thi thông qua GUI. Tên value được mã hóa ROT13; dữ liệu nhị phân chứa số lần chạy và thời điểm chạy gần nhất.<sup>[[1]](#references)</sup>
- Hãy xem `UserAssist` là bằng chứng hỗ trợ mạnh, không phải kết luận độc lập: tính năng này chủ yếu theo dõi ứng dụng hoặc tệp `.lnk` được khởi chạy qua Explorer, và có thể bỏ sót việc thực thi qua command line hoặc service. Trên Windows 10 trở lên, một số entry không nhất thiết có nghĩa là process đã chạy hoàn chỉnh.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` và `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: dấu vết thực thi trên Windows 10/11 hiện đại, có thông tin SID và thời điểm thực thi gần nhất. Chúng đặc biệt hữu ích với binary được thực thi cục bộ, nhưng entry cũ có thể nhanh chóng bị loại bỏ; dữ liệu về việc thực thi từ network share/thiết bị lưu trữ rời cũng kém tin cậy hơn.
- Để xem các artifact thực thi rộng hơn như Prefetch, Amcache, ShimCache và SRUM, hãy xem [tổng quan về forensics Windows](README.md#programs-executed).

### Shellbag

- Shellbag được lưu trong cả `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` và `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`.<sup>[[1]](#references)</sup>
- Các entry trong `NTUSER.DAT` đặc biệt hữu ích để khảo sát UNC/network; trên Windows Vista trở lên, `UsrClass.dat` thường là nơi lưu shellbag của thư mục cục bộ/thiết bị lưu trữ rời.
- Chúng có thể cho biết thư mục từng tồn tại, được duyệt qua và các tùy chọn hiển thị thư mục, ngay cả sau khi thư mục bị xóa. Việc truy cập tệp archive theo cách tương tự Explorer cũng có thể để lại dấu vết shellbag.<sup>[[1]](#references)</sup>
- Không phải shellbag nào cũng chứng minh rằng thư mục đã được truy cập thành công, vì vậy hãy đối chiếu với LNK, Jump List, timestamp hoặc ánh xạ volume.
- Dùng **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** hoặc **SBECmd** để phân tích chúng.

### Thông tin USB

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: danh mục chính của các thiết bị lưu trữ USB (vendor, product, revision, serial/device instance).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: danh mục thiết bị USB rộng hơn, bao gồm cả thiết bị không phải thiết bị lưu trữ.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: trên các bản build Windows 10/11 gần đây, đây là nơi có giá trị cao để tìm timestamp vòng đời của từng thiết bị, chẳng hạn thời điểm cài đặt, cài đặt lần đầu, kết nối gần nhất và tháo kết nối gần nhất.<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`: ánh xạ volume và device identifier sang ký tự ổ đĩa / volume GUID. Có thể chỉ ánh xạ gần nhất cho một ký tự ổ đĩa được giữ lại.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: điểm pivot hữu ích để tìm serial number của volume và metadata của thiết bị lưu trữ trước đây.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: lịch sử tương tác theo từng người dùng với ký tự ổ đĩa và share.<sup>[[2]](#references)</sup>
- Điện thoại và máy tính bảng hiện đại kết nối qua MTP/PTP có thể **không** xuất hiện trong `USBSTOR`. Hãy kiểm tra cả `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` và `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`.<sup>[[2]](#references)</sup>
- Để liên kết thiết bị với người dùng, hãy pivot từ device identifier hoặc volume identifier sang các artifact theo từng người dùng như shellbag, LNK, Jump List, `RecentDocs` và `MountPoints2`.<sup>[[2]](#references)</sup>

## References

- [1] [Tài liệu tham khảo nhanh về forensics Windows Registry 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [Forensics thiết bị USB trên Windows 10 và 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
