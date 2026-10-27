# Các dấu hiệu leo thang quyền qua phiên và dịch vụ đĩa trên SUSE

{{#include ../../banners/hacktricks-training.md}}

## Cấp quyền cho phiên SSH thông qua PAM

CVE-2025-6018 ảnh hưởng đến các cấu hình PAM trên SUSE 15, trong đó ngăn xếp xác thực SSH tải `pam_env` trước khi ngăn xếp phiên tải `pam_systemd`. Khi `pam_env` đọc `.pam_environment` của người dùng, người dùng đó có thể cung cấp các giá trị `XDG_SEAT` và `XDG_VTNR` khiến Polkit xem phiên SSH như thể đang hoạt động trực tiếp tại máy. Khi đó, một hành động có `allow_active=yes` có thể trở nên khả dụng với người dùng từ xa. Điều này thay đổi việc cấp quyền cho phiên; bản thân nó không đảm bảo có được quyền root. SUSE đã sửa hành vi mặc định khi đọc môi trường người dùng trong `pam` và vị trí mô-đun do `pam-config` tạo ra.<sup>[[1]](#references)[[2]](#references)</sup>

Kiểm tra chuỗi include thực tế của `/etc/pam.d/sshd`, thứ tự của `pam_env.so` và `pam_systemd.so`, cũng như mọi tùy chọn `user_readenv=1` được khai báo rõ ràng. Gói `pam` đã vá sẽ thay đổi hành vi mặc định, nhưng tùy chọn được khai báo rõ ràng vẫn có thể yêu cầu đọc môi trường người dùng. Gói `pam-config` mới hơn không chứng minh rằng ngăn xếp PAM đã bị chỉnh sửa cục bộ hoặc đã cũ được tạo lại. Hãy kiểm tra đồng thời bản phát hành gói của nhà cung cấp và cấu hình thực tế.<sup>[[1]](#references)[[2]](#references)</sup>

## Đường dẫn dịch vụ đĩa dành cho người dùng đang hoạt động

CVE-2025-6019 là một đường dẫn leo thang quyền trong `libblockdev` thông qua `udisks2`: trong khi thay đổi kích thước XFS, hệ thống tệp do kẻ tấn công cung cấp có thể tạm thời được gắn kết mà không có giới hạn `nosuid` như mong đợi. Đường dẫn này yêu cầu dịch vụ UDisks D-Bus có thể sử dụng được, hỗ trợ thay đổi kích thước XFS, hành động Polkit liên quan khả dụng với người gọi và gói thư viện bị ảnh hưởng. CVE-2025-6018 là một cách để có được phiên người dùng đang hoạt động, nhưng người dùng đã có phiên hoạt động cũng có thể truy cập độc lập vào đường dẫn dịch vụ đĩa.<sup>[[3]](#references)</sup>

Để rà soát thụ động, hãy kiểm tra metadata của dịch vụ UDisks, chính sách `org.freedesktop.udisks2.modify-device`, `xfs_growfs` và gói `libbd_fs2` đã cài đặt. SUSE liệt kê phiên bản `libbd_fs2` `2.26-150400.3.5.1` là đã được sửa lỗi cho openSUSE Leap 15.6; phiên bản sửa lỗi chính xác tùy thuộc vào sản phẩm. Chỉ riêng sự hiện diện của chính sách và gói là manh mối, không phải bằng chứng cho thấy người gọi có thể gắn kết hoặc thay đổi kích thước thiết bị. Tránh thay đổi các điểm gắn kết hoặc gọi phương thức D-Bus trong khi kiểm kê.<sup>[[3]](#references)</sup>

## References

- [1] [Thông báo CVE-2025-6018 của SUSE](https://www.suse.com/security/cve/CVE-2025-6018.html)
- [2] [Bản cập nhật bảo mật pam-config của SUSE](https://www.suse.com/support/update/announcement/2025/suse-su-202502082-1)
- [3] [Thông báo CVE-2025-6019 của SUSE](https://www.suse.com/security/cve/CVE-2025-6019.html)
{{#include ../../banners/hacktricks-training.md}}
