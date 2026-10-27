# Tài liệu về Kernel, LPE và CVE

{{#include ../../../banners/hacktricks-training.md}}

Các nghiên cứu tình huống này đề cập đến những primitive leo thang đặc quyền cục bộ riêng biệt. Hãy kiểm tra sản phẩm hoặc kernel bị ảnh hưởng, cấu hình và các điều kiện tiên quyết trong từng bài viết trước khi áp dụng kỹ thuật. Để liệt kê thông tin máy chủ trên diện rộng hơn, hãy dùng [danh sách kiểm tra leo thang đặc quyền trên Linux](../linux-privilege-escalation-checklist.md).

Đối với Dirty Pipe (CVE-2022-0847), [nghiên cứu ban đầu](https://dirtypipe.cm4all.com/) xác định các bản sửa lỗi stable upstream tại các phiên bản 5.10.102, 5.15.25 và 5.16.11. Kernel có phiên bản thuộc dải cũ bị ảnh hưởng chỉ là dấu hiệu cần xem xét: kernel của bản phân phối có thể backport các bản sửa lỗi với tên bản phát hành khác, và file đích liên quan phải có quyền đọc để primitive ghi page-cache hoạt động. Ghi đè một tệp thực thi SUID có thể đọc là một con đường leo thang đặc quyền, nếu quá trình chuyển đổi set-ID vẫn có hiệu lực; việc sửa đổi `/etc/passwd` rồi xác thực cũng có thể phụ thuộc vào PAM stack cục bộ. Trước khi đánh giá khả năng khai thác, hãy kiểm tra gói kernel của nhà cung cấp đã cài đặt, kernel đang chạy sau khi khởi động lại, quyền của đích, tùy chọn mount `nosuid` và `no_new_privs`. Không chạy thử thao tác ghi trong quá trình liệt kê thụ động. Xem [trạng thái theo từng bản phát hành của Ubuntu](https://ubuntu.com/security/CVE-2022-0847).

- [Khám phá dịch vụ VMware Tools, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): thực thi với đặc quyền thông qua quá trình khám phá đường dẫn tiến trình không đáng tin cậy.
- [Ghi đè page-cache bằng AF_ALG splice, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): một đường ghi đè page-cache của kernel.
- [Cuộc đua TOCTOU với bộ định thời CPU POSIX và khai thác, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md#root-cause-toctou-between-irq-time-expiry-and-concurrent-deletion-under-task-exit): quá trình hết hạn/xóa bộ định thời khi task thoát, bao gồm các điều kiện tiên quyết của đường IRQ và nghiên cứu khai thác.
- [Cuộc đua khi thoát của Linux ptrace và đánh cắp file descriptor bằng `pidfd_getfd`](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): truy cập descriptor trong một cuộc đua khi tiến trình thoát.

## Các nghiên cứu tình huống khai thác nhị phân liên quan

Phần Binary Exploitation đi sâu hơn vào các primitive khai thác, bố cục bộ nhớ và cách vượt qua cơ chế giảm thiểu cho những mục tiêu Linux kernel này:

- [AF_UNIX out-of-band SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): lỗi socket được phát triển thành các primitive đọc và ghi kernel.
- [AF_ALG concurrent-writer scatterlist underflow](../../../binary-exploitation/linux-kernel-exploitation/af-alg-concurrent-writer-scatterlist-oob.md): cuộc đua giữa các tiến trình ghi skcipher được phát triển thành thao tác ghi kernel.
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): primitive ghi con trỏ được mở rộng thông qua pipe buffer và workqueue.
- [ksmbd streams out-of-bounds write, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): khai thác kernel heap và vượt qua các cơ chế giảm thiểu.
- [Arm64 static linear-map KASLR bypass](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): khám phá địa chỉ để khai thác kernel arm64.
- [Adreno A7xx GPU/SMMU privilege bypass](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): một đường khai thác GPU Android để truy cập bộ nhớ kernel.
- [Pixel Bigwave job-timeout use-after-free](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): lỗi bộ tăng tốc Android được dùng để ghi vào kernel.
{{#include ../../../banners/hacktricks-training.md}}
