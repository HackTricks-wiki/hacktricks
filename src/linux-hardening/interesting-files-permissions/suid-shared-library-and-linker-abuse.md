# Lạm dụng thư viện dùng chung và linker SUID

{{#include ../../banners/hacktricks-training.md}}

Các binary SUID thường được kiểm tra khả năng thực thi lệnh trực tiếp, nhưng các chương trình SUID tùy chỉnh cũng có thể dễ bị tấn công thông qua dynamic linker. Điểm chung rất đơn giản: một executable có đặc quyền tải mã từ một đường dẫn hoặc cấu hình mà người dùng có ít đặc quyền hơn có thể kiểm soát.<sup>[[1]](#references)</sup>

Trang này tập trung vào các mẫu kỹ thuật tổng quát: thiếu thư viện, thư mục thư viện có quyền ghi, `RPATH`/`RUNPATH`, `LD_PRELOAD` thông qua sudo, cấu hình linker và nhầm lẫn hardlink SUID.

Để tìm hiểu về ELF program headers, dynamic section và hành vi của loader liên quan đến các bước kiểm tra này, xem [Thông tin cơ bản về ELF](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md).

## Liệt kê nhanh

Bắt đầu bằng cách tìm các file SUID bất thường và kiểm tra xem chúng có được liên kết động hay không:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```

Sử dụng `readelf` với các executable chưa rõ nguồn gốc: [`ldd` có thể thực thi ELF interpreter không đáng tin cậy](https://man7.org/linux/man-pages/man1/ldd.1.html). `readelf` hiển thị các dependency trực tiếp, vì vậy hãy xác nhận riêng đường dẫn mà loader thực sự chọn.<sup>[[1]](#references)[[3]](#references)</sup>

Tập trung vào các vị trí không tiêu chuẩn, đường dẫn ứng dụng tùy chỉnh, binary thuộc sở hữu của root nhưng nằm ngoài các thư mục do package quản lý, và các dependency được tải từ thư mục có quyền ghi.<sup>[[1]](#references)</sup>

Các bước kiểm tra quyền ghi hữu ích:

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```

## Missing Shared Object Injection

Một số binary SUID tùy chỉnh cố tải một shared object không tồn tại. Nếu đường dẫn không tồn tại nằm trong thư mục do attacker kiểm soát, binary có thể tải mã do attacker cung cấp với quyền của effective user.<sup>[[1]](#references)</sup>

Ranh giới tương tự cũng áp dụng cho **binary tùy chỉnh được phép chạy qua sudo** khi nó gọi `dlopen()` với đường dẫn `.so` tuyệt đối nằm trong thư mục home hoặc thư mục cấu hình mà người gọi có quyền ghi. Việc tải thư viện muộn này có thể không xuất hiện trong `ldd` và các mục ELF `NEEDED`. Kiểm tra `strings` trong phạm vi giới hạn hoặc trace một lần chạy **không có đặc quyền** có thể cho biết đường dẫn được thử tải; mật khẩu ứng dụng hoặc lựa chọn menu có thể kiểm soát việc tra cứu. Hãy xác nhận quy tắc sudo có hiệu lực, đường dẫn chính xác cùng quyền của thư mục cha, và việc chạy với đặc quyền có đi đến bước tra cứu đó hay không trước khi xem đây là một cách nâng quyền. Không chạy mục tiêu sudo chỉ để liệt kê nó.

Tìm các lần tra cứu thư viện thất bại bằng bộ lọc syscall của `strace`:<sup>[[2]](#references)</sup>

```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```

Nếu binary tìm `libexample.so` trong một đường dẫn có quyền ghi, một proof library tối giản có thể sử dụng constructor. Hãy đảm bảo proof-of-impact không gây hại trong quá trình xác thực:<sup>[[6]](#references)</sup>

```c
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
static void init(void) {
    setuid(0);
    setgid(0);
    system("id > /tmp/suid-so-ran");
}
```

Hãy biên dịch nó với tên tệp chính xác mà binary cố tải:

```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```

Điều kiện có thể khai thác không chỉ là thiếu thư viện. Kẻ tấn công phải có khả năng đặt một shared object tương thích vào đường dẫn mà loader có đặc quyền chấp nhận.<sup>[[1]](#references)</sup>

## Thư mục thư viện có quyền ghi

Đôi khi mọi dependency đều tồn tại, nhưng một trong các thư mục được dùng để phân giải chúng có quyền ghi. Điều này có thể cho phép thay thế một thư viện đã được tải hoặc đặt một thư viện có cùng tên nhưng được ưu tiên cao hơn.<sup>[[1]](#references)</sup>

Cách kiểm tra tương tự cũng áp dụng cho ELF tùy chỉnh **được sudo cho phép**, ngay cả khi ELF không có bit SUID và tài khoản RunAs được cho phép không phải root. So sánh các mục `DT_NEEDED` của nó với đường dẫn thư viện mà loader sẽ phân giải; sau đó kiểm tra xem người gọi có thể ghi vào tệp đó hoặc thay thế nó thông qua thư mục cha có quyền ghi và tìm kiếm hay không. Xác nhận chính xác quy tắc sudo RunAs, symlink và ACL, chính sách của loader, cũng như việc tiến trình đích tải thư viện bằng tài khoản có đặc quyền cao hơn. Một `.so` có quyền ghi hoặc chỉ riêng tên dependency mới là dấu hiệu cần kiểm tra; hãy xem metadata mà không chạy lệnh sudo.<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>

Kiểm tra các đường dẫn dependency:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```

Nếu thư mục có quyền ghi, hãy kiểm tra bằng phương pháp an toàn khi sao chép trong môi trường lab. Thay thế thư viện hệ thống trên máy đang hoạt động có thể khiến các tiến trình khởi chạy đồng thời sử dụng phiên bản thư viện không nhất quán.<sup>[[8]](#references)</sup>

### Thư viện có quyền ghi bên trong chroot

Chỉ dùng chroot không đóng các file descriptor được kế thừa hoặc giới hạn mọi quyền truy cập hệ thống tệp. Nếu sandbox để lại một directory descriptor trỏ ra ngoài root mới và tiến trình bị giam có thể truy cập descriptor đó (ví dụ qua một mục `/proc/<pid>/fd/` mà nó có quyền truy cập), các đường dẫn trên host vẫn có thể truy cập được. Đây là vấn đề về ranh giới hệ thống tệp; bản thân nó không cấp quyền root.<sup>[[11]](#references)[[12]](#references)</sup>

Hãy kiểm tra riêng xem người dùng bị giam có thể ghi vào thư mục thư viện mà một **host root-SUID executable** sẽ sử dụng khi được khởi chạy từ jail hay không. Loader phân giải các dependency theo góc nhìn hệ thống tệp của tiến trình, vì vậy thư viện do attacker kiểm soát ở đó có thể chạy với danh tính hiệu lực của chương trình SUID. Xác nhận chính xác executable, SUID bit và chính sách mount của nó, đích đến và quyền truy cập của descriptor, đường dẫn tìm kiếm thư viện của jail, cũng như việc chương trình có thể truy cập host executable hay không. File capability trên sandbox launcher, jail có quyền ghi hoặc host SUID binary chỉ là manh mối; chuỗi khai thác hoàn chỉnh phụ thuộc vào cách triển khai sandbox.<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>

## RPATH and RUNPATH

`RPATH` và `RUNPATH` là các entry trong dynamic section cho loader biết nơi tìm thư viện. Chúng nguy hiểm trong các chương trình SUID nếu trỏ đến những thư mục attacker có quyền ghi.<sup>[[1]](#references)</sup>

Phát hiện chúng:<sup>[[3]](#references)[[10]](#references)</sup>

```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```

Ví dụ về đầu ra rủi ro:

```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```

Nếu `/opt/app/lib` có quyền ghi và binary cần `libcustom.so`, attacker có thể đặt một `libcustom.so` độc hại tại đó:<sup>[[1]](#references)</sup>

```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```

`RPATH` và `RUNPATH` không giống nhau trong mọi chi tiết phân giải, nhưng khi rà soát khả năng leo thang đặc quyền, câu hỏi thực tế vẫn như nhau: liệu binary SUID có tìm kiếm thư viện theo tên trong một thư mục mà kẻ tấn công có thể ghi hay không?<sup>[[1]](#references)</sup>

## LD_PRELOAD, LD_LIBRARY_PATH và SUID

Với các chương trình thông thường, `LD_PRELOAD` và `LD_LIBRARY_PATH` có thể buộc hoặc tác động đến việc tải shared object. Với các chương trình SUID, dynamic loader thường chuyển sang chế độ thực thi an toàn và bỏ qua các biến môi trường nguy hiểm.<sup>[[1]](#references)</sup>

Điều này có nghĩa là một binary SUID thông thường thường không dễ bị tấn công chỉ vì người dùng có thể đặt `LD_PRELOAD`:<sup>[[1]](#references)</sup>

```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```

Ngoại lệ phổ biến là chính sách sudo cho phép gán biến môi trường trên dòng lệnh cho target, chẳng hạn như tag `SETENV` hoặc tùy chọn `setenv` phù hợp. Nếu target được liên kết động và sudo chấp nhận `LD_PRELOAD=/path/to/library`, target có thể nạp mã do người gọi kiểm soát. Hãy kiểm tra quy tắc có hiệu lực và danh tính của target. Chỉ thêm `LD_PRELOAD` vào `env_keep` là chưa đủ trên các hệ thống mà dynamic loader loại bỏ `LD_PRELOAD` được kế thừa trước khi tiến trình SUID `sudo` khởi chạy; sudo xử lý biến được gán trên dòng lệnh sau khi chính nó khởi động.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
sudo -l
# Check SETENV/setenv and the target command's allowed arguments
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```

Đừng nhầm lẫn các trường hợp này; các quy tắc của loader và policy sudo ở trên phân biệt chúng:<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- `LD_PRELOAD` với binary SUID thông thường: thường bị chặn bởi secure execution.
- `LD_PRELOAD` được chấp nhận dưới dạng biến gán trên dòng lệnh sudo cho target có đặc quyền và liên kết động: có thể khai thác được.
- Thiếu `.so` trong đường dẫn có quyền ghi: có thể khai thác khi binary SUID tự nhiên tải đường dẫn đó.
- `RPATH`/`RUNPATH` trỏ đến thư mục có quyền ghi: có thể khai thác khi kiểm soát được thư viện cần thiết.
- Có quyền ghi vào `/etc/ld.so.preload` hoặc cấu hình linker: ảnh hưởng toàn hệ thống và có tác động lớn.

## Cấu hình linker

`ld.so` sử dụng linker cache và `/etc/ld.so.preload`; `ldconfig` tạo cache đó từ `/etc/ld.so.conf` và các file được include từ file này, thường là trong `/etc/ld.so.conf.d/`.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Các kiểm tra có giá trị cao:

```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```

Cấu hình linker có quyền ghi thường nghiêm trọng hơn một binary SUID dễ bị tấn công, vì nó có thể ảnh hưởng đến nhiều tiến trình được liên kết động. `/etc/ld.so.preload` đặc biệt nguy hiểm vì có thể buộc các tiến trình đặc quyền nạp một shared object.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## Nhầm lẫn Hardlink SUID

Hardlink có thể khiến cùng một inode SUID xuất hiện dưới nhiều tên khác nhau.<sup>[[9]](#references)</sup> Điều này hữu ích để che giấu một helper đặc quyền, gây nhầm lẫn khi dọn dẹp hoặc vượt qua việc rà soát đơn giản chỉ dựa trên đường dẫn.

Tìm các tệp SUID có nhiều hơn một liên kết:<sup>[[9]](#references)</sup>

```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```

Kiểm tra tất cả các đường dẫn đến cùng một inode:<sup>[[9]](#references)</sup>

```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```

Việc abuse không phải là hardlink thay đổi quyền. Abuse nằm ở sự nhầm lẫn đường dẫn: một inode đặc quyền có thể được truy cập qua một tên mà các biện pháp phòng thủ hoặc script không mong đợi.<sup>[[9]](#references)</sup> Để tìm hiểu sâu hơn về inode và quy trình hardlink, xem [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Ghi chú phòng thủ

- Giữ các binary SUID ở mức tối thiểu, được kiểm tra và quản lý bằng package khi có thể.
- Tránh các mục `RPATH`/`RUNPATH` trỏ đến thư mục có thể ghi hoặc do ứng dụng quản lý.<sup>[[1]](#references)[[8]](#references)</sup>
- Đảm bảo các thư mục library thuộc sở hữu của root và người dùng thông thường không thể ghi vào.<sup>[[8]](#references)</sup>
- Không giữ lại `LD_PRELOAD`, `LD_LIBRARY_PATH` hoặc các biến loader tương tự khi dùng sudo.<sup>[[1]](#references)[[5]](#references)</sup>
- Giám sát `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` và các file SUID bất thường.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- Kiểm tra các file SUID được hardlink và điều tra các wrapper SUID tùy chỉnh nằm ngoài những đường dẫn hệ thống tiêu chuẩn.<sup>[[9]](#references)</sup>

## References

- [1] [ld.so(8) — Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [strace(1) — Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man1/strace.1.html)
- [3] [readelf (Tiện ích Binary của GNU)](https://sourceware.org/binutils/docs/binutils/readelf.html)
- [4] [sudo(8) — Trang hướng dẫn Linux](https://www.man7.org/linux/man-pages/man8/sudo.8.html)
- [5] [sudoers(5) — Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [6] [Thuộc tính thông dụng (GCC)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [7] [ldconfig(8) — Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [8] [Gia cố Dynamic Linker (Thư viện GNU C)](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [9] [Hard Links (GNU Findutils)](https://www.gnu.org/software/findutils/manual/html_node/find_html/Hard-Links.html)
- [10] [objdump (Tiện ích Binary của GNU)](https://www.sourceware.org/binutils/docs/binutils/objdump.html)
- [11] [chroot(2) — Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [12] [proc_pid_fd(5) — Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
{{#include ../../banners/hacktricks-training.md}}
