# Điều tra pháp chứng Linux

{{#include ../../banners/hacktricks-training.md}}

## Thu thập thông tin ban đầu

### Thông tin cơ bản

Trước tiên, bạn nên chuẩn bị một **USB** chứa **các binary và thư viện đáng tin cậy** (bạn có thể tải Ubuntu rồi sao chép các thư mục _/bin_, _/sbin_, _/lib,_ và _/lib64_), sau đó gắn USB và chỉnh sửa các biến môi trường để sử dụng những binary đó:

```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```

Sau khi đã cấu hình hệ thống để sử dụng các binary tốt và đã biết, bạn có thể bắt đầu **trích xuất một số thông tin cơ bản**:

```bash
date #Date and time (Clock may be skewed, Might be at a different timezone)
uname -a #OS info
ifconfig -a || ip a #Network interfaces (promiscuous mode?)
ps -ef #Running processes
netstat -anp #Proccess and ports
lsof -V #Open files
netstat -rn; route #Routing table
df; mount #Free space and mounted devices
free #Meam and swap space
w #Who is connected
last -Faiwx #Logins
lsmod #What is loaded
cat /etc/passwd #Unexpected data?
cat /etc/shadow #Unexpected data?
find /directory -type f -mtime -1 -print #Find modified files during the last minute in the directory
```

#### Thông tin đáng ngờ

Khi thu thập thông tin cơ bản, bạn nên kiểm tra những điểm bất thường như:

- Các tiến trình **root** thường chạy với PID thấp, vì vậy nếu bạn phát hiện một tiến trình root có PID lớn, bạn có thể nghi ngờ
- Kiểm tra **các tài khoản đăng nhập đã đăng ký** của người dùng không có shell trong `/etc/passwd`
- Kiểm tra **password hash** trong `/etc/shadow` của người dùng không có shell

### Memory Dump

Để lấy bộ nhớ của hệ thống đang chạy, bạn nên sử dụng [**LiME**](https://github.com/504ensicsLabs/LiME).\
Để **biên dịch** nó, bạn cần sử dụng **cùng kernel** mà máy nạn nhân đang chạy.

> [!TIP]
> Hãy nhớ rằng bạn **không thể cài đặt LiME hay bất kỳ thứ gì khác** trên máy nạn nhân vì điều đó sẽ tạo ra nhiều thay đổi trên máy

Vì vậy, nếu có một phiên bản Ubuntu giống hệt, bạn có thể dùng `apt-get install lime-forensics-dkms`\
Trong các trường hợp khác, bạn cần tải [**LiME**](https://github.com/504ensicsLabs/LiME) từ github và biên dịch nó với kernel header phù hợp. Để **lấy chính xác kernel header** của máy nạn nhân, bạn chỉ cần **sao chép thư mục** `/lib/modules/<kernel version>` sang máy của mình, rồi **biên dịch** LiME bằng các header đó:

```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```

LiME hỗ trợ 3 **định dạng**:

- Raw (mọi phân đoạn được nối lại với nhau)
- Padded (giống raw, nhưng có thêm các số 0 ở các bit bên phải)
- Lime (định dạng được khuyến nghị, có metadata)

LiME cũng có thể được dùng để **gửi bản dump qua mạng** thay vì lưu trên hệ thống bằng cách dùng thứ gì đó như: `path=tcp:4444`

### Tạo ảnh đĩa

#### Tắt máy

Trước tiên, bạn cần **tắt hệ thống**. Không phải lúc nào đây cũng là một lựa chọn vì đôi khi hệ thống là máy chủ production mà công ty không thể tắt.\
Có **2 cách** để tắt hệ thống: **tắt máy bình thường** và **rút nguồn**. Cách thứ nhất cho phép các **process** **kết thúc như thường lệ** và **hệ thống tệp** được **đồng bộ**, nhưng cũng có thể tạo cơ hội cho **malware** **hủy hoại bằng chứng**. Cách **rút nguồn** có thể gây **mất một ít thông tin** (không nhiều thông tin bị mất vì chúng ta đã tạo ảnh bộ nhớ) và **malware sẽ không có cơ hội** làm gì cả. Vì vậy, nếu bạn **nghi ngờ** có thể có **malware**, chỉ cần chạy **lệnh** **`sync`** trên hệ thống rồi rút nguồn.

#### Tạo ảnh đĩa

Lưu ý rằng **trước khi kết nối máy tính của bạn với bất cứ thứ gì liên quan đến vụ việc**, bạn cần đảm bảo máy sẽ được **mount ở chế độ chỉ đọc** để tránh sửa đổi bất kỳ thông tin nào.

```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```

### Phân tích sơ bộ ảnh đĩa

Tạo ảnh đĩa mà không có thêm dữ liệu.

```bash
#Find out if it's a disk image using "file" command
file disk.img
disk.img: Linux rev 1.0 ext4 filesystem data, UUID=59e7a736-9c90-4fab-ae35-1d6a28e5de27 (extents) (64bit) (large files) (huge files)

#Check which type of disk image it's
img_stat -t evidence.img
raw
#You can list supported types with
img_stat -i list
Supported image format types:
        raw (Single or split raw file (dd))
        aff (Advanced Forensic Format)
        afd (AFF Multiple File)
        afm (AFF with external metadata)
        afflib (All AFFLIB image formats (including beta ones))
        ewf (Expert Witness Format (EnCase))

#Data of the image
fsstat -i raw -f ext4 disk.img
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: Ext4
Volume Name:
Volume ID: 162850f203fd75afab4f1e4736a7e776

Last Written at: 2020-02-06 06:22:48 (UTC)
Last Checked at: 2020-02-06 06:15:09 (UTC)

Last Mounted at: 2020-02-06 06:15:18 (UTC)
Unmounted properly
Last mounted on: /mnt/disk0

Source OS: Linux
[...]

#ls inside the image
fls -i raw -f ext4 disk.img
d/d 11: lost+found
d/d 12: Documents
d/d 8193:       folder1
d/d 8194:       folder2
V/V 65537:      $OrphanFiles

#ls inside folder
fls -i raw -f ext4 disk.img 12
r/r 16: secret.txt

#cat file inside image
icat -i raw -f ext4 disk.img 16
ThisisTheMasterSecret
```

## Tìm kiếm Malware đã biết

### Tệp hệ thống bị sửa đổi

Linux cung cấp các công cụ để đảm bảo tính toàn vẹn của các thành phần hệ thống, rất cần thiết để phát hiện những tệp có khả năng gây ra vấn đề.<sup>[[1]](#references)</sup>

- **Các hệ thống dựa trên RedHat**: Dùng `rpm -Va` để kiểm tra toàn diện.
- **Các hệ thống dựa trên Debian**: Dùng `dpkg --verify` để xác minh ban đầu, sau đó chạy `debsums | grep -v "OK$"` (sau khi cài đặt `debsums` bằng `apt-get install debsums`) để xác định các vấn đề.

### Công cụ phát hiện Malware/Rootkit

Đọc trang sau để tìm hiểu về các công cụ có thể hữu ích trong việc tìm malware:


{{#ref}}
malware-analysis.md
{{#endref}}

## Tìm kiếm các chương trình đã cài đặt

Để tìm kiếm hiệu quả các chương trình đã cài đặt trên cả hệ thống Debian và RedHat, hãy cân nhắc tận dụng nhật ký hệ thống và cơ sở dữ liệu, đồng thời kiểm tra thủ công các thư mục phổ biến.<sup>[[1]](#references)</sup>

- Với Debian, kiểm tra _**`/var/lib/dpkg/status`**_ và _**`/var/log/dpkg.log`**_ để lấy thông tin chi tiết về các gói đã cài đặt, dùng `grep` để lọc thông tin cụ thể.
- Người dùng RedHat có thể truy vấn cơ sở dữ liệu RPM bằng `rpm -qa --root=/mntpath/var/lib/rpm` để liệt kê các gói đã cài đặt.

Để tìm phần mềm được cài đặt thủ công hoặc bên ngoài các trình quản lý gói này, hãy kiểm tra các thư mục như _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_ và _**`/sbin`**_. Kết hợp liệt kê thư mục với các lệnh dành riêng cho hệ thống để xác định những tệp thực thi không liên kết với các gói đã biết, từ đó mở rộng phạm vi tìm kiếm tất cả chương trình đã cài đặt.

```bash
# Debian package and log details
cat /var/lib/dpkg/status | grep -E "Package:|Status:"
cat /var/log/dpkg.log | grep installed
# RedHat RPM database query
rpm -qa --root=/mntpath/var/lib/rpm
# Listing directories for manual installations
ls /usr/sbin /usr/bin /bin /sbin
# Identifying non-package executables (Debian)
find /sbin/ -exec dpkg -S {} \; | grep "no path found"
# Identifying non-package executables (RedHat)
find /sbin/ –exec rpm -qf {} \; | grep "is not"
# Find exacuable files
find / -type f -executable | grep <something>
```

## Khôi phục các binary đang chạy đã bị xóa

Hãy tưởng tượng một tiến trình được chạy từ /tmp/exec rồi bị xóa. Có thể trích xuất nó.

```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```

## Phân loại dấu vết syscall bằng SQLite và FTS5

Khi một process vẫn đang chạy hoặc có thể được thực thi lại trong lab, **`strace`** có thể nhanh chóng ghi lại hành vi mà không cần kernel module hoặc telemetry EDR đầy đủ. Với các trace lớn, tránh đọc trực tiếp raw log hoặc dán nó vào LLM: hãy lưu log vào cơ sở dữ liệu **SQLite** và chỉ truy vấn tập dữ liệu tối thiểu cần thiết.<sup>[[7]](#references)[[8]](#references)[[9]](#references)</sup>

> [!WARNING]
> Gắn `strace` sẽ làm thay đổi thời gian chạy của process và có thể ảnh hưởng đến các điều kiện tranh chấp hoặc những bug khó tái hiện khác. Khi có thể, hãy ưu tiên tái hiện trên hệ thống lab/bản sao.

### Thu thập

Đối với một process mới:

```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log <command>
```

Đối với một tiến trình đang chạy:

```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log -p <PID>
```

Các tùy chọn hữu ích:

- `-ff`: theo dõi fork/thread và lưu đầu ra riêng cho từng tiến trình
- `-ttt`: dấu thời gian Unix để dễ đối chiếu dòng thời gian
- `-yy`: phân giải file descriptor thành đường dẫn/socket tương ứng khi có thể
- `-s 4096`: giữ nguyên các đối số đường dẫn và bộ đệm dài, tránh bị cắt ngắn

### Chuẩn hóa

Một schema thực tế gồm một hàng cho mỗi lời gọi hệ thống và một hàng cho mỗi đối số:

```sql
CREATE TABLE syscalls (
    id        INTEGER PRIMARY KEY,
    pid       INTEGER NOT NULL,
    timestamp REAL    NOT NULL,
    name      TEXT    NOT NULL,
    ret_val   INTEGER,
    errno     TEXT
);

CREATE TABLE syscall_args (
    id         INTEGER PRIMARY KEY,
    syscall_id INTEGER NOT NULL REFERENCES syscalls(id),
    position   INTEGER NOT NULL,
    raw        TEXT    NOT NULL,
    type       INTEGER NOT NULL
);
```

Điều này giúp tránh việc cố gắng dồn các dòng syscall không đồng nhất vào một bảng rộng duy nhất và giữ cho các phép join dễ dự đoán trong quá trình phân loại.

### Lập chỉ mục các đối số nhiều văn bản bằng FTS5

Việc tìm kiếm đường dẫn theo cách ngây thơ bằng `LIKE "%...%"` trở nên rất chậm trên các trace lớn. Hãy tạo chỉ mục FTS5 cho văn bản đối số rồi tìm kiếm trên đó:

```sql
CREATE VIRTUAL TABLE syscall_args_fts
USING fts5(raw, content='syscall_args', content_rowid='id');

INSERT INTO syscall_args_fts(rowid, raw)
SELECT id, raw FROM syscall_args;
```

Ví dụ: khôi phục hoạt động tệp trong `/tmp` mà không cần quét từng hàng:

```sql
SELECT s.timestamp, s.pid, s.name, a.position, a.raw
FROM syscall_args_fts f
JOIN syscall_args a ON a.id = f.rowid
JOIN syscalls s ON s.id = a.syscall_id
WHERE syscall_args_fts MATCH 'tmp'
  AND s.name IN ('openat', 'stat', 'lstat', 'rename', 'unlink', 'execve')
ORDER BY s.timestamp;
```

### Điều tra có tín hiệu cao

- **Chiếm quyền PATH / sudo giả**: tìm các thao tác ghi và `chmod`/`rename` trong `~/.local/bin/`, sau đó đối chiếu với các lần `execve` sau đó của những tên có vẻ đặc quyền như `sudo`.
- **TOCTOU trên tệp tạm thời**: lần theo cùng một đường dẫn `/tmp/...` qua `stat`, `access`, `openat`, `rename`, `unlink`, `link`, `symlink` và `execve` để xác định khoảng trống giữa kiểm tra và sử dụng.
- **Nguyên nhân gốc của sự cố crash**: đối chiếu thao tác `mmap` một tệp với việc một tiến trình khác ghi hoặc cắt ngắn cùng inode/đường dẫn, sau đó kiểm tra chuỗi signal/exit để xác định `SIGBUS`.
- **Khôi phục đích mạng**: lọc `connect`, `sendto`, `sendmsg`, `recvfrom` và các đối số liên quan đến socket để trích xuất IP và port của máy ngang hàng.

### Phân tích trace với sự hỗ trợ của LLM

Nếu muốn LLM hỗ trợ, hãy cung cấp một kết nối SQLite **chỉ đọc** và toàn bộ schema. Cho phép nó chạy SQL thô thay vì bọc database sau các hàm trợ giúp hạn chế. Cách này thường hiệu quả hơn với các truy vấn join, đối chiếu theo thời gian và tra cứu FTS.

Quy tắc thực tế:

- Giữ database ở chế độ chỉ đọc, ví dụ dùng `sqlite3 'file:trace.db?mode=ro'`.
- Cung cấp cho model các ví dụ về truy vấn `JOIN` và `FTS5 MATCH` hợp lệ.
- **Không** dán các log `strace` thô nhiều GB vào prompt.
- Đặt các câu hỏi tập trung như:
  - "Liệt kê các tệp bền vững do chương trình này ghi."
  - "Chương trình có tạo hoặc thay thế các tệp thực thi trong các thư mục PATH do người dùng kiểm soát không?"
  - "Giải thích vì sao trace này kết thúc bằng SIGBUS."

## Kiểm tra các vị trí tự khởi động

### Tác vụ theo lịch trình

```bash
cat /var/spool/cron/crontabs/*  \
/var/spool/cron/atjobs \
/var/spool/anacron \
/etc/cron* \
/etc/at* \
/etc/anacrontab \
/etc/incron.d/* \
/var/spool/incron/* \

#MacOS
ls -l /usr/lib/cron/tabs/ /Library/LaunchAgents/ /Library/LaunchDaemons/ ~/Library/LaunchAgents/
```

#### Truy tìm: Lạm dụng Cron/Anacron qua stub 0anacron và các stub đáng ngờ
Kẻ tấn công thường chỉnh sửa stub 0anacron trong từng thư mục /etc/cron.*/ để đảm bảo thực thi định kỳ.<sup>[[4]](#references)</sup>

```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```

#### Săn tìm: rollback hardening SSH và backdoor shells
Các thay đổi đối với sshd_config và shell của tài khoản hệ thống thường được thực hiện trong giai đoạn post-exploitation nhằm duy trì quyền truy cập.<sup>[[4]](#references)</sup>

```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```

#### Săn tìm: Dấu hiệu Cloud C2 (Dropbox/Cloudflare Tunnel)
- Beacon Dropbox API thường sử dụng api.dropboxapi.com hoặc content.dropboxapi.com qua HTTPS với token Authorization: Bearer.
  - Tìm trong proxy/Zeek/NetFlow các kết nối Dropbox outbound bất thường từ máy chủ.
- Cloudflare Tunnel (`cloudflared`) cung cấp C2 dự phòng qua cổng 443 outbound.<sup>[[4]](#references)</sup>

```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```

### Dịch vụ

Các đường dẫn nơi có thể cài đặt mã độc dưới dạng dịch vụ:

- **/etc/inittab**: Gọi các script khởi tạo như rc.sysinit, từ đó chuyển tiếp đến các script khởi động.
- **/etc/rc.d/** và **/etc/rc.boot/**: Chứa các script khởi động dịch vụ; thư mục sau thường có trong các phiên bản Linux cũ.
- **/etc/init.d/**: Được dùng trong một số phiên bản Linux như Debian để lưu các script khởi động.
- Dịch vụ cũng có thể được kích hoạt thông qua **/etc/inetd.conf** hoặc **/etc/xinetd/**, tùy biến thể Linux.
- **/etc/systemd/system**: Thư mục chứa các script dành cho trình quản lý hệ thống và dịch vụ.
- **/etc/systemd/system/multi-user.target.wants/**: Chứa các liên kết đến những dịch vụ cần khởi động trong runlevel nhiều người dùng.
- **/usr/local/etc/rc.d/**: Dành cho các dịch vụ tùy chỉnh hoặc của bên thứ ba.
- **\~/.config/autostart/**: Dành cho các ứng dụng tự khởi động theo từng người dùng; đây có thể là nơi ẩn mã độc nhắm vào người dùng.
- **/lib/systemd/system/**: Chứa các tệp unit mặc định trên toàn hệ thống do các gói đã cài đặt cung cấp.

#### Săn tìm: systemd timers và transient units

Cơ chế duy trì hiện diện của systemd không chỉ giới hạn ở các tệp `.service`. Hãy kiểm tra các unit `.timer`, unit cấp người dùng và **transient units** được tạo trong thời gian chạy.

```bash
# Enumerate timers and inspect referenced services
systemctl list-timers --all
systemctl cat <name>.timer
systemctl cat <name>.service

# Search common system and user paths
find /etc/systemd/system /run/systemd/system /usr/lib/systemd/system -maxdepth 3 \( -name '*.service' -o -name '*.timer' \) -ls
find /home -path '*/.config/systemd/user/*' -type f \( -name '*.service' -o -name '*.timer' \) -ls

# Transient units created via systemd-run often land here
find /run/systemd/transient -maxdepth 2 -type f -ls 2>/dev/null

# Pull execution history for a suspicious unit
journalctl -u <name>.service
journalctl _SYSTEMD_UNIT=<name>.service
```

Các transient unit rất dễ bị bỏ sót vì `/run/systemd/transient/` **không được lưu bền vững**. Nếu đang thu thập live image, hãy lấy nó trước khi tắt máy.

### Kernel Modules

Các kernel module của Linux, thường được malware sử dụng làm thành phần rootkit, được tải khi hệ thống khởi động. Các thư mục và tệp quan trọng đối với những module này bao gồm:

- **/lib/modules/$(uname -r)**: Chứa các module dành cho phiên bản kernel đang chạy.
- **/etc/modprobe.d**: Chứa các tệp cấu hình để kiểm soát việc tải module.
- **/etc/modprobe** và **/etc/modprobe.conf**: Các tệp thiết lập module trên toàn cục.

### Các vị trí tự khởi chạy khác

Linux sử dụng nhiều tệp khác nhau để tự động chạy chương trình khi người dùng đăng nhập; các tệp này có thể chứa malware:

- **/etc/profile.d/**\*, **/etc/profile**, và **/etc/bash.bashrc**: Được thực thi khi bất kỳ người dùng nào đăng nhập.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile**, và **\~/.config/autostart**: Các tệp riêng của người dùng, chạy khi họ đăng nhập.
- **/etc/rc.local**: Chạy sau khi tất cả dịch vụ hệ thống đã khởi động, đánh dấu thời điểm kết thúc quá trình chuyển sang môi trường nhiều người dùng.

## Kiểm tra log

Hệ thống Linux theo dõi hoạt động của người dùng và các sự kiện hệ thống thông qua nhiều tệp log. Những log này có vai trò then chốt trong việc phát hiện truy cập trái phép, nhiễm malware và các sự cố bảo mật khác.<sup>[[2]](#references)</sup> Các tệp log quan trọng gồm:

- **/var/log/syslog** (Debian) hoặc **/var/log/messages** (RedHat): Ghi lại thông báo và hoạt động trên toàn hệ thống.
- **/var/log/auth.log** (Debian) hoặc **/var/log/secure** (RedHat): Ghi lại các lần xác thực, bao gồm đăng nhập thành công và thất bại.
  - Dùng `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` để lọc các sự kiện xác thực liên quan.
- **/var/log/boot.log**: Chứa các thông báo khi hệ thống khởi động.
- **/var/log/maillog** hoặc **/var/log/mail.log**: Ghi lại hoạt động của máy chủ email, hữu ích để theo dõi các dịch vụ liên quan đến email.
- **/var/log/kern.log**: Lưu thông báo của kernel, bao gồm lỗi và cảnh báo.
- **/var/log/dmesg**: Chứa thông báo của trình điều khiển thiết bị.
- **/var/log/faillog**: Ghi lại các lần đăng nhập thất bại, hỗ trợ điều tra vi phạm bảo mật.
- **/var/log/cron**: Ghi lại việc thực thi các cron job.
- **/var/log/daemon.log**: Theo dõi hoạt động của các dịch vụ chạy nền.
- **/var/log/btmp**: Ghi lại các lần đăng nhập thất bại.
- **/var/log/httpd/**: Chứa log lỗi và truy cập của Apache HTTPD.
- **/var/log/mysqld.log** hoặc **/var/log/mysql.log**: Ghi lại hoạt động của cơ sở dữ liệu MySQL.
- **/var/log/xferlog**: Ghi lại các lần truyền tệp FTP.
- **/var/log/**: Luôn kiểm tra xem có log bất thường ở đây không.

> [!TIP]
> Log hệ thống Linux và các hệ thống con kiểm tra có thể bị vô hiệu hóa hoặc xóa trong sự cố xâm nhập hay malware. Vì log trên hệ thống Linux thường chứa một số thông tin hữu ích nhất về hoạt động độc hại, kẻ xâm nhập thường xuyên xóa chúng. Do đó, khi kiểm tra các tệp log hiện có, điều quan trọng là tìm các khoảng trống hoặc mục không đúng thứ tự, vì chúng có thể cho thấy log đã bị xóa hoặc can thiệp.

### Phân loại ban đầu Journald (`journalctl`)

Trên các máy Linux hiện đại, **systemd journal** thường là nguồn thông tin có giá trị nhất về **việc thực thi dịch vụ**, **sự kiện xác thực**, **hoạt động gói phần mềm** và **thông báo từ kernel/không gian người dùng**. Khi ứng phó trực tiếp, hãy cố gắng lưu giữ cả journal **bền vững** (`/var/log/journal/`) lẫn journal **thời gian chạy** (`/run/log/journal/`), vì hoạt động ngắn hạn của kẻ tấn công có thể chỉ tồn tại trong journal sau.<sup>[[5]](#references)</sup>

```bash
# List available boots and pivot around the suspicious one
journalctl --list-boots
journalctl -b -1

# Review a mounted image or copied journal directory offline
journalctl --directory /mnt/image/var/log/journal --list-boots
journalctl --directory /mnt/image/var/log/journal -b -1

# Inspect a single journal file and check integrity/corruption
journalctl --file system.journal --header
journalctl --file system.journal --verify

# High-signal filters
journalctl -u ssh.service
journalctl _SYSTEMD_UNIT=cron.service
journalctl _UID=0
journalctl _EXE=/usr/sbin/useradd
```

Các trường journal hữu ích cho việc triage bao gồm `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID` và `MESSAGE`. Nếu journald được cấu hình không dùng bộ nhớ lưu trữ lâu dài, chỉ nên kỳ vọng tìm thấy dữ liệu gần đây trong `/run/log/journal/`.

### Triage framework audit (`auditd`)

Nếu `auditd` được bật, hãy ưu tiên dùng nó khi cần **quy kết tiến trình** cho các thay đổi tệp, thực thi lệnh, hoạt động đăng nhập hoặc cài đặt gói.<sup>[[6]](#references)</sup>

```bash
# Fast summaries
aureport --start today --summary -i
aureport --start today --login --failed -i
aureport --start today --executable -i

# Search raw events
ausearch --start today -m EXECVE -i
ausearch --start today -ua 1000 -m USER_CMD,EXECVE -i
ausearch --start today -m SERVICE_START,SERVICE_STOP -i

# Software installation/update events (especially useful on RHEL-like systems)
ausearch -m SOFTWARE_UPDATE -i
```

Khi các rule được triển khai kèm theo key, hãy pivot từ chúng thay vì grep trực tiếp log thô:

```bash
ausearch --start this-week -k <rule_key> --raw | aureport --file --summary -i
ausearch --start this-week -k <rule_key> --raw | aureport --user --summary -i
```

**Linux duy trì lịch sử lệnh cho từng người dùng**, được lưu tại:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

Ngoài ra, lệnh `last -Faiwx` cung cấp danh sách các lần đăng nhập của người dùng. Hãy kiểm tra danh sách này để tìm các lần đăng nhập không xác định hoặc bất thường.

Kiểm tra các tệp có thể cấp thêm quyền:

- Xem lại `/etc/sudoers` để tìm các quyền người dùng bất thường có thể đã được cấp.
- Xem lại `/etc/sudoers.d/` để tìm các quyền người dùng bất thường có thể đã được cấp.
- Kiểm tra `/etc/groups` để xác định các thành viên nhóm hoặc quyền bất thường.
- Kiểm tra `/etc/passwd` để xác định các thành viên nhóm hoặc quyền bất thường.

Một số ứng dụng cũng tạo nhật ký riêng:

- **SSH**: Kiểm tra _\~/.ssh/authorized_keys_ và _\~/.ssh/known_hosts_ để tìm các kết nối từ xa trái phép.
- **Gnome Desktop**: Kiểm tra _\~/.recently-used.xbel_ để xem các tệp được truy cập gần đây qua ứng dụng Gnome.
- **Firefox/Chrome**: Kiểm tra lịch sử trình duyệt và các tệp tải xuống trong _\~/.mozilla/firefox_ hoặc _\~/.config/google-chrome_ để tìm hoạt động đáng ngờ.
- **VIM**: Xem lại _\~/.viminfo_ để biết chi tiết sử dụng, chẳng hạn như đường dẫn tệp đã truy cập và lịch sử tìm kiếm.
- **Open Office**: Kiểm tra các tài liệu được truy cập gần đây để tìm dấu hiệu cho thấy tệp đã bị xâm phạm.
- **FTP/SFTP**: Xem lại nhật ký trong _\~/.ftp_history_ hoặc _\~/.sftp_history_ để tìm các lần truyền tệp có thể trái phép.
- **MySQL**: Kiểm tra _\~/.mysql_history_ để xem các truy vấn MySQL đã thực thi, có thể tiết lộ hoạt động cơ sở dữ liệu trái phép.
- **Less**: Phân tích _\~/.lesshst_ để xem lịch sử sử dụng, bao gồm các tệp đã xem và lệnh đã thực thi.
- **Git**: Kiểm tra _\~/.gitconfig_ và _.git/logs_ của dự án để tìm các thay đổi đối với repository.

### Nhật ký USB

[**usbrip**](https://github.com/snovvcrash/usbrip) là một phần mềm nhỏ được viết hoàn toàn bằng Python 3, phân tích các tệp nhật ký Linux (`/var/log/syslog*` hoặc `/var/log/messages*`, tùy theo distro) để tạo bảng lịch sử sự kiện USB.

Việc **biết tất cả USB đã được sử dụng** là rất hữu ích; sẽ càng hữu ích hơn nếu bạn có danh sách USB được phép để tìm các “sự kiện vi phạm” (việc sử dụng USB không có trong danh sách đó).

### Cài đặt

```bash
pip3 install usbrip
usbrip ids download #Download USB ID database
```

### Ví dụ

```bash
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```

Thêm ví dụ và thông tin tại GitHub: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## Kiểm tra tài khoản người dùng và hoạt động đăng nhập

Kiểm tra _**/etc/passwd**_, _**/etc/shadow**_ và **nhật ký bảo mật** để tìm tên hoặc tài khoản bất thường được tạo và/hoặc sử dụng gần thời điểm xảy ra các sự kiện trái phép đã biết. Ngoài ra, hãy kiểm tra các cuộc tấn công brute-force sudo.\
Đồng thời, kiểm tra các tệp như _**/etc/sudoers**_ và _**/etc/groups**_ để tìm các quyền không mong muốn được cấp cho người dùng.\
Cuối cùng, hãy tìm các tài khoản **không có mật khẩu** hoặc có mật khẩu **dễ đoán**.<sup>[[1]](#references)</sup>

## Kiểm tra hệ thống tệp

### Phân tích cấu trúc hệ thống tệp trong điều tra malware

Khi điều tra các sự cố malware, cấu trúc hệ thống tệp là một nguồn thông tin quan trọng, giúp tiết lộ cả trình tự sự kiện lẫn nội dung của malware. Tuy nhiên, các tác giả malware đang phát triển những kỹ thuật cản trở việc phân tích này, chẳng hạn như sửa đổi dấu thời gian của tệp hoặc tránh sử dụng hệ thống tệp để lưu trữ dữ liệu.<sup>[[1]](#references)</sup>

Để đối phó với các phương pháp anti-forensic này, cần:

- **Tiến hành phân tích dòng thời gian kỹ lưỡng** bằng các công cụ như **Autopsy** để trực quan hóa dòng thời gian sự kiện hoặc `mactime` của **Sleuth Kit** để lấy dữ liệu dòng thời gian chi tiết.
- **Điều tra các script bất thường** trong $PATH của hệ thống, có thể bao gồm script shell hoặc PHP do kẻ tấn công sử dụng.
- **Kiểm tra `/dev` để tìm các tệp bất thường**; thư mục này thường chứa các tệp đặc biệt, nhưng cũng có thể chứa các tệp liên quan đến malware.
- **Tìm các tệp hoặc thư mục ẩn** có tên như ".. " (dot dot space) hoặc "..^G" (dot dot control-G), có thể được dùng để che giấu nội dung độc hại.
- **Xác định các tệp setuid root** bằng lệnh: `find / -user root -perm -04000 -print` Lệnh này tìm các tệp có quyền cao, có thể bị kẻ tấn công lạm dụng.
- **Kiểm tra dấu thời gian xóa** trong các bảng inode để phát hiện việc xóa hàng loạt tệp, có thể cho thấy sự hiện diện của rootkit hoặc trojan.
- **Kiểm tra các inode liên tiếp** để tìm những tệp độc hại nằm gần đó sau khi xác định được một tệp, vì chúng có thể đã được đặt cạnh nhau.
- **Kiểm tra các thư mục chứa binary phổ biến** (_/bin_, _/sbin_) để tìm các tệp mới được sửa đổi, vì malware có thể đã thay đổi chúng.

````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````

> [!TIP]
> Lưu ý rằng **kẻ tấn công** có thể **thay đổi** **thời gian** để khiến **các tệp trông có vẻ** **hợp pháp**, nhưng không thể thay đổi **inode**. Nếu bạn thấy một **tệp** cho biết nó được tạo và chỉnh sửa **cùng thời điểm** với các tệp còn lại trong cùng thư mục, nhưng **inode** lại **lớn hơn bất thường**, thì **dấu thời gian của tệp đó đã bị thay đổi**.

### Phân loại nhanh tập trung vào inode

Nếu nghi ngờ có anti-forensics, hãy sớm chạy các bước kiểm tra tập trung vào inode sau:

```bash
# Filesystem inode pressure (possible inode exhaustion DoS)
df -i

# Identify all names that point to one inode
find / -xdev -inum <inode_number> 2>/dev/null

# Find deleted files still open by running processes
lsof +L1
lsof | grep '(deleted)'
```

Khi một inode đáng ngờ nằm trên image/thiết bị của hệ thống tệp EXT, hãy kiểm tra trực tiếp metadata của inode:

```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```

Các trường hữu ích:
- **Links**: nếu là `0`, hiện không có mục thư mục nào tham chiếu đến inode.
- **dtime**: dấu thời gian xóa được đặt khi inode bị gỡ liên kết.
- **ctime/mtime**: giúp đối chiếu các thay đổi về metadata/nội dung với dòng thời gian của sự cố.

### Capabilities, xattrs và rootkit userland dựa trên preload

Cơ chế duy trì truy cập trên Linux hiện đại thường tránh các binary `setuid` dễ nhận thấy, thay vào đó lạm dụng **file capabilities**, **extended attributes** và dynamic loader.

```bash
# Enumerate file capabilities (think cap_setuid, cap_sys_admin, cap_dac_override)
getcap -r / 2>/dev/null

# Inspect extended attributes on suspicious binaries and libraries
getfattr -d -m - /path/to/suspicious/file 2>/dev/null

# Global preload hook affecting every dynamically linked binary
cat /etc/ld.so.preload 2>/dev/null
stat /etc/ld.so.preload 2>/dev/null

# If a suspicious library is referenced, inspect its metadata and links
ls -lah /lib /lib64 /usr/lib /usr/lib64 /usr/local/lib 2>/dev/null | grep -E '\\.so(\\.|$)'
ldd /bin/ls
```

Đặc biệt chú ý đến các thư viện được tham chiếu từ những đường dẫn **có quyền ghi** như `/tmp`, `/dev/shm`, `/var/tmp` hoặc các vị trí bất thường trong `/usr/local/lib`. Đồng thời kiểm tra các binary có capability nằm ngoài phạm vi quản lý gói thông thường và đối chiếu chúng với kết quả xác minh gói (`rpm -Va`, `dpkg --verify`, `debsums`).

## So sánh các phiên bản filesystem

### Tóm tắt so sánh phiên bản filesystem

Để so sánh các phiên bản filesystem và xác định những thay đổi, chúng ta dùng các lệnh `git diff` đơn giản hóa:<sup>[[3]](#references)</sup>

- **Để tìm các file mới**, hãy so sánh hai thư mục:

```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```

- **Đối với nội dung đã chỉnh sửa**, hãy liệt kê các thay đổi và bỏ qua những dòng cụ thể:

```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```

- **Để phát hiện các tệp đã bị xóa**:

```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```

- **Tùy chọn lọc** (`--diff-filter`) giúp thu hẹp kết quả vào các thay đổi cụ thể như tệp được thêm (`A`), bị xóa (`D`) hoặc được sửa đổi (`M`).
  - `A`: Tệp được thêm
  - `C`: Tệp được sao chép
  - `D`: Tệp bị xóa
  - `M`: Tệp được sửa đổi
  - `R`: Tệp được đổi tên
  - `T`: Thay đổi loại (ví dụ: tệp thành symlink)
  - `U`: Tệp chưa được hợp nhất
  - `X`: Tệp không xác định
  - `B`: Tệp bị hỏng

## References

- [1] [Cẩm nang thực địa về điều tra pháp chứng malware trên hệ thống Linux: Cẩm nang thực địa về điều tra pháp chứng kỹ thuật số – Chương 3](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [2] [Giải thích về log Linux](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [3] [Tài liệu git diff – tùy chọn --diff-filter](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- [4] [Red Canary – Vá lỗi để duy trì quyền truy cập: Cách malware DripDropper trên Linux di chuyển trong cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [5] [Phân tích pháp chứng nhật ký Linux](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [6] [Red Hat Enterprise Linux 9 - Kiểm tra hệ thống](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)
- [7] [Chào Pike!](https://www.synacktiv.com/en/publications/say-hi-to-pike.html)
- [8] [strace](https://strace.io/)
- [9] [Tiện ích mở rộng SQLite FTS5](https://www.sqlite.org/fts5.html)
{{#include ../../banners/hacktricks-training.md}}
