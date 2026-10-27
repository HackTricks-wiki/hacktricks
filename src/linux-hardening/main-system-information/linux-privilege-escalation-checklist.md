# Danh sách kiểm tra nâng quyền Linux

{{#include ../../banners/hacktricks-training.md}}

# Danh sách kiểm tra - Nâng quyền Linux



### **Công cụ tốt nhất để tìm các vector nâng quyền cục bộ trên Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Thông tin hệ thống](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Lấy **thông tin hệ điều hành**
- [ ] Kiểm tra [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path), có **thư mục nào ghi được** không?
- [ ] Kiểm tra [**biến môi trường**](../linux-basics/linux-privilege-escalation/index.html#env-info), có thông tin nhạy cảm nào không?
- [ ] Tìm [**kernel exploit**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **bằng script** (DirtyCow?)
- [ ] Trước khi chạy kernel PoC, hãy xác minh **các điều kiện tiên quyết thực tế**, không chỉ dựa vào `uname -r`: kiến trúc, các tùy chọn/module `CONFIG_*` bắt buộc, khả năng tạo namespace và các biện pháp giảm thiểu đang hoạt động. Ví dụ: kiểm tra khả năng sử dụng user/network namespace bằng `unshare -Urn true`; các exploit netfilter hiện đại có thể cần `CONFIG_USER_NS`, user namespace không đặc quyền và `CONFIG_NF_TABLES`.<sup>[[3]](#references)</sup>
- [ ] **Kiểm tra** xem [**phiên bản sudo có lỗ hổng hay không**](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** xác minh chữ ký thất bại](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Kiểm tra [**cấu hình sai kernel module và việc tải module**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, thực thi chữ ký và `modules_disabled`.
- [ ] Kiểm tra [**các đường dẫn lạm dụng kernel.modprobe / modprobe_path**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) nếu có thể sửa đổi hoặc kích hoạt đường dẫn helper.
- [ ] Kiểm tra [**các đường dẫn ghi được trong /lib/modules**](kernel-modules-and-modprobe.md#writable-libmodules-review), bao gồm các tệp `.ko*` và metadata `modules.*` ghi được.
- [ ] Liệt kê thêm thông tin hệ thống ([ngày giờ, thống kê hệ thống, thông tin CPU, máy in](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Liệt kê thêm các biện pháp phòng thủ](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Ổ đĩa](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Liệt kê** các ổ đĩa đã mount
- [ ] Có ổ đĩa nào **chưa được mount** không?
- [ ] Có **thông tin đăng nhập trong fstab** không?

### [**Phần mềm đã cài đặt**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Kiểm tra xem có cài đặt** [**phần mềm hữu ích**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **hay không**
- [ ] **Kiểm tra xem có cài đặt** [**phần mềm dễ bị tấn công**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **hay không**
- [ ] Trên Debian/Ubuntu, kiểm tra xem đã cài đặt/bật **quét interpreter của needrestart** chưa: `dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`. Các bản dễ bị tấn công đã vượt qua ranh giới đặc quyền bằng cách tái sử dụng `PYTHONPATH`/`RUBYLIB` do attacker kiểm soát, chạy đua với `/proc/<pid>/exe` hoặc quét các đường dẫn Perl do attacker kiểm soát khi APT hoặc `unattended-upgrades` gọi needrestart với quyền root.<sup>[[4]](#references)</sup>

### [Tiến trình](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Có **phần mềm không rõ nguồn gốc nào đang chạy** không?
- [ ] Có phần mềm nào chạy với **đặc quyền cao hơn mức cần thiết** không?
- [ ] Tìm **exploit cho các tiến trình đang chạy** (đặc biệt là phiên bản đang chạy).
- [ ] Bạn có thể **sửa binary** của tiến trình đang chạy nào không?
- [ ] **Theo dõi tiến trình** và kiểm tra xem có tiến trình đáng chú ý nào chạy thường xuyên không.
- [ ] Bạn có thể **đọc** bộ nhớ của **tiến trình đáng chú ý** nào không (nơi có thể lưu mật khẩu)?

### [Tác vụ đã lên lịch/Cron?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Có cron nào đang sửa đổi [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path) và bạn có thể **ghi** vào đó không?
- [ ] Có [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)nào trong tác vụ cron không?
- [ ] Có [**script có thể sửa đổi** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)nào đang được **thực thi** hoặc nằm trong **thư mục có thể sửa đổi** không?
- [ ] Bạn có phát hiện **script** nào có thể hoặc đang được [**thực thi** rất **thường xuyên**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs) không? (mỗi 1, 2 hoặc 5 phút)

### [Dịch vụ](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Có tệp **.service ghi được** nào không?
- [ ] Có **binary ghi được** nào được **dịch vụ** thực thi không?
- [ ] Có **helper, tệp cấu hình hoặc tệp môi trường ghi được nào được root unit tham chiếu** không (`ExecStartPre=`, `ExecStartPost=`, `EnvironmentFile=`)? Kiểm tra unit đã hợp nhất bằng `systemctl cat <unit>` và xem lại [việc lạm dụng tệp service/socket](../interesting-files-permissions/write-to-root.md).
- [ ] Có workflow đặc quyền theo yêu cầu nào chạy helper trong thư mục cấp thấp hơn mà người dùng có thể ghi không? Kiểm tra cả helper lẫn thư mục cha để tìm [việc thực thi đường dẫn do người dùng sửa đổi với quyền root](../interesting-files-permissions/write-to-root.md#root-executing-user-writable-scriptsbinaries); helper chạy trong thời gian ngắn có thể chỉ xuất hiện khi workflow đang chạy.
- [ ] Có **thư mục nào trong PATH của systemd ghi được** không?
- [ ] Có **systemd unit drop-in ghi được** nào trong `/etc/systemd/system/<unit>.d/*.conf` có thể ghi đè `ExecStart`/`User` không?<sup>[[2]](#references)</sup>

### [Timer](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Có **timer ghi được** nào không?

### [Socket](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Có tệp **.socket ghi được** nào không?
- [ ] Bạn có thể **giao tiếp với socket nào** không?
- [ ] Có **HTTP socket** nào chứa thông tin đáng chú ý không?
- [ ] Bạn có thể truy cập [**API của container runtime hoặc node agent**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) như `docker.sock`, `containerd.sock`, `crio.sock`, `podman.sock`, `buildkitd.sock` hoặc endpoint kubelet không? Hãy kiểm tra API HTTP/gRPC thô ngay cả khi không có CLI thường dùng.

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Bạn có thể **giao tiếp với D-Bus nào** không?

### [Mạng](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Liệt kê mạng để xác định vị trí của bạn
- [ ] Có **cổng mở nào trước đây bạn không truy cập được** nhưng giờ có thể truy cập sau khi lấy được shell trên máy không?
- [ ] Bạn có thể **bắt gói tin** bằng `tcpdump` không?

### [Người dùng](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Liệt kê **người dùng/nhóm** thông thường
- [ ] Bạn có **UID rất lớn** không? **Máy** có **dễ bị tấn công** không?
- [ ] Bạn có thể [**nâng quyền nhờ một nhóm**](../user-information/interesting-groups-linux-pe/index.html) mà bạn thuộc về không?
- [ ] Có dữ liệu **clipboard** không?
- [ ] Chính sách mật khẩu?
- [ ] Thử **dùng** mọi **mật khẩu đã biết** mà bạn phát hiện trước đó để đăng nhập bằng **từng người dùng** có thể. Cũng thử đăng nhập không cần mật khẩu.

### [PATH ghi được](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Nếu bạn có **quyền ghi vào thư mục nào đó trong PATH**, bạn có thể nâng quyền

### [Lệnh SUDO và SUID](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Bạn có thể chạy **lệnh nào bằng sudo** không? Bạn có thể dùng nó để ĐỌC, GHI hoặc THỰC THI bất cứ thứ gì với quyền root không? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Nếu `sudo -l` cho phép `sudoedit`, hãy kiểm tra **chèn tham số sudoedit** (CVE-2023-22809) thông qua `SUDO_EDITOR`/`VISUAL`/`EDITOR` để sửa các tệp tùy ý trên phiên bản dễ bị tấn công (`sudo -V` < 1.9.12p2). Ví dụ: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`.<sup>[[1]](#references)</sup>
- [ ] Có **binary SUID nào có thể bị khai thác** không? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Các lệnh [**sudo** có bị giới hạn theo **đường dẫn** không? Bạn có thể **vượt qua** các hạn chế đó không](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Lệnh Sudo/binary SUID không chỉ định đường dẫn**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**Binary SUID chỉ định đường dẫn**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Vượt qua giới hạn
- [ ] [**Lỗ hổng LD_PRELOAD**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] Có [**thiếu thư viện .so trong binary SUID**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) nằm trong thư mục ghi được không?
- [ ] Có [**RPATH/RUNPATH của SUID hoặc đường dẫn thư viện ghi được**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath) không?
- [ ] Có [**SUDO token khả dụng**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens) không? [**Bạn có thể tạo SUDO token**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than) không?
- [ ] Bạn có thể [**đọc hoặc sửa tệp sudoers**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d) không?
- [ ] Bạn có thể [**sửa đổi /etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration) không?
- [ ] Lệnh [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas)

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] Có binary nào sở hữu **capability bất thường** không?

### [ACL](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] Có tệp nào sở hữu **ACL bất thường** không?

### [Phiên shell đang mở](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL PRNG có thể dự đoán - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Các giá trị cấu hình SSH đáng chú ý**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Tệp đáng chú ý](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Tệp profile** - Có thể đọc dữ liệu nhạy cảm không? Có thể ghi để nâng quyền không?
- [ ] **Tệp passwd/shadow** - Có thể đọc dữ liệu nhạy cảm không? Có thể ghi để nâng quyền không?
- [ ] **Kiểm tra các thư mục thường chứa thông tin đáng chú ý** để tìm dữ liệu nhạy cảm
- [ ] **Tệp ở vị trí lạ/thuộc sở hữu bất thường,** bạn có thể truy cập hoặc sửa đổi các tệp thực thi
- [ ] Tệp được **sửa đổi** trong vài phút gần đây
- [ ] **Tệp cơ sở dữ liệu Sqlite**
- [ ] **Tệp ẩn**
- [ ] **Script/Binary trong PATH**
- [ ] **Tệp web** (mật khẩu?)
- [ ] **Bản sao lưu**?
- [ ] **Các tệp thường chứa mật khẩu**: Dùng **Linpeas** và **LaZagne**
- [ ] **Tìm kiếm tổng quát**

### [**Tệp ghi được**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] Có thể **sửa thư viện python** để chạy lệnh tùy ý không?
- [ ] Bạn có thể **sửa tệp log** không? Exploit **Logtotten**
- [ ] Bạn có thể **sửa /etc/sysconfig/network-scripts/** không? Exploit Centos/Redhat
- [ ] Bạn có thể [**ghi vào các tệp ini, int.d, systemd hoặc rc.d**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d) không?

### [**Thủ thuật khác**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Bạn có thể [**lạm dụng NFS để nâng quyền**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation) không?
- [ ] Bạn có cần [**thoát khỏi shell bị hạn chế**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells) không?



## References

- [1] [Khuyến cáo bảo mật của Sudo: sudoedit cho phép sửa tệp tùy ý](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Tài liệu Oracle Linux: cấu hình systemd drop-in](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn: yêu cầu và nghiên cứu về exploit CVE-2024-1086](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Khuyến cáo bảo mật của Qualys: LPE trong needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
