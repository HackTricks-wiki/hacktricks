# Liệt kê tiến trình và đường dẫn dịch vụ

{{#include ../../banners/hacktricks-training.md}}

Câu hỏi hữu ích là tiến trình có đặc quyền nào đang sử dụng dữ liệu hoặc mã mà người dùng có ít đặc quyền hơn có thể kiểm soát. Kiểm tra cây tiến trình, môi trường đang chạy, các tệp đang mở và unit hoặc script đã khởi chạy từng tiến trình đáng chú ý.

## Ánh xạ tiến trình và chủ sở hữu

```bash
ps -eo user,pid,ppid,tty,comm,args --sort=ppid
pstree -alp 2>/dev/null
systemctl list-units --type=service --state=running 2>/dev/null
ss -lntup
```

Một quan hệ cha-con giữa các người dùng khác nhau có thể là bình thường, nhưng một chuyển tiếp bất thường cần được xem xét: kiểm tra lệnh của tiến trình cha, các đối số, tệp thực thi, thư mục làm việc và các tệp được tham chiếu. Dùng [users and sessions](../user-information/user-and-session-triage.md) để xác định chủ sở hữu và ngữ cảnh đăng nhập.

### Console máy ảo cục bộ

Xem xét các tùy chọn `-spice` của tiến trình QEMU cùng với địa chỉ đang lắng nghe. [Tài liệu QEMU](https://www.qemu.org/docs/master/system/qemu-manpage.html) nêu rằng `disable-ticketing` cho phép các client SPICE kết nối mà không cần xác thực. Listener gắn với loopback vẫn có khả năng được những người dùng khác trên máy chủ cục bộ truy cập. Xác nhận listener đang hoạt động, các tùy chọn xác thực và quyền truy cập cục bộ trước khi kết luận rằng command line làm lộ console. Việc điều khiển console ảnh hưởng đến **guest**; có được tài khoản guest hoặc thay đổi trạng thái khởi động của guest cần các điều kiện riêng ở phía guest và không cấp quyền root trên host ảo hóa. Đọc đối số tiến trình và metadata socket mà không kết nối tới hoặc khởi động lại guest trong quá trình liệt kê thụ động.

Một web interface có thể truy cập cục bộ có thể thực thi code bằng tài khoản dịch vụ, ngay cả khi shell ban đầu không thể truy cập các tệp của tài khoản đó. Ví dụ, CVE-2023-0297 ảnh hưởng đến xử lý `/flash/addcrypted2` của pyLoad khi JavaScript không đáng tin cậy được chuyển tới Js2Py với tính năng import Python được bật; [bản sửa upstream](https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d) đã tắt `pyimport`. Đối chiếu chủ sở hữu tiến trình đang chạy, địa chỉ lắng nghe, mức độ lộ endpoint và bản vá đã cài đặt hoặc bản backport của nhà cung cấp trước khi xem tiến trình pyLoad là một đường dẫn leo thang đặc quyền. Chỉ riêng tên tiến trình, cổng đang mở hoặc phiên bản package không chứng minh được hệ thống bị lộ; quá trình liệt kê thụ động không nên gửi payload thực thi.

### Privileged login shell dùng chung terminal

Một shell tương tác có đặc quyền chạy `su --login <user>` mà không có pseudo-terminal riêng có thể để terminal dùng chung với login shell có ít đặc quyền hơn. Nếu có thể kiểm soát startup file của người dùng đó và code trong file có thể dùng `TIOCSTI` để chèn input vào terminal, input đó có thể đến shell có đặc quyền khi shell này tiếp tục hoạt động. [Tài liệu util-linux `su`](https://man7.org/linux/man-pages/man1/su.1.html#SECURITY_NOTES) mô tả rủi ro dùng chung terminal và khuyến nghị dùng `su --pty`/`-P` khi thao tác tương tác; `su -c` khởi chạy một session riêng không có controlling terminal. Rủi ro này phụ thuộc vào shell cha thực tế, quan hệ terminal, startup file đích và chính sách kernel. Chỉ riêng tên tiến trình hoặc đối số `su -l` chỉ là dấu hiệu cần xem xét thêm.

Kiểm tra cây tiến trình quan sát được và các cột TTY, sau đó kiểm tra launcher có thể đọc được cùng chủ sở hữu/quyền của startup file. Trên Linux, `/proc/sys/dev/tty/legacy_tiocsti` có thể giúp xác định chính sách khi có tệp này; việc không có tệp không chứng minh hệ thống an toàn. [Tài liệu Linux `TIOCSTI`](https://man7.org/linux/man-pages/man2/TIOCSTI.2const.html) lưu ý rằng kể từ Linux 6.2, thao tác này có thể yêu cầu `CAP_SYS_ADMIN` khi sysctl này là false. Không gọi ioctl này chỉ để liệt kê máy chủ.

Đôi khi một tài khoản database có thể sửa startup file của người dùng đích mà không có quyền ghi trực tiếp lên filesystem. `COPY ... TO 'filename'` phía máy chủ PostgreSQL ghi tệp bằng tài khoản OS của database server, nhưng [các giới hạn của PostgreSQL](https://www.postgresql.org/docs/current/sql-copy.html) chỉ cho phép dạng tệp này đối với database superuser hoặc các role như `pg_write_server_files`. Xác nhận cả database role lẫn quyền tệp của OS server; chỉ riêng connection string của ứng dụng không cấp quyền ghi tệp. Khi đánh giá chuỗi tấn công, hãy xem xét riêng launcher có đặc quyền và các khả năng của tài khoản database.

## Kiểm tra artifact runtime

```bash
readlink /proc/<PID>/exe
tr '\0' ' ' </proc/<PID>/cmdline; echo
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

Các executable đã bị xóa và các file đã bị xóa nhưng vẫn đang mở sẽ tiếp tục được tham chiếu cho đến khi descriptor cuối cùng đóng lại. Chúng có thể lưu giữ bằng chứng hoặc các secret có thể truy cập được. Môi trường và bộ nhớ của process có thể chứa thông tin xác thực, nhưng việc đọc process khác bị giới hạn bởi quyền sở hữu, các tùy chọn mount `/proc`, chính sách ptrace của Yama và những biện pháp kiểm soát bảo mật khác. Xem [file descriptors](../main-system-information/filesystem-links-and-file-descriptors.md) và [post-exploitation credential hunting](../post-exploitation/README.md) để biết các kỹ thuật liên quan.

Các syscall trace đã lưu là một ranh giới quyền truy cập file khác. [`strace` ghi các đối số syscall vào file đầu ra](https://man7.org/linux/man-pages/man1/strace.1.html), vì vậy một trace có thể đọc được của các đối số [`execve`](https://man7.org/linux/man-pages/man2/execve.2.html) có thể làm lộ mật khẩu mà một job đặc quyền truyền trên command line. Trước tiên, hãy xác minh rằng người dùng hiện tại có thể đọc trace cụ thể đó và đối số thực sự chứa thông tin xác thực; việc chuyển sang một Unix account khác sau đó cần có bằng chứng riêng rằng thông tin xác thực được chấp nhận ở đó. Metadata của file là một manh mối thụ động hữu ích, không cần quét mọi trace hay in nội dung của chúng trong quá trình liệt kê thông thường.

## Socket tự động hóa văn phòng có đặc quyền

LibreOffice và OpenOffice có thể cung cấp API UNO thông qua một đối số `--accept=socket,host=<host>,port=<port>;urp;`. Một process văn phòng do root sở hữu với endpoint có thể truy cập được có thể cho phép người dùng cục bộ có ít đặc quyền hơn gọi các dịch vụ API trong security context của process đó. Service `SystemShellExecute` có một thao tác để khởi chạy lệnh hệ thống. Bind vào loopback sẽ hạn chế khả năng truy cập từ xa, nhưng socket vẫn có thể được người dùng cục bộ truy cập, trừ khi có biện pháp kiểm soát khác ngăn chặn việc này.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
ps -eo user,args | grep -E '[s]office|[l]ibreoffice|[o]penoffice'
ss -ltn 2>/dev/null
```

Đối chiếu chủ sở hữu tiến trình, đối số `--accept` chính xác, cùng địa chỉ và cổng đang lắng nghe. Acceptor được cấu hình nhưng không bind được chỉ là một manh mối; không kết nối hoặc gọi API trong quá trình liệt kê thụ động. Tránh khởi chạy một phiên bản office có đặc quyền chỉ để kiểm tra điều kiện này.

## Bộ nhớ dùng chung System V được các tiến trình có đặc quyền sử dụng

Một helper do root sở hữu có thể tạo một segment bộ nhớ dùng chung System V mà người dùng khác có thể ghi vào. Nếu sau đó helper tin cậy dữ liệu từ segment đó trong một lệnh shell hoặc thao tác nhạy cảm khác, segment này vượt qua ranh giới đặc quyền ngay cả khi executable và các tệp của nó được bảo vệ. `shmget()` lấy quyền truy cập từ chín bit thấp của các flag; mode `0666` cho phép người dùng khác ghi, trong khi flag `IPC_CREAT` không thu hẹp các quyền đó. Kiểm tra thụ động các segment đang hoạt động bằng `ipcs -m` và đối chiếu chủ sở hữu, mode, thời gian tồn tại của chúng với tiến trình có đặc quyền và cách xử lý đầu vào của tiến trình đó. Một segment có quyền ghi cho mọi người dùng tự nó không chứng minh được khả năng thực thi lệnh.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ipcs -m
```

Các segment System V khác với các tệp shared memory POSIX trong `/dev/shm`. Một segment chỉ được tạo trong chốc lát có thể không xuất hiện trong một lần chụp `ipcs`, vì vậy kết quả trống không chứng minh rằng một helper không sử dụng shared memory. Hãy xem xét mã nguồn hoặc hành vi của binary cùng mọi quy tắc `sudo` khởi chạy nó; đừng gọi helper có đặc quyền chỉ để làm segment xuất hiện khi liệt kê. [Hướng dẫn về IPC namespace](../containers-namespaces/container-security/protections/namespaces/ipc-namespace.md) giải thích cách namespace ảnh hưởng đến khả năng hiển thị.<sup>[[2]](#references)[[3]](#references)</sup>

## Kiểm tra script của Consul agent

Consul có thể chạy các kiểm tra tình trạng bằng script với danh tính hệ điều hành của agent. Nếu agent chạy với quyền root, bật `enable_script_checks` và cho phép người dùng có ít đặc quyền hơn đăng ký service kèm kiểm tra bằng script thông qua HTTP API cục bộ, người dùng đó có thể khiến các lệnh chạy với quyền root. Chỉ bind API vào `127.0.0.1` vẫn cho phép người dùng cục bộ truy cập. Cấu hình `enable_local_script_checks` hẹp hơn: cấu hình này loại trừ các kiểm tra bằng script được gửi qua đăng ký HTTP API. Khi bật Consul ACL, việc đăng ký service cần quyền `service:write`; chỉ riêng dòng `acl.default_policy=allow` không chứng minh rằng caller ẩn danh có thể đăng ký. Hãy xem xét đồng thời danh tính thực tế của agent, các thiết lập đã nạp, địa chỉ bind API và cơ chế cấp quyền.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
ps -eo user,args | grep '[c]onsul agent'
ls -l /etc/consul.d 2>/dev/null
```

Theo dõi các đối số `-config-dir` và `-config-file` của agent đang chạy để tìm cấu hình liên quan, và chỉ kiểm tra tên trường cùng các cài đặt của script-check và ACL. Tệp cấu hình cũng có thể chứa gossip key hoặc token; tránh đưa chúng vào log dùng chung. Đừng đăng ký service hay chạy health check chỉ để xác định tình trạng này.

Có một đường dẫn qua tệp cục bộ riêng nếu người dùng có quyền thấp hơn có thể **ghi và tìm kiếm** trong thư mục được chỉ định bởi `-config-dir` của agent chạy bằng quyền root: một định nghĩa service mới có đuôi `.hcl` hoặc `.json` có thể được tải từ thư mục đó. Quyền tìm kiếm và ghi trên thư mục có thể cho phép thêm tệp ngay cả khi không được phép liệt kê nội dung thư mục. Để xác nhận khả năng thực thi lệnh với quyền root, hãy xác minh agent thực sự tải thư mục đó, cài đặt script-check **có hiệu lực** cho phép định nghĩa cục bộ, định nghĩa đã được tải và agent vẫn giữ quyền root. [Consul documents](https://developer.hashicorp.com/consul/docs/fundamentals/agent#reloadable-configurations) nêu rõ những cài đặt và định nghĩa health check nào có thể được tải lại; việc bật script checks có thể cần khởi động lại, vì vậy hãy xác minh hành vi của phiên bản đã cài đặt. Khi ACL bảo vệ agent, [`consul reload` requires `agent:write`](https://developer.hashicorp.com/consul/api-docs/agent#reload-agent); chỉ có quyền ghi KV thì không cấp quyền đó. Xem metadata của thư mục có thể ghi là dấu hiệu cần rà soát, không phải bằng chứng về quyền tải lại, khởi động lại hoặc thực thi lệnh được cấp phép. Kiểm tra đường dẫn, quyền và policy mà không ghi cấu hình hoặc gọi API.

## Theo dõi chuỗi thực thi service

```bash
systemctl cat <unit>.service
systemctl show <unit>.service -p User -p Group -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/from/ExecStart
```

Kiểm tra unit, drop-in, `EnvironmentFile=`, helper script, lệnh tương đối, thư mục có quyền ghi và socket activation. Unit thuộc sở hữu của root vẫn có thể không an toàn nếu nó đọc config hoặc script mà người dùng có quyền ghi. Trang [arbitrary file write](../interesting-files-permissions/write-to-root.md) trình bày các đường lạm dụng service và unit thường gặp. Theo dõi các job chạy trong thời gian ngắn bằng [pspy](https://github.com/DominicBreuker/pspy) hoặc telemetry về audit/process khi một lần chạy `ps` không bắt gặp được chúng.

Với service **xinetd** tùy chỉnh, đối chiếu các mục cấu hình đã bật gồm `server`, `user` và quyền truy cập với listener đang hoạt động và executable chính xác. Cài đặt [`user`](https://manpages.debian.org/testing/xinetd/xinetd.conf.5.en.html) chọn danh tính của process được khởi chạy, trong khi bit set-user-ID trên executable có thể thay đổi riêng danh tính hiệu lực nếu [`execve` cho phép chuyển đổi đó](https://man7.org/linux/man-pages/man2/execve.2.html). Một binary có đặc quyền, có thể truy cập và nhận đầu vào không đáng tin cậy là lý do để xem xét source hoặc disassembly ngoại tuyến nhằm tìm lỗi an toàn bộ nhớ, chẳng hạn như phép chuyển đổi chuỗi [`scanf` không giới hạn](https://www.gnu.org/software/libc/manual/html_node/String-Input-Conversions.html) vào buffer cố định. Ánh xạ service và metadata set-user-ID chỉ là manh mối, không phải bằng chứng về lỗi như vậy; đừng gửi đầu vào gây crash hoặc debug service có đặc quyền đang chạy trong quá trình liệt kê thụ động.

Với listener có đặc quyền tùy chỉnh và source có thể đọc được, xem xét từng độ dài do caller kiểm soát được dùng trong thao tác sao chép như [`memcpy`](https://man7.org/linux/man-pages/man3/memcpy.3.html). Chỉ kiểm tra rằng chỉ số ghi hiện tại nằm trong buffer cố định không chứng minh được **độ dài sao chép** vừa với phần dung lượng còn lại; hãy xác minh `copy_length <= capacity - index` sau khi xác nhận chỉ số nằm trong phạm vi, đồng thời kiểm tra signedness và tràn số học. Đây chỉ là manh mối cần xem xét khi đầu vào đi đến thao tác đó, listener có thể được người dùng ít đặc quyền truy cập và process giữ danh tính hiệu lực cao hơn. Kiểm tra source và metadata process ngoại tuyến; đừng gửi đầu vào gây crash đến service đang chạy trong quá trình liệt kê.

Trên hệ thống dùng **Upstart**, định nghĩa system job có thể nằm trong `/etc/init/*.conf`. File job mà người dùng hiện tại có quyền ghi là điều đáng lưu ý khi daemon init đang hoạt động nạp đúng job đó, stanza `script` hoặc `exec` chạy với danh tính có đặc quyền cao hơn, và người dùng có thể khởi chạy job bằng lệnh `initctl` được phép hoặc một trigger thực tế khác. Chỉ riêng quyền sudo `initctl` không chứng minh rằng file job nào có thể ghi được hoặc job đã sửa sẽ chạy. Kiểm tra quyền của đúng file job, cài đặt run-as hiệu lực, daemon đang hoạt động và trigger; không chỉnh sửa hay khởi chạy job trong quá trình liệt kê. Xem tài liệu [cấu hình job Upstart](https://manpages.ubuntu.com/manpages/trusty/man5/init.5.html) và [`initctl`](https://manpages.ubuntu.com/manpages/xenial/man8/initctl.8.html).

Một file mật khẩu autologin có thể đọc được, chẳng hạn `/etc/autologin/passwd` trên hệ thống mà [boot job đọc đúng đường dẫn này](https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/master/chromeos-base/autologin/files/init/autologin.conf), là manh mối về việc lộ thông tin xác thực. Xác nhận boot job đã được cài đặt và sử dụng file đó, sau đó kiểm tra riêng xem mật khẩu có hợp lệ cho tài khoản hoặc service cục bộ khác hay không. Chỉ tên file không chứng minh được việc tái sử dụng mật khẩu; ghi lại đường dẫn và metadata quyền truy cập mà không đưa mật khẩu vào kết quả liệt kê dùng chung.

`ExecStart=` của unit hoặc một lệnh được lập lịch có thể tiết lộ chính xác đường dẫn đến script trong thư mục không thể liệt kê. [Quyền tìm kiếm thư mục](https://man7.org/linux/man-pages/man7/path_resolution.7.html) vẫn có thể cho phép danh tính hiện tại truy cập đường dẫn đã biết đó; hãy xác nhận quyền tìm kiếm trên mọi thư mục cha và quyền đọc trên file, thay vì cho rằng việc liệt kê thư mục thất bại đồng nghĩa file được bảo vệ. Script đọc được có thể chứa thông tin xác thực để chuyển dữ liệu, nhưng việc truy cập được tài khoản khác đòi hỏi thông tin xác thực đó vẫn hợp lệ và được chấp nhận độc lập ở đó. Ghi lại đường dẫn và bằng chứng về quyền mà không in giá trị bí mật vào log dùng chung.

Với script Node.js CommonJS được lập lịch, xem xét các import không có đường dẫn như `require('package')` ngay cả khi bản thân script chỉ có quyền đọc. [Node tìm `node_modules` cạnh file đang import rồi đến các thư mục cha](https://nodejs.org/api/modules.html#loading-from_node_modules-folders), trước khi chuyển sang các đường dẫn global được cấu hình. Người dùng ít đặc quyền có thể **ghi và tìm kiếm** trong một trong các thư mục cha đó có thể tạo một package được khớp trước. Xác nhận import chính xác đó được thực thi, package được chọn không phải module tích hợp sẵn, có thể tạo hoặc thay đổi đường dẫn liên quan, module được phân giải đến đó trong runtime đã cài đặt và job có đặc quyền cao hơn sẽ nạp nó ở lần chạy sau. Metadata cho thấy thư mục cha có quyền ghi chỉ là dấu hiệu cần xem xét; kiểm tra script và scheduler một cách thụ động, không cài module hoặc kích hoạt job.

Một package index Python riêng là ranh giới tin cậy khác khi một job tự động cài đặt package bằng danh tính OS khác. Đối chiếu chính xác job và tài khoản run-as với index đã cấu hình, tên package được chọn và khả năng người dùng ít đặc quyền phát hành hoặc thay thế package mà job thực sự sẽ cài đặt. Việc build source distribution có thể chạy build backend hoặc `setup.py` kiểu cũ dưới danh tính của installer; import package đã cài đặt là một đường thực thi riêng. Chỉ riêng listener của index, hash mật khẩu tải lên đọc được hoặc tên file package không chứng minh được chuỗi này. Xem xét job, quyền xác thực của index và nguồn gốc package mà không tải lên hoặc cài đặt bất cứ thứ gì trong quá trình liệt kê. Xem [giao diện build-system của pip](https://pip.pypa.io/en/stable/reference/build-system/) và [hướng dẫn cài đặt an toàn](https://pip.pypa.io/en/stable/topics/secure-installs/).

Agent có đặc quyền có thể thăm dò hàng đợi tác vụ do web service hoặc container riêng quản lý. Nếu danh tính có mức độ tin cậy thấp hơn có thể ghi vào database tác vụ của service, hãy xác định các hàng đó có thực sự được gửi đến agent hay không và liệu tác vụ command có chạy bằng danh tính OS của agent hay không. Xác nhận riêng quyền ghi database, session đích hoặc routing key, hoạt động polling, quyền của tác vụ và user hiệu lực của agent. Root bên trong container không đồng nghĩa với quyền truy cập host-root; ranh giới chỉ bị vượt qua nếu một consumer có đặc quyền trên host thực thi dữ liệu tác vụ do attacker kiểm soát. Kiểm tra metadata process, file database và service mà không sửa hàng đợi hoặc gửi tác vụ trong quá trình liệt kê.

Thay vào đó, một job định kỳ có thể đọc lệnh từ một hàng cấu hình trong database ứng dụng. Xác nhận role database ít đặc quyền có thể thay đổi đúng hàng đó, job đang hoạt động đọc nó sau khi thay đổi và giá trị được chuyển đến shell hoặc trình chạy lệnh tương đương dưới danh tính OS có đặc quyền cao hơn. Quyền ghi database hoặc một giá trị trông giống lệnh không tự chứng minh được việc thực thi; kiểm tra job và quyền mà không thay đổi hàng trong quá trình liệt kê thụ động.

Thông điệp trong hàng đợi cũng có thể chứa URL thay vì code. Nếu consumer có đặc quyền tải URL đó rồi nạp phản hồi dưới dạng Lua hoặc plugin thực thi khác, hãy xác minh quyền của publisher trên đúng exchange và routing key, binding tới queue được tiêu thụ, đường dẫn tải và nạp plugin, cùng danh tính hiệu lực của worker. [RabbitMQ định tuyến thông điệp đã publish qua các exchange](https://www.rabbitmq.com/docs/exchanges); chỉ riêng listener của broker hoặc thông tin đăng nhập hợp lệ không chứng minh thông điệp được chuyển đến worker này. Thông tin xác thực broker dạng plaintext bị thu thập là một manh mối riêng, đòi hỏi quyền truy cập packet capture thực tế và lưu lượng có thể đọc được; chúng không chứng minh quyền publish. Plugin Lua chỉ có thể gọi lệnh shell qua [`os.execute`](https://www.lua.org/manual/5.4/manual.html#pdf-os.execute) nếu API đó khả dụng trong runtime của nó. Xem xét cấu hình và code mà không thu thập lưu lượng, publish thông điệp hoặc tải plugin trong quá trình liệt kê thụ động.

Khi một Python service có đặc quyền mở endpoint HTTP hoặc socket cục bộ, script đọc được có thể cho thấy đường đi từ đầu vào đến code ngay cả khi quyền file không cho phép sửa đổi. Đối chiếu process và danh tính unit đang hoạt động với đúng script, listener, quyền của route và các trường do caller kiểm soát. Sau đó lần theo các trường này qua quá trình phân tích cú pháp và xác thực đến sink `eval()` hoặc `exec()` động. Cụ thể, tạo f-string mới từ văn bản request rồi đánh giá nó có thể diễn giải các trường thay thế do attacker cung cấp thành biểu thức Python ([cảnh báo về Python `eval`](https://docs.python.org/3/library/functions.html#eval); [ngữ nghĩa f-string](https://docs.python.org/3/reference/lexical_analysis.html#f-strings)). Chỉ thấy từ khóa `eval` hoặc binding loopback không chứng minh caller không đáng tin cậy có thể đến được sink; hãy xem xét luồng dữ liệu và quyền truy cập thực tế mà không gửi payload thử nghiệm trong quá trình liệt kê.

Cơ chế kiểm tra signed request trên route đó cần được xem xét riêng. Nếu source đọc được cho thấy khóa ký được tạo từ không gian đầu ra nhỏ hoặc dễ đoán, đồng thời service cung cấp một mẫu đã ký hợp lệ, chữ ký có thể không còn bảo vệ được sink `eval()` có đặc quyền. Xác minh chính xác cách tạo khóa và verifier, danh tính service đang chạy và quyền truy cập của caller cục bộ, cũng như liệu trường đã ký có đi đến sink hay không; việc import module [`random` của Python](https://docs.python.org/3/library/random.html) hoặc chỉ có mẫu chữ ký không chứng minh được bất kỳ điều kiện nào trong số đó. Python cũng cảnh báo rằng giới hạn `__builtins__` [không phải ranh giới bảo mật cho đầu vào `eval()` không đáng tin cậy](https://docs.python.org/3/library/functions.html#eval). Phân tích khóa ngoại tuyến và không gửi request giả mạo trong quá trình liệt kê thụ động.

Một thư mục `/etc/systemd/system/<unit>.service.d` trống nhưng có quyền ghi vẫn đáng lưu ý ngay cả khi file unit và mọi drop-in hiện có đều được bảo vệ: người dùng có thể tạo một override `.conf` mới. Kiểm tra danh tính hiện tại có quyền ghi và tìm kiếm trong thư mục hay không, unit đã được nạp và chạy với quyền root hay chưa, cũng như liệu có thể daemon reload rồi restart hay không. Quyền reload hoặc restart, timer hay lần khởi động sau có thể khiến thay đổi có hiệu lực; chỉ quyền ghi thư mục không làm thay đổi có hiệu lực ngay.

Với service đang chạy, theo các đường dẫn `EnvironmentFile=` ghi rõ trong phần `[Service]` của unit, kể cả các file có tên không bắt đầu bằng `.env`. Nếu người dùng ít đặc quyền có thể đọc một file, hãy liệt kê tên khóa trông giống thông tin xác thực như `API_TOKEN` hoặc `APP_SECRET_KEY` mà không in giá trị vào log dùng chung. Kiểm tra các override drop-in và tiền tố `-` tùy chọn khi xác định cấu hình unit có hiệu lực. Quyền đọc là manh mối về việc lộ thông tin xác thực; giá trị vẫn phải hợp lệ cho một hành động có đặc quyền thì mới dẫn đến leo thang quyền.

### Xử lý upload không đáng tin cậy với quyền cao

Một file watcher chạy bằng root có thể chuyển file từ thư mục upload mà người dùng có quyền ghi đến parser hoặc extractor chạy trong thời gian ngắn. Theo dõi script cha hoặc service của watcher đang chạy và xác nhận chính xác thư mục, người có thể đặt file vào đó, lệnh con và các đối số, cùng danh tính mà lệnh con chạy dưới quyền đó. Ảnh chụp process có thể cho thấy watcher nhưng bỏ lỡ extractor chạy giữa các lần upload. Đừng đặt payload thử nghiệm hoặc kích hoạt watcher trong quá trình liệt kê thụ động.

Một ví dụ cụ thể là chế độ giải nén của Binwalk (`-e`) xử lý dữ liệu PFS do attacker kiểm soát. [CVE-2022-4510](https://github.com/ReFirmLabs/binwalk/pull/617) cho phép PFS extractor ghi ra ngoài thư mục dự kiến, bao gồm cả đường dẫn plugin mà Binwalk có thể nạp sau đó. Upstream đã đưa bản sửa vào [2.3.4](https://github.com/ReFirmLabs/binwalk/releases/tag/v2.3.4), nhưng các bản backport của distribution có thể vẫn hiển thị phiên bản cũ hơn; hãy kiểm tra trạng thái bảo mật của package đã cài đặt, chẳng hạn [tracker của Debian](https://security-tracker.debian.org/tracker/CVE-2022-4510), trước khi đánh giá mức độ ảnh hưởng. Chỉ riêng phiên bản Binwalk đã cài đặt không chứng minh được đường leo thang quyền: một process có đặc quyền cao hơn phải thực sự gọi chức năng giải nén trên đầu vào mà người dùng ít đặc quyền có thể kiểm soát.

### Build được lập lịch với dependency cục bộ

`cargo run` được lập lịch sẽ biên dịch lại source bằng user run-as của job. Kiểm tra các dependency cục bộ `{ path = "..." }` trong manifest, cùng quyền của source và các thư mục cha của từng dependency, chứ không chỉ crate chính. Nếu người dùng ít đặc quyền có thể sửa dependency mà Cargo biên dịch, và job được lập lịch chạy kết quả đó, code đã biên dịch có thể chạy bằng user run-as đó. Xác nhận chính xác lệnh scheduler có hiệu lực, working directory, cách phân giải dependency và liệu có build lại hay không; một file source Rust có quyền ghi ở nơi khác chỉ là manh mối. Chỉ cần đọc manifest và metadata đường dẫn là đủ để sàng lọc thụ động. Xem [tài liệu Cargo về path dependency](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-path-dependencies).

## Tệp framebuffer Xvfb

`Xvfb -fbdir <directory>` sử dụng các file memory-mapped tên `Xvfb_screen<n>` cho các màn hình ảo. Nếu process Xvfb đang chạy của người dùng khác chỉ đến một thư mục có các file màn hình mà người dùng hiện tại đọc được, framebuffer có thể làm lộ nội dung desktop của người đó. Xác nhận đồng thời process, chủ sở hữu file và quyền truy cập; chỉ riêng việc đọc được file không chứng minh màn hình có nội dung hữu ích. Trước tiên hãy kiểm tra đường dẫn và metadata, không sao chép dữ liệu ảnh vào kết quả liệt kê dùng chung. [Tài liệu Xvfb](https://xorg.freedesktop.org/archive/X11R7.5/doc/man/man1/Xvfb.1.html) mô tả hành vi của `-fbdir`.

```bash
pgrep -a -x Xvfb
ls -l /path/from/-fbdir/Xvfb_screen*
```

## References

1. [Trang hướng dẫn `shmget(2)` của Linux](https://man7.org/linux/man-pages/man2/shmget.2.html)
2. [Trang hướng dẫn `ipcs(1)` của Linux](https://man7.org/linux/man-pages/man1/ipcs.1.html)
3. [Trang hướng dẫn `ipcs(1)` của OpenBSD](https://man.openbsd.org/ipcs.1)
4. [Cấu hình Consul agent: kiểm tra script](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/general)
5. [API đăng ký service của Consul agent](https://developer.hashicorp.com/consul/api-docs/agent/service)
6. [Cấu hình ACL của Consul](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/acl)
7. [Trợ giúp LibreOffice: mở socket cho các client API bên ngoài](https://help.libreoffice.org/latest/en-US/text/sbasic/shared/03/sf_intro.html)
8. [SDK LibreOffice: `XSystemShellExecute`](https://api.libreoffice.org/docs/idl/ref/interfacecom_1_1sun_1_1star_1_1system_1_1XSystemShellExecute.html)

{{#include ../../banners/hacktricks-training.md}}
